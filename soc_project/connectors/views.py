import json

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from accounts.decorators import admin_required, analyst_required
from accounts.models import (
    ACTION_CONNECTOR_CREATED,
    ACTION_CONNECTOR_DELETED,
    ACTION_CONNECTOR_TESTED,
    ACTION_CONNECTOR_UPDATED,
    log_action,
)

from .forms import (
    ADV_FIELDS_BY_TYPE,
    AUTH_TYPE_CHOICES_BY_TYPE,
    AUTH_TYPE_CREDENTIAL_FIELDS,
    CREDENTIAL_FIELDS_BY_TYPE,
    QUERY_LANGUAGE_LABEL_BY_TYPE,
    SIEMConnectorForm,
    required_credential_fields,
    required_extra_fields,
)
from .models import SIEMConnector
from . import splunk_service

# Prefills por tipo de SIEM cuando se llega desde la galería (?type=splunk, etc).
SIEM_TYPE_DEFAULTS = {
    'splunk': {
        'port': 8089,
        'auth_type': 'user_password',
        'custom_query': 'search index=soc_alerts',
        'batch_size': 50,
        'verify_ssl': False,  # típico en instancias locales con certificado autofirmado
    },
    'sentinel': {
        'host': 'management.azure.com',  # base real de la Azure Resource Manager API
        'custom_query': "SecurityIncident | where Status == 'New'",
    },
    'qradar': {
        'port': 443,
        'verify_ssl': False,  # instalaciones on-prem suelen usar certificado autofirmado
        'custom_query': "SELECT * FROM offenses WHERE status='OPEN'",
    },
    'elastic': {
        'port': 9200,
        'auth_type': 'api_key',
        'verify_ssl': False,
        'index_pattern': '.alerts-security.alerts-*',
    },
    'wazuh': {
        'port': 55000,
        'auth_type': 'user_password',
        'verify_ssl': False,
        'index_pattern': 'wazuh-alerts-*',
    },
    'cortex_xsiam': {
        'min_severity': 'MEDIUM',
    },
    # XDRs
    'crowdstrike': {
        'host': 'api.crowdstrike.com',
        'custom_query': "status:'new'+severity_name:['High','Critical']",
    },
    'defender_xdr': {
        'host': 'graph.microsoft.com',
        'min_severity': 'HIGH',
    },
    'cortex_xdr': {},
    'trendmicro': {
        'host': 'api.trendmicro.com',
    },
}


def _form_context():
    return {
        'credential_fields_json': json.dumps(CREDENTIAL_FIELDS_BY_TYPE),
        'auth_type_credential_fields_json': json.dumps(AUTH_TYPE_CREDENTIAL_FIELDS),
        'auth_type_choices_by_type_json': json.dumps(AUTH_TYPE_CHOICES_BY_TYPE),
        'adv_fields_by_type_json': json.dumps(ADV_FIELDS_BY_TYPE),
        'query_language_label_by_type_json': json.dumps(QUERY_LANGUAGE_LABEL_BY_TYPE),
    }


@login_required
@admin_required
def connector_list_view(request):
    connectors = SIEMConnector.objects.select_related('created_by').all()
    return render(request, 'connectors/connector_list.html', {
        'connectors': connectors,
        'source_choices': SIEMConnector.SOURCE_CHOICES,
    })


@login_required
@analyst_required
def connector_status_view(request):
    """
    Vista de solo lectura para analistas (N1/N2/N3) — mismo estado que ve el
    admin (conectado/error/no probado, últimas fechas de prueba y sync), pero
    sin credenciales, sin config de conexión y sin botones de gestión. Crear/
    editar/eliminar/probar sigue siendo exclusivo de admin_required.
    """
    connectors = SIEMConnector.objects.all()
    return render(request, 'connectors/connector_status.html', {'connectors': connectors})


@login_required
@admin_required
def connector_create_view(request):
    initial_type = request.GET.get('type', '')
    initial = {'source_type': initial_type, **SIEM_TYPE_DEFAULTS.get(initial_type, {})} if initial_type else None
    form = SIEMConnectorForm(initial=initial)

    if request.method == 'POST':
        form = SIEMConnectorForm(request.POST)
        if form.is_valid():
            connector = form.save(commit=False)
            connector.created_by = request.user
            connector.credentials = form.build_credentials()
            connector.extra_config = form.build_extra_config()
            connector.save()

            log_action(
                request.user,
                ACTION_CONNECTOR_CREATED,
                f'Conector "{connector.name}" ({connector.get_source_type_display()}) creado por {request.user.username}.',
            )
            messages.success(request, f'Conector "{connector.name}" creado. Todavía no fue probado.')
            return redirect('connector_list')

    return render(request, 'connectors/connector_form.html', {
        'form': form,
        'is_edit': False,
        **_form_context(),
    })


@login_required
@admin_required
def connector_edit_view(request, pk):
    connector = get_object_or_404(SIEMConnector, pk=pk)
    # extra_config no es secreto — a diferencia de credentials, sí se
    # prefillea en el form (el usuario ve y puede editar el valor real).
    form = SIEMConnectorForm(instance=connector, initial=connector.extra_config)

    if request.method == 'POST':
        form = SIEMConnectorForm(request.POST, instance=connector)
        if form.is_valid():
            connector = form.save(commit=False)
            connector.credentials = form.build_credentials()
            connector.extra_config = form.build_extra_config()
            # Cambiar config invalida la última prueba de conexión.
            connector.status = 'not_tested'
            connector.last_test_message = ''
            connector.save()

            log_action(
                request.user,
                ACTION_CONNECTOR_UPDATED,
                f'Conector "{connector.name}" editado por {request.user.username}.',
            )
            messages.success(request, f'Conector "{connector.name}" actualizado.')
            return redirect('connector_list')

    return render(request, 'connectors/connector_form.html', {
        'form': form,
        'is_edit': True,
        'connector': connector,
        **_form_context(),
    })


@login_required
@admin_required
@require_POST
def connector_delete_view(request, pk):
    connector = get_object_or_404(SIEMConnector, pk=pk)
    name = connector.name
    connector.delete()
    log_action(request.user, ACTION_CONNECTOR_DELETED, f'Conector "{name}" eliminado por {request.user.username}.')
    messages.success(request, f'Conector "{name}" eliminado.')
    return redirect('connector_list')


@login_required
@admin_required
@require_POST
def connector_test_view(request, pk):
    """
    Splunk: prueba de conexión REAL contra la REST API de management
    (ver splunk_service.py). El resto de los tipos siguen simulados — no
    hay una instancia real contra la cual probarlos todavía.
    """
    connector = get_object_or_404(SIEMConnector, pk=pk)

    missing_creds = [
        f for f in required_credential_fields(connector.source_type, connector.auth_type)
        if not connector.credentials.get(f)
    ]
    missing_extra = [
        f for f in required_extra_fields(connector.source_type)
        if not connector.extra_config.get(f)
    ]

    if not connector.host:
        success, message = False, 'Falta configurar el host del SIEM.'
    elif missing_creds:
        success, message = False, f'Faltan credenciales configuradas: {", ".join(missing_creds)}.'
    elif missing_extra:
        success, message = False, f'Falta configurar: {", ".join(missing_extra)}.'
    elif connector.source_type == 'splunk':
        success, message = splunk_service.test_connection(connector)
    else:
        success, message = True, f'Conexión simulada exitosa a {connector.get_source_type_display()}.'

    connector.status = 'connected' if success else 'error'
    connector.last_tested_at = timezone.now()
    connector.last_test_message = message
    connector.save(update_fields=['status', 'last_tested_at', 'last_test_message'])

    log_action(
        request.user,
        ACTION_CONNECTOR_TESTED,
        f'Prueba de conexión ({"éxito" if success else "error"}) al conector "{connector.name}" — {message}',
    )

    return JsonResponse({
        'status': connector.status,
        'status_label': connector.get_status_display(),
        'message': message,
        'tested_at': connector.last_tested_at.strftime('%d/%m/%Y %H:%M'),
    })
