import io
import csv
import json
from collections import Counter
from datetime import datetime, date

import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer

from django.contrib.auth.models import User
from django.http import JsonResponse
from django.utils import timezone

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db.models import Count, F, Q
from django.db.models.functions import TruncDate
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render

from accounts.decorators import admin_required, analyst_required, role_required
from accounts.models import (
    ACTION_PREDICT_JSON,
    ACTION_PREDICT_MANUAL,
    ACTION_UPLOAD_ALERTS,
    ACTION_PIPELINE_NORMALIZATION,
    ACTION_PIPELINE_EXPORT,
    ACTION_ALERT_ASSIGNED,
    ACTION_REPORT_EXPORT,
    ACTION_ALERT_EVALUATED,
    ACTION_ALERT_ESCALATED,
    log_action,
)

# Roles a los que cada rol puede asignar alertas (incluye auto-asignación)
ASSIGNMENT_TARGETS = {
    'admin':      ('admin', 'analyst_n3', 'analyst_n2', 'analyst_n1', 'trainee'),
    'analyst_n3': ('admin', 'analyst_n3'),
    'analyst_n2': ('analyst_n2', 'analyst_n3', 'analyst_n1'),
    'analyst_n1': ('analyst_n1', 'analyst_n2', 'trainee'),
    'trainee':    (),
}
from .forms import PredictionForm, JSONPredictionForm
from .models import Alert, TurnoNota, log_error
from .utils import predict_alert, predict_batch, extract_valid_fields, calculate_risk_score, calculate_shap_values, compute_shap_safe
from .pipeline import (
    REQUIRED_COLUMNS,
    OPTIONAL_COLUMNS,
    DISPLAY_COLUMNS,
    NUMERIC_COLUMNS,
    COLUMN_METADATA,
    parse_file,
    validate_columns,
    validate_column_types,
    apply_mapping,
    clean_records,
    export_to_csv,
    export_to_json,
)

@login_required
def dashboard_view(request):
    if request.method == 'POST':
        profile = getattr(request.user, 'profile', None)
        if profile and profile.role != 'trainee':
            contenido = request.POST.get('contenido', '').strip()
            if contenido:
                TurnoNota.objects.create(contenido=contenido, autor=request.user)
        return redirect('dashboard')

    alerts = Alert.objects.all()

    total_alerts     = alerts.count()
    total_pending    = alerts.filter(predicted_class='').count()
    total_malicioso  = alerts.filter(predicted_class='malicioso').count()
    total_investigar = alerts.filter(predicted_class='a_investigar').count()
    total_benigno    = alerts.filter(predicted_class='benigno').count()

    recent_alerts = alerts.order_by('-created_at')[:6]

    tactic_qs = (
        alerts
        .exclude(mitre_tactic='')
        .values('mitre_tactic')
        .annotate(total=Count('id'))
        .order_by('-total')[:6]
    )
    tactic_labels = [item['mitre_tactic'] for item in tactic_qs]
    tactic_counts  = [item['total'] for item in tactic_qs]

    severity_qs = (
        alerts
        .exclude(severity='')
        .values('severity')
        .annotate(total=Count('id'))
        .order_by('-total')
    )
    severity_labels = [item['severity'] for item in severity_qs]
    severity_counts  = [item['total'] for item in severity_qs]

    killchain_qs = (
        alerts
        .exclude(kill_chain_stage='')
        .values('kill_chain_stage')
        .annotate(total=Count('id'))
        .order_by('-total')
    )
    killchain_labels = [item['kill_chain_stage'] for item in killchain_qs]
    killchain_counts  = [item['total'] for item in killchain_qs]

    daily_data = (
        alerts
        .annotate(day=TruncDate('created_at'))
        .values('day')
        .annotate(total=Count('id'))
        .order_by('day')
    )
    daily_labels = [item['day'].strftime('%Y-%m-%d') for item in daily_data if item['day']]
    daily_totals = [item['total'] for item in daily_data]

    turno_notas = TurnoNota.objects.select_related('autor')[:5]

    context = {
        'total_alerts':     total_alerts,
        'total_pending':    total_pending,
        'total_malicioso':  total_malicioso,
        'total_investigar': total_investigar,
        'total_benigno':    total_benigno,
        'recent_alerts':    recent_alerts,
        'turno_notas':      turno_notas,

        'class_labels_json': json.dumps(['Benigno', 'A investigar', 'Malicioso']),
        'class_data_json':   json.dumps([total_benigno, total_investigar, total_malicioso]),

        'tactic_labels_json': json.dumps(tactic_labels),
        'tactic_data_json':   json.dumps(tactic_counts),

        'severity_labels_json': json.dumps(severity_labels),
        'severity_data_json':   json.dumps(severity_counts),

        'killchain_labels_json': json.dumps(killchain_labels),
        'killchain_data_json':   json.dumps(killchain_counts),

        'daily_labels_json': json.dumps(daily_labels),
        'daily_totals_json': json.dumps(daily_totals),
    }
    return render(request, 'predictor/dashboard.html', context)

@login_required
@analyst_required
def predict_view(request):
    form = PredictionForm()
    result = None
    probabilities = None

    if request.method == 'POST':
        form = PredictionForm(request.POST)
        if form.is_valid():
            data = form.cleaned_data
            try:
                result, probabilities = predict_alert(data)
                log_action(
                    request.user,
                    ACTION_PREDICT_MANUAL,
                    f'Predicción manual ejecutada. Resultado: {result}.',
                )
            except Exception as exc:
                log_error(request.user, 'predict_manual', str(exc))
                messages.error(
                    request,
                    'Ocurrió un error al ejecutar la predicción. '
                    'Verifique los datos ingresados e intente nuevamente.',
                )

    return render(request, 'predictor/predict.html', {
        'form': form,
        'result': result,
        'probabilities': probabilities,
    })

@login_required
@analyst_required
def predict_json_view(request):
    form = JSONPredictionForm()
    result = None
    probabilities = None
    cleaned_payload = None
    missing_fields = []

    if request.method == 'POST':
        form = JSONPredictionForm(request.POST)
        if form.is_valid():
            payload = form.cleaned_data['payload']
            try:
                cleaned_payload = extract_valid_fields(payload)
                missing_fields = [k for k, v in cleaned_payload.items() if v is None]

                if not missing_fields:
                    result, probabilities = predict_alert(cleaned_payload)
                    log_action(
                        request.user,
                        ACTION_PREDICT_JSON,
                        f'Predicción por JSON ejecutada. Resultado: {result}.',
                    )
            except Exception as exc:
                log_error(request.user, 'predict_json', str(exc))
                messages.error(
                    request,
                    'El payload JSON no pudo ser procesado. '
                    'Verifique que los campos y valores sean correctos.',
                )

    return render(request, 'predictor/predict_json.html', {
        'form': form,
        'result': result,
        'probabilities': probabilities,
        'cleaned_payload': cleaned_payload,
        'missing_fields': missing_fields,
    })

# ─────────────────────────────────────────────────────────────────────────────
# HU028 — Historial de alertas procesadas (n2 / n3 / admin)
# ─────────────────────────────────────────────────────────────────────────────

@login_required
@role_required('admin', 'analyst_n3', 'analyst_n2')
def alert_history_view(request):
    qs = (
        Alert.objects
        .exclude(predicted_class='')
        .select_related('created_by', 'investigated_by', 'assigned_to', 'ml_evaluated_by')
        .order_by('-created_at')
    )

    date_from = request.GET.get('date_from', '').strip()
    if date_from:
        qs = qs.filter(created_at__date__gte=date_from)

    date_to = request.GET.get('date_to', '').strip()
    if date_to:
        qs = qs.filter(created_at__date__lte=date_to)

    class_filter = request.GET.get('predicted_class', '').strip()
    if class_filter:
        qs = qs.filter(predicted_class=class_filter)

    status_filter = request.GET.get('investigation_status', '').strip()
    if status_filter:
        qs = qs.filter(investigation_status=status_filter)

    tactic_filter = request.GET.get('mitre_tactic', '').strip()
    if tactic_filter:
        qs = qs.filter(mitre_tactic__icontains=tactic_filter)

    attack_filter = request.GET.get('attack_type', '').strip()
    if attack_filter:
        qs = qs.filter(attack_type__icontains=attack_filter)

    eval_filter = request.GET.get('ml_evaluation', '').strip()
    if eval_filter == '__none__':
        qs = qs.filter(ml_evaluation='')
    elif eval_filter:
        qs = qs.filter(ml_evaluation=eval_filter)

    analyst_filter = request.GET.get('analyst', '').strip()
    if analyst_filter:
        qs = qs.filter(investigated_by__username__icontains=analyst_filter)

    priority_filter = request.GET.get('analyst_priority', '').strip()
    if priority_filter == 'none':
        qs = qs.filter(analyst_priority='')
    elif priority_filter:
        qs = qs.filter(analyst_priority=priority_filter)

    risk_min = request.GET.get('risk_min', '').strip()
    risk_max = request.GET.get('risk_max', '').strip()
    try:
        if risk_min:
            qs = qs.filter(risk_score__gte=float(risk_min))
    except ValueError:
        risk_min = ''
    try:
        if risk_max:
            qs = qs.filter(risk_score__lte=float(risk_max))
    except ValueError:
        risk_max = ''

    total_count = qs.count()
    paginator = Paginator(qs, 10)
    page_obj = paginator.get_page(request.GET.get('page'))

    mitre_tactics = (
        Alert.objects.exclude(mitre_tactic='')
        .values_list('mitre_tactic', flat=True)
        .distinct().order_by('mitre_tactic')
    )

    _p = request.GET.copy()
    _p.pop('page', None)

    return render(request, 'predictor/alert_history.html', {
        'page_obj':         page_obj,
        'total_count':      total_count,
        'date_from':        date_from,
        'date_to':          date_to,
        'class_filter':     class_filter,
        'status_filter':    status_filter,
        'tactic_filter':    tactic_filter,
        'attack_filter':    attack_filter,
        'eval_filter':      eval_filter,
        'analyst_filter':   analyst_filter,
        'priority_filter':  priority_filter,
        'risk_min':         risk_min,
        'risk_max':         risk_max,
        'mitre_tactics':    mitre_tactics,
        'status_choices':   Alert.INVESTIGATION_STATUS_CHOICES,
        'eval_choices':     Alert.ML_EVALUATION_CHOICES,
        'priority_choices': Alert.ANALYST_PRIORITY_CHOICES,
        'query_string':     _p.urlencode(),
    })


@login_required
@analyst_required
def upload_alerts_view(request):
    context = {'processed': [], 'failed': [], 'error': None, 'summary': None}

    if request.method != 'POST':
        return render(request, 'predictor/upload_alerts.html', context)

    file = request.FILES.get('file')

    if not file:
        context['error'] = 'No se seleccionó ningún archivo.'
        return render(request, 'predictor/upload_alerts.html', context)

    if file.size == 0:
        context['error'] = 'El archivo está vacío.'
        return render(request, 'predictor/upload_alerts.html', context)

    if file.size > 10 * 1024 * 1024:
        context['error'] = 'El archivo supera el límite de 10 MB.'
        return render(request, 'predictor/upload_alerts.html', context)

    filename = file.name.lower()

    if filename.endswith('.json'):
        records, error = _parse_json_file(file)
        source = 'upload_json'
    elif filename.endswith('.csv'):
        records, error = _parse_csv_file(file)
        source = 'upload_csv'
    else:
        context['error'] = f'Tipo de archivo no soportado: "{file.name}". Use .json o .csv.'
        return render(request, 'predictor/upload_alerts.html', context)

    if error:
        context['error'] = error
        return render(request, 'predictor/upload_alerts.html', context)

    if not records:
        context['error'] = 'El archivo no contiene registros.'
        return render(request, 'predictor/upload_alerts.html', context)

    processed = []
    failed = []
    error_count = 0

    try:
        # Fase 1 — validación y limpieza vectorizada con pandas
        _, missing_cols = validate_columns(records)
        if missing_cols:
            context['error'] = f'El archivo no contiene las columnas requeridas: {", ".join(missing_cols)}'
            return render(request, 'predictor/upload_alerts.html', context)

        clean, stats = clean_records(records)

        if not clean:
            context['error'] = 'Ningún registro pasó la validación. Verificá el formato del archivo.'
            return render(request, 'predictor/upload_alerts.html', context)

        error_count = stats['duplicates_removed'] + stats['invalid_rows_removed']
        if error_count > 0:
            parts = []
            if stats['duplicates_removed']:
                parts.append(f'{stats["duplicates_removed"]} duplicados')
            if stats['invalid_rows_removed']:
                parts.append(f'{stats["invalid_rows_removed"]} con valores inválidos')
            failed.append({
                'record': '—',
                'errors': f'Registros removidos durante limpieza: {", ".join(parts)}.',
            })

        valid_records = [(i + 1, rec, rec) for i, rec in enumerate(clean)]

        if valid_records:
            # Fase 2 — predicción en batch
            valid_data_list = [d for _, _, d in valid_records]
            try:
                batch_results = predict_batch(valid_data_list)
            except Exception as exc:
                log_error(request.user, 'upload_alerts', f'predict_batch falló, usando predict_alert por registro: {exc}')
                batch_results = None

            # Fase 3 — construir instancias Alert sin tocar la DB
            alert_instances = []
            pending_processed = []
            for i, (index, record, data) in enumerate(valid_records):
                try:
                    if batch_results is not None:
                        predicted_class, probabilities = batch_results[i]
                    else:
                        predicted_class, probabilities = predict_alert(data)
                    risk_score = calculate_risk_score(probabilities)
                    shap_data = None  # se calcula lazy al primer clic en SHAP

                    alert_instances.append(Alert(
                        event_category=data.get('event_category', ''),
                        protocol=data.get('protocol', ''),
                        traffic_type=data.get('traffic_type', ''),
                        mitre_tactic=data.get('mitre_tactic', ''),
                        kill_chain_stage=data.get('kill_chain_stage', ''),
                        failed_login_attempts=data.get('failed_login_attempts', 0),
                        request_rate_per_min=data.get('request_rate_per_min', 0.0),
                        ids_ips_alert=data.get('ids_ips_alert', ''),
                        asset_criticality=data.get('asset_criticality', ''),
                        log_source=data.get('log_source', ''),
                        firewall_action=data.get('firewall_action', ''),
                        severity=data.get('severity', ''),
                        has_threat_family=data.get('has_threat_family', 0),
                        evidence_role=data.get('evidence_role', 'unknown'),
                        os_family=data.get('os_family', 'unknown'),
                        correlation_id=data.get('correlation_id', 'unknown'),
                        mitre_techniques=data.get('mitre_techniques', ''),
                        attack_type=record.get('attack_type', ''),
                        attack_signature=record.get('attack_signature', ''),
                        malware_indicator=record.get('malware_indicator', ''),
                        label=record.get('label', ''),
                        predicted_class=predicted_class,
                        risk_score=risk_score,
                        probabilities=probabilities,
                        shap_values=shap_data,
                        created_by=request.user,
                    ))
                    pending_processed.append({'record': index, 'predicted_class': predicted_class, 'risk_score': risk_score})

                except Exception as exc:
                    log_error(request.user, 'upload_alerts', f'Registro #{index}: {exc}')
                    failed.append({
                        'record': index,
                        'errors': {'_error': ['Error interno al procesar este registro. El resto del archivo se procesó normalmente.']},
                    })

            # Fase 4 — un único INSERT para todos los registros válidos
            if alert_instances:
                Alert.objects.bulk_create(alert_instances)
                processed.extend(pending_processed)

    except Exception as exc:
        log_error(request.user, 'upload_alerts', str(exc))
        context['error'] = (
            'Ocurrió un error inesperado durante el procesamiento del archivo. '
            'Verifique el formato e intente nuevamente.'
        )
        return render(request, 'predictor/upload_alerts.html', context)

    if processed:
        log_action(
            request.user,
            ACTION_UPLOAD_ALERTS,
            f'Archivo "{file.name}" subido: {len(processed)} alertas importadas, {error_count} con errores.',
        )
        messages.success(
            request,
            f'Alertas importadas: {len(processed)} de {len(records)} registros procesados correctamente.'
        )
        return redirect('alert_list')

    context['processed'] = processed
    context['failed'] = failed
    context['summary'] = {
        'file': file.name,
        'total': len(records),
        'ok': len(processed),
        'errors': error_count,
    }
    return render(request, 'predictor/upload_alerts.html', context)


def _friendly_serializer_errors(errors: dict) -> dict:
    """Convierte errores de serializer en mensajes amigables para el usuario."""
    friendly = {}
    field_names = {
        'event_category': 'Categoría de evento',
        'attack_type': 'Tipo de ataque',
        'attack_signature': 'Firma de ataque',
        'protocol': 'Protocolo',
        'traffic_type': 'Tipo de tráfico',
        'mitre_tactic': 'Táctica MITRE',
        'kill_chain_stage': 'Etapa kill chain',
        'failed_login_attempts': 'Intentos de login fallidos',
        'request_rate_per_min': 'Tasa de peticiones/min',
        'ids_ips_alert': 'Alerta IDS/IPS',
        'malware_indicator': 'Indicador de malware',
        'asset_criticality': 'Criticidad del activo',
        'log_source': 'Fuente de log',
        'firewall_action': 'Acción del firewall',
        'severity': 'Severidad',
        'label': 'Etiqueta',
    }
    for field, messages_list in errors.items():
        label = field_names.get(field, field)
        friendly[label] = [str(m) for m in messages_list]
    return friendly


@login_required
def alert_list_view(request):
    is_admin = request.user.profile.is_admin
    role     = request.user.profile.role
    qs = Alert.objects.select_related('created_by', 'assigned_to').filter(is_incident=False)

    # Filtros automáticos por rol — no pueden ser sobreescritos por el usuario
    if role in ('analyst_n1', 'trainee'):
        qs = qs.filter(predicted_class='benigno')
    elif role == 'analyst_n2':
        qs = qs.exclude(predicted_class__in=('benigno', ''))

    # Toggle "Mis alertas" / "Todas las alertas"
    mine = request.GET.get('mine', '').strip()
    if mine == '1':
        qs = qs.filter(created_by=request.user)

    search = request.GET.get('q', '').strip()
    if search:
        qs = qs.filter(
            Q(event_category__icontains=search)
            | Q(attack_type__icontains=search)
            | Q(attack_signature__icontains=search)
            | Q(protocol__icontains=search)
            | Q(severity__icontains=search)
            | Q(mitre_tactic__icontains=search)
            | Q(log_source__icontains=search)
            | Q(firewall_action__icontains=search)
        )

    severity_filter = request.GET.get('severity', '').strip()
    if severity_filter:
        qs = qs.filter(severity__iexact=severity_filter)

    # Filtro por clase ML ('pending' → sin clasificar)
    class_filter = request.GET.get('predicted_class', '').strip()
    if class_filter == 'pending':
        qs = qs.filter(predicted_class='')
    elif class_filter:
        qs = qs.filter(predicted_class=class_filter)

    # Filtro por estado de investigación
    status_filter = request.GET.get('investigation_status', '').strip()
    if status_filter:
        qs = qs.filter(investigation_status=status_filter)

    # Filtro por prioridad del analista ('none' → sin ajuste)
    priority_filter = request.GET.get('analyst_priority', '').strip()
    if priority_filter == 'none':
        qs = qs.filter(analyst_priority='')
    elif priority_filter:
        qs = qs.filter(analyst_priority=priority_filter)

    # Filtro por usuario: admins pueden filtrar por cualquier usuario;
    # usuarios normales solo pueden aplicar el toggle "mine"
    user_filter = request.GET.get('user', '').strip()
    if user_filter and is_admin:
        qs = qs.filter(created_by__username__icontains=user_filter)

    date_from = request.GET.get('date_from', '').strip()
    if date_from:
        qs = qs.filter(created_at__date__gte=date_from)

    date_to = request.GET.get('date_to', '').strip()
    if date_to:
        qs = qs.filter(created_at__date__lte=date_to)

    risk_min = request.GET.get('risk_min', '').strip()
    risk_max = request.GET.get('risk_max', '').strip()
    try:
        if risk_min:
            qs = qs.filter(risk_score__gte=float(risk_min))
    except ValueError:
        risk_min = ''
    try:
        if risk_max:
            qs = qs.filter(risk_score__lte=float(risk_max))
    except ValueError:
        risk_max = ''

    assigned_filter = request.GET.get('assigned_to', '').strip()
    if assigned_filter:
        qs = qs.filter(assigned_to__username__icontains=assigned_filter)

    order = request.GET.get('order', 'date_desc').strip()
    _order_map = {
        'risk_desc': F('risk_score').desc(nulls_last=True),
        'risk_asc':  F('risk_score').asc(nulls_last=True),
        'date_desc': '-created_at',
        'date_asc':  'created_at',
    }
    qs = qs.order_by(_order_map.get(order, '-created_at'))

    severity_choices = (
        Alert.objects.values_list('severity', flat=True)
        .distinct()
        .order_by('severity')
    )

    # Contador de alertas pendientes (sin clasificar) para mostrar el botón
    pending_base = Alert.objects.filter(predicted_class='')
    if not is_admin:
        pending_base = pending_base.filter(created_by=request.user)
    pending_count = pending_base.count()

    paginator = Paginator(qs, 10)
    page_obj = paginator.get_page(request.GET.get('page'))

    _qs_params = request.GET.copy()
    _qs_params.pop('page', None)

    context = {
        'page_obj': page_obj,
        'is_admin': is_admin,
        'role':     role,
        'mine': mine,
        'search': search,
        'severity_filter': severity_filter,
        'class_filter': class_filter,
        'user_filter': user_filter,
        'date_from': date_from,
        'date_to': date_to,
        'severity_choices': severity_choices,
        'pending_count':    pending_count,
        'total_count':      qs.count(),
        'order':            order,
        'priority_filter':  priority_filter,
        'status_filter':    status_filter,
        'risk_min':         risk_min,
        'risk_max':         risk_max,
        'assigned_filter':  assigned_filter,
        'query_string':     _qs_params.urlencode(),
    }
    return render(request, 'predictor/alert_list.html', context)


@login_required
@analyst_required
def predict_pending_view(request):
    """Clasifica todas las alertas sin predicción y asigna risk_score."""
    if request.method != 'POST':
        return redirect('alert_list')

    is_admin = request.user.profile.is_admin
    qs = Alert.objects.filter(predicted_class='')
    if not is_admin:
        qs = qs.filter(created_by=request.user)

    classified = 0
    for alert in qs.iterator():
        data = {
            'event_category'        : alert.event_category,
            'protocol'              : alert.protocol,
            'traffic_type'          : alert.traffic_type,
            'mitre_tactic'          : alert.mitre_tactic,
            'kill_chain_stage'      : alert.kill_chain_stage,
            'failed_login_attempts' : alert.failed_login_attempts,
            'request_rate_per_min'  : alert.request_rate_per_min,
            'ids_ips_alert'         : alert.ids_ips_alert,
            'asset_criticality'     : alert.asset_criticality,
            'log_source'            : alert.log_source,
            'firewall_action'       : alert.firewall_action,
            'severity'              : alert.severity,
            'has_threat_family'     : alert.has_threat_family,
            'evidence_role'         : alert.evidence_role,
            'os_family'             : alert.os_family,
            'correlation_id'        : alert.correlation_id,
            'mitre_techniques'      : alert.mitre_techniques,
        }
        try:
            predicted_class, probabilities = predict_alert(data)
            alert.predicted_class = predicted_class
            alert.risk_score = calculate_risk_score(probabilities)
            alert.probabilities = probabilities
            alert.shap_values = compute_shap_safe(data)
            alert.save(update_fields=['predicted_class', 'risk_score', 'probabilities', 'shap_values'])
            classified += 1
        except Exception as exc:
            log_error(request.user, 'predict_pending', str(exc))

    if classified:
        messages.success(
            request,
            f'{classified} alerta{"s" if classified != 1 else ""} clasificada{"s" if classified != 1 else ""} correctamente.',
        )
    else:
        messages.info(request, 'No había alertas pendientes de clasificar.')

    return redirect('alert_list')


def _normalize_keys(record):
    """Normaliza claves: minúsculas, sin espacios extremos, espacios → guión bajo."""
    return {
        k.strip().lower().replace(' ', '_'): v
        for k, v in record.items()
    }


def _parse_json_file(file):
    try:
        content = file.read().decode('utf-8')
        data = json.loads(content)
    except UnicodeDecodeError:
        return None, 'El archivo no tiene codificación UTF-8 válida.'
    except json.JSONDecodeError:
        return None, 'El contenido del archivo no es JSON válido.'

    if isinstance(data, dict):
        data = [data]

    if not isinstance(data, list):
        return None, 'El JSON debe ser un array de objetos o un único objeto.'

    if not all(isinstance(item, dict) for item in data):
        return None, 'Cada elemento del JSON debe ser un objeto (clave-valor).'

    return [_normalize_keys(item) for item in data], None


def _parse_csv_file(file):
    try:
        content = file.read().decode('utf-8-sig')  # utf-8-sig maneja BOM de Excel
        reader = csv.DictReader(io.StringIO(content))
        records = [_normalize_keys(row) for row in reader]
    except UnicodeDecodeError:
        return None, 'El archivo CSV no tiene codificación UTF-8 válida.'
    except csv.Error:
        return None, 'El archivo CSV tiene un formato incorrecto.'

    if not records:
        return None, 'El CSV no contiene filas de datos (solo encabezado o vacío).'

    return records, None


# ─────────────────────────────────────────────────────────────────────────────
# HU009 — Pipeline de normalización de datos
# ─────────────────────────────────────────────────────────────────────────────

_PIPELINE_SESSION_KEYS = [
    'pipeline_records',
    'pipeline_filename',
    'pipeline_columns',
    'pipeline_missing',
    'pipeline_mapping',
    'pipeline_clean_records',
    'pipeline_stats',
]


def _clear_pipeline_session(session):
    for key in _PIPELINE_SESSION_KEYS:
        session.pop(key, None)


@login_required
@analyst_required
def pipeline_view(request):
    """Paso 1: Formulario de carga de archivo."""
    _clear_pipeline_session(request.session)
    return render(request, 'predictor/pipeline.html', {
        'stage': 'upload',
        'required_cols': REQUIRED_COLUMNS,
    })


@login_required
@analyst_required
def pipeline_upload_view(request):
    """POST: Parsea el archivo, detecta columnas y decide el siguiente paso."""
    if request.method != 'POST':
        return redirect('pipeline')

    def _render_upload_error(error):
        return render(request, 'predictor/pipeline.html', {
            'stage': 'upload',
            'required_cols': REQUIRED_COLUMNS,
            'error': error,
        })

    file = request.FILES.get('file')
    if not file:
        return _render_upload_error('No se seleccionó ningún archivo.')
    if file.size == 0:
        return _render_upload_error('El archivo está vacío.')
    if file.size > 10 * 1024 * 1024:
        return _render_upload_error('El archivo supera el límite de 10 MB.')

    try:
        records, error = parse_file(file)
        if error:
            return _render_upload_error(error)
        if not records:
            return _render_upload_error('El archivo no contiene registros.')

        detected_cols, missing_cols = validate_columns(records)
        missing_optional = [c for c in OPTIONAL_COLUMNS if c not in detected_cols]
        missing_display  = [c for c in DISPLAY_COLUMNS  if c not in detected_cols]

        request.session['pipeline_records']          = records
        request.session['pipeline_filename']         = file.name
        request.session['pipeline_columns']          = detected_cols
        request.session['pipeline_missing']          = missing_cols
        request.session['pipeline_missing_optional'] = missing_optional
        request.session['pipeline_missing_display']  = missing_display
        request.session['pipeline_already_saved']    = False
    except Exception as exc:
        log_error(request.user, 'pipeline_upload', str(exc))
        return _render_upload_error(
            'No se pudo procesar el archivo. Verifique que el formato sea '
            'CSV o JSON válido e intente nuevamente.'
        )

    return redirect('pipeline_map')


def _map_ctx(detected_cols, filename, missing_required, missing_optional, missing_display, prev_mapping, type_warnings):
    """Construye el contexto del template para el paso de mapeo."""
    def _rows(cols):
        result = []
        for col in cols:
            meta = COLUMN_METADATA.get(col, {})
            result.append({
                'name':        col,
                'desc':        meta.get('desc', ''),
                'example':     meta.get('example', ''),
                'dtype':       meta.get('type', 'str'),
                'prev_source': prev_mapping.get(col, ''),
                'warning':     type_warnings.get(col),
            })
        return result

    req_rows  = _rows(missing_required)
    opt_rows  = _rows(missing_optional)
    disp_rows = _rows(missing_display)

    sections = [
        {
            'rows':           req_rows,
            'title':          'Columnas requeridas — el modelo no puede predecir sin estas',
            'header_class':   'bg-red-500/10 border-red-500/20',
            'dot_class':      'bg-red-400',
            'title_class':    'text-red-400',
            'col_name_class': 'text-red-400',
        },
        {
            'rows':           opt_rows,
            'title':          'Columnas opcionales — mejoran la predicción ML',
            'header_class':   'bg-amber-500/10 border-amber-500/20',
            'dot_class':      'bg-amber-400',
            'title_class':    'text-amber-400',
            'col_name_class': 'text-amber-400',
        },
        {
            'rows':           disp_rows,
            'title':          'Columnas de visualización — solo para la tabla de alertas, no afectan la predicción',
            'header_class':   'bg-slate-700/40 border-slate-600',
            'dot_class':      'bg-slate-400',
            'title_class':    'text-slate-400',
            'col_name_class': 'text-slate-400',
        },
    ]

    return {
        'stage':           'map',
        'detected_cols':   detected_cols,
        'filename':        filename,
        'required_rows':   req_rows,
        'optional_rows':   opt_rows,
        'display_rows':    disp_rows,
        'sections':        sections,
        'type_warnings':   type_warnings,
    }


@login_required
@analyst_required
def pipeline_map_view(request):
    """Paso 2: Mapeo de columnas — requeridas, opcionales y de visualización."""
    records = request.session.get('pipeline_records')
    if not records:
        return redirect('pipeline')

    detected_cols    = request.session.get('pipeline_columns', [])
    missing_required = request.session.get('pipeline_missing', [])
    missing_optional = request.session.get('pipeline_missing_optional', [])
    missing_display  = request.session.get('pipeline_missing_display', [])
    filename         = request.session.get('pipeline_filename', '')

    all_missing = missing_required + missing_optional + missing_display

    def _build_col_rows(cols, prev_mapping, type_warnings):
        rows = []
        for col in cols:
            meta = COLUMN_METADATA.get(col, {})
            rows.append({
                'name':         col,
                'desc':         meta.get('desc', ''),
                'example':      meta.get('example', ''),
                'dtype':        meta.get('type', 'str'),
                'prev_source':  prev_mapping.get(col, ''),
                'warning':      type_warnings.get(col),
            })
        return rows

    if request.method == 'POST':
        mapping = {}
        for col in all_missing:
            source = request.POST.get(f'map_{col}', '').strip()
            if source and source != '__skip__':
                mapping[col] = source

        type_warnings = validate_column_types(records, mapping)
        prev_mapping  = {col: request.POST.get(f'map_{col}', '') for col in all_missing}

        if type_warnings and not request.POST.get('force_continue'):
            return render(request, 'predictor/pipeline.html', _map_ctx(
                detected_cols, filename, missing_required, missing_optional, missing_display,
                prev_mapping, type_warnings,
            ))

        mapped_records = apply_mapping(records, mapping)
        new_detected, new_missing        = validate_columns(mapped_records)
        new_missing_optional = [c for c in OPTIONAL_COLUMNS if c not in new_detected]
        new_missing_display  = [c for c in DISPLAY_COLUMNS  if c not in new_detected]

        request.session['pipeline_records']          = mapped_records
        request.session['pipeline_mapping']          = mapping
        request.session['pipeline_columns']          = new_detected
        request.session['pipeline_missing']          = new_missing
        request.session['pipeline_missing_optional'] = new_missing_optional
        request.session['pipeline_missing_display']  = new_missing_display

        return redirect('pipeline_normalize')

    return render(request, 'predictor/pipeline.html', _map_ctx(
        detected_cols, filename, missing_required, missing_optional, missing_display, {}, {},
    ))


@login_required
@analyst_required
def pipeline_normalize_view(request):
    """
    GET: Muestra preview de datos en bruto y botón de normalización.
    POST: Ejecuta la limpieza y redirige al preview limpio.
    """
    records = request.session.get('pipeline_records')
    if not records:
        return redirect('pipeline')

    detected_cols = request.session.get('pipeline_columns', [])
    filename = request.session.get('pipeline_filename', '')
    missing_cols = [col for col in REQUIRED_COLUMNS if col not in detected_cols]

    if request.method == 'POST':
        if request.session.get('pipeline_already_saved'):
            return redirect('pipeline_preview')

        try:
            clean, stats = clean_records(records)
        except Exception as exc:
            log_error(request.user, 'pipeline_normalize', str(exc))
            return render(request, 'predictor/pipeline.html', {
                'stage': 'normalize',
                'filename': filename,
                'detected_cols': detected_cols,
                'preview_rows': [],
                'total_records': len(records),
                'missing_cols': missing_cols,
                'error': (
                    'Ocurrió un error durante la normalización de los datos. '
                    'Verifique que los campos numéricos contengan valores válidos.'
                ),
            })

        if not clean:
            return render(request, 'predictor/pipeline.html', {
                'stage': 'normalize',
                'filename': filename,
                'detected_cols': detected_cols,
                'preview_rows': [],
                'total_records': len(records),
                'missing_cols': missing_cols,
                'error': 'No quedaron registros tras la limpieza. Verifica el archivo.',
                'stats': stats,
            })

        request.session['pipeline_clean_records'] = clean
        request.session['pipeline_stats'] = stats

        # Batch prediction — aprovecha correlation_id para features reales por incidente.
        # Si falla (datos corruptos, columnas inesperadas), cae al fallback por registro.
        try:
            batch_results = predict_batch(clean)
        except Exception as exc:
            log_error(request.user, 'pipeline_normalize_predict', str(exc))
            batch_results = None

        saved_count = 0
        failed_count = 0

        alert_instances = []
        for i, record in enumerate(clean):
            try:
                if batch_results is not None:
                    predicted_class, probabilities = batch_results[i]
                else:
                    predicted_class, probabilities = predict_alert(record)
                risk_score = calculate_risk_score(probabilities)
                shap_data = None  # se calcula lazy al primer clic en SHAP
                alert_instances.append(Alert(
                    event_category=record.get('event_category', ''),
                    protocol=record.get('protocol', ''),
                    traffic_type=record.get('traffic_type', ''),
                    mitre_tactic=record.get('mitre_tactic', ''),
                    kill_chain_stage=record.get('kill_chain_stage', ''),
                    failed_login_attempts=int(record.get('failed_login_attempts') or 0),
                    request_rate_per_min=float(record.get('request_rate_per_min') or 0.0),
                    ids_ips_alert=record.get('ids_ips_alert', ''),
                    asset_criticality=record.get('asset_criticality', ''),
                    log_source=record.get('log_source', ''),
                    firewall_action=record.get('firewall_action', ''),
                    severity=record.get('severity', ''),
                    has_threat_family=int(record.get('has_threat_family') or 0),
                    evidence_role=record.get('evidence_role', 'unknown'),
                    os_family=record.get('os_family', 'unknown'),
                    correlation_id=record.get('correlation_id', 'unknown'),
                    mitre_techniques=record.get('mitre_techniques', ''),
                    attack_type=record.get('attack_type', ''),
                    attack_signature=record.get('attack_signature', ''),
                    malware_indicator=record.get('malware_indicator', ''),
                    label=record.get('label', ''),
                    predicted_class=predicted_class,
                    risk_score=risk_score,
                    probabilities=probabilities,
                    shap_values=shap_data,
                    created_by=request.user,
                ))
            except Exception as exc:
                log_error(request.user, 'pipeline_normalize_save', str(exc))
                failed_count += 1

        if alert_instances:
            try:
                Alert.objects.bulk_create(alert_instances)
                saved_count = len(alert_instances)
            except Exception as exc:
                log_error(request.user, 'pipeline_normalize_save', f'bulk_create: {exc}')
                failed_count += len(alert_instances)

        request.session['pipeline_saved_count'] = saved_count
        request.session['pipeline_failed_count'] = failed_count
        request.session['pipeline_already_saved'] = True
        request.session.modified = True

        log_action(
            request.user,
            ACTION_PIPELINE_NORMALIZATION,
            (
                f'Ejecutó pipeline de normalización sobre "{filename}". '
                f'Registros procesados: {stats["total_clean"]}. '
                f'Duplicados eliminados: {stats["duplicates_removed"]}. '
                f'Nulos rellenados: {stats["nulls_filled"]}. '
                f'Alertas guardadas: {saved_count}.'
            ),
        )
        return redirect('pipeline_preview')

    preview_rows = [
        [record.get(col, '') for col in detected_cols]
        for record in records[:10]
    ]

    return render(request, 'predictor/pipeline.html', {
        'stage': 'normalize',
        'filename': filename,
        'detected_cols': detected_cols,
        'preview_rows': preview_rows,
        'total_records': len(records),
        'missing_cols': missing_cols,
    })


@login_required
@analyst_required
def pipeline_preview_view(request):
    """Paso 4: Preview del dataset limpio y botones de exportación."""
    clean = request.session.get('pipeline_clean_records')
    if not clean:
        return redirect('pipeline')

    preview_rows = [
        [record.get(col, '') for col in REQUIRED_COLUMNS]
        for record in clean[:10]
    ]

    return render(request, 'predictor/pipeline.html', {
        'stage': 'preview',
        'filename': request.session.get('pipeline_filename', ''),
        'stats': request.session.get('pipeline_stats', {}),
        'required_cols': REQUIRED_COLUMNS,
        'preview_rows': preview_rows,
        'total_records': len(clean),
        'saved_count': request.session.get('pipeline_saved_count', 0),
        'failed_count': request.session.get('pipeline_failed_count', 0),
    })


@login_required
@analyst_required
def pipeline_export_view(request):
    """POST: Genera y descarga el dataset limpio en CSV o JSON."""
    if request.method != 'POST':
        return redirect('pipeline_preview')

    clean = request.session.get('pipeline_clean_records')
    if not clean:
        return redirect('pipeline')

    export_format = request.POST.get('format', 'csv').lower()
    filename = request.session.get('pipeline_filename', 'dataset')
    base_name = filename.rsplit('.', 1)[0] if '.' in filename else filename

    try:
        if export_format == 'json':
            content = export_to_json(clean)
            response = HttpResponse(content, content_type='application/json; charset=utf-8')
            response['Content-Disposition'] = (
                f'attachment; filename="{base_name}_clean.json"'
            )
        else:
            content = export_to_csv(clean)
            response = HttpResponse(content, content_type='text/csv; charset=utf-8')
            response['Content-Disposition'] = (
                f'attachment; filename="{base_name}_clean.csv"'
            )
    except Exception as exc:
        log_error(request.user, 'pipeline_export', str(exc))
        messages.error(
            request,
            'No se pudo generar el archivo de exportación. Intente nuevamente.',
        )
        return redirect('pipeline_preview')

    log_action(
        request.user,
        ACTION_PIPELINE_EXPORT,
        (
            f'Exportó dataset limpio "{base_name}_clean.{export_format}". '
            f'Registros exportados: {len(clean)}. '
            f'Formato: {export_format.upper()}.'
        ),
    )


@login_required
def alert_set_status_view(request, pk):
    from django.shortcuts import get_object_or_404
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)

    alert = get_object_or_404(Alert, pk=pk)

    profile = request.user.profile
    if profile.is_trainee and alert.assigned_to_id != request.user.pk:
        return JsonResponse({'error': 'No tenés permisos para modificar esta alerta.'}, status=403)

    try:
        data = json.loads(request.body)
    except (json.JSONDecodeError, ValueError):
        return JsonResponse({'error': 'JSON inválido'}, status=400)

    status_value = data.get('status', '').strip()
    notes        = data.get('notes', '').strip()

    valid = {'new', 'investigating', 'investigated', 'false_positive'}
    if status_value not in valid:
        return JsonResponse({'error': 'Estado inválido'}, status=400)

    alert.investigation_status = status_value
    alert.investigation_notes  = notes
    alert.investigated_by      = request.user
    alert.investigated_at      = timezone.now()
    alert.save(update_fields=[
        'investigation_status', 'investigation_notes',
        'investigated_by', 'investigated_at',
    ])

    return JsonResponse({
        'ok':       True,
        'status':   status_value,
        'by':       request.user.username,
        'at':       alert.investigated_at.strftime('%Y-%m-%d %H:%M'),
    })


@login_required
@analyst_required
def alert_set_priority_view(request, pk):
    from django.shortcuts import get_object_or_404
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)

    alert = get_object_or_404(Alert, pk=pk)

    try:
        data = json.loads(request.body)
    except (json.JSONDecodeError, ValueError):
        return JsonResponse({'error': 'JSON inválido'}, status=400)

    priority = data.get('priority', '').strip()
    note     = data.get('note', '').strip()

    if priority not in {'', 'low', 'medium', 'high', 'critical'}:
        return JsonResponse({'error': 'Prioridad inválida'}, status=400)

    alert.analyst_priority = priority
    alert.analyst_note     = note
    alert.save(update_fields=['analyst_priority', 'analyst_note'])

    return JsonResponse({'ok': True, 'priority': priority})


@login_required
def alert_shap_view(request, pk):
    from django.shortcuts import get_object_or_404
    import json as _json

    alert = get_object_or_404(Alert, pk=pk)

    if not alert.predicted_class:
        messages.warning(request, 'Esta alerta no está clasificada. Clasificala primero para ver la explicabilidad.')
        return redirect('alert_list')

    shap_data = alert.shap_values

    if shap_data is None:
        data = {
            'event_category'       : alert.event_category,
            'protocol'             : alert.protocol,
            'traffic_type'         : alert.traffic_type,
            'mitre_tactic'         : alert.mitre_tactic,
            'kill_chain_stage'     : alert.kill_chain_stage,
            'failed_login_attempts': alert.failed_login_attempts,
            'request_rate_per_min' : alert.request_rate_per_min,
            'ids_ips_alert'        : alert.ids_ips_alert,
            'asset_criticality'    : alert.asset_criticality,
            'log_source'           : alert.log_source,
            'firewall_action'      : alert.firewall_action,
            'severity'             : alert.severity,
            'has_threat_family'    : alert.has_threat_family,
            'evidence_role'        : alert.evidence_role,
            'os_family'            : alert.os_family,
            'correlation_id'       : alert.correlation_id,
            'mitre_techniques'     : alert.mitre_techniques,
        }
        shap_data = calculate_shap_values(data)
        alert.shap_values = shap_data
        alert.save(update_fields=['shap_values'])

    user_role = request.user.profile.role
    allowed_roles = ASSIGNMENT_TARGETS.get(user_role, ())
    assignable_users = (
        User.objects.filter(profile__role__in=allowed_roles)
        .select_related('profile')
        .order_by('username')
        if allowed_roles else User.objects.none()
    )

    is_trainee   = request.user.profile.is_trainee
    can_evaluate = request.user.profile.role in ('admin', 'analyst_n3', 'analyst_n2', 'analyst_n1')
    can_escalate = (
        user_role in ('admin', 'analyst_n2')
        and not alert.is_incident
        and alert.predicted_class in ('malicioso', 'a_investigar')
    )
    readonly     = request.GET.get('readonly') == '1'

    _back_map = {
        'alert_list':    ('alert_list',    'Volver a alertas'),
        'alert_history': ('alert_history', 'Volver al historial'),
        'incident_desk': ('incident_desk', 'Volver a incidentes'),
        'dashboard':     ('dashboard',     'Volver al dashboard'),
    }
    from django.urls import reverse as _reverse
    _next = request.GET.get('next', 'alert_list')
    _back_qs = request.GET.get('back_qs', '')
    if _next == 'incident_detail':
        _back_url   = _reverse('incident_detail', args=[alert.pk])
        _back_label = 'Volver al incidente'
    else:
        _back_name, _back_label = _back_map.get(_next, _back_map['alert_list'])
        _back_url = _reverse(_back_name) + ('?' + _back_qs if _back_qs else '')

    return render(request, 'predictor/alert_shap.html', {
        'alert'              : alert,
        'shap_s1'            : _json.dumps(shap_data['s1']),
        'shap_s2'            : _json.dumps(shap_data['s2']),
        'status_choices'     : Alert.INVESTIGATION_STATUS_CHOICES,
        'evaluation_choices' : Alert.ML_EVALUATION_CHOICES,
        'can_assign'         : bool(allowed_roles),
        'assignable_users'   : assignable_users,
        'is_trainee'         : is_trainee,
        'assigned_to_me'     : alert.assigned_to_id == request.user.pk,
        'can_evaluate'       : can_evaluate,
        'can_escalate'       : can_escalate,
        'readonly'           : readonly,
        'back_url'           : _back_url,
        'back_label'         : _back_label,
    })


@login_required
async def alert_explain_view(request, pk):
    from .claude_service import generate_shap_explanation_async

    if request.method != 'POST':
        return JsonResponse({'error': 'Método no permitido.'}, status=405)

    try:
        alert = await Alert.objects.aget(pk=pk)
    except Alert.DoesNotExist:
        return JsonResponse({'error': 'Alerta no encontrada.'}, status=404)

    if not alert.predicted_class:
        return JsonResponse({'error': 'La alerta no está clasificada.'}, status=400)

    if not alert.shap_values:
        return JsonResponse({'error': 'Esta alerta no tiene valores SHAP calculados.'}, status=400)

    if alert.shap_explanation:
        return JsonResponse({'explanation': alert.shap_explanation, 'cached': True})

    try:
        explanation = await generate_shap_explanation_async(alert)
        alert.shap_explanation = explanation
        await alert.asave(update_fields=['shap_explanation'])
        return JsonResponse({'explanation': explanation, 'cached': False})
    except Exception as exc:
        return JsonResponse({'error': f'Error al generar la explicación: {exc}'}, status=500)


@login_required
@analyst_required
def alert_assign_view(request, pk):
    if request.method != 'POST':
        return JsonResponse({'error': 'Método no permitido.'}, status=405)

    alert = get_object_or_404(Alert, pk=pk)
    assigner_role = request.user.profile.role
    allowed_roles = ASSIGNMENT_TARGETS.get(assigner_role, ())

    try:
        data = json.loads(request.body)
    except (json.JSONDecodeError, ValueError):
        return JsonResponse({'error': 'JSON inválido'}, status=400)

    assigned_to_id = data.get('assigned_to')

    if not assigned_to_id:
        alert.assigned_to = None
        alert.save(update_fields=['assigned_to'])
        log_action(request.user, ACTION_ALERT_ASSIGNED, f'Alerta #{pk} desasignada.')
        return JsonResponse({'ok': True, 'assigned_to': None, 'username': ''})

    target_user = get_object_or_404(User, pk=assigned_to_id)
    target_profile = getattr(target_user, 'profile', None)

    if target_profile is None or target_profile.role not in allowed_roles:
        return JsonResponse({'error': 'No tenés permisos para asignar a ese analista.'}, status=403)

    alert.assigned_to = target_user
    alert.save(update_fields=['assigned_to'])
    log_action(
        request.user,
        ACTION_ALERT_ASSIGNED,
        f'Alerta #{pk} asignada a {target_user.username} ({target_profile.get_role_display()}).',
    )
    return JsonResponse({'ok': True, 'assigned_to': target_user.pk, 'username': target_user.username})


# ─────────────────────────────────────────────────────────────────────────────
# HU030 — Evaluación de decisiones ML
# ─────────────────────────────────────────────────────────────────────────────

@login_required
def alert_evaluate_view(request, pk):
    if request.method != 'POST':
        return JsonResponse({'error': 'Método no permitido.'}, status=405)

    profile = request.user.profile
    if profile.role not in ('admin', 'analyst_n3', 'analyst_n2', 'analyst_n1'):
        return JsonResponse({'error': 'No tenés permisos para evaluar decisiones ML.'}, status=403)

    alert = get_object_or_404(Alert, pk=pk)

    if not alert.predicted_class:
        return JsonResponse({'error': 'La alerta no está clasificada aún.'}, status=400)

    try:
        data = json.loads(request.body)
    except (json.JSONDecodeError, ValueError):
        return JsonResponse({'error': 'JSON inválido'}, status=400)

    evaluation = data.get('evaluation', '').strip()
    notes      = data.get('notes', '').strip()

    valid = {'correct', 'partially_correct', 'incorrect'}
    if evaluation not in valid:
        return JsonResponse({'error': 'Evaluación inválida.'}, status=400)

    alert.ml_evaluation       = evaluation
    alert.ml_evaluation_notes = notes
    alert.ml_evaluated_by     = request.user
    alert.ml_evaluated_at     = timezone.now()
    alert.save(update_fields=[
        'ml_evaluation', 'ml_evaluation_notes', 'ml_evaluated_by', 'ml_evaluated_at',
    ])

    LABELS = dict(Alert.ML_EVALUATION_CHOICES)
    log_action(
        request.user,
        ACTION_ALERT_EVALUATED,
        f'Evaluó la predicción ML de alerta #{pk} como "{LABELS[evaluation]}". Notas: {notes or "—"}',
    )

    return JsonResponse({
        'ok':         True,
        'evaluation': evaluation,
        'label':      LABELS[evaluation],
        'by':         request.user.username,
        'at':         alert.ml_evaluated_at.strftime('%Y-%m-%d %H:%M'),
    })


# ─────────────────────────────────────────────────────────────────────────────
# HU026 / HU027 — Reportes y exportación
# ─────────────────────────────────────────────────────────────────────────────

def _build_report_queryset(params):
    """Aplica filtros de fecha, clase predicha, severidad y estado de investigación."""
    qs = Alert.objects.all()

    date_from = params.get('date_from')
    date_to   = params.get('date_to')
    if date_from:
        try:
            qs = qs.filter(created_at__date__gte=datetime.strptime(date_from, '%Y-%m-%d').date())
        except ValueError:
            pass
    if date_to:
        try:
            qs = qs.filter(created_at__date__lte=datetime.strptime(date_to, '%Y-%m-%d').date())
        except ValueError:
            pass

    predicted_class = params.get('predicted_class', '').strip()
    if predicted_class:
        qs = qs.filter(predicted_class=predicted_class)

    severity = params.get('severity', '').strip()
    if severity:
        qs = qs.filter(severity=severity)

    investigation_status = params.get('investigation_status', '').strip()
    if investigation_status:
        qs = qs.filter(investigation_status=investigation_status)

    ml_evaluation = params.get('ml_evaluation', '').strip()
    if ml_evaluation == '__none__':
        qs = qs.filter(ml_evaluation='')
    elif ml_evaluation:
        qs = qs.filter(ml_evaluation=ml_evaluation)

    analyst_priority = params.get('analyst_priority', '').strip()
    if analyst_priority == 'none':
        qs = qs.filter(analyst_priority='')
    elif analyst_priority:
        qs = qs.filter(analyst_priority=analyst_priority)

    return qs


def _build_report_summary(qs):
    total     = qs.count()
    by_class  = dict(qs.values_list('predicted_class').annotate(n=Count('id')).order_by())
    by_status = dict(qs.values_list('investigation_status').annotate(n=Count('id')).order_by())
    by_sev    = dict(qs.values_list('severity').annotate(n=Count('id')).order_by())
    by_eval   = dict(qs.exclude(ml_evaluation='').values_list('ml_evaluation').annotate(n=Count('id')).order_by())
    return {
        'total':       total,
        'by_class':    by_class,
        'by_status':   by_status,
        'by_severity': by_sev,
        'by_eval':     by_eval,
        'evaluated':   sum(by_eval.values()),
    }


@login_required
@admin_required
def report_view(request):
    params = request.GET
    qs = _build_report_queryset(params)
    summary = _build_report_summary(qs)

    alerts_page = Paginator(qs.select_related('created_by', 'assigned_to'), 10).get_page(
        params.get('page')
    )

    _qs_params = request.GET.copy()
    _qs_params.pop('page', None)

    severities = Alert.objects.values_list('severity', flat=True).distinct().order_by('severity')
    class_choices = [
        ('malicioso',   'Malicioso'),
        ('a_investigar', 'A investigar'),
        ('benigno',     'Benigno'),
        ('',            'Sin clasificar'),
    ]

    status_breakdown = [
        (label, summary['by_status'].get(val, 0))
        for val, label in Alert.INVESTIGATION_STATUS_CHOICES
    ]
    eval_breakdown = [
        (label, summary['by_eval'].get(val, 0))
        for val, label in Alert.ML_EVALUATION_CHOICES
    ]

    return render(request, 'predictor/reports.html', {
        'alerts':            alerts_page,
        'summary':           summary,
        'params':            params,
        'severities':        severities,
        'class_choices':     class_choices,
        'status_choices':    Alert.INVESTIGATION_STATUS_CHOICES,
        'eval_choices':      Alert.ML_EVALUATION_CHOICES,
        'priority_choices':  Alert.ANALYST_PRIORITY_CHOICES,
        'status_breakdown':  status_breakdown,
        'eval_breakdown':    eval_breakdown,
        'query_string':      _qs_params.urlencode(),
    })


@login_required
@admin_required
def report_export_excel_view(request):
    params = request.GET
    qs = _build_report_queryset(params)

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = 'Reporte de Alertas'

    header_fill  = PatternFill(fill_type='solid', fgColor='1E3A5F')
    header_font  = Font(bold=True, color='FFFFFF', size=11)
    center_align = Alignment(horizontal='center', vertical='center')

    headers = [
        'ID', 'Fecha', 'Categoría', 'Protocolo', 'Táctica MITRE',
        'Severidad', 'Clase Predicha', 'Riesgo', 'Estado Investigación',
        'Prioridad Analista', 'Evaluación ML', 'Asignado a', 'Creado por',
    ]
    ws.append(headers)
    for col_idx, _ in enumerate(headers, start=1):
        cell = ws.cell(row=1, column=col_idx)
        cell.fill   = header_fill
        cell.font   = header_font
        cell.alignment = center_align

    STATUS_LABELS = dict(Alert.INVESTIGATION_STATUS_CHOICES)
    PRIORITY_LABELS = dict(Alert.ANALYST_PRIORITY_CHOICES)
    EVAL_LABELS = dict(Alert.ML_EVALUATION_CHOICES)

    for alert in qs.select_related('created_by', 'assigned_to'):
        ws.append([
            alert.pk,
            alert.created_at.strftime('%Y-%m-%d %H:%M') if alert.created_at else '',
            alert.event_category,
            alert.protocol,
            alert.mitre_tactic,
            alert.severity,
            alert.predicted_class or 'Sin clasificar',
            round(alert.risk_score, 4) if alert.risk_score is not None else '',
            STATUS_LABELS.get(alert.investigation_status, alert.investigation_status),
            PRIORITY_LABELS.get(alert.analyst_priority, '') if alert.analyst_priority else '',
            EVAL_LABELS.get(alert.ml_evaluation, '') if alert.ml_evaluation else 'Sin evaluar',
            alert.assigned_to.username if alert.assigned_to else '',
            alert.created_by.username if alert.created_by else '',
        ])

    for col in ws.columns:
        max_len = max(len(str(cell.value or '')) for cell in col)
        ws.column_dimensions[col[0].column_letter].width = min(max_len + 4, 40)

    buffer = io.BytesIO()
    wb.save(buffer)
    buffer.seek(0)

    filename = f'reporte_alertas_{date.today().isoformat()}.xlsx'
    log_action(
        request.user,
        ACTION_REPORT_EXPORT,
        f'Exportó reporte de alertas en Excel. Registros: {qs.count()}.',
    )

    response = HttpResponse(
        buffer.getvalue(),
        content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    )
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response


@login_required
@admin_required
def report_export_pdf_view(request):
    params = request.GET
    qs = _build_report_queryset(params)
    summary = _build_report_summary(qs)

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=landscape(A4),
        leftMargin=1.5 * cm,
        rightMargin=1.5 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'ReportTitle',
        parent=styles['Title'],
        fontSize=16,
        textColor=colors.HexColor('#1E3A5F'),
        spaceAfter=6,
    )
    subtitle_style = ParagraphStyle(
        'ReportSubtitle',
        parent=styles['Normal'],
        fontSize=9,
        textColor=colors.grey,
        spaceAfter=12,
    )
    section_style = ParagraphStyle(
        'SectionTitle',
        parent=styles['Heading2'],
        fontSize=11,
        textColor=colors.HexColor('#1E3A5F'),
        spaceBefore=12,
        spaceAfter=6,
    )

    story = []

    story.append(Paragraph('Reporte de Alertas SOC', title_style))
    story.append(Paragraph(
        f'Generado el {date.today().strftime("%d/%m/%Y")} — Total: {summary["total"]} alertas',
        subtitle_style,
    ))

    # Resumen
    story.append(Paragraph('Resumen ejecutivo', section_style))

    CLASS_LABELS = {'malicioso': 'Malicioso', 'a_investigar': 'A investigar', 'benigno': 'Benigno', '': 'Sin clasificar'}
    STATUS_LABELS = dict(Alert.INVESTIGATION_STATUS_CHOICES)
    EVAL_LABELS   = dict(Alert.ML_EVALUATION_CHOICES)

    summary_data = [['Métrica', 'Valor']]
    summary_data.append(['Total de alertas', str(summary['total'])])
    for cls, count in summary['by_class'].items():
        summary_data.append([f'  Clase: {CLASS_LABELS.get(cls, cls or "Sin clasificar")}', str(count)])
    for st, count in summary['by_status'].items():
        summary_data.append([f'  Estado: {STATUS_LABELS.get(st, st)}', str(count)])
    for sev, count in summary['by_severity'].items():
        summary_data.append([f'  Severidad: {sev}', str(count)])
    summary_data.append([f'Alertas evaluadas por analistas', str(summary['evaluated'])])
    for ev, count in summary['by_eval'].items():
        summary_data.append([f'  Evaluación: {EVAL_LABELS.get(ev, ev)}', str(count)])

    summary_table = Table(summary_data, colWidths=[10 * cm, 4 * cm])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1E3A5F')),
        ('TEXTCOLOR',  (0, 0), (-1, 0), colors.white),
        ('FONTNAME',   (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE',   (0, 0), (-1, -1), 9),
        ('GRID',       (0, 0), (-1, -1), 0.4, colors.HexColor('#CCCCCC')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F5F7FA')]),
        ('LEFTPADDING',  (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING',   (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 0.5 * cm))

    # Detalle de alertas
    story.append(Paragraph('Detalle de alertas', section_style))

    detail_headers = [
        'ID', 'Fecha', 'Categoría', 'Táctica MITRE',
        'Severidad', 'Clase Predicha', 'Estado', 'Evaluación ML', 'Asignado a',
    ]
    detail_data = [detail_headers]

    for alert in qs.select_related('assigned_to')[:500]:
        detail_data.append([
            str(alert.pk),
            alert.created_at.strftime('%Y-%m-%d') if alert.created_at else '',
            alert.event_category[:20],
            alert.mitre_tactic[:18],
            alert.severity,
            CLASS_LABELS.get(alert.predicted_class, alert.predicted_class or 'Sin clasificar'),
            STATUS_LABELS.get(alert.investigation_status, alert.investigation_status),
            EVAL_LABELS.get(alert.ml_evaluation, '—') if alert.ml_evaluation else '—',
            alert.assigned_to.username[:12] if alert.assigned_to else '—',
        ])

    col_widths = [1.2*cm, 2.3*cm, 3.5*cm, 4*cm, 2.2*cm, 2.8*cm, 3*cm, 3*cm, 2.7*cm]
    detail_table = Table(detail_data, colWidths=col_widths, repeatRows=1)
    detail_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1E3A5F')),
        ('TEXTCOLOR',  (0, 0), (-1, 0), colors.white),
        ('FONTNAME',   (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTNAME',   (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE',   (0, 0), (-1, -1), 7.5),
        ('GRID',       (0, 0), (-1, -1), 0.3, colors.HexColor('#CCCCCC')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F5F7FA')]),
        ('VALIGN',     (0, 0), (-1, -1), 'MIDDLE'),
        ('LEFTPADDING',  (0, 0), (-1, -1), 5),
        ('RIGHTPADDING', (0, 0), (-1, -1), 5),
        ('TOPPADDING',   (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    story.append(detail_table)

    doc.build(story)
    buffer.seek(0)

    filename = f'reporte_alertas_{date.today().isoformat()}.pdf'
    log_action(
        request.user,
        ACTION_REPORT_EXPORT,
        f'Exportó reporte de alertas en PDF. Registros: {qs.count()}.',
    )

    response = HttpResponse(buffer.getvalue(), content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response


# ─────────────────────────────────────────────────────────────────────────────
# Fase 5 — Escalado a incidente y Mesa de Incidentes Activos
# ─────────────────────────────────────────────────────────────────────────────

@login_required
@role_required('admin', 'analyst_n2')
def alert_escalate_view(request, pk):
    if request.method != 'POST':
        return JsonResponse({'error': 'Método no permitido.'}, status=405)

    alert = get_object_or_404(Alert, pk=pk)

    if alert.is_incident:
        return JsonResponse({'error': 'Esta alerta ya fue escalada a incidente.'}, status=400)

    if not alert.predicted_class or alert.predicted_class == 'benigno':
        return JsonResponse({'error': 'Solo se pueden escalar alertas maliciosas o a investigar.'}, status=400)

    alert.is_incident  = True
    alert.escalated_at = timezone.now()
    alert.escalated_by = request.user
    alert.save(update_fields=['is_incident', 'escalated_at', 'escalated_by'])

    log_action(
        request.user,
        ACTION_ALERT_ESCALATED,
        f'Escaló alerta #{alert.pk} ({alert.predicted_class}) a incidente activo.',
    )

    return JsonResponse({
        'ok':  True,
        'msg': f'Alerta #{alert.pk} escalada a incidente correctamente.',
    })


@login_required
@role_required('admin', 'analyst_n3')
def incident_detail_view(request, pk):
    alert = get_object_or_404(Alert, pk=pk, is_incident=True)
    mttr = None
    if alert.is_resolved and alert.resolved_at and alert.escalated_at:
        delta = alert.resolved_at - alert.escalated_at
        total_minutes = max(int(delta.total_seconds() / 60), 0)
        mttr = f"{total_minutes // 60}h {total_minutes % 60}m"
    back_qs = request.GET.get('back_qs', '')
    return render(request, 'predictor/incident_detail.html', {
        'alert':   alert,
        'mttr':    mttr,
        'back_qs': back_qs,
    })


@login_required
@role_required('admin', 'analyst_n3')
def incident_resolve_view(request, pk):
    if request.method != 'POST':
        return JsonResponse({'error': 'Método no permitido.'}, status=405)
    alert = get_object_or_404(Alert, pk=pk, is_incident=True)
    if alert.is_resolved:
        return JsonResponse({'error': 'Este incidente ya fue cerrado.'}, status=400)
    root_cause      = request.POST.get('root_cause', '').strip()
    lessons_learned = request.POST.get('lessons_learned', '').strip()
    if not root_cause:
        return JsonResponse({'error': 'La causa raíz es obligatoria.'}, status=400)
    alert.root_cause      = root_cause
    alert.lessons_learned = lessons_learned
    alert.is_resolved     = True
    alert.resolved_at     = timezone.now()
    alert.resolved_by     = request.user
    alert.save(update_fields=['root_cause', 'lessons_learned', 'is_resolved', 'resolved_at', 'resolved_by'])
    return JsonResponse({'ok': True, 'msg': f'Incidente #{alert.pk} cerrado correctamente.'})


@login_required
async def incident_chat_view(request, pk):
    from asgiref.sync import sync_to_async
    role = await sync_to_async(
        lambda: getattr(getattr(request.user, 'profile', None), 'role', None)
    )()
    if role not in ('admin', 'analyst_n3'):
        return JsonResponse({'error': 'Sin permisos.'}, status=403)
    if request.method != 'POST':
        return JsonResponse({'error': 'Método no permitido.'}, status=405)
    try:
        alert = await Alert.objects.aget(pk=pk, is_incident=True)
    except Alert.DoesNotExist:
        return JsonResponse({'error': 'Incidente no encontrado.'}, status=404)
    message = request.POST.get('message', '').strip()
    if not message:
        return JsonResponse({'error': 'Mensaje vacío.'}, status=400)
    try:
        from .claude_service import generate_incident_chat_async
        response = await generate_incident_chat_async(alert, message)
        return JsonResponse({'ok': True, 'response': response})
    except Exception as exc:
        return JsonResponse({'error': str(exc)}, status=500)


@login_required
@role_required('admin', 'analyst_n3')
def incident_desk_view(request):
    qs = (
        Alert.objects
        .filter(is_incident=True)
        .select_related('created_by', 'assigned_to', 'escalated_by', 'investigated_by')
    )

    search = request.GET.get('q', '').strip()
    if search:
        qs = qs.filter(
            Q(event_category__icontains=search)
            | Q(attack_type__icontains=search)
            | Q(attack_signature__icontains=search)
            | Q(protocol__icontains=search)
            | Q(mitre_tactic__icontains=search)
        )

    class_filter = request.GET.get('predicted_class', '').strip()
    if class_filter:
        qs = qs.filter(predicted_class=class_filter)

    date_from = request.GET.get('date_from', '').strip()
    if date_from:
        qs = qs.filter(escalated_at__date__gte=date_from)

    date_to = request.GET.get('date_to', '').strip()
    if date_to:
        qs = qs.filter(escalated_at__date__lte=date_to)

    order = request.GET.get('order', 'date_desc').strip()
    _order_map = {
        'risk_desc':    F('risk_score').desc(nulls_last=True),
        'risk_asc':     F('risk_score').asc(nulls_last=True),
        'date_desc':    '-escalated_at',
        'date_asc':     'escalated_at',
    }
    qs = qs.order_by(_order_map.get(order, '-escalated_at'))

    from urllib.parse import quote as _quote

    _qs_params = request.GET.copy()
    _qs_params.pop('page', None)
    _raw_qs    = _qs_params.urlencode()

    paginator = Paginator(qs, 10)
    page_obj  = paginator.get_page(request.GET.get('page'))

    return render(request, 'predictor/incident_desk.html', {
        'page_obj':     page_obj,
        'search':       search,
        'class_filter': class_filter,
        'date_from':    date_from,
        'date_to':      date_to,
        'order':        order,
        'total_count':  qs.count(),
        'query_string': _raw_qs,
        'encoded_qs':   _quote(_raw_qs),
    })
