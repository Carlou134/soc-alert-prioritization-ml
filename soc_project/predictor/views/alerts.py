import json

from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import F, Q
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django_q.tasks import async_task

from accounts.decorators import analyst_required, role_required
from accounts.models import (
    ACTION_ALERT_ASSIGNED,
    ACTION_ALERT_ESCALATED,
    ACTION_ALERT_EVALUATED,
    ACTION_UPLOAD_ALERTS,
    log_action,
)

from ..mitre_metadata import resolve_techniques
from ..models import Alert, AlertWorkflow, Dataset, Incident, PredictionLog, log_error
from ..pipeline import REQUIRED_COLUMNS, parse_file, validate_columns, clean_records
from ..utils import (
    calculate_risk_score, calculate_shap_values, compute_shap_safe,
    get_active_model_version, predict_alert,
)

# Roles a los que cada rol puede asignar alertas (incluye auto-asignación)
ASSIGNMENT_TARGETS = {
    'admin':      ('admin', 'analyst_n3', 'analyst_n2', 'analyst_n1', 'trainee'),
    'analyst_n3': ('admin', 'analyst_n3'),
    'analyst_n2': ('analyst_n2', 'analyst_n3', 'analyst_n1'),
    'analyst_n1': ('analyst_n1', 'analyst_n2', 'trainee'),
    'trainee':    (),
}

# ─────────────────────────────────────────────────────────────────────────────
# HU028 — Historial de alertas procesadas (n2 / n3 / admin)
# ─────────────────────────────────────────────────────────────────────────────

@login_required
@role_required('admin', 'analyst_n3', 'analyst_n2')
def alert_history_view(request):
    qs = (
        Alert.objects
        .exclude(predictionlog__isnull=True)
        .select_related('created_by', 'workflow', 'workflow__investigated_by', 'workflow__assigned_to', 'workflow__ml_evaluated_by')
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
        qs = qs.filter(predictionlog__predicted_class=class_filter)

    status_filter = request.GET.get('investigation_status', '').strip()
    if status_filter:
        qs = qs.filter(workflow__investigation_status=status_filter)

    tactic_filter = request.GET.get('mitre_tactic', '').strip()
    if tactic_filter:
        qs = qs.filter(mitre_tactic__icontains=tactic_filter)

    attack_filter = request.GET.get('attack_type', '').strip()
    if attack_filter:
        qs = qs.filter(attack_type__icontains=attack_filter)

    eval_filter = request.GET.get('ml_evaluation', '').strip()
    if eval_filter == '__none__':
        qs = qs.filter(workflow__ml_evaluation='')
    elif eval_filter:
        qs = qs.filter(workflow__ml_evaluation=eval_filter)

    analyst_filter = request.GET.get('analyst', '').strip()
    if analyst_filter:
        qs = qs.filter(workflow__investigated_by__username__icontains=analyst_filter)

    priority_filter = request.GET.get('analyst_priority', '').strip()
    if priority_filter == 'none':
        qs = qs.filter(workflow__analyst_priority='')
    elif priority_filter:
        qs = qs.filter(workflow__analyst_priority=priority_filter)

    risk_min = request.GET.get('risk_min', '').strip()
    risk_max = request.GET.get('risk_max', '').strip()
    try:
        if risk_min:
            qs = qs.filter(predictionlog__risk_score__gte=float(risk_min))
    except ValueError:
        risk_min = ''
    try:
        if risk_max:
            qs = qs.filter(predictionlog__risk_score__lte=float(risk_max))
    except ValueError:
        risk_max = ''

    qs = qs.distinct()
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
        'status_choices':   AlertWorkflow.INVESTIGATION_STATUS_CHOICES,
        'eval_choices':     AlertWorkflow.ML_EVALUATION_CHOICES,
        'priority_choices': AlertWorkflow.ANALYST_PRIORITY_CHOICES,
        'query_string':     _p.urlencode(),
    })


def _build_alert_instance(record, predicted_class, probabilities, user):
    """Devuelve (alert, prediction_kwargs) — sin guardar.

    Los campos de predicción ya no viven en Alert (Track 1); se devuelven
    aparte para construir el PredictionLog pareado en _bulk_create_alerts().
    """
    alert = Alert(
        event_category        = record.get('event_category', ''),
        protocol              = record.get('protocol', ''),
        traffic_type          = record.get('traffic_type', ''),
        mitre_tactic          = record.get('mitre_tactic', ''),
        kill_chain_stage      = record.get('kill_chain_stage', ''),
        failed_login_attempts = record.get('failed_login_attempts', 0),
        request_rate_per_min  = record.get('request_rate_per_min', 0.0),
        ids_ips_alert         = record.get('ids_ips_alert', ''),
        asset_criticality     = record.get('asset_criticality', ''),
        log_source            = record.get('log_source', ''),
        firewall_action       = record.get('firewall_action', ''),
        severity               = record.get('severity', ''),
        has_threat_family     = record.get('has_threat_family', 0),
        evidence_role         = record.get('evidence_role', 'unknown'),
        os_family             = record.get('os_family', 'unknown'),
        correlation_id        = record.get('correlation_id', 'unknown'),
        mitre_techniques      = record.get('mitre_techniques', ''),
        attack_type           = record.get('attack_type', ''),
        attack_signature      = record.get('attack_signature', ''),
        malware_indicator     = record.get('malware_indicator', ''),
        label                 = record.get('label', ''),
        created_by            = user,
    )
    prediction_kwargs = {
        'predicted_class': predicted_class,
        'risk_score': calculate_risk_score(probabilities),
        'probabilities': probabilities,
        'shap_values': None,
    }
    return alert, prediction_kwargs


@transaction.atomic
def _bulk_create_alerts(pairs, user):
    """Crea Alert + AlertWorkflow pareado (siempre) + PredictionLog (si hubo predicción).

    `pairs` es una lista de (alert, prediction_kwargs) sin guardar todavía.
    bulk_create no dispara save()/señales, así que el parseo se arma a mano aquí
    en vez de depender de un hook automático. Devuelve los Alert ya guardados,
    en el mismo orden que `pairs`.

    @transaction.atomic a propósito: si algo falla a mitad de camino (ej.
    get_active_model_version()), todo se revierte — nunca quedan Alert o
    AlertWorkflow huérfanos sin su PredictionLog.
    """
    if not pairs:
        return []

    alerts = [alert for alert, _ in pairs]
    created = Alert.objects.bulk_create(alerts, batch_size=500)

    AlertWorkflow.objects.bulk_create(
        [AlertWorkflow(alert=alert, created_by=alert.created_by) for alert in created],
        batch_size=500,
    )

    model_version = get_active_model_version()
    predictions = [
        PredictionLog(alert=alert, model_version=model_version, **kwargs)
        for alert, (_, kwargs) in zip(created, pairs)
        if kwargs is not None
    ]
    if predictions:
        PredictionLog.objects.bulk_create(predictions, batch_size=500)

    return created


@login_required
@analyst_required
def upload_alerts_view(request):
    if request.method != 'POST':
        return render(request, 'predictor/upload_alerts.html', {})

    file = request.FILES.get('file')
    if not file:
        return JsonResponse({'error': 'No se seleccionó ningún archivo.'}, status=400)
    if file.size == 0:
        return JsonResponse({'error': 'El archivo está vacío.'}, status=400)
    if file.size > 10 * 1024 * 1024:
        return JsonResponse({'error': 'El archivo supera el límite de 10 MB.'}, status=400)

    records, error = parse_file(file)
    if error:
        return JsonResponse({'error': error}, status=400)
    if not records:
        return JsonResponse({'error': 'El archivo no contiene registros.'}, status=400)

    _, missing_cols = validate_columns(records)
    if missing_cols:
        return JsonResponse({'error': f'Faltan columnas requeridas: {", ".join(missing_cols)}'}, status=400)

    clean, stats = clean_records(records)
    if not clean:
        return JsonResponse({'error': 'Ningún registro pasó la validación. Verificá el formato del archivo.'}, status=400)

    dataset = Dataset.objects.create(
        filename=file.name,
        row_count=len(clean),
        uploaded_by=request.user,
    )
    async_task('predictor.tasks.process_alert_batch', dataset.pk, clean, request.user.pk)

    log_action(
        request.user,
        ACTION_UPLOAD_ALERTS,
        (
            f'Archivo "{file.name}" encolado para procesamiento en segundo plano '
            f'({len(clean)} registros, dataset #{dataset.pk}).'
        ),
    )

    return JsonResponse({
        'dataset_id': dataset.pk,
        'total':      len(clean),
        'stats': {
            'duplicates_removed':   stats.get('duplicates_removed', 0),
            'invalid_rows_removed': stats.get('invalid_rows_removed', 0),
        },
    })


@login_required
@analyst_required
def dataset_status_view(request, pk):
    """JSON de estado/progreso de un Dataset — usado por el polling de
    upload_alerts.html y pipeline.html (Track 5)."""
    dataset = get_object_or_404(Dataset, pk=pk)
    return JsonResponse({
        'status':        dataset.status,
        'row_count':     dataset.row_count,
        'saved_count':   dataset.saved_count,
        'failed_count':  dataset.failed_count,
        'error_message': dataset.error_message,
    })


@login_required
def notifications_unread_count_view(request):
    """JSON liviano para el badge de la campanita en el navbar (Track 7) —
    suma dos señales distintas, a pedido explícito del usuario (mostrar 99
    de una subida masiva de alertas resultaba alarmante/inútil comparado con
    un simple aviso de "llegó un lote nuevo"):

    1. Lotes (Dataset) con alertas nuevas SIN asignar todavía — 1 por lote,
       sin importar cuántas alertas tenga adentro (99 alertas en un mismo
       upload = 1, no 99). Es la señal genérica de "entró algo, andá a
       mirar la cola" — no depende de que nadie reclame nada a mano, por
       eso se dispara solo al subir/sincronizar (ver el fix anterior: si
       dependiera de assigned_to nunca se disparaba con un lote recién
       llegado, porque assigned_to queda nulo hasta la asignación manual).
    2. Alertas asignadas puntualmente a MÍ y todavía en 'Nueva' — ahí sí
       cuenta 1 a 1 (1, 2, 3...), porque una vez asignada es responsabilidad
       personal del analista, no un lote genérico.

    Ambas señales usan el mismo filtro automático por rol que ya usa
    alert_list_view (N1/practicante solo ven benigno, N2 solo lo que no es
    benigno, N3/admin ven todo), y excluyen alertas ya escaladas a incidente
    (salieron de la cola normal). Solo auth de sesión — no es un endpoint
    del API externa (/api/...), así que no lleva JWT. Polling corto desde
    JS (2-3s), mismo patrón ya usado y probado en dataset_status_view
    (Track 5) — no WebSockets, no Redis, sin cambios de infraestructura."""
    role = request.user.profile.role
    base_qs = AlertWorkflow.objects.filter(
        investigation_status='new', alert__incident__isnull=True,
    )
    if role in ('analyst_n1', 'trainee'):
        base_qs = base_qs.filter(alert__predictionlog__predicted_class='benigno')
    elif role == 'analyst_n2':
        base_qs = base_qs.exclude(alert__predictionlog__isnull=True).exclude(alert__predictionlog__predicted_class='benigno')

    pending_datasets = (
        base_qs.filter(assigned_to__isnull=True)
        .values('alert__dataset_id').distinct().count()
    )
    assigned_to_me = base_qs.filter(assigned_to=request.user).distinct().count()

    return JsonResponse({'count': pending_datasets + assigned_to_me})


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
    qs = (
        Alert.objects
        .select_related('created_by', 'workflow', 'workflow__assigned_to')
        .filter(incident__isnull=True)
    )

    # Filtros automáticos por rol — no pueden ser sobreescritos por el usuario
    if role in ('analyst_n1', 'trainee'):
        qs = qs.filter(predictionlog__predicted_class='benigno')
    elif role == 'analyst_n2':
        qs = qs.exclude(predictionlog__isnull=True).exclude(predictionlog__predicted_class='benigno')

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
        qs = qs.filter(predictionlog__isnull=True)
    elif class_filter:
        qs = qs.filter(predictionlog__predicted_class=class_filter)

    # Filtro por estado de investigación
    status_filter = request.GET.get('investigation_status', '').strip()
    if status_filter:
        qs = qs.filter(workflow__investigation_status=status_filter)

    # Filtro por prioridad del analista ('none' → sin ajuste)
    priority_filter = request.GET.get('analyst_priority', '').strip()
    if priority_filter == 'none':
        qs = qs.filter(workflow__analyst_priority='')
    elif priority_filter:
        qs = qs.filter(workflow__analyst_priority=priority_filter)

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
            qs = qs.filter(predictionlog__risk_score__gte=float(risk_min))
    except ValueError:
        risk_min = ''
    try:
        if risk_max:
            qs = qs.filter(predictionlog__risk_score__lte=float(risk_max))
    except ValueError:
        risk_max = ''

    assigned_filter = request.GET.get('assigned_to', '').strip()
    if assigned_filter:
        qs = qs.filter(workflow__assigned_to__username__icontains=assigned_filter)

    order = request.GET.get('order', 'date_desc').strip()
    _order_map = {
        'risk_desc': F('predictionlog__risk_score').desc(nulls_last=True),
        'risk_asc':  F('predictionlog__risk_score').asc(nulls_last=True),
        'date_desc': '-created_at',
        'date_asc':  'created_at',
    }
    qs = qs.order_by(_order_map.get(order, '-created_at')).distinct()

    severity_choices = (
        Alert.objects.values_list('severity', flat=True)
        .distinct()
        .order_by('severity')
    )

    # Contador de alertas pendientes (sin clasificar) para mostrar el botón
    pending_base = Alert.objects.filter(predictionlog__isnull=True)
    if not is_admin:
        pending_base = pending_base.filter(created_by=request.user)
    pending_count = pending_base.distinct().count()

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
    qs = Alert.objects.filter(predictionlog__isnull=True).distinct()
    if not is_admin:
        qs = qs.filter(created_by=request.user)

    classified = 0
    model_version = get_active_model_version()
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
            PredictionLog.objects.create(
                alert=alert,
                model_version=model_version,
                predicted_class=predicted_class,
                risk_score=calculate_risk_score(probabilities),
                probabilities=probabilities,
                shap_values=compute_shap_safe(data),
            )
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


@login_required
def alert_set_status_view(request, pk):
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)

    alert = get_object_or_404(Alert.objects.select_related('workflow'), pk=pk)

    profile = request.user.profile
    if profile.is_trainee and alert.workflow.assigned_to_id != request.user.pk:
        return JsonResponse({'error': 'No tienes permisos para modificar esta alerta.'}, status=403)

    try:
        data = json.loads(request.body)
    except (json.JSONDecodeError, ValueError):
        return JsonResponse({'error': 'JSON inválido'}, status=400)

    status_value = data.get('status', '').strip()
    notes        = data.get('notes', '').strip()

    valid = {'new', 'investigating', 'investigated', 'false_positive'}
    if status_value not in valid:
        return JsonResponse({'error': 'Estado inválido'}, status=400)

    workflow = alert.workflow
    workflow.investigation_status = status_value
    workflow.investigation_notes  = notes
    workflow.investigated_by      = request.user
    workflow.investigated_at      = timezone.now()
    workflow.save(update_fields=[
        'investigation_status', 'investigation_notes',
        'investigated_by', 'investigated_at',
    ])

    return JsonResponse({
        'ok':       True,
        'status':   status_value,
        'by':       request.user.username,
        'at':       workflow.investigated_at.strftime('%Y-%m-%d %H:%M'),
    })


@login_required
@analyst_required
def alert_set_priority_view(request, pk):
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)

    alert = get_object_or_404(Alert.objects.select_related('workflow'), pk=pk)

    try:
        data = json.loads(request.body)
    except (json.JSONDecodeError, ValueError):
        return JsonResponse({'error': 'JSON inválido'}, status=400)

    priority = data.get('priority', '').strip()
    note     = data.get('note', '').strip()

    if priority not in {'', 'low', 'medium', 'high', 'critical'}:
        return JsonResponse({'error': 'Prioridad inválida'}, status=400)

    workflow = alert.workflow
    workflow.analyst_priority = priority
    workflow.analyst_note     = note
    workflow.save(update_fields=['analyst_priority', 'analyst_note'])

    return JsonResponse({'ok': True, 'priority': priority})


@login_required
def alert_shap_view(request, pk):
    import json as _json

    alert = get_object_or_404(Alert.objects.select_related('workflow', 'incident'), pk=pk)

    prediction = alert.latest_prediction
    if prediction is None:
        messages.warning(request, 'Esta alerta no está clasificada. Clasificala primero para ver la explicabilidad.')
        return redirect('alert_list')

    shap_data = prediction.shap_values

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
        prediction.shap_values = shap_data
        prediction.save(update_fields=['shap_values'])

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
        and alert.incident_id is None
        and prediction.predicted_class in ('malicioso', 'a_investigar')
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
        'prediction'         : prediction,
        'mitre_techniques_resolved': resolve_techniques(alert.mitre_techniques),
        'shap_s1'            : _json.dumps(shap_data['s1']),
        'shap_s2'            : _json.dumps(shap_data['s2']),
        'status_choices'     : AlertWorkflow.INVESTIGATION_STATUS_CHOICES,
        'evaluation_choices' : AlertWorkflow.ML_EVALUATION_CHOICES,
        'can_assign'         : bool(allowed_roles),
        'assignable_users'   : assignable_users,
        'is_trainee'         : is_trainee,
        'assigned_to_me'     : alert.workflow.assigned_to_id == request.user.pk,
        'can_evaluate'       : can_evaluate,
        'can_escalate'       : can_escalate,
        'readonly'           : readonly,
        'back_url'           : _back_url,
        'back_label'         : _back_label,
    })


@login_required
async def alert_explain_view(request, pk):
    from asgiref.sync import sync_to_async
    from ..claude_service import generate_shap_explanation_async

    if request.method != 'POST':
        return JsonResponse({'error': 'Método no permitido.'}, status=405)

    try:
        alert = await Alert.objects.aget(pk=pk)
    except Alert.DoesNotExist:
        return JsonResponse({'error': 'Alerta no encontrada.'}, status=404)

    prediction = await sync_to_async(lambda: alert.latest_prediction)()
    if prediction is None:
        return JsonResponse({'error': 'La alerta no está clasificada.'}, status=400)

    if not prediction.shap_values:
        return JsonResponse({'error': 'Esta alerta no tiene valores SHAP calculados.'}, status=400)

    if prediction.shap_explanation:
        return JsonResponse({'explanation': prediction.shap_explanation, 'cached': True})

    try:
        explanation = await generate_shap_explanation_async(alert, prediction)
        prediction.shap_explanation = explanation
        await prediction.asave(update_fields=['shap_explanation'])
        return JsonResponse({'explanation': explanation, 'cached': False})
    except Exception as exc:
        return JsonResponse({'error': f'Error al generar la explicación: {exc}'}, status=500)


@login_required
@analyst_required
def alert_assign_view(request, pk):
    if request.method != 'POST':
        return JsonResponse({'error': 'Método no permitido.'}, status=405)

    alert = get_object_or_404(Alert.objects.select_related('workflow'), pk=pk)
    assigner_role = request.user.profile.role
    allowed_roles = ASSIGNMENT_TARGETS.get(assigner_role, ())

    try:
        data = json.loads(request.body)
    except (json.JSONDecodeError, ValueError):
        return JsonResponse({'error': 'JSON inválido'}, status=400)

    assigned_to_id = data.get('assigned_to')
    workflow = alert.workflow

    if not assigned_to_id:
        workflow.assigned_to = None
        workflow.save(update_fields=['assigned_to'])
        log_action(request.user, ACTION_ALERT_ASSIGNED, f'Alerta #{pk} desasignada.')
        return JsonResponse({'ok': True, 'assigned_to': None, 'username': ''})

    target_user = get_object_or_404(User, pk=assigned_to_id)
    target_profile = getattr(target_user, 'profile', None)

    if target_profile is None or target_profile.role not in allowed_roles:
        return JsonResponse({'error': 'No tienes permisos para asignar a ese analista.'}, status=403)

    workflow.assigned_to = target_user
    workflow.save(update_fields=['assigned_to'])
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
        return JsonResponse({'error': 'No tienes permisos para evaluar decisiones ML.'}, status=403)

    alert = get_object_or_404(Alert.objects.select_related('workflow'), pk=pk)

    if alert.latest_prediction is None:
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

    workflow = alert.workflow
    workflow.ml_evaluation       = evaluation
    workflow.ml_evaluation_notes = notes
    workflow.ml_evaluated_by     = request.user
    workflow.ml_evaluated_at     = timezone.now()
    workflow.save(update_fields=[
        'ml_evaluation', 'ml_evaluation_notes', 'ml_evaluated_by', 'ml_evaluated_at',
    ])

    LABELS = dict(AlertWorkflow.ML_EVALUATION_CHOICES)
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
        'at':         workflow.ml_evaluated_at.strftime('%Y-%m-%d %H:%M'),
    })


# ─────────────────────────────────────────────────────────────────────────────
# Fase 5 — Escalado a incidente
# ─────────────────────────────────────────────────────────────────────────────

@login_required
@role_required('admin', 'analyst_n2')
def alert_escalate_view(request, pk):
    if request.method != 'POST':
        return JsonResponse({'error': 'Método no permitido.'}, status=405)

    alert = get_object_or_404(Alert, pk=pk)

    if alert.incident_id is not None:
        return JsonResponse({'error': 'Esta alerta ya fue escalada a incidente.'}, status=400)

    prediction = alert.latest_prediction
    predicted_class = prediction.predicted_class if prediction else ''
    if not predicted_class or predicted_class == 'benigno':
        return JsonResponse({'error': 'Solo se pueden escalar alertas maliciosas o a investigar.'}, status=400)

    raw_correlation = (alert.correlation_id or '').strip()
    is_real = bool(raw_correlation) and raw_correlation.lower() != 'unknown'

    if is_real:
        # Alertas con el mismo correlation_id real comparten un mismo Incident.
        incident, _ = Incident.objects.get_or_create(
            correlation_id=raw_correlation,
            defaults={'escalated_at': timezone.now(), 'escalated_by': request.user},
        )
    else:
        # Sin correlation_id real no se agrupa — evita fusionar incidentes no relacionados.
        incident = Incident.objects.create(
            correlation_id=f'alert-{alert.pk}',
            escalated_at=timezone.now(),
            escalated_by=request.user,
        )

    alert.incident = incident
    alert.save(update_fields=['incident'])

    log_action(
        request.user,
        ACTION_ALERT_ESCALATED,
        f'Escaló alerta #{alert.pk} ({predicted_class}) a incidente activo.',
    )

    return JsonResponse({
        'ok':  True,
        'msg': f'Alerta #{alert.pk} escalada a incidente correctamente.',
    })
