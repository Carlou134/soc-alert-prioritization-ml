# ─────────────────────────────────────────────────────────────────────────────
# Fase 5 — Mesa de Incidentes Activos
# ─────────────────────────────────────────────────────────────────────────────
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db.models import F, Q
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, render
from django.utils import timezone

from accounts.decorators import role_required
from accounts.models import ACTION_INCIDENT_RESOLVED, log_action

from ..models import Alert


@login_required
@role_required('admin', 'analyst_n3')
def incident_detail_view(request, pk):
    alert = get_object_or_404(
        Alert.objects.select_related('incident', 'workflow'),
        pk=pk, incident__isnull=False,
    )
    incident = alert.incident
    prediction = alert.latest_prediction
    mttr = None
    if incident.is_resolved and incident.resolved_at and incident.escalated_at:
        delta = incident.resolved_at - incident.escalated_at
        total_minutes = max(int(delta.total_seconds() / 60), 0)
        mttr = f"{total_minutes // 60}h {total_minutes % 60}m"
    back_qs = request.GET.get('back_qs', '')
    return render(request, 'predictor/incident_detail.html', {
        'alert':      alert,
        'incident':   incident,
        'prediction': prediction,
        'mttr':       mttr,
        'back_qs':    back_qs,
    })


@login_required
@role_required('admin', 'analyst_n3')
def incident_resolve_view(request, pk):
    if request.method != 'POST':
        return JsonResponse({'error': 'Método no permitido.'}, status=405)
    alert = get_object_or_404(Alert.objects.select_related('incident'), pk=pk, incident__isnull=False)
    incident = alert.incident
    if incident.is_resolved:
        return JsonResponse({'error': 'Este incidente ya fue cerrado.'}, status=400)
    root_cause      = request.POST.get('root_cause', '').strip()
    lessons_learned = request.POST.get('lessons_learned', '').strip()
    if not root_cause:
        return JsonResponse({'error': 'La causa raíz es obligatoria.'}, status=400)
    incident.root_cause      = root_cause
    incident.lessons_learned = lessons_learned
    incident.is_resolved     = True
    incident.resolved_at     = timezone.now()
    incident.resolved_by     = request.user
    incident.save(update_fields=['root_cause', 'lessons_learned', 'is_resolved', 'resolved_at', 'resolved_by'])
    log_action(
        request.user,
        ACTION_INCIDENT_RESOLVED,
        f'Cerró incidente #{alert.pk} — Causa raíz: {root_cause}.',
    )
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
        alert = await Alert.objects.aget(pk=pk, incident__isnull=False)
    except Alert.DoesNotExist:
        return JsonResponse({'error': 'Incidente no encontrado.'}, status=404)
    prediction = await sync_to_async(lambda: alert.latest_prediction)()
    message = request.POST.get('message', '').strip()
    if not message:
        return JsonResponse({'error': 'Mensaje vacío.'}, status=400)
    try:
        from ..claude_service import generate_incident_chat_async
        response = await generate_incident_chat_async(alert, prediction, message)
        return JsonResponse({'ok': True, 'response': response})
    except Exception as exc:
        return JsonResponse({'error': str(exc)}, status=500)


@login_required
@role_required('admin', 'analyst_n3')
def incident_desk_view(request):
    qs = (
        Alert.objects
        .filter(incident__isnull=False)
        .select_related(
            'created_by', 'workflow', 'workflow__assigned_to', 'workflow__investigated_by',
            'incident', 'incident__escalated_by',
        )
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
        qs = qs.filter(predictionlog__predicted_class=class_filter)

    date_from = request.GET.get('date_from', '').strip()
    if date_from:
        qs = qs.filter(incident__escalated_at__date__gte=date_from)

    date_to = request.GET.get('date_to', '').strip()
    if date_to:
        qs = qs.filter(incident__escalated_at__date__lte=date_to)

    resolved_filter = request.GET.get('resolved_filter', '').strip()
    if resolved_filter == 'active':
        qs = qs.filter(incident__is_resolved=False)
    elif resolved_filter == 'resolved':
        qs = qs.filter(incident__is_resolved=True)

    order = request.GET.get('order', 'date_desc').strip()
    _order_map = {
        'risk_desc':    F('predictionlog__risk_score').desc(nulls_last=True),
        'risk_asc':     F('predictionlog__risk_score').asc(nulls_last=True),
        'date_desc':    '-incident__escalated_at',
        'date_asc':     'incident__escalated_at',
    }
    qs = qs.order_by(_order_map.get(order, '-incident__escalated_at')).distinct()

    from urllib.parse import quote as _quote

    _qs_params = request.GET.copy()
    _qs_params.pop('page', None)
    _raw_qs    = _qs_params.urlencode()

    paginator = Paginator(qs, 10)
    page_obj  = paginator.get_page(request.GET.get('page'))

    return render(request, 'predictor/incident_desk.html', {
        'page_obj':        page_obj,
        'search':          search,
        'class_filter':    class_filter,
        'date_from':       date_from,
        'date_to':         date_to,
        'order':           order,
        'resolved_filter': resolved_filter,
        'total_count':     qs.count(),
        'query_string':    _raw_qs,
        'encoded_qs':      _quote(_raw_qs),
    })
