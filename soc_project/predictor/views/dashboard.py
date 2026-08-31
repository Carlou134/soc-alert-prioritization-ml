import json

from django.contrib.auth.decorators import login_required
from django.db.models import Count
from django.db.models.functions import TruncDate
from django.shortcuts import redirect, render

from ..models import Alert, TurnoNota


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
    total_pending    = alerts.filter(predictionlog__isnull=True).distinct().count()
    total_malicioso  = alerts.filter(predictionlog__predicted_class='malicioso').distinct().count()
    total_investigar = alerts.filter(predictionlog__predicted_class='a_investigar').distinct().count()
    total_benigno    = alerts.filter(predictionlog__predicted_class='benigno').distinct().count()

    recent_alerts = alerts.select_related('workflow', 'incident').order_by('-created_at')[:6]

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
