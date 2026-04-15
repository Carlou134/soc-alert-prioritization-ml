import io
import csv
import json
from collections import Counter

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db.models import Count, Q
from django.db.models.functions import TruncDate
from django.shortcuts import redirect, render

from accounts.models import (
    ACTION_PREDICT_JSON,
    ACTION_PREDICT_MANUAL,
    ACTION_UPLOAD_ALERTS,
    log_action,
)
from .forms import PredictionForm, JSONPredictionForm
from .models import Alert, PredictionLog
from .utils import predict_alert, extract_valid_fields
from .serializers import PredictionRequestSerializer

@login_required
def dashboard_view(request):
    user_logs = PredictionLog.objects.filter(user=request.user)

    total_predictions = user_logs.count()
    total_malicioso = user_logs.filter(predicted_class='malicioso').count()
    total_investigar = user_logs.filter(predicted_class='a_investigar').count()
    total_benigno = user_logs.filter(predicted_class='benigno').count()

    recent_predictions = user_logs.order_by('-created_at')[:5]

    class_counts = Counter(user_logs.values_list('predicted_class', flat=True))
    source_counts = Counter(user_logs.values_list('source', flat=True))

    daily_data = (
        user_logs
        .annotate(day=TruncDate('created_at'))
        .values('day')
        .annotate(total=Count('id'))
        .order_by('day')
    )

    daily_labels = [item['day'].strftime('%Y-%m-%d') for item in daily_data if item['day']]
    daily_totals = [item['total'] for item in daily_data]

    context = {
        'total_predictions': total_predictions,
        'total_malicioso': total_malicioso,
        'total_investigar': total_investigar,
        'total_benigno': total_benigno,
        'recent_predictions': recent_predictions,

        'class_labels': ['benigno', 'a_investigar', 'malicioso'],
        'class_data': [
            class_counts.get('benigno', 0),
            class_counts.get('a_investigar', 0),
            class_counts.get('malicioso', 0),
        ],

        'source_labels': ['manual', 'json', 'api'],
        'source_data': [
            source_counts.get('manual', 0),
            source_counts.get('json', 0),
            source_counts.get('api', 0),
        ],

        'daily_labels': daily_labels,
        'daily_totals': daily_totals,
    }
    return render(request, 'predictor/dashboard.html', context)

@login_required
def predict_view(request):
    form = PredictionForm()
    result = None
    probabilities = None

    if request.method == 'POST':
        form = PredictionForm(request.POST)
        if form.is_valid():
            data = form.cleaned_data
            result, probabilities = predict_alert(data)

            PredictionLog.objects.create(
                user=request.user,
                input_data=data,
                predicted_class=result,
                probabilities=probabilities,
                source='manual'
            )
            log_action(
                request.user,
                ACTION_PREDICT_MANUAL,
                f'Predicción manual ejecutada. Resultado: {result}.',
            )

    return render(request, 'predictor/predict.html', {
        'form': form,
        'result': result,
        'probabilities': probabilities
    })

@login_required
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
            cleaned_payload = extract_valid_fields(payload)
            missing_fields = [k for k, v in cleaned_payload.items() if v is None]

            if not missing_fields:
                result, probabilities = predict_alert(cleaned_payload)

                PredictionLog.objects.create(
                    user=request.user,
                    input_data=cleaned_payload,
                    predicted_class=result,
                    probabilities=probabilities,
                    source='json'
                )
                log_action(
                    request.user,
                    ACTION_PREDICT_JSON,
                    f'Predicción por JSON ejecutada. Resultado: {result}.',
                )

    return render(request, 'predictor/predict_json.html', {
        'form': form,
        'result': result,
        'probabilities': probabilities,
        'cleaned_payload': cleaned_payload,
        'missing_fields': missing_fields,
    })

@login_required
def history_view(request):
    logs = PredictionLog.objects.filter(user=request.user).order_by('-created_at')
    return render(request, 'predictor/history.html', {'logs': logs})


@login_required
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

    for index, record in enumerate(records, start=1):
        serializer = PredictionRequestSerializer(data=record)
        if serializer.is_valid():
            data = serializer.validated_data
            predicted_class, probabilities = predict_alert(data)

            PredictionLog.objects.create(
                user=request.user,
                input_data=data,
                predicted_class=predicted_class,
                probabilities=probabilities,
                source=source,
            )

            Alert.objects.create(
                event_category=data.get('event_category', ''),
                attack_type=data.get('attack_type', ''),
                attack_signature=data.get('attack_signature', ''),
                protocol=data.get('protocol', ''),
                traffic_type=data.get('traffic_type', ''),
                mitre_tactic=data.get('mitre_tactic', ''),
                kill_chain_stage=data.get('kill_chain_stage', ''),
                failed_login_attempts=data.get('failed_login_attempts', 0),
                request_rate_per_min=data.get('request_rate_per_min', 0.0),
                ids_ips_alert=data.get('ids_ips_alert', ''),
                malware_indicator=data.get('malware_indicator', ''),
                asset_criticality=data.get('asset_criticality', ''),
                log_source=data.get('log_source', ''),
                firewall_action=data.get('firewall_action', ''),
                severity=data.get('severity', ''),
                label=record.get('label', ''),
                created_by=request.user,
            )

            processed.append({'record': index, 'predicted_class': predicted_class})
        else:
            failed.append({'record': index, 'errors': serializer.errors})

    if processed:
        log_action(
            request.user,
            ACTION_UPLOAD_ALERTS,
            f'Archivo "{file.name}" subido: {len(processed)} alertas importadas, {len(failed)} con errores.',
        )
        messages.success(
            request,
            f'Alertas importadas correctamente: {len(processed)} de {len(records)} registros almacenados.'
        )
        return redirect('alert_list')

    context['processed'] = processed
    context['failed'] = failed
    context['summary'] = {
        'file': file.name,
        'total': len(records),
        'ok': len(processed),
        'errors': len(failed),
    }
    return render(request, 'predictor/upload_alerts.html', context)


@login_required
def alert_list_view(request):
    is_admin = request.user.profile.is_admin
    qs = Alert.objects.select_related('created_by').all()

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

    severity_choices = (
        Alert.objects.values_list('severity', flat=True)
        .distinct()
        .order_by('severity')
    )

    paginator = Paginator(qs, 20)
    page_obj = paginator.get_page(request.GET.get('page'))

    context = {
        'page_obj': page_obj,
        'is_admin': is_admin,
        'mine': mine,
        'search': search,
        'severity_filter': severity_filter,
        'user_filter': user_filter,
        'date_from': date_from,
        'date_to': date_to,
        'severity_choices': severity_choices,
        'total_count': qs.count(),
    }
    return render(request, 'predictor/alert_list.html', context)


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