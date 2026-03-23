from collections import Counter, defaultdict
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from django.db.models.functions import TruncDate
from django.db.models import Count

from .forms import PredictionForm, JSONPredictionForm
from .models import PredictionLog
from .utils import predict_alert, extract_valid_fields

@login_required
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