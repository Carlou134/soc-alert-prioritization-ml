from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import render

from accounts.decorators import analyst_required
from accounts.models import ACTION_PREDICT_JSON, ACTION_PREDICT_MANUAL, log_action

from ..forms import PredictionForm, JSONPredictionForm
from ..models import log_error
from ..pipeline import REQUIRED_COLUMNS
from ..utils import predict_alert, extract_valid_fields


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
                missing_fields = [k for k in REQUIRED_COLUMNS if cleaned_payload.get(k) is None]

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
