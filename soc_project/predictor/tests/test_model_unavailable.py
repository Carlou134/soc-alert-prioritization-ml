"""CP014-B — el modelo ML no está disponible al procesar alertas."""
import json
from datetime import timedelta

import pytest
from django.contrib.messages import get_messages
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client
from django.utils import timezone

from devtools.models import FaultFlag
from predictor.models import Alert, AlertWorkflow, Dataset, ErrorLog, PredictionLog
from predictor.tasks import MODEL_UNAVAILABLE_NOTICE
from predictor.views.alerts import MODEL_UNAVAILABLE_PENDING_MESSAGE

pytestmark = pytest.mark.django_db

RECORDS = [
    {
        'event_category': 'malware', 'protocol': 'tcp', 'traffic_type': 'https',
        'mitre_tactic': 'execution', 'kill_chain_stage': 'delivery',
        'severity': 'high', 'ids_ips_alert': 'suspicious pattern',
        'asset_criticality': 'medium', 'log_source': 'edr',
        'firewall_action': 'monitored', 'failed_login_attempts': 3,
        'request_rate_per_min': 20.0, 'label': f'no-model-{i}',
        'correlation_id': f'NO-MODEL-{i}',
    }
    for i in range(3)
]


@pytest.fixture
def model_unavailable_fault(settings):
    settings.ENABLE_FAULT_INJECTION = True
    FaultFlag.objects.create(key='model_unavailable', expires_at=timezone.now() + timedelta(minutes=5))


def _upload(client):
    upload = SimpleUploadedFile('alerts.json', json.dumps(RECORDS).encode(), content_type='application/json')
    return client.post('/upload-alerts/', data={'file': upload})


def test_upload_keeps_alerts_pending_when_model_is_unavailable(
    analyst_n1_user, model_unavailable_fault, q_cluster_sync,
):
    client = Client()
    client.force_login(analyst_n1_user)

    dataset = Dataset.objects.get(pk=_upload(client).json()['dataset_id'])

    assert dataset.status == 'processed'
    assert dataset.saved_count == len(RECORDS)
    assert dataset.failed_count == 0
    assert dataset.error_message == MODEL_UNAVAILABLE_NOTICE
    alerts = Alert.objects.filter(dataset=dataset)
    assert alerts.count() == len(RECORDS)
    assert AlertWorkflow.objects.filter(alert__in=alerts).count() == len(RECORDS)
    assert not PredictionLog.objects.filter(alert__in=alerts).exists()
    assert ErrorLog.objects.filter(context='process_alert_batch_model').count() == 1


def test_status_endpoint_reports_model_unavailable_notice(
    analyst_n1_user, model_unavailable_fault, q_cluster_sync,
):
    client = Client()
    client.force_login(analyst_n1_user)
    dataset_id = _upload(client).json()['dataset_id']

    body = client.get(f'/datasets/{dataset_id}/status/').json()

    assert body['status'] == 'processed'
    assert body['error_message'] == MODEL_UNAVAILABLE_NOTICE


def test_rest_of_system_keeps_working_without_model(
    analyst_n1_user, model_unavailable_fault, q_cluster_sync,
):
    client = Client()
    client.force_login(analyst_n1_user)
    _upload(client)

    assert client.get('/alerts/').status_code == 200
    assert client.get('/dashboard/').status_code == 200


def test_predict_pending_stops_and_keeps_alerts_pending(admin_user, make_alert, model_unavailable_fault):
    alert = make_alert(admin_user, predicted_class=None)
    client = Client()
    client.force_login(admin_user)

    resp = client.post('/alerts/predict-pending/')

    assert resp.status_code == 302
    assert MODEL_UNAVAILABLE_PENDING_MESSAGE in [str(m) for m in get_messages(resp.wsgi_request)]
    assert not PredictionLog.objects.filter(alert=alert).exists()
    assert ErrorLog.objects.filter(context='predict_pending').count() == 1


def test_pending_alerts_get_classified_once_model_is_back(admin_user, make_alert, model_unavailable_fault):
    alert = make_alert(admin_user, predicted_class=None)
    client = Client()
    client.force_login(admin_user)
    client.post('/alerts/predict-pending/')

    FaultFlag.objects.all().delete()
    client.post('/alerts/predict-pending/')

    assert PredictionLog.objects.filter(alert=alert).exists()
