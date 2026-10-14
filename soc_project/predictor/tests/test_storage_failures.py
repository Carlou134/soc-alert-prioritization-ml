"""CP008-B — fallo de la BD al guardar un lote de alertas subido."""
import json
from datetime import timedelta

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client
from django.utils import timezone

from devtools.models import FaultFlag
from predictor.models import Alert, AlertWorkflow, Dataset, ErrorLog, PredictionLog
from predictor.tasks import STORAGE_ERROR_MESSAGE

pytestmark = pytest.mark.django_db

RECORDS = [
    {
        'event_category': 'malware', 'protocol': 'tcp', 'traffic_type': 'https',
        'mitre_tactic': 'execution', 'kill_chain_stage': 'delivery',
        'severity': 'high', 'ids_ips_alert': 'suspicious pattern',
        'asset_criticality': 'medium', 'log_source': 'edr',
        'firewall_action': 'monitored', 'failed_login_attempts': 3,
        'request_rate_per_min': 20.0, 'label': f'storage-{i}',
        'correlation_id': f'STORAGE-{i}',
    }
    for i in range(3)
]


@pytest.fixture
def db_save_fault(settings):
    settings.ENABLE_FAULT_INJECTION = True
    FaultFlag.objects.create(key='db_save', expires_at=timezone.now() + timedelta(minutes=5))


def _upload(client):
    upload = SimpleUploadedFile('alerts.json', json.dumps(RECORDS).encode(), content_type='application/json')
    return client.post('/upload-alerts/', data={'file': upload})


def test_storage_failure_marks_dataset_failed_without_partial_records(
    analyst_n1_user, db_save_fault, q_cluster_sync,
):
    client = Client()
    client.force_login(analyst_n1_user)
    counts_before = (Alert.objects.count(), AlertWorkflow.objects.count(), PredictionLog.objects.count())

    resp = _upload(client)

    assert resp.status_code == 200
    dataset = Dataset.objects.get(pk=resp.json()['dataset_id'])
    assert dataset.status == 'failed'
    assert dataset.error_message == STORAGE_ERROR_MESSAGE
    assert dataset.saved_count == 0
    assert dataset.failed_count == len(RECORDS)
    # El fallo ocurre después de insertar las Alert: el rollback no deja nada a medias.
    assert (Alert.objects.count(), AlertWorkflow.objects.count(), PredictionLog.objects.count()) == counts_before
    assert ErrorLog.objects.filter(context='process_alert_batch_bulk').exists()


def test_status_endpoint_reports_storage_failure(analyst_n1_user, db_save_fault, q_cluster_sync):
    client = Client()
    client.force_login(analyst_n1_user)
    dataset_id = _upload(client).json()['dataset_id']

    body = client.get(f'/datasets/{dataset_id}/status/').json()

    assert body['status'] == 'failed'
    assert body['error_message'] == STORAGE_ERROR_MESSAGE


def test_upload_succeeds_once_fault_is_disabled(analyst_n1_user, db_save_fault, q_cluster_sync):
    FaultFlag.objects.all().delete()
    client = Client()
    client.force_login(analyst_n1_user)

    dataset = Dataset.objects.get(pk=_upload(client).json()['dataset_id'])

    assert dataset.status == 'processed'
    assert dataset.saved_count == len(RECORDS)
