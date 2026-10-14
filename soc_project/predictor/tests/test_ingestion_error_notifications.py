"""CP010-B — un error crítico de ingesta se notifica en la campanita."""
import json
from datetime import timedelta

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client
from django.utils import timezone

from devtools.models import FaultFlag
from predictor.models import Alert, Dataset, ErrorLog
from predictor.tasks import INGEST_ERROR_MESSAGE

pytestmark = pytest.mark.django_db

RECORDS = [
    {
        'event_category': 'malware', 'protocol': 'tcp', 'traffic_type': 'https',
        'mitre_tactic': 'execution', 'kill_chain_stage': 'delivery',
        'severity': 'high', 'ids_ips_alert': 'suspicious pattern',
        'asset_criticality': 'medium', 'log_source': 'edr',
        'firewall_action': 'monitored', 'failed_login_attempts': 3,
        'request_rate_per_min': 20.0, 'label': f'ingest-{i}',
        'correlation_id': f'INGEST-{i}',
    }
    for i in range(3)
]


@pytest.fixture
def ingest_fault(settings):
    settings.ENABLE_FAULT_INJECTION = True
    FaultFlag.objects.create(key='ingest_critical', expires_at=timezone.now() + timedelta(minutes=5))


def _upload(client):
    upload = SimpleUploadedFile('lote.json', json.dumps(RECORDS).encode(), content_type='application/json')
    return client.post('/upload-alerts/', data={'file': upload})


def _bell(client):
    return client.get('/notifications/unread-count/').json()


def test_critical_error_marks_dataset_failed_and_is_logged(analyst_n1_user, ingest_fault, q_cluster_sync):
    client = Client()
    client.force_login(analyst_n1_user)

    dataset = Dataset.objects.get(pk=_upload(client).json()['dataset_id'])

    assert dataset.status == 'failed'
    assert dataset.error_message == INGEST_ERROR_MESSAGE
    assert not Alert.objects.filter(dataset=dataset).exists()
    assert ErrorLog.objects.filter(context='process_alert_batch', user=analyst_n1_user).count() == 1


def test_failed_batch_shows_in_uploader_bell(analyst_n1_user, ingest_fault, q_cluster_sync):
    client = Client()
    client.force_login(analyst_n1_user)
    _upload(client)

    body = _bell(client)

    assert body['ingestion_errors'] == 1
    assert body['count'] == 1


def test_failed_batch_does_not_show_in_other_users_bell(
    analyst_n1_user, analyst_n2_user, ingest_fault, q_cluster_sync,
):
    client = Client()
    client.force_login(analyst_n1_user)
    _upload(client)

    client.force_login(analyst_n2_user)
    assert _bell(client)['ingestion_errors'] == 0


def test_alert_list_shows_error_notice_with_ack_button(analyst_n1_user, ingest_fault, q_cluster_sync):
    client = Client()
    client.force_login(analyst_n1_user)
    _upload(client)

    resp = client.get('/alerts/?investigation_status=new')

    content = resp.content.decode()
    assert 'data-testid="ingestion-error"' in content
    assert 'lote.json' in content
    assert INGEST_ERROR_MESSAGE in content


def test_ack_clears_notification(analyst_n1_user, ingest_fault, q_cluster_sync):
    client = Client()
    client.force_login(analyst_n1_user)
    dataset_id = _upload(client).json()['dataset_id']

    resp = client.post(f'/datasets/{dataset_id}/ack-error/')

    assert resp.status_code == 302
    assert Dataset.objects.get(pk=dataset_id).error_seen_at is not None
    assert _bell(client)['ingestion_errors'] == 0
    assert b'data-testid="ingestion-error"' not in client.get('/alerts/').content


def test_cannot_ack_another_users_dataset(analyst_n1_user, analyst_n2_user, ingest_fault, q_cluster_sync):
    client = Client()
    client.force_login(analyst_n1_user)
    dataset_id = _upload(client).json()['dataset_id']

    client.force_login(analyst_n2_user)
    resp = client.post(f'/datasets/{dataset_id}/ack-error/')

    assert resp.status_code == 404
    assert Dataset.objects.get(pk=dataset_id).error_seen_at is None


def test_successful_upload_does_not_notify_error(analyst_n1_user, q_cluster_sync):
    client = Client()
    client.force_login(analyst_n1_user)
    _upload(client)

    assert _bell(client)['ingestion_errors'] == 0
