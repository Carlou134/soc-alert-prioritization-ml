"""Smoke E2E — 3-5 casos de camino feliz con el test Client de Django (sin
navegador real). Decidido en el Track 3: red de CI propia, no reemplaza ni
duplica el trabajo de QA (Selenium formal).
"""
import json

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client

from predictor.models import Dataset

pytestmark = pytest.mark.django_db


def test_smoke_login_upload_queue_escalate(admin_user, make_alert, q_cluster_sync):
    """Login real → subir alertas → verlas en la cola → escalar a incidente.

    Corre con Q_CLUSTER en modo sync para que el procesamiento en background
    del Track 5 se ejecute en el mismo proceso del test, sin depender de un
    qcluster real corriendo aparte.
    """
    client = Client()

    # 1. Login real (no force_login) — ejercita accounts.views.login_view.
    resp = client.post('/login/', data={
        'username': admin_user.username,
        'password': 'Testpass@2025',
    })
    assert resp.status_code == 302
    assert resp.url.endswith('/dashboard/')

    # 2. Subir alertas — dispara Track 5 (Dataset + django-q2 en sync).
    records = [
        {
            'event_category': 'malware', 'protocol': 'tcp', 'traffic_type': 'https',
            'mitre_tactic': 'execution', 'kill_chain_stage': 'delivery',
            'severity': 'high', 'ids_ips_alert': 'suspicious pattern',
            'asset_criticality': 'medium', 'log_source': 'edr',
            'firewall_action': 'monitored', 'failed_login_attempts': 3,
            'request_rate_per_min': 20.0, 'label': f'smoke-{i}',
            'correlation_id': f'SMOKE-{i}',
        }
        for i in range(3)
    ]
    upload = SimpleUploadedFile('smoke.json', json.dumps(records).encode(), content_type='application/json')
    resp = client.post('/upload-alerts/', data={'file': upload})
    assert resp.status_code == 200
    body = resp.json()
    assert body['total'] == 3

    dataset = Dataset.objects.get(pk=body['dataset_id'])
    assert dataset.status == 'processed'
    assert dataset.saved_count == 3
    assert dataset.failed_count == 0

    # 3. Cola — con sync=True el Dataset ya terminó de procesar, sin polling.
    resp = client.get('/alerts/')
    assert resp.status_code == 200
    visible_labels = {a.label for a in resp.context['page_obj'].object_list}
    assert visible_labels == {'smoke-0', 'smoke-1', 'smoke-2'}

    # 4. Escalar — alerta sembrada con clase conocida (make_alert), para no
    # depender de qué clase le asigne el modelo real a los datos sintéticos
    # del paso 2 (evita un test no determinístico).
    escalable = make_alert(admin_user, predicted_class='malicioso', label='smoke-escalate')
    resp = client.post(f'/alerts/{escalable.pk}/escalate/')
    assert resp.status_code == 200
    escalable.refresh_from_db()
    assert escalable.incident is not None

    resp = client.get('/incidents/')
    assert resp.status_code == 200


def test_smoke_login_pipeline_normalize_queue(admin_user, q_cluster_sync):
    """Camino feliz del pipeline (HU009, priorizado en el Track 5): subir →
    mapear → normalizar → ver en la cola, todo via el flujo de sesión real."""
    client = Client()
    client.force_login(admin_user)

    records = [{
        'event_category': 'malware', 'protocol': 'tcp',
        'label': 'pipeline-smoke-1', 'correlation_id': 'PIPE-SMOKE-1',
    }]
    upload = SimpleUploadedFile('pipe.json', json.dumps(records).encode(), content_type='application/json')
    resp = client.post('/pipeline/upload/', data={'file': upload})
    assert resp.status_code == 302
    assert resp.url == '/pipeline/map/'

    resp = client.post('/pipeline/map/')
    assert resp.status_code == 302
    assert resp.url == '/pipeline/normalize/'

    resp = client.post('/pipeline/normalize/')
    assert resp.status_code == 302
    assert resp.url == '/pipeline/preview/'

    dataset_id = client.session.get('pipeline_dataset_id')
    assert dataset_id is not None
    dataset = Dataset.objects.get(pk=dataset_id)
    assert dataset.status == 'processed'
    assert dataset.saved_count == 1


def test_smoke_login_rejected_with_wrong_password(admin_user):
    """Camino infeliz mínimo — asegura que el smoke no de falsos positivos
    por sesión ya autenticada de otro test."""
    client = Client()
    resp = client.post('/login/', data={
        'username': admin_user.username,
        'password': 'contraseña-incorrecta',
    })
    assert resp.status_code == 200  # re-renderiza el form con error, no redirige
    assert resp.context['error'] is not None
