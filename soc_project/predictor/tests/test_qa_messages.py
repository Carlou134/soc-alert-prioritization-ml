"""Textos de los mensajes alineados con los casos de prueba de QA (P20261086).

Los textos van escritos a mano a propósito (no se importan las constantes):
si alguien cambia un mensaje, este archivo tiene que fallar.
"""
import json
from datetime import timedelta

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client
from django.utils import timezone

from accounts.models import ACTION_ALERT_STATUS_CHANGE_FAILED, UserActionLog
from devtools.models import FaultFlag
from predictor.models import Alert, Dataset

pytestmark = pytest.mark.django_db


def _client(user=None):
    client = Client()
    if user is not None:
        client.force_login(user)
    return client


# ── CP001-B — usuario duplicado ──────────────────────────────────────────────

def test_cp001b_duplicate_user_message(admin_user):
    resp = _client(admin_user).post('/users/create/', {
        'username': admin_user.username.upper(), 'email': 'otro@test.local',
        'password1': 'Testpass@2025x', 'password2': 'Testpass@2025x', 'role': 'analyst_n1',
    })

    assert 'El usuario ya existe.' in resp.content.decode()


# ── CP004-B — usuario inactivo ───────────────────────────────────────────────

def test_cp004b_inactive_user_message(make_user):
    user = make_user('inactivo_qa')
    user.is_active = False
    user.save(update_fields=['is_active'])

    resp = _client().post('/login/', {'username': 'inactivo_qa', 'password': 'Testpass@2025'})

    content = resp.content.decode()
    assert 'usuario está desactivado' in content
    assert 'inactivo' in content


# ── CP006 — formato inválido ─────────────────────────────────────────────────

@pytest.mark.parametrize('name, body', [
    ('roto.json', b'{"event_category": "malware",'),
    ('roto.csv',  b'solo_una_columna\nvalor\n'),
])
def test_cp006_invalid_format_upload(analyst_n1_user, name, body):
    resp = _client(analyst_n1_user).post('/upload-alerts/', {'file': SimpleUploadedFile(name, body)})

    assert resp.status_code == 400
    assert resp.json()['error'].startswith('Formato inválido')
    assert not Dataset.objects.exists()


def test_cp006_invalid_format_pipeline(analyst_n1_user):
    resp = _client(analyst_n1_user).post(
        '/pipeline/upload/', {'file': SimpleUploadedFile('roto.json', b'[{"a": 1},')},
    )

    assert 'Formato inválido' in resp.content.decode()
    assert not Alert.objects.exists()


# ── CP007 — datos incompletos ────────────────────────────────────────────────

def test_cp007_pipeline_stops_with_incomplete_data(analyst_n3_user):
    client = _client(analyst_n3_user)
    records = [{'event_category': 'malware', 'protocol': 'tcp'}]
    client.post('/pipeline/upload/', {'file': SimpleUploadedFile('parcial.json', json.dumps(records).encode())})

    resp = client.post('/pipeline/map/')

    assert resp.status_code == 200
    assert 'Datos incompletos' in resp.content.decode()
    # El proceso se detiene: no se puede normalizar ni se crea ningún dataset.
    assert client.post('/pipeline/normalize/').url == '/pipeline/map/'
    assert not Dataset.objects.exists()


def test_cp007_upload_reports_incomplete_data(analyst_n1_user):
    records = [{'event_category': 'malware'}]
    upload = SimpleUploadedFile('parcial.json', json.dumps(records).encode())

    resp = _client(analyst_n1_user).post('/upload-alerts/', {'file': upload})

    assert resp.status_code == 400
    assert resp.json()['error'].startswith('Datos incompletos')


# ── CP011-B — no se pudo clasificar ──────────────────────────────────────────

def test_cp011b_json_prediction_with_insufficient_data(analyst_n2_user):
    resp = _client(analyst_n2_user).post('/predict-json/', {'payload': json.dumps({'protocol': 'tcp'})})

    content = resp.content.decode()
    assert 'No se pudo clasificar la alerta.' in content
    assert resp.context['result'] is None


# ── CP012-B / CP013 / CP030 — detalle de la alerta ──────────────────────────

def test_cp012b_and_cp030_unclassified_alert(analyst_n2_user, admin_user, make_alert):
    alert = make_alert(admin_user, predicted_class=None)

    content = _client(analyst_n2_user).get(f'/alerts/{alert.pk}/shap/').content.decode()

    assert 'Debe clasificarse previamente.' in content
    assert 'No hay información disponible' in content


def test_cp013_alert_without_shap(settings, analyst_n2_user, admin_user, make_alert):
    settings.ENABLE_FAULT_INJECTION = True
    FaultFlag.objects.create(key='shap_unavailable', expires_at=timezone.now() + timedelta(minutes=5))
    alert = make_alert(admin_user, predicted_class='malicioso')

    content = _client(analyst_n2_user).get(f'/alerts/{alert.pk}/shap/').content.decode()

    assert 'No hay información disponible' in content


# ── CP025 — no se pudo registrar la acción ───────────────────────────────────

def test_cp025_message_and_failed_attempt_audited(settings, analyst_n1_user, admin_user, make_alert):
    settings.ENABLE_FAULT_INJECTION = True
    FaultFlag.objects.create(key='db_save', expires_at=timezone.now() + timedelta(minutes=5))
    alert = make_alert(admin_user, predicted_class='benigno')

    resp = _client(analyst_n1_user).post(
        f'/alerts/{alert.pk}/status/',
        data=json.dumps({'status': 'investigated', 'notes': 'x'}), content_type='application/json',
    )

    assert resp.json()['error'] == 'No se pudo registrar la acción. Intente nuevamente.'
    entry = UserActionLog.objects.get(user=analyst_n1_user, action=ACTION_ALERT_STATUS_CHANGE_FAILED)
    assert f'alerta #{alert.pk}' in entry.description


# ── CP028-B — historial vacío ────────────────────────────────────────────────

def test_cp028b_empty_history(analyst_n2_user):
    content = _client(analyst_n2_user).get('/alerts/history/').content.decode()

    assert 'No existen alertas en el historial.' in content
