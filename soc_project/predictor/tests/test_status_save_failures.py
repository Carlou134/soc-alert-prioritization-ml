"""CP025 — fallo de la BD al guardar el cambio de estado de una alerta."""
import json
from datetime import timedelta

import pytest
from django.test import Client
from django.utils import timezone

from accounts.models import ACTION_ALERT_STATUS_CHANGED, UserActionLog
from devtools.models import FaultFlag
from predictor.models import ErrorLog
from predictor.views.alerts import STATUS_SAVE_ERROR_MESSAGE

pytestmark = pytest.mark.django_db


@pytest.fixture
def db_save_fault(settings):
    settings.ENABLE_FAULT_INJECTION = True
    FaultFlag.objects.create(key='db_save', expires_at=timezone.now() + timedelta(minutes=5))


def _set_status(client, alert, payload):
    return client.post(f'/alerts/{alert.pk}/status/', data=json.dumps(payload), content_type='application/json')


def test_status_save_failure_returns_retry_message(analyst_n1_user, admin_user, make_alert, db_save_fault):
    alert = make_alert(admin_user, predicted_class='benigno')
    client = Client()
    client.force_login(analyst_n1_user)

    resp = _set_status(client, alert, {'status': 'investigated', 'notes': 'IP interna conocida'})

    assert resp.status_code == 503
    assert resp.json()['error'] == STATUS_SAVE_ERROR_MESSAGE
    assert ErrorLog.objects.filter(context='alert_set_status').exists()


def test_status_save_failure_rolls_back_status_and_audit(analyst_n1_user, admin_user, make_alert, db_save_fault):
    alert = make_alert(admin_user, predicted_class='benigno')
    client = Client()
    client.force_login(analyst_n1_user)

    _set_status(client, alert, {'status': 'investigated', 'notes': 'IP interna conocida'})

    alert.workflow.refresh_from_db()
    assert alert.workflow.investigation_status == 'new'
    assert alert.workflow.investigation_notes == ''
    assert alert.workflow.investigated_by_id is None
    assert not UserActionLog.objects.filter(action=ACTION_ALERT_STATUS_CHANGED).exists()


def test_status_save_succeeds_on_retry_once_fault_is_disabled(
    analyst_n1_user, admin_user, make_alert, db_save_fault,
):
    alert = make_alert(admin_user, predicted_class='benigno')
    client = Client()
    client.force_login(analyst_n1_user)
    _set_status(client, alert, {'status': 'investigated', 'notes': 'IP interna conocida'})

    FaultFlag.objects.all().delete()
    resp = _set_status(client, alert, {'status': 'investigated', 'notes': 'IP interna conocida'})

    assert resp.status_code == 200
    alert.workflow.refresh_from_db()
    assert alert.workflow.investigation_status == 'investigated'
    assert UserActionLog.objects.filter(action=ACTION_ALERT_STATUS_CHANGED).count() == 1
