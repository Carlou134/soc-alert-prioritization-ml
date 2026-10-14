"""CP013 / CP015 — el cálculo SHAP falla al abrir el detalle de una alerta."""
from datetime import timedelta

import pytest
from django.test import Client
from django.utils import timezone

from devtools.models import FaultFlag
from predictor.models import ErrorLog
from predictor.views.alerts import SHAP_UNAVAILABLE_MESSAGE

pytestmark = pytest.mark.django_db


@pytest.fixture
def shap_fault(settings):
    settings.ENABLE_FAULT_INJECTION = True
    FaultFlag.objects.create(key='shap_unavailable', expires_at=timezone.now() + timedelta(minutes=5))


def test_detail_shows_notice_and_alert_info_when_shap_fails(admin_user, make_alert, shap_fault):
    alert = make_alert(admin_user, predicted_class='malicioso')
    client = Client()
    client.force_login(admin_user)

    resp = client.get(f'/alerts/{alert.pk}/shap/')

    assert resp.status_code == 200
    assert resp.context['shap_available'] is False
    assert SHAP_UNAVAILABLE_MESSAGE in resp.content.decode()
    assert b'data-testid="shap-unavailable"' in resp.content
    assert b'id="chartS1"' not in resp.content
    # La información general y el formulario de estado siguen disponibles.
    assert b'Trazabilidad' in resp.content
    assert b'data-testid="status-save"' in resp.content


def test_shap_failure_is_logged_and_classification_unchanged(admin_user, make_alert, shap_fault):
    alert = make_alert(admin_user, predicted_class='malicioso')
    prediction = alert.latest_prediction
    risk_before = prediction.risk_score
    client = Client()
    client.force_login(admin_user)

    client.get(f'/alerts/{alert.pk}/shap/')

    prediction.refresh_from_db()
    assert prediction.predicted_class == 'malicioso'
    assert prediction.risk_score == risk_before
    assert prediction.shap_values is None
    assert ErrorLog.objects.filter(context='alert_shap').count() == 1


def test_navigation_keeps_working_after_shap_failure(admin_user, make_alert, shap_fault):
    alert = make_alert(admin_user, predicted_class='malicioso')
    client = Client()
    client.force_login(admin_user)
    client.get(f'/alerts/{alert.pk}/shap/')

    assert client.get('/alerts/').status_code == 200
    assert client.get('/dashboard/').status_code == 200


def test_shap_is_computed_on_next_open_once_fault_is_disabled(admin_user, make_alert, shap_fault):
    alert = make_alert(admin_user, predicted_class='malicioso')
    client = Client()
    client.force_login(admin_user)
    client.get(f'/alerts/{alert.pk}/shap/')

    FaultFlag.objects.all().delete()
    resp = client.get(f'/alerts/{alert.pk}/shap/')

    assert resp.context['shap_available'] is True
    alert.latest_prediction.refresh_from_db()
    assert alert.latest_prediction.shap_values is not None
