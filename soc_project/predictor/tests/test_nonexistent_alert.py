"""CP020 — intento de acceso al detalle de una alerta que no existe."""
import pytest
from django.test import Client

from accounts.models import ACTION_ALERT_NOT_FOUND, UserActionLog
from predictor.views.alerts import ALERT_NOT_FOUND_MESSAGE

pytestmark = pytest.mark.django_db

MISSING_PK = 999999


def test_nonexistent_alert_shows_message_on_alert_list(analyst_n2_user):
    client = Client()
    client.force_login(analyst_n2_user)

    resp = client.get(f'/alerts/{MISSING_PK}/shap/', follow=True)

    assert resp.redirect_chain[-1][0] == '/alerts/'
    assert resp.status_code == 200
    assert ALERT_NOT_FOUND_MESSAGE in resp.content.decode()


def test_nonexistent_alert_access_is_audited(analyst_n2_user):
    client = Client()
    client.force_login(analyst_n2_user)

    client.get(f'/alerts/{MISSING_PK}/shap/')

    entry = UserActionLog.objects.get(user=analyst_n2_user, action=ACTION_ALERT_NOT_FOUND)
    assert f'alerta #{MISSING_PK}' in entry.description


def test_existing_alert_access_is_not_audited_as_not_found(admin_user, make_alert):
    alert = make_alert(admin_user, predicted_class='malicioso')
    client = Client()
    client.force_login(admin_user)

    client.get(f'/alerts/{alert.pk}/shap/')

    assert not UserActionLog.objects.filter(action=ACTION_ALERT_NOT_FOUND).exists()
