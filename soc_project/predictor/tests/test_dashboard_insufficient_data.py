"""CP017 — dashboard con datos insuficientes."""
import pytest
from django.test import Client

from predictor.views.dashboard import INSUFFICIENT_DATA_MESSAGE, MIN_CLASSIFIED_ALERTS

pytestmark = pytest.mark.django_db

NOTICE = b'data-testid="dashboard-insufficient-data"'


def _dashboard(user):
    client = Client()
    client.force_login(user)
    return client.get('/dashboard/')


def test_empty_system_shows_notice_and_renders_charts(admin_user):
    resp = _dashboard(admin_user)

    assert resp.status_code == 200
    assert resp.context['insufficient_data'] is True
    assert INSUFFICIENT_DATA_MESSAGE in resp.content.decode()
    assert b'data-testid="dashboard-refresh"' in resp.content
    # Los gráficos se dibujan igual, con series vacías.
    assert resp.context['tactic_data_json'] == '[]'
    assert resp.context['class_data_json'] == '[0, 0, 0]'


def test_notice_shown_below_threshold(admin_user, make_alert):
    for _ in range(MIN_CLASSIFIED_ALERTS - 1):
        make_alert(admin_user, predicted_class='benigno')

    assert NOTICE in _dashboard(admin_user).content


def test_unclassified_alerts_do_not_count_toward_threshold(admin_user, make_alert):
    for _ in range(MIN_CLASSIFIED_ALERTS):
        make_alert(admin_user, predicted_class=None)

    assert NOTICE in _dashboard(admin_user).content


def test_notice_hidden_once_threshold_is_reached(admin_user, make_alert):
    for _ in range(MIN_CLASSIFIED_ALERTS):
        make_alert(admin_user, predicted_class='malicioso')

    resp = _dashboard(admin_user)

    assert resp.context['insufficient_data'] is False
    assert NOTICE not in resp.content
