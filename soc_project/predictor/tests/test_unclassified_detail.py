"""CP030 / CP012-B — detalle de una alerta cuyo procesamiento no terminó."""
import pytest
from django.test import Client

from predictor.models import PredictionLog
from predictor.views.alerts import REQUIRES_CLASSIFICATION_MESSAGE, UNCLASSIFIED_MESSAGE

pytestmark = pytest.mark.django_db


@pytest.fixture
def unclassified_alert(admin_user, make_alert):
    return make_alert(admin_user, predicted_class=None, severity='high', event_category='malware_activity')


def _detail(user, alert):
    client = Client()
    client.force_login(user)
    return client.get(f'/alerts/{alert.pk}/shap/?next=alert_list')


def test_detail_shows_general_info_and_no_info_notice(analyst_n2_user, unclassified_alert):
    resp = _detail(analyst_n2_user, unclassified_alert)

    assert resp.status_code == 200
    content = resp.content.decode()
    assert UNCLASSIFIED_MESSAGE in content
    assert 'data-testid="alert-unclassified"' in content
    assert 'Detalle completo de la alerta' in content
    assert 'malware_activity' in content
    assert 'Trazabilidad' in content


def test_detail_shows_risk_warning_instead_of_score(analyst_n2_user, unclassified_alert):
    """CP012-B: no hay score y se avisa que la alerta debe clasificarse primero."""
    resp = _detail(analyst_n2_user, unclassified_alert)

    assert REQUIRES_CLASSIFICATION_MESSAGE in resp.content.decode()
    assert not PredictionLog.objects.filter(alert=unclassified_alert).exists()


def test_detail_does_not_invent_classification_explanation_or_actions(analyst_n2_user, unclassified_alert):
    resp = _detail(analyst_n2_user, unclassified_alert)

    content = resp.content.decode()
    assert resp.context['classified'] is False
    assert resp.context['can_evaluate'] is False
    assert resp.context['can_escalate'] is False
    # Sin clase por defecto (antes caía en "Benigno"), sin gráficos ni explicación IA.
    assert '>Benigno<' not in content
    assert 'id="chartS1"' not in content
    assert 'explain-loading' not in content


def test_alert_list_links_unclassified_alerts_to_detail(admin_user, unclassified_alert):
    client = Client()
    client.force_login(admin_user)

    resp = client.get('/alerts/?predicted_class=pending')

    assert f'data-testid="alert-detail-link-{unclassified_alert.pk}"'.encode() in resp.content
