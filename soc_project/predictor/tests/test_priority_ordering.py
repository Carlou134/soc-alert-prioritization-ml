"""HU021 / CP021 — orden del listado por prioridad efectiva (analista o ML)."""
import pytest
from django.test import Client

from predictor.models import PredictionLog

pytestmark = pytest.mark.django_db


@pytest.fixture
def prioritized(admin_user, make_alert):
    def _make(label, priority, predicted_class='benigno'):
        alert = make_alert(admin_user, predicted_class=predicted_class, label=label)
        alert.workflow.analyst_priority = priority
        alert.workflow.save(update_fields=['analyst_priority'])
        return alert
    return _make


@pytest.fixture
def scored(admin_user, make_alert):
    """Alerta sin ajuste del analista, con un risk_score ML concreto."""
    def _make(label, risk):
        alert = make_alert(admin_user, predicted_class='a_investigar', label=label)
        alert.predictionlog_set.update(risk_score=risk)
        return alert
    return _make


def _labels(user, params=None):
    client = Client()
    client.force_login(user)
    resp = client.get('/alerts/', params or {})
    assert resp.status_code == 200
    return [a.label for a in resp.context['page_obj'].object_list]


def test_list_is_ordered_by_priority_by_default(admin_user, prioritized):
    prioritized('baja', 'low')
    prioritized('critica', 'critical')
    prioritized('media', 'medium')
    prioritized('alta', 'high')

    assert _labels(admin_user) == ['critica', 'alta', 'media', 'baja']


def test_only_medium_and_low_are_listed_medium_first(admin_user, prioritized):
    """CP021: sin alertas críticas, se listan las disponibles (Media antes que Baja)."""
    prioritized('baja', 'low')
    prioritized('media', 'medium')

    assert _labels(admin_user) == ['media', 'baja']


def test_without_analyst_priority_orders_by_ml_risk(admin_user, scored):
    """Bug 0003084: sin ajuste del analista, el orden usa el risk_score del ML."""
    scored('r083', 0.83)
    scored('r028', 0.28)
    scored('r077', 0.77)
    scored('r060', 0.60)

    assert _labels(admin_user) == ['r083', 'r077', 'r060', 'r028']


def test_priority_desc_differs_from_date_desc(admin_user, scored):
    """Bug 0003084: ?order=priority_desc no puede ser idéntico a ?order=date_desc."""
    scored('alta', 0.9)
    scored('baja', 0.1)

    assert _labels(admin_user, {'order': 'priority_desc'}) == ['alta', 'baja']
    assert _labels(admin_user, {'order': 'date_desc'}) == ['baja', 'alta']


def test_analyst_priority_overrides_ml_band(admin_user, prioritized, scored):
    scored('ml-alta', 0.95)
    prioritized('analista-critica', 'critical')
    prioritized('analista-baja', 'low', predicted_class='malicioso')

    assert _labels(admin_user) == ['analista-critica', 'ml-alta', 'analista-baja']


def test_uses_latest_prediction_risk(admin_user, scored, model_version):
    vieja = scored('re-scoreada', 0.95)
    PredictionLog.objects.create(
        alert=vieja, model_version=model_version, predicted_class='benigno', risk_score=0.05,
    )
    scored('media', 0.5)

    assert _labels(admin_user) == ['media', 're-scoreada']


def test_alerts_without_priority_nor_prediction_go_last_newest_first(admin_user, prioritized):
    prioritized('sin-1', '', predicted_class=None)
    prioritized('baja', 'low')
    prioritized('sin-2', '', predicted_class=None)

    assert _labels(admin_user) == ['baja', 'sin-2', 'sin-1']


def test_priority_ascending_order(admin_user, prioritized):
    prioritized('alta', 'high')
    prioritized('baja', 'low')
    prioritized('sin', '', predicted_class=None)

    assert _labels(admin_user, {'order': 'priority_asc'}) == ['baja', 'alta', 'sin']


def test_unknown_order_falls_back_to_priority(admin_user, prioritized):
    prioritized('baja', 'low')
    prioritized('alta', 'high')

    client = Client()
    client.force_login(admin_user)
    resp = client.get('/alerts/', {'order': 'nope'})

    assert resp.context['order'] == 'priority_desc'
    assert [a.label for a in resp.context['page_obj'].object_list] == ['alta', 'baja']
