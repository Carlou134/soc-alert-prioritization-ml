"""HU021 / CP021 — orden del listado por prioridad del analista."""
import pytest
from django.test import Client

pytestmark = pytest.mark.django_db


@pytest.fixture
def prioritized(admin_user, make_alert):
    def _make(label, priority):
        alert = make_alert(admin_user, predicted_class='benigno', label=label)
        alert.workflow.analyst_priority = priority
        alert.workflow.save(update_fields=['analyst_priority'])
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


def test_alerts_without_priority_go_last_newest_first(admin_user, prioritized):
    prioritized('sin-1', '')
    prioritized('baja', 'low')
    prioritized('sin-2', '')

    assert _labels(admin_user) == ['baja', 'sin-2', 'sin-1']


def test_priority_ascending_order(admin_user, prioritized):
    prioritized('alta', 'high')
    prioritized('baja', 'low')
    prioritized('sin', '')

    assert _labels(admin_user, {'order': 'priority_asc'}) == ['baja', 'alta', 'sin']


def test_unknown_order_falls_back_to_priority(admin_user, prioritized):
    prioritized('baja', 'low')
    prioritized('alta', 'high')

    client = Client()
    client.force_login(admin_user)
    resp = client.get('/alerts/', {'order': 'nope'})

    assert resp.context['order'] == 'priority_desc'
    assert [a.label for a in resp.context['page_obj'].object_list] == ['alta', 'baja']
