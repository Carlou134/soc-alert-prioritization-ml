"""CP022 / CP024 — ids de alerta o analista que no existen en los endpoints JSON."""
import json

import pytest
from django.test import Client

from predictor.views.alerts import ALERT_NOT_FOUND_MESSAGE, ANALYST_NOT_FOUND_MESSAGE

pytestmark = pytest.mark.django_db

MISSING_PK = 999999


def _post_json(client, url, payload):
    return client.post(url, data=json.dumps(payload), content_type='application/json')


@pytest.mark.parametrize('url, payload', [
    (f'/alerts/{MISSING_PK}/priority/', {'priority': 'high', 'note': 'x'}),
    (f'/alerts/{MISSING_PK}/status/',   {'status': 'investigating'}),
    (f'/alerts/{MISSING_PK}/assign/',   {'assigned_to': None}),
    (f'/alerts/{MISSING_PK}/evaluate/', {'evaluation': 'correct'}),
    (f'/alerts/{MISSING_PK}/escalate/', {}),
])
def test_unknown_alert_returns_json_error(admin_user, url, payload):
    client = Client()
    client.force_login(admin_user)

    resp = _post_json(client, url, payload)

    assert resp.status_code == 404
    assert resp['Content-Type'] == 'application/json'
    assert resp.json()['error'] == ALERT_NOT_FOUND_MESSAGE


def test_priority_change_on_unknown_alert_changes_nothing(admin_user, make_alert):
    """CP022: ninguna prioridad cambia en la BD."""
    alert = make_alert(admin_user)
    client = Client()
    client.force_login(admin_user)

    _post_json(client, f'/alerts/{MISSING_PK}/priority/', {'priority': 'critical'})

    alert.workflow.refresh_from_db()
    assert alert.workflow.analyst_priority == ''


@pytest.mark.parametrize('assigned_to', [MISSING_PK, 'abc'])
def test_assign_to_unknown_analyst_returns_json_error(admin_user, analyst_n1_user, make_alert, assigned_to):
    """CP024: el analista destino no existe → error y la asignación no cambia."""
    alert = make_alert(admin_user)
    alert.workflow.assigned_to = analyst_n1_user
    alert.workflow.save(update_fields=['assigned_to'])
    client = Client()
    client.force_login(admin_user)

    resp = _post_json(client, f'/alerts/{alert.pk}/assign/', {'assigned_to': assigned_to})

    assert resp.status_code == 404
    assert resp.json()['error'] == ANALYST_NOT_FOUND_MESSAGE
    alert.workflow.refresh_from_db()
    assert alert.workflow.assigned_to_id == analyst_n1_user.pk


def _deactivate(user):
    user.is_active = False
    user.save(update_fields=['is_active'])


def test_assign_to_deactivated_analyst_is_treated_as_unknown(admin_user, analyst_n1_user, analyst_n2_user, make_alert):
    """CP024: los usuarios se desactivan, no se borran; uno desactivado cuenta
    como inexistente → error y la asignación no cambia."""
    alert = make_alert(admin_user)
    alert.workflow.assigned_to = analyst_n1_user
    alert.workflow.save(update_fields=['assigned_to'])
    _deactivate(analyst_n2_user)
    client = Client()
    client.force_login(admin_user)

    resp = _post_json(client, f'/alerts/{alert.pk}/assign/', {'assigned_to': analyst_n2_user.pk})

    assert resp.status_code == 404
    assert resp.json()['error'] == ANALYST_NOT_FOUND_MESSAGE
    alert.workflow.refresh_from_db()
    assert alert.workflow.assigned_to_id == analyst_n1_user.pk


def test_deactivated_analyst_is_not_offered_for_assignment(admin_user, analyst_n2_user, analyst_n3_user, make_alert):
    alert = make_alert(admin_user)
    _deactivate(analyst_n2_user)
    client = Client()
    client.force_login(admin_user)

    users = list(client.get(f'/alerts/{alert.pk}/shap/').context['assignable_users'])

    assert analyst_n2_user not in users
    assert analyst_n3_user in users
