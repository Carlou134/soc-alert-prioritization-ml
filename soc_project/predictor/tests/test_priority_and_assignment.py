import json

import pytest
from django.test import Client


def _post_json(client, url, payload):
    return client.post(url, data=json.dumps(payload), content_type='application/json')


# ── HU022 — alert_set_priority_view ──────────────────────────────────────────

@pytest.mark.django_db
def test_set_priority_updates_workflow(admin_user, make_alert):
    alert = make_alert(admin_user)
    client = Client()
    client.force_login(admin_user)

    resp = _post_json(client, f'/alerts/{alert.pk}/priority/', {'priority': 'high', 'note': 'urgente'})

    assert resp.status_code == 200
    alert.workflow.refresh_from_db()
    assert alert.workflow.analyst_priority == 'high'
    assert alert.workflow.analyst_note == 'urgente'


@pytest.mark.django_db
def test_set_priority_rejects_invalid_value(admin_user, make_alert):
    alert = make_alert(admin_user)
    client = Client()
    client.force_login(admin_user)
    resp = _post_json(client, f'/alerts/{alert.pk}/priority/', {'priority': 'urgentisimo'})
    assert resp.status_code == 400


@pytest.mark.django_db
def test_set_priority_requires_post(admin_user, make_alert):
    alert = make_alert(admin_user)
    client = Client()
    client.force_login(admin_user)
    resp = client.get(f'/alerts/{alert.pk}/priority/')
    assert resp.status_code == 405


@pytest.mark.django_db
def test_set_priority_blocks_trainee(trainee_user, admin_user, make_alert):
    """trainee no está en @analyst_required — role_required redirige (302),
    no devuelve 403 JSON (mismo patrón que alert_escalate_view)."""
    alert = make_alert(admin_user)
    client = Client()
    client.force_login(trainee_user)
    resp = _post_json(client, f'/alerts/{alert.pk}/priority/', {'priority': 'high'})
    assert resp.status_code == 302


# ── HU024 — alert_assign_view ─────────────────────────────────────────────────

@pytest.mark.django_db
def test_admin_assigns_alert_to_allowed_target(admin_user, analyst_n2_user, make_alert):
    alert = make_alert(admin_user)
    client = Client()
    client.force_login(admin_user)

    resp = _post_json(client, f'/alerts/{alert.pk}/assign/', {'assigned_to': analyst_n2_user.pk})

    assert resp.status_code == 200
    alert.workflow.refresh_from_db()
    assert alert.workflow.assigned_to_id == analyst_n2_user.pk


@pytest.mark.django_db
def test_assign_rejects_disallowed_target_role(analyst_n1_user, admin_user, make_alert):
    """analyst_n1 solo puede asignar a (analyst_n1, analyst_n2, trainee) — admin
    está fuera de ASSIGNMENT_TARGETS['analyst_n1'], debe rechazarse con 403 JSON
    (chequeo inline dentro de la vista, no el decorador)."""
    alert = make_alert(admin_user)
    client = Client()
    client.force_login(analyst_n1_user)
    resp = _post_json(client, f'/alerts/{alert.pk}/assign/', {'assigned_to': admin_user.pk})
    assert resp.status_code == 403


@pytest.mark.django_db
def test_unassign_alert(admin_user, analyst_n2_user, make_alert):
    alert = make_alert(admin_user)
    alert.workflow.assigned_to = analyst_n2_user
    alert.workflow.save(update_fields=['assigned_to'])

    client = Client()
    client.force_login(admin_user)
    resp = _post_json(client, f'/alerts/{alert.pk}/assign/', {'assigned_to': None})

    assert resp.status_code == 200
    alert.workflow.refresh_from_db()
    assert alert.workflow.assigned_to_id is None


@pytest.mark.django_db
def test_assign_blocks_trainee(trainee_user, admin_user, make_alert):
    alert = make_alert(admin_user)
    client = Client()
    client.force_login(trainee_user)
    resp = _post_json(client, f'/alerts/{alert.pk}/assign/', {'assigned_to': admin_user.pk})
    assert resp.status_code == 302
