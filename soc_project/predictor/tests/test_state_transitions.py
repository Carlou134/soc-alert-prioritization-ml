import json

import pytest
from django.test import Client

from predictor.models import Incident


def _post_json(client, url, payload):
    return client.post(url, data=json.dumps(payload), content_type='application/json')


# ── alert_set_status_view ────────────────────────────────────────────────────

@pytest.mark.django_db
def test_set_status_updates_workflow(admin_user, make_alert):
    alert = make_alert(admin_user)
    client = Client()
    client.force_login(admin_user)

    resp = _post_json(client, f'/alerts/{alert.pk}/status/', {'status': 'investigating', 'notes': 'en curso'})

    assert resp.status_code == 200
    alert.workflow.refresh_from_db()
    assert alert.workflow.investigation_status == 'investigating'
    assert alert.workflow.investigation_notes == 'en curso'
    assert alert.workflow.investigated_by_id == admin_user.pk


@pytest.mark.django_db
def test_set_status_rejects_invalid_value(admin_user, make_alert):
    alert = make_alert(admin_user)
    client = Client()
    client.force_login(admin_user)
    resp = _post_json(client, f'/alerts/{alert.pk}/status/', {'status': 'not_a_real_status'})
    assert resp.status_code == 400


@pytest.mark.django_db
def test_set_status_rejects_get_method(admin_user, make_alert):
    alert = make_alert(admin_user)
    client = Client()
    client.force_login(admin_user)
    resp = client.get(f'/alerts/{alert.pk}/status/')
    assert resp.status_code == 405


@pytest.mark.django_db
def test_set_status_trainee_blocked_when_not_assigned(trainee_user, admin_user, make_alert):
    alert = make_alert(admin_user)
    client = Client()
    client.force_login(trainee_user)
    resp = _post_json(client, f'/alerts/{alert.pk}/status/', {'status': 'investigating'})
    assert resp.status_code == 403


@pytest.mark.django_db
def test_set_status_trainee_allowed_when_assigned_to_self(trainee_user, admin_user, make_alert):
    alert = make_alert(admin_user)
    alert.workflow.assigned_to = trainee_user
    alert.workflow.save(update_fields=['assigned_to'])

    client = Client()
    client.force_login(trainee_user)
    resp = _post_json(client, f'/alerts/{alert.pk}/status/', {'status': 'investigating'})
    assert resp.status_code == 200


# ── alert_evaluate_view ──────────────────────────────────────────────────────

@pytest.mark.django_db
def test_evaluate_records_ml_evaluation(analyst_n2_user, admin_user, make_alert):
    alert = make_alert(admin_user, predicted_class='malicioso')
    client = Client()
    client.force_login(analyst_n2_user)

    resp = _post_json(client, f'/alerts/{alert.pk}/evaluate/', {'evaluation': 'correct', 'notes': 'ok'})

    assert resp.status_code == 200
    alert.workflow.refresh_from_db()
    assert alert.workflow.ml_evaluation == 'correct'
    assert alert.workflow.ml_evaluated_by_id == analyst_n2_user.pk


@pytest.mark.django_db
def test_evaluate_rejects_invalid_value(analyst_n2_user, admin_user, make_alert):
    alert = make_alert(admin_user)
    client = Client()
    client.force_login(analyst_n2_user)
    resp = _post_json(client, f'/alerts/{alert.pk}/evaluate/', {'evaluation': 'meh'})
    assert resp.status_code == 400


@pytest.mark.django_db
def test_evaluate_requires_existing_prediction(analyst_n2_user, admin_user, make_alert):
    alert = make_alert(admin_user, predicted_class=None)  # sin PredictionLog
    client = Client()
    client.force_login(analyst_n2_user)
    resp = _post_json(client, f'/alerts/{alert.pk}/evaluate/', {'evaluation': 'correct'})
    assert resp.status_code == 400


@pytest.mark.django_db
def test_evaluate_blocks_trainee(trainee_user, admin_user, make_alert):
    alert = make_alert(admin_user)
    client = Client()
    client.force_login(trainee_user)
    resp = _post_json(client, f'/alerts/{alert.pk}/evaluate/', {'evaluation': 'correct'})
    assert resp.status_code == 403


# ── alert_escalate_view ──────────────────────────────────────────────────────

@pytest.mark.django_db
def test_escalate_creates_incident_for_malicious_alert(analyst_n2_user, admin_user, make_alert):
    alert = make_alert(admin_user, predicted_class='malicioso', correlation_id='unknown')
    client = Client()
    client.force_login(analyst_n2_user)

    resp = client.post(f'/alerts/{alert.pk}/escalate/')

    assert resp.status_code == 200
    alert.refresh_from_db()
    assert alert.incident is not None
    assert alert.incident.correlation_id == f'alert-{alert.pk}'


@pytest.mark.django_db
def test_escalate_groups_alerts_by_real_correlation_id(analyst_n2_user, admin_user, make_alert):
    alert1 = make_alert(admin_user, predicted_class='malicioso', correlation_id='INC-REAL-1')
    alert2 = make_alert(admin_user, predicted_class='a_investigar', correlation_id='INC-REAL-1')
    client = Client()
    client.force_login(analyst_n2_user)

    client.post(f'/alerts/{alert1.pk}/escalate/')
    client.post(f'/alerts/{alert2.pk}/escalate/')

    alert1.refresh_from_db()
    alert2.refresh_from_db()
    assert alert1.incident_id == alert2.incident_id
    assert Incident.objects.filter(correlation_id='INC-REAL-1').count() == 1


@pytest.mark.django_db
def test_escalate_rejects_benign_alert(analyst_n2_user, admin_user, make_alert):
    alert = make_alert(admin_user, predicted_class='benigno')
    client = Client()
    client.force_login(analyst_n2_user)
    resp = client.post(f'/alerts/{alert.pk}/escalate/')
    assert resp.status_code == 400


@pytest.mark.django_db
def test_escalate_rejects_already_escalated_alert(analyst_n2_user, admin_user, make_alert):
    alert = make_alert(admin_user, predicted_class='malicioso')
    client = Client()
    client.force_login(analyst_n2_user)
    client.post(f'/alerts/{alert.pk}/escalate/')
    resp = client.post(f'/alerts/{alert.pk}/escalate/')
    assert resp.status_code == 400


@pytest.mark.django_db
def test_escalate_blocked_for_unauthorized_role(analyst_n1_user, admin_user, make_alert):
    """analyst_n1 no está en @role_required('admin', 'analyst_n2') — role_required
    redirige a dashboard (302), no devuelve 403 JSON como los otros checks inline."""
    alert = make_alert(admin_user, predicted_class='malicioso')
    client = Client()
    client.force_login(analyst_n1_user)
    resp = client.post(f'/alerts/{alert.pk}/escalate/')
    assert resp.status_code == 302
    assert resp.url == '/dashboard/' or resp.url.endswith('/dashboard/')


# ── incident_resolve_view ────────────────────────────────────────────────────

@pytest.mark.django_db
def test_resolve_incident_closes_it_with_root_cause(admin_user, analyst_n2_user, make_alert):
    alert = make_alert(admin_user, predicted_class='malicioso')
    client = Client()
    client.force_login(analyst_n2_user)
    client.post(f'/alerts/{alert.pk}/escalate/')

    client.force_login(admin_user)
    resp = client.post(f'/incidents/{alert.pk}/resolve/', data={
        'root_cause': 'phishing',
        'lessons_learned': 'reforzar capacitación',
    })

    assert resp.status_code == 200
    alert.refresh_from_db()
    assert alert.incident.is_resolved is True
    assert alert.incident.root_cause == 'phishing'
    assert alert.incident.resolved_by_id == admin_user.pk


@pytest.mark.django_db
def test_resolve_incident_requires_root_cause(admin_user, analyst_n2_user, make_alert):
    alert = make_alert(admin_user, predicted_class='malicioso')
    client = Client()
    client.force_login(analyst_n2_user)
    client.post(f'/alerts/{alert.pk}/escalate/')

    client.force_login(admin_user)
    resp = client.post(f'/incidents/{alert.pk}/resolve/', data={'root_cause': ''})
    assert resp.status_code == 400


@pytest.mark.django_db
def test_resolve_incident_rejects_already_resolved(admin_user, analyst_n2_user, make_alert):
    alert = make_alert(admin_user, predicted_class='malicioso')
    client = Client()
    client.force_login(analyst_n2_user)
    client.post(f'/alerts/{alert.pk}/escalate/')

    client.force_login(admin_user)
    client.post(f'/incidents/{alert.pk}/resolve/', data={'root_cause': 'phishing'})
    resp = client.post(f'/incidents/{alert.pk}/resolve/', data={'root_cause': 'malware'})
    assert resp.status_code == 400


@pytest.mark.django_db
def test_resolve_incident_404_when_alert_not_escalated(admin_user, make_alert):
    alert = make_alert(admin_user, predicted_class='malicioso')  # nunca escalada
    client = Client()
    client.force_login(admin_user)
    resp = client.post(f'/incidents/{alert.pk}/resolve/', data={'root_cause': 'phishing'})
    assert resp.status_code == 404


@pytest.mark.django_db
def test_resolve_incident_blocked_for_unauthorized_role(admin_user, analyst_n2_user, analyst_n1_user, make_alert):
    alert = make_alert(admin_user, predicted_class='malicioso')
    client = Client()
    client.force_login(analyst_n2_user)
    client.post(f'/alerts/{alert.pk}/escalate/')

    client.force_login(analyst_n1_user)
    resp = client.post(f'/incidents/{alert.pk}/resolve/', data={'root_cause': 'phishing'})
    assert resp.status_code == 302
