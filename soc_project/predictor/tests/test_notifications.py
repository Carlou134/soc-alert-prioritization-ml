import pytest
from django.test import Client

from predictor.models import Dataset, Incident


# ── Track 7 — notifications_unread_count_view (campanita de notificaciones) ──
# Badge = (# de lotes/Dataset con alertas nuevas SIN asignar — 1 por lote,
# sin importar cuántas alertas tenga adentro) + (# de alertas asignadas
# puntualmente a MÍ que siguen en 'Nueva').

def _make_dataset(user):
    return Dataset.objects.create(filename='lote.csv', row_count=1, uploaded_by=user)


@pytest.mark.django_db
def test_one_batch_of_many_unassigned_alerts_counts_as_one(admin_user, make_alert):
    """El caso que reportó el usuario: subir 99 alertas en un solo lote no
    debe mostrar 99 en la campanita, sino 1 — es un solo evento "llegó un
    lote nuevo", no 99 cosas para revisar una por una todavía."""
    dataset = _make_dataset(admin_user)
    for _ in range(5):
        make_alert(admin_user, dataset=dataset)

    client = Client()
    client.force_login(admin_user)
    resp = client.get('/notifications/unread-count/')

    assert resp.status_code == 200
    assert resp.json()['count'] == 1


@pytest.mark.django_db
def test_two_separate_batches_count_as_two(admin_user, make_alert):
    dataset1 = _make_dataset(admin_user)
    dataset2 = _make_dataset(admin_user)
    make_alert(admin_user, dataset=dataset1)
    make_alert(admin_user, dataset=dataset2)

    client = Client()
    client.force_login(admin_user)
    resp = client.get('/notifications/unread-count/')

    assert resp.json()['count'] == 2


@pytest.mark.django_db
def test_alerts_assigned_to_me_count_individually(admin_user, analyst_n2_user, make_alert):
    """Una vez asignada a un analista puntual, ya no es "un lote genérico" —
    pasa a ser responsabilidad personal y cuenta 1 a 1."""
    dataset = _make_dataset(admin_user)
    a1 = make_alert(admin_user, predicted_class='a_investigar', dataset=dataset)
    a2 = make_alert(admin_user, predicted_class='a_investigar', dataset=dataset)
    for a in (a1, a2):
        a.workflow.assigned_to = analyst_n2_user
        a.workflow.save(update_fields=['assigned_to'])

    client = Client()
    client.force_login(analyst_n2_user)
    resp = client.get('/notifications/unread-count/')

    assert resp.json()['count'] == 2


@pytest.mark.django_db
def test_mixed_batch_sums_pending_dataset_plus_assigned_to_me(admin_user, analyst_n2_user, make_alert):
    """Mismo lote: 2 alertas sin asignar (cuentan 1 por el lote) + 1 asignada
    puntualmente al analista (cuenta 1 más) = 2 en total para ese analista."""
    dataset = _make_dataset(admin_user)
    make_alert(admin_user, predicted_class='a_investigar', dataset=dataset)
    make_alert(admin_user, predicted_class='a_investigar', dataset=dataset)
    assigned = make_alert(admin_user, predicted_class='a_investigar', dataset=dataset)
    assigned.workflow.assigned_to = analyst_n2_user
    assigned.workflow.save(update_fields=['assigned_to'])

    client = Client()
    client.force_login(analyst_n2_user)
    resp = client.get('/notifications/unread-count/')

    assert resp.json()['count'] == 2  # 1 (lote con las 2 sin asignar) + 1 (la asignada a mí)


@pytest.mark.django_db
def test_alerts_assigned_to_other_user_dont_count(admin_user, analyst_n1_user, analyst_n2_user, make_alert):
    alert = make_alert(admin_user, predicted_class='a_investigar')
    alert.workflow.assigned_to = analyst_n2_user
    alert.workflow.save(update_fields=['assigned_to'])

    client = Client()
    client.force_login(analyst_n1_user)
    resp = client.get('/notifications/unread-count/')

    assert resp.json()['count'] == 0


@pytest.mark.django_db
def test_role_scoping_still_applies(admin_user, analyst_n1_user, make_alert):
    make_alert(admin_user, predicted_class='benigno')
    make_alert(admin_user, predicted_class='malicioso')

    client = Client()
    client.force_login(analyst_n1_user)
    resp = client.get('/notifications/unread-count/')

    assert resp.json()['count'] == 1  # el lote general solo tiene 1 alerta benigno visible para N1


@pytest.mark.django_db
def test_unread_count_excludes_non_new_status(admin_user, make_alert):
    alert = make_alert(admin_user)
    alert.workflow.investigation_status = 'investigating'
    alert.workflow.save(update_fields=['investigation_status'])

    client = Client()
    client.force_login(admin_user)
    resp = client.get('/notifications/unread-count/')

    assert resp.json()['count'] == 0


@pytest.mark.django_db
def test_unread_count_excludes_escalated_alerts(admin_user, make_alert):
    alert = make_alert(admin_user)
    alert.incident = Incident.objects.create(correlation_id='inc-1')
    alert.save(update_fields=['incident'])

    client = Client()
    client.force_login(admin_user)
    resp = client.get('/notifications/unread-count/')

    assert resp.json()['count'] == 0


@pytest.mark.django_db
def test_unread_count_requires_login():
    client = Client()
    resp = client.get('/notifications/unread-count/')
    assert resp.status_code == 302  # redirect a login, no JSON — @login_required sin role_required
