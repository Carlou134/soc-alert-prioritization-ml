import pytest
from django.test import Client

from predictor.models import Incident


# ── Track 7 — notifications_unread_count_view (campanita de notificaciones) ──
# A propósito NO depende de assigned_to: cuenta alertas 'new' en la cola que
# le corresponde revisar al ROL del usuario logueado, igual que alert_list_view,
# así se dispara sola apenas entra un lote nuevo (sin esperar a que alguien
# asigne cada alerta a mano).

@pytest.mark.django_db
def test_admin_sees_all_new_alerts_regardless_of_class(admin_user, make_alert):
    make_alert(admin_user, predicted_class='benigno')
    make_alert(admin_user, predicted_class='a_investigar')
    make_alert(admin_user, predicted_class='malicioso')

    client = Client()
    client.force_login(admin_user)
    resp = client.get('/notifications/unread-count/')

    assert resp.status_code == 200
    assert resp.json()['count'] == 3


@pytest.mark.django_db
def test_analyst_n1_only_sees_benigno(admin_user, analyst_n1_user, make_alert):
    make_alert(admin_user, predicted_class='benigno')
    make_alert(admin_user, predicted_class='malicioso')

    client = Client()
    client.force_login(analyst_n1_user)
    resp = client.get('/notifications/unread-count/')

    assert resp.json()['count'] == 1


@pytest.mark.django_db
def test_analyst_n2_excludes_benigno_and_unclassified(admin_user, analyst_n2_user, make_alert):
    make_alert(admin_user, predicted_class='benigno')
    make_alert(admin_user, predicted_class=None)
    make_alert(admin_user, predicted_class='a_investigar')
    make_alert(admin_user, predicted_class='malicioso')

    client = Client()
    client.force_login(analyst_n2_user)
    resp = client.get('/notifications/unread-count/')

    assert resp.json()['count'] == 2


@pytest.mark.django_db
def test_unread_count_fires_without_manual_assignment(admin_user, make_alert):
    """El caso de uso real: un lote recién subido/sincronizado no tiene a
    nadie asignado todavía (assigned_to nulo por defecto, Track 1) — el
    badge tiene que contar igual, no depender de que alguien reclame la
    alerta primero."""
    alert = make_alert(admin_user)
    assert alert.workflow.assigned_to is None

    client = Client()
    client.force_login(admin_user)
    resp = client.get('/notifications/unread-count/')

    assert resp.json()['count'] == 1


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
    """Una alerta ya escalada a incidente sale de la cola normal
    (alert_list_view la excluye con incident__isnull=True) — el badge no
    debe contarla, para que el número coincida con lo que se ve al hacer
    click."""
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
