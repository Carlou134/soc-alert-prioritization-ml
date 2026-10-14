"""CP005-B — la sesión expira por inactividad y se vuelve a pedir login."""
from datetime import timedelta

import pytest
from django.conf import settings
from django.contrib.sessions.models import Session
from django.test import Client
from django.utils import timezone

pytestmark = pytest.mark.django_db


def test_session_expires_after_60_minutes_of_inactivity():
    assert settings.SESSION_COOKIE_AGE == 60 * 60
    assert settings.SESSION_SAVE_EVERY_REQUEST is True


def test_activity_extends_the_session(admin_user):
    client = Client()
    client.force_login(admin_user)
    session = Session.objects.get(session_key=client.session.session_key)
    session.expire_date = timezone.now() + timedelta(seconds=30)
    session.save()

    client.get('/dashboard/')

    session.refresh_from_db()
    assert session.expire_date > timezone.now() + timedelta(seconds=settings.SESSION_COOKIE_AGE - 60)


def _expire_date(client):
    return Session.objects.get(session_key=client.session.session_key).expire_date


@pytest.mark.parametrize('polling_url', ['/notifications/unread-count/'])
def test_background_polling_does_not_extend_the_session(admin_user, polling_url):
    """El bug que reportó QA: la campanita consulta cada 3 s y renovaba la
    sesión, así que nunca expiraba por inactividad con la pestaña abierta."""
    client = Client()
    client.force_login(admin_user)
    almost_expired = timezone.now() + timedelta(seconds=30)
    Session.objects.filter(session_key=client.session.session_key).update(expire_date=almost_expired)

    for _ in range(5):
        assert client.get(polling_url).status_code == 200

    assert _expire_date(client) == almost_expired


def test_dataset_status_polling_does_not_extend_the_session(analyst_n1_user):
    from predictor.models import Dataset
    dataset = Dataset.objects.create(filename='lote.csv', row_count=1, uploaded_by=analyst_n1_user)
    client = Client()
    client.force_login(analyst_n1_user)
    almost_expired = timezone.now() + timedelta(seconds=30)
    Session.objects.filter(session_key=client.session.session_key).update(expire_date=almost_expired)

    client.get(f'/datasets/{dataset.pk}/status/')

    assert _expire_date(client) == almost_expired


def test_polling_after_expiry_no_longer_authenticates(admin_user):
    client = Client()
    client.force_login(admin_user)
    Session.objects.filter(session_key=client.session.session_key).update(
        expire_date=timezone.now() - timedelta(seconds=1),
    )

    resp = client.get('/notifications/unread-count/')

    assert resp.status_code == 302
    assert resp.url.startswith('/login/')


def test_expired_session_redirects_to_login(admin_user):
    client = Client()
    client.force_login(admin_user)
    Session.objects.filter(session_key=client.session.session_key).update(
        expire_date=timezone.now() - timedelta(seconds=1),
    )

    resp = client.get('/alerts/')

    assert resp.status_code == 302
    assert resp.url.startswith('/login/')
