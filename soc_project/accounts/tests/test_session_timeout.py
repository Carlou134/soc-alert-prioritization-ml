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


def test_expired_session_redirects_to_login(admin_user):
    client = Client()
    client.force_login(admin_user)
    Session.objects.filter(session_key=client.session.session_key).update(
        expire_date=timezone.now() - timedelta(seconds=1),
    )

    resp = client.get('/alerts/')

    assert resp.status_code == 302
    assert resp.url.startswith('/login/')
