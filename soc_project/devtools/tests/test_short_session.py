"""CP005-B desde el módulo de desarrollador: "Sesión corta (3 minutos)"."""
from datetime import timedelta

import pytest
from django.conf import settings as django_settings
from django.contrib.sessions.models import Session
from django.test import Client
from django.utils import timezone

from devtools.faults import SHORT_SESSION_SECONDS
from devtools.models import FaultFlag

pytestmark = pytest.mark.django_db

PANEL_URL = '/devtools/faults/'


@pytest.fixture
def faults_on(settings):
    settings.ENABLE_FAULT_INJECTION = True


def _login(user):
    client = Client()
    client.force_login(user)
    return client


def _session_row(client):
    return Session.objects.get(session_key=client.session.session_key)


def _expires_in(client):
    return (_session_row(client).expire_date - timezone.now()).total_seconds()


def test_short_session_is_three_minutes():
    assert SHORT_SESSION_SECONDS == 180


def test_admin_activates_short_session_from_panel(faults_on, admin_user):
    client = _login(admin_user)

    # follow=True: el POST redirige al panel, como en el navegador. El middleware
    # corre antes que la vista, así que la sesión corta aplica desde ese GET.
    client.post(PANEL_URL, {'key': 'short_session', 'action': 'enable'}, follow=True)

    assert FaultFlag.objects.filter(key='short_session').exists()
    assert _expires_in(client) <= SHORT_SESSION_SECONDS


def test_active_short_session_limits_every_authenticated_session(faults_on, admin_user, analyst_n1_user):
    FaultFlag.objects.create(key='short_session', expires_at=timezone.now() + timedelta(minutes=15))
    client = _login(analyst_n1_user)

    client.get('/dashboard/')

    assert SHORT_SESSION_SECONDS - 5 <= _expires_in(client) <= SHORT_SESSION_SECONDS


def test_inactivity_beyond_short_session_asks_for_login(faults_on, analyst_n1_user):
    FaultFlag.objects.create(key='short_session', expires_at=timezone.now() + timedelta(minutes=15))
    client = _login(analyst_n1_user)
    client.get('/dashboard/')
    Session.objects.filter(session_key=client.session.session_key).update(
        expire_date=timezone.now() - timedelta(seconds=1),
    )

    resp = client.get('/alerts/')

    assert resp.status_code == 302
    assert resp.url.startswith('/login/')


def test_session_returns_to_normal_after_disabling(faults_on, admin_user):
    client = _login(admin_user)
    client.post(PANEL_URL, {'key': 'short_session', 'action': 'enable'})

    client.post(PANEL_URL, {'key': 'short_session', 'action': 'disable'})
    client.get('/dashboard/')

    assert _expires_in(client) > django_settings.SESSION_COOKIE_AGE - 60


def test_session_returns_to_normal_when_flag_expires(faults_on, analyst_n1_user):
    flag = FaultFlag.objects.create(key='short_session', expires_at=timezone.now() + timedelta(minutes=15))
    client = _login(analyst_n1_user)
    client.get('/dashboard/')

    flag.expires_at = timezone.now() - timedelta(seconds=1)
    flag.save()
    client.get('/dashboard/')

    assert _expires_in(client) > django_settings.SESSION_COOKIE_AGE - 60


def test_short_session_ignored_when_module_disabled(settings, analyst_n1_user):
    settings.ENABLE_FAULT_INJECTION = False
    FaultFlag.objects.create(key='short_session', expires_at=timezone.now() + timedelta(minutes=15))
    client = _login(analyst_n1_user)

    client.get('/dashboard/')

    assert _expires_in(client) > django_settings.SESSION_COOKIE_AGE - 60


def test_panel_explains_short_session(faults_on, admin_user):
    content = _login(admin_user).get(PANEL_URL).content.decode()

    assert 'data-testid="fault-help-short_session"' in content
    assert '3 minutos sin actividad' in content
    assert 'CP005-B' in content
