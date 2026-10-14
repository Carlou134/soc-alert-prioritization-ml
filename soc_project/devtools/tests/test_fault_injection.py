from datetime import timedelta

import pytest
from django.test import Client
from django.utils import timezone

from accounts.models import ACTION_FAULT_TOGGLED, UserActionLog
from devtools.faults import InjectedFault, is_active, raise_if_active
from devtools.models import FaultFlag

PANEL_URL = '/devtools/faults/'


@pytest.fixture
def faults_on(settings):
    settings.ENABLE_FAULT_INJECTION = True


def _admin_client(user):
    client = Client()
    client.force_login(user)
    return client


# ── Interruptor general ──────────────────────────────────────────────────────

@pytest.mark.django_db
def test_panel_is_404_when_module_disabled(settings, admin_user):
    settings.ENABLE_FAULT_INJECTION = False
    resp = _admin_client(admin_user).get(PANEL_URL)
    assert resp.status_code == 404


@pytest.mark.django_db
def test_flag_is_ignored_when_module_disabled(settings, admin_user):
    FaultFlag.objects.create(key='db_save', expires_at=timezone.now() + timedelta(minutes=5))
    settings.ENABLE_FAULT_INJECTION = False
    assert is_active('db_save') is False
    raise_if_active('db_save')  # no-op


# ── Acceso ───────────────────────────────────────────────────────────────────

@pytest.mark.django_db
def test_panel_redirects_non_admin(faults_on, analyst_n1_user):
    resp = _admin_client(analyst_n1_user).get(PANEL_URL)
    assert resp.status_code == 302
    assert not FaultFlag.objects.exists()


@pytest.mark.django_db
def test_panel_lists_faults_for_admin(faults_on, admin_user):
    resp = _admin_client(admin_user).get(PANEL_URL)
    assert resp.status_code == 200
    assert b'data-testid="fault-row-db_save"' in resp.content


# ── Activar / desactivar ─────────────────────────────────────────────────────

@pytest.mark.django_db
def test_enable_creates_expiring_flag_and_audit_entry(faults_on, admin_user):
    resp = _admin_client(admin_user).post(PANEL_URL, {'key': 'db_save', 'action': 'enable'})

    assert resp.status_code == 302
    flag = FaultFlag.objects.get(key='db_save')
    assert flag.enabled_by == admin_user
    assert timezone.now() + timedelta(minutes=14) < flag.expires_at <= timezone.now() + timedelta(minutes=15)
    assert is_active('db_save') is True
    assert UserActionLog.objects.filter(user=admin_user, action=ACTION_FAULT_TOGGLED).count() == 1


@pytest.mark.django_db
def test_disable_removes_flag_and_logs(faults_on, admin_user):
    client = _admin_client(admin_user)
    client.post(PANEL_URL, {'key': 'db_save', 'action': 'enable'})
    client.post(PANEL_URL, {'key': 'db_save', 'action': 'disable'})

    assert not FaultFlag.objects.exists()
    assert is_active('db_save') is False
    assert UserActionLog.objects.filter(action=ACTION_FAULT_TOGGLED).count() == 2


@pytest.mark.django_db
def test_unknown_fault_key_is_rejected(faults_on, admin_user):
    _admin_client(admin_user).post(PANEL_URL, {'key': 'drop_tables', 'action': 'enable'})
    assert not FaultFlag.objects.exists()
    assert not UserActionLog.objects.filter(action=ACTION_FAULT_TOGGLED).exists()


# ── Expiración y disparo ─────────────────────────────────────────────────────

@pytest.mark.django_db
def test_expired_flag_is_inactive(faults_on):
    FaultFlag.objects.create(key='db_save', expires_at=timezone.now() - timedelta(seconds=1))
    assert is_active('db_save') is False


@pytest.mark.django_db
def test_raise_if_active_raises_given_exception(faults_on):
    FaultFlag.objects.create(key='db_save', expires_at=timezone.now() + timedelta(minutes=5))

    with pytest.raises(InjectedFault):
        raise_if_active('db_save')
    with pytest.raises(ValueError):
        raise_if_active('db_save', ValueError('simulado'))


# ── Banner ───────────────────────────────────────────────────────────────────

@pytest.mark.django_db
def test_banner_is_visible_to_other_roles_while_fault_active(faults_on, admin_user, analyst_n1_user):
    _admin_client(admin_user).post(PANEL_URL, {'key': 'db_save', 'action': 'enable'})

    resp = _admin_client(analyst_n1_user).get('/alerts/')

    assert b'data-testid="fault-banner"' in resp.content
    assert b'data-testid="nav-devtools"' not in resp.content  # el link es solo para admin


@pytest.mark.django_db
def test_no_banner_when_no_fault_active(faults_on, analyst_n1_user):
    resp = _admin_client(analyst_n1_user).get('/alerts/')
    assert b'data-testid="fault-banner"' not in resp.content
