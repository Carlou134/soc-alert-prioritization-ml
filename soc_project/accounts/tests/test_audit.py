import pytest
from django.test import Client

from accounts.models import log_action


# ── HU025 — el registro de una acción persiste ───────────────────────────────

@pytest.mark.django_db
def test_log_action_persists_entry(admin_user):
    from accounts.models import UserActionLog

    log_action(admin_user, 'user_created', 'Usuario de prueba creado.')

    entry = UserActionLog.objects.get(user=admin_user, action='user_created')
    assert entry.description == 'Usuario de prueba creado.'
    assert entry.get_action_label() == 'Creación de usuario'


# ── HU029 — audit_list_view ───────────────────────────────────────────────────

@pytest.mark.django_db
def test_admin_sees_all_audit_entries(admin_user, analyst_n1_user):
    log_action(admin_user, 'user_created', 'entrada admin')
    log_action(analyst_n1_user, 'upload_alerts', 'entrada n1')

    client = Client()
    client.force_login(admin_user)
    resp = client.get('/audit/')

    assert resp.status_code == 200
    assert resp.context['total_count'] == 2


@pytest.mark.django_db
def test_non_admin_sees_only_own_audit_entries(admin_user, analyst_n1_user):
    log_action(admin_user, 'user_created', 'entrada admin')
    log_action(analyst_n1_user, 'upload_alerts', 'entrada n1')

    client = Client()
    client.force_login(analyst_n1_user)
    resp = client.get('/audit/')

    assert resp.status_code == 200
    assert resp.context['total_count'] == 1
    entries = list(resp.context['page_obj'].object_list)
    assert entries[0].user_id == analyst_n1_user.pk


@pytest.mark.django_db
def test_audit_empty_state_no_crash(admin_user):
    """HU029 Esc.2 — sin registros: no debe romper."""
    client = Client()
    client.force_login(admin_user)
    resp = client.get('/audit/')
    assert resp.status_code == 200
    assert resp.context['total_count'] == 0
