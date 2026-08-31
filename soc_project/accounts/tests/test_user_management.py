import pytest
from django.contrib.auth.models import User
from django.test import Client

from accounts.models import UserActionLog


# ── HU003 — Asignación de rol al crear usuario ───────────────────────────────

@pytest.mark.django_db
def test_admin_creates_user_with_role(admin_user):
    client = Client()
    client.force_login(admin_user)

    resp = client.post('/users/create/', data={
        'username': 'nuevo_n2',
        'email': 'nuevo_n2@test.local',
        'password1': 'Segura@2025x',
        'password2': 'Segura@2025x',
        'role': 'analyst_n2',
        'is_active': 'on',
    })

    assert resp.status_code == 302
    created = User.objects.get(username='nuevo_n2')
    assert created.profile.role == 'analyst_n2'
    assert created.is_active is True
    assert UserActionLog.objects.filter(user=admin_user, action='user_created').exists()


@pytest.mark.django_db
def test_non_admin_cannot_create_user(analyst_n1_user):
    client = Client()
    client.force_login(analyst_n1_user)
    resp = client.post('/users/create/', data={
        'username': 'intruso',
        'email': 'intruso@test.local',
        'password1': 'Segura@2025x',
        'password2': 'Segura@2025x',
        'role': 'admin',
        'is_active': 'on',
    })
    assert resp.status_code == 302  # admin_required redirige, no crea
    assert not User.objects.filter(username='intruso').exists()


# ── HU004 — Activación / desactivación de usuario ────────────────────────────

@pytest.mark.django_db
def test_admin_deactivates_user(admin_user, analyst_n1_user):
    client = Client()
    client.force_login(admin_user)

    resp = client.post(f'/users/{analyst_n1_user.pk}/edit/', data={
        'role': analyst_n1_user.profile.role,
        # 'is_active' ausente == checkbox destildado
    })

    assert resp.status_code == 302
    analyst_n1_user.refresh_from_db()
    assert analyst_n1_user.is_active is False
    assert UserActionLog.objects.filter(
        user=admin_user, action='user_deactivated',
    ).exists()


@pytest.mark.django_db
def test_admin_reactivates_user(admin_user, analyst_n1_user):
    analyst_n1_user.is_active = False
    analyst_n1_user.save(update_fields=['is_active'])

    client = Client()
    client.force_login(admin_user)
    resp = client.post(f'/users/{analyst_n1_user.pk}/edit/', data={
        'role': analyst_n1_user.profile.role,
        'is_active': 'on',
    })

    assert resp.status_code == 302
    analyst_n1_user.refresh_from_db()
    assert analyst_n1_user.is_active is True
    assert UserActionLog.objects.filter(
        user=admin_user, action='user_activated',
    ).exists()


@pytest.mark.django_db
def test_admin_changes_user_role_logs_action(admin_user, analyst_n1_user):
    client = Client()
    client.force_login(admin_user)
    resp = client.post(f'/users/{analyst_n1_user.pk}/edit/', data={
        'role': 'analyst_n3',
        'is_active': 'on',
    })

    assert resp.status_code == 302
    analyst_n1_user.profile.refresh_from_db()
    assert analyst_n1_user.profile.role == 'analyst_n3'
    assert UserActionLog.objects.filter(
        user=admin_user, action='user_role_changed',
    ).exists()


@pytest.mark.django_db
def test_non_admin_cannot_edit_user(analyst_n1_user, analyst_n2_user):
    client = Client()
    client.force_login(analyst_n1_user)
    resp = client.post(f'/users/{analyst_n2_user.pk}/edit/', data={
        'role': 'admin',
        'is_active': 'on',
    })
    assert resp.status_code == 302
    analyst_n2_user.profile.refresh_from_db()
    assert analyst_n2_user.profile.role == 'analyst_n2'  # sin cambios
