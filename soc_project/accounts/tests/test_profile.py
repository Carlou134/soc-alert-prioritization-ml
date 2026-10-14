import pytest
from django.contrib.auth.models import User
from django.test import Client

from accounts.models import UserActionLog

PROFILE_URL = '/settings/profile/'


def _post_profile(client, **overrides):
    data = {
        'first_name': 'Ana',
        'last_name': 'Pérez',
        'email': 'ana.perez@test.local',
    }
    data.update(overrides)
    return client.post(PROFILE_URL, data=data)


# ── Acceso ───────────────────────────────────────────────────────────────────

@pytest.mark.django_db
def test_anonymous_user_is_redirected_to_login():
    resp = Client().get(PROFILE_URL)
    assert resp.status_code == 302
    assert '/login/' in resp.url


@pytest.mark.django_db
def test_profile_page_prefills_current_data(analyst_n1_user):
    analyst_n1_user.first_name = 'Nora'
    analyst_n1_user.save(update_fields=['first_name'])

    client = Client()
    client.force_login(analyst_n1_user)
    resp = client.get(PROFILE_URL)

    assert resp.status_code == 200
    form = resp.context['form']
    assert form.initial['first_name'] == 'Nora'
    assert form.initial['email'] == 'n1_test@test.local'


@pytest.mark.django_db
@pytest.mark.parametrize('role', ['admin', 'analyst_n3', 'analyst_n2', 'analyst_n1', 'trainee'])
def test_sidebar_shows_settings_link_for_every_role(make_user, role):
    client = Client()
    client.force_login(make_user(f'user_{role}', role=role))

    resp = client.get(PROFILE_URL)

    assert b'data-testid="nav-settings"' in resp.content
    assert f'href="{PROFILE_URL}"'.encode() in resp.content


# ── Edición ──────────────────────────────────────────────────────────────────

@pytest.mark.django_db
def test_user_updates_own_profile_and_action_is_logged(analyst_n1_user):
    client = Client()
    client.force_login(analyst_n1_user)

    resp = _post_profile(client, email='Ana.Perez@Test.Local')

    assert resp.status_code == 302
    analyst_n1_user.refresh_from_db()
    assert analyst_n1_user.first_name == 'Ana'
    assert analyst_n1_user.last_name == 'Pérez'
    assert analyst_n1_user.email == 'ana.perez@test.local'
    assert UserActionLog.objects.filter(
        user=analyst_n1_user, action='profile_updated',
    ).exists()


@pytest.mark.django_db
def test_submitting_unchanged_data_does_not_log_action(analyst_n1_user):
    client = Client()
    client.force_login(analyst_n1_user)

    resp = _post_profile(client, first_name='', last_name='', email='n1_test@test.local')

    assert resp.status_code == 302
    assert not UserActionLog.objects.filter(
        user=analyst_n1_user, action='profile_updated',
    ).exists()


@pytest.mark.django_db
def test_email_already_used_by_another_user_is_rejected(analyst_n1_user, analyst_n2_user):
    client = Client()
    client.force_login(analyst_n1_user)

    resp = _post_profile(client, email='N2_TEST@test.local')

    assert resp.status_code == 200
    assert 'email' in resp.context['form'].errors
    analyst_n1_user.refresh_from_db()
    assert analyst_n1_user.email == 'n1_test@test.local'


@pytest.mark.django_db
def test_email_is_required(analyst_n1_user):
    client = Client()
    client.force_login(analyst_n1_user)

    resp = _post_profile(client, email='')

    assert resp.status_code == 200
    assert 'email' in resp.context['form'].errors


@pytest.mark.django_db
def test_user_cannot_escalate_role_or_status_from_profile(analyst_n1_user):
    client = Client()
    client.force_login(analyst_n1_user)

    resp = _post_profile(client, role='admin', is_active='', is_staff='on', username='hacker')

    assert resp.status_code == 302
    analyst_n1_user.refresh_from_db()
    assert analyst_n1_user.profile.role == 'analyst_n1'
    assert analyst_n1_user.is_active is True
    assert analyst_n1_user.is_staff is False
    assert analyst_n1_user.username == 'n1_test'
    assert not User.objects.filter(username='hacker').exists()
