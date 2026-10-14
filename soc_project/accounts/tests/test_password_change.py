import pytest
from django.test import Client

from accounts.models import UserActionLog

PASSWORD_URL = '/settings/password/'
CURRENT_PASSWORD = 'Testpass@2025'  # el que asigna el fixture make_user
NEW_PASSWORD = 'NuevaClave@2026x'


def _post_password(client, **overrides):
    data = {
        'old_password': CURRENT_PASSWORD,
        'new_password1': NEW_PASSWORD,
        'new_password2': NEW_PASSWORD,
    }
    data.update(overrides)
    return client.post(PASSWORD_URL, data=data)


@pytest.mark.django_db
def test_anonymous_user_is_redirected_to_login():
    resp = Client().post(PASSWORD_URL)
    assert resp.status_code == 302
    assert '/login/' in resp.url


@pytest.mark.django_db
def test_get_redirects_to_profile_page(analyst_n1_user):
    client = Client()
    client.force_login(analyst_n1_user)

    resp = client.get(PASSWORD_URL)

    assert resp.status_code == 302
    assert resp.url == '/settings/profile/'


@pytest.mark.django_db
def test_profile_page_includes_password_form(analyst_n1_user):
    client = Client()
    client.force_login(analyst_n1_user)

    resp = client.get('/settings/profile/')

    assert 'password_form' in resp.context


@pytest.mark.django_db
def test_user_changes_password_and_stays_logged_in(analyst_n1_user):
    client = Client()
    client.force_login(analyst_n1_user)

    resp = _post_password(client)

    assert resp.status_code == 302
    analyst_n1_user.refresh_from_db()
    assert analyst_n1_user.check_password(NEW_PASSWORD)
    # update_session_auth_hash: la sesión sigue válida tras el cambio
    assert client.get('/settings/profile/').status_code == 200
    assert UserActionLog.objects.filter(
        user=analyst_n1_user, action='password_changed',
    ).exists()


@pytest.mark.django_db
def test_wrong_current_password_is_rejected(analyst_n1_user):
    client = Client()
    client.force_login(analyst_n1_user)

    resp = _post_password(client, old_password='incorrecta')

    assert resp.status_code == 200
    assert 'old_password' in resp.context['password_form'].errors
    analyst_n1_user.refresh_from_db()
    assert analyst_n1_user.check_password(CURRENT_PASSWORD)
    assert not UserActionLog.objects.filter(action='password_changed').exists()


@pytest.mark.django_db
def test_mismatched_new_passwords_are_rejected(analyst_n1_user):
    client = Client()
    client.force_login(analyst_n1_user)

    resp = _post_password(client, new_password2='OtraClave@2026x')

    assert resp.status_code == 200
    assert 'new_password2' in resp.context['password_form'].errors
    analyst_n1_user.refresh_from_db()
    assert analyst_n1_user.check_password(CURRENT_PASSWORD)
