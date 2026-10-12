"""Validadores de contraseña (AUTH_PASSWORD_VALIDATORS) en todos los flujos que
asignan una contraseña. El login no valida fortaleza: las cuentas existentes con
contraseñas débiles siguen entrando."""
import pytest
from django.contrib.auth.models import User
from django.test import Client
from rest_framework.test import APIClient

WEAK_PASSWORDS = [
    pytest.param('123', id='corta'),
    pytest.param('20252025', id='solo-numeros'),
    pytest.param('password', id='comun'),
]


@pytest.mark.django_db
@pytest.mark.parametrize('weak', WEAK_PASSWORDS)
def test_web_register_rejects_weak_password(weak):
    resp = Client().post('/register/', data={
        'username': 'nuevo_web',
        'email': 'nuevo_web@test.local',
        'password1': weak,
        'password2': weak,
    })

    assert resp.status_code == 200
    assert 'password2' in resp.context['form'].errors
    assert not User.objects.filter(username='nuevo_web').exists()


@pytest.mark.django_db
@pytest.mark.parametrize('weak', WEAK_PASSWORDS)
def test_api_register_rejects_weak_password(weak):
    resp = APIClient().post('/api/accounts/register/', data={
        'username': 'nuevo_api',
        'email': 'nuevo_api@test.local',
        'password': weak,
    }, format='json')

    assert resp.status_code == 400
    assert resp.json()['detail']
    assert not User.objects.filter(username='nuevo_api').exists()


@pytest.mark.django_db
def test_api_register_rejects_password_similar_to_username():
    resp = APIClient().post('/api/accounts/register/', data={
        'username': 'analista_soc',
        'email': 'analista_soc@test.local',
        'password': 'analista_soc1',
    }, format='json')

    assert resp.status_code == 400
    assert not User.objects.filter(username='analista_soc').exists()


@pytest.mark.django_db
def test_admin_create_user_rejects_weak_password(admin_user):
    client = Client()
    client.force_login(admin_user)

    resp = client.post('/users/create/', data={
        'username': 'nuevo_admin',
        'email': 'nuevo_admin@test.local',
        'password1': '123',
        'password2': '123',
        'role': 'analyst_n1',
        'is_active': 'on',
    })

    assert resp.status_code == 200
    assert not User.objects.filter(username='nuevo_admin').exists()


@pytest.mark.django_db
def test_profile_password_change_rejects_weak_password(analyst_n1_user):
    client = Client()
    client.force_login(analyst_n1_user)

    resp = client.post('/settings/password/', data={
        'old_password': 'Testpass@2025',
        'new_password1': '123',
        'new_password2': '123',
    })

    assert resp.status_code == 200
    assert 'new_password2' in resp.context['password_form'].errors
    analyst_n1_user.refresh_from_db()
    assert analyst_n1_user.check_password('Testpass@2025')


@pytest.mark.django_db
def test_existing_account_with_weak_password_can_still_log_in():
    # create_user no valida: simula una cuenta creada antes de activar los validadores.
    User.objects.create_user(username='cuenta_vieja', password='123')

    resp = Client().post('/login/', data={'username': 'cuenta_vieja', 'password': '123'})

    assert resp.status_code == 302
    assert resp.url == '/dashboard/'
