import pytest
from django.contrib.auth.models import User
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken


@pytest.fixture
def client():
    return APIClient()


# ── Register (HU001) ─────────────────────────────────────────────────────────
# QA (su CP) cubre Esc.1 Registro exitoso — acá cubrimos Esc.2, el gap que
# el propio mapeo de QA señaló sin caso de prueba formal.

@pytest.mark.django_db
def test_register_creates_user_and_returns_jwt_tokens(client):
    resp = client.post('/api/accounts/register/', data={
        'username': 'nuevo_analista',
        'email': 'nuevo@test.local',
        'password': 'Segura@2025',
    }, format='json')
    assert resp.status_code == 201
    body = resp.json()
    assert body['user']['username'] == 'nuevo_analista'
    assert 'access' in body and 'refresh' in body
    assert User.objects.filter(username='nuevo_analista').exists()


@pytest.mark.django_db
def test_register_rejects_duplicate_username(client, make_user):
    make_user('repetido', role='analyst_n1')
    resp = client.post('/api/accounts/register/', data={
        'username': 'repetido',
        'email': 'otro@test.local',
        'password': 'Segura@2025',
    }, format='json')
    assert resp.status_code == 400
    assert 'username' in resp.json()['detail'].lower()


@pytest.mark.django_db
def test_register_rejects_duplicate_email(client, make_user):
    make_user('otro_user', role='analyst_n1')
    User.objects.filter(username='otro_user').update(email='dup@test.local')
    resp = client.post('/api/accounts/register/', data={
        'username': 'nombre_distinto',
        'email': 'dup@test.local',
        'password': 'Segura@2025',
    }, format='json')
    assert resp.status_code == 400
    assert 'email' in resp.json()['detail'].lower()


@pytest.mark.django_db
def test_register_rejects_missing_fields(client):
    resp = client.post('/api/accounts/register/', data={'username': 'incompleto'}, format='json')
    assert resp.status_code == 400


# ── Login (HU002) ────────────────────────────────────────────────────────────
# QA cubre Esc.2 Credenciales inválidas — acá cubrimos Esc.1, el gap señalado.

@pytest.mark.django_db
def test_login_succeeds_with_valid_credentials(client, make_user):
    make_user('valido', role='analyst_n2', password='Correcta@2025')
    resp = client.post('/api/accounts/login/', data={
        'username': 'valido',
        'password': 'Correcta@2025',
    }, format='json')
    assert resp.status_code == 200
    body = resp.json()
    assert body['user']['username'] == 'valido'
    assert 'access' in body and 'refresh' in body


@pytest.mark.django_db
def test_login_rejects_invalid_credentials(client, make_user):
    make_user('valido2', role='analyst_n1', password='Correcta@2025')
    resp = client.post('/api/accounts/login/', data={
        'username': 'valido2',
        'password': 'Incorrecta',
    }, format='json')
    assert resp.status_code == 401


@pytest.mark.django_db
def test_login_rejects_missing_credentials(client):
    resp = client.post('/api/accounts/login/', data={'username': 'x'}, format='json')
    assert resp.status_code == 400


# ── Logout (HU005) ───────────────────────────────────────────────────────────
# QA cubre Esc.2 Sesión expirada — acá cubrimos Esc.1 Cierre de sesión exitoso.

@pytest.mark.django_db
def test_logout_blacklists_refresh_token(make_user):
    user = make_user('con_sesion', role='analyst_n1')
    refresh = RefreshToken.for_user(user)
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

    resp = client.post('/api/accounts/logout/', data={'refresh': str(refresh)}, format='json')
    assert resp.status_code == 200

    # El refresh token ya blacklisteado no debe poder usarse para pedir uno nuevo.
    resp2 = client.post('/api/token/refresh/', data={'refresh': str(refresh)}, format='json')
    assert resp2.status_code == 401


@pytest.mark.django_db
def test_logout_requires_authentication():
    client = APIClient()
    resp = client.post('/api/accounts/logout/', data={'refresh': 'whatever'}, format='json')
    assert resp.status_code == 401


@pytest.mark.django_db
def test_logout_rejects_invalid_refresh_token(make_user):
    user = make_user('con_sesion2', role='analyst_n1')
    refresh = RefreshToken.for_user(user)
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')
    resp = client.post('/api/accounts/logout/', data={'refresh': 'token-invalido'}, format='json')
    assert resp.status_code == 400
