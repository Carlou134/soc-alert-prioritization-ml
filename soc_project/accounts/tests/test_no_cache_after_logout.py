"""CP005-A — tras el logout, el botón "Atrás" no muestra páginas protegidas."""
import pytest
from django.test import Client

pytestmark = pytest.mark.django_db


@pytest.mark.parametrize('url', ['/dashboard/', '/alerts/', '/reports/'])
def test_protected_pages_are_not_cacheable(admin_user, url):
    client = Client()
    client.force_login(admin_user)

    resp = client.get(url)

    assert resp.status_code == 200
    cache_control = resp['Cache-Control']
    assert 'no-store' in cache_control
    assert 'no-cache' in cache_control
    assert 'private' in cache_control


def test_public_login_page_is_not_forced_no_store():
    resp = Client().get('/login/')

    assert 'no-store' not in resp.get('Cache-Control', '')


def test_protected_page_after_logout_redirects_to_login(admin_user):
    client = Client()
    client.force_login(admin_user)
    client.get('/alerts/')

    client.post('/logout/')
    resp = client.get('/alerts/')

    assert resp.status_code == 302
    assert resp.url.startswith('/login/')
