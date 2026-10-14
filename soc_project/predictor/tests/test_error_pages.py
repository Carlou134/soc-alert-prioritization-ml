import pytest
from django.test import Client, RequestFactory
from django.views.defaults import server_error


@pytest.mark.django_db
def test_404_page_for_authenticated_user_keeps_navigation(admin_user):
    client = Client()
    client.force_login(admin_user)

    resp = client.get('/alerts/999999/shap/')

    assert resp.status_code == 404
    assert '404.html' in [t.name for t in resp.templates]
    assert b'data-testid="error-page-404"' in resp.content
    assert b'href="/dashboard/"' in resp.content


@pytest.mark.django_db
def test_404_page_for_anonymous_user_links_to_login():
    resp = Client().get('/esta-ruta-no-existe/')

    assert resp.status_code == 404
    assert b'data-testid="error-page-404"' in resp.content
    assert b'href="/login/"' in resp.content


def test_500_page_renders_without_request_context():
    """Django renderiza 500.html sin contexto: si heredara de base.html, fallaría."""
    resp = server_error(RequestFactory().get('/'))

    assert resp.status_code == 500
    assert b'data-testid="error-page-500"' in resp.content
