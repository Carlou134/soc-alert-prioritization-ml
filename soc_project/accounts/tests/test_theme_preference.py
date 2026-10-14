import pytest
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.test import Client, RequestFactory

from accounts.models import UserProfile


@pytest.mark.django_db
def test_new_user_defaults_to_dark_theme(make_user):
    user = make_user('nuevo_tema')
    assert user.profile.theme == UserProfile.THEME_DARK == 'dark'


def test_theme_choices_are_dark_and_light():
    assert [value for value, _ in UserProfile.THEME_CHOICES] == ['dark', 'light']


@pytest.mark.django_db
def test_light_theme_is_persisted(make_user):
    user = make_user('tema_claro')
    user.profile.theme = UserProfile.THEME_LIGHT
    user.profile.save(update_fields=['theme'])

    assert UserProfile.objects.get(user=user).theme == 'light'


@pytest.mark.django_db
def test_unknown_theme_is_rejected_by_validation(make_user):
    profile = make_user('tema_raro').profile
    profile.theme = 'neon'

    with pytest.raises(ValidationError) as exc:
        profile.full_clean()
    assert 'theme' in exc.value.message_dict


# ── <html data-theme> ────────────────────────────────────────────────────────

@pytest.mark.django_db
def test_anonymous_pages_render_dark_theme():
    resp = Client().get('/login/')
    assert b'<html lang="es" data-theme="dark">' in resp.content


@pytest.mark.django_db
def test_authenticated_page_renders_user_theme(make_user):
    user = make_user('usa_claro')
    user.profile.theme = UserProfile.THEME_LIGHT
    user.profile.save(update_fields=['theme'])

    client = Client()
    client.force_login(user)
    resp = client.get('/settings/profile/')

    assert b'<html lang="es" data-theme="light">' in resp.content


@pytest.mark.django_db
def test_user_without_profile_falls_back_to_dark(make_user):
    from accounts.context_processors import theme

    user = make_user('sin_perfil')
    UserProfile.objects.filter(user=user).delete()
    request = RequestFactory().get('/')
    request.user = User.objects.get(pk=user.pk)  # instancia fresca, sin el perfil cacheado

    assert theme(request) == {'ui_theme': 'dark'}


@pytest.mark.django_db
def test_invalid_stored_theme_falls_back_to_dark(make_user):
    user = make_user('tema_corrupto')
    # update() salta la validación de choices, como lo haría un dato sucio en la BD
    UserProfile.objects.filter(user=user).update(theme='neon')

    client = Client()
    client.force_login(user)
    resp = client.get('/settings/profile/')

    assert b'<html lang="es" data-theme="dark">' in resp.content


# ── Selector de tema en Configuración ────────────────────────────────────────

THEME_URL = '/settings/theme/'


@pytest.mark.django_db
def test_anonymous_cannot_change_theme():
    resp = Client().post(THEME_URL, data={'theme': 'light'})
    assert resp.status_code == 302
    assert '/login/' in resp.url


@pytest.mark.django_db
def test_profile_page_includes_theme_form_with_current_value(make_user):
    user = make_user('ve_selector')
    client = Client()
    client.force_login(user)

    resp = client.get('/settings/profile/')

    assert resp.context['theme_form'].initial['theme'] == 'dark'
    assert b'data-testid="theme-form"' in resp.content


@pytest.mark.django_db
def test_user_switches_to_light_and_page_renders_light(make_user):
    user = make_user('cambia_tema')
    client = Client()
    client.force_login(user)

    resp = client.post(THEME_URL, data={'theme': 'light'}, follow=True)

    user.profile.refresh_from_db()
    assert user.profile.theme == 'light'
    assert resp.redirect_chain[-1][0] == '/settings/profile/'
    assert b'<html lang="es" data-theme="light">' in resp.content


@pytest.mark.django_db
def test_invalid_theme_is_rejected(make_user):
    user = make_user('tema_invalido')
    client = Client()
    client.force_login(user)

    resp = client.post(THEME_URL, data={'theme': 'neon'})

    assert resp.status_code == 200
    assert 'theme' in resp.context['theme_form'].errors
    user.profile.refresh_from_db()
    assert user.profile.theme == 'dark'


@pytest.mark.django_db
def test_get_on_theme_url_redirects_to_profile(make_user):
    client = Client()
    client.force_login(make_user('get_tema'))

    resp = client.get(THEME_URL)

    assert resp.status_code == 302
    assert resp.url == '/settings/profile/'


@pytest.mark.django_db
def test_theme_post_cannot_change_role(make_user):
    user = make_user('tema_y_rol')
    client = Client()
    client.force_login(user)

    client.post(THEME_URL, data={'theme': 'light', 'role': 'admin'})

    user.profile.refresh_from_db()
    assert user.profile.theme == 'light'
    assert user.profile.role == 'analyst_n1'
