"""CP003 — asignar rol a un usuario que no existe."""
import pytest
from django.contrib.auth.models import User
from django.test import Client

from accounts.models import ACTION_USER_ROLE_CHANGED, UserActionLog, UserProfile
from accounts.views import USER_NOT_FOUND_MESSAGE

pytestmark = pytest.mark.django_db

MISSING_ID = 999999


def test_edit_unknown_user_shows_not_found_message(admin_user):
    client = Client()
    client.force_login(admin_user)

    resp = client.get(f'/users/{MISSING_ID}/edit/', follow=True)

    assert resp.redirect_chain[-1][0] == '/users/'
    assert USER_NOT_FOUND_MESSAGE in resp.content.decode()


def test_role_assignment_to_unknown_user_changes_nothing(admin_user):
    client = Client()
    client.force_login(admin_user)
    users_before = User.objects.count()
    roles_before = list(UserProfile.objects.order_by('pk').values_list('pk', 'role'))

    resp = client.post(f'/users/{MISSING_ID}/edit/', {'role': 'analyst_n3', 'is_active': 'on'}, follow=True)

    assert USER_NOT_FOUND_MESSAGE in resp.content.decode()
    assert User.objects.count() == users_before
    assert list(UserProfile.objects.order_by('pk').values_list('pk', 'role')) == roles_before
    assert not UserActionLog.objects.filter(action=ACTION_USER_ROLE_CHANGED).exists()


def test_unknown_user_keeps_safe_next_url(admin_user):
    client = Client()
    client.force_login(admin_user)

    resp = client.get(f'/users/{MISSING_ID}/edit/?next=/users/?role=admin')

    assert resp.status_code == 302
    assert resp.url == '/users/?role=admin'
