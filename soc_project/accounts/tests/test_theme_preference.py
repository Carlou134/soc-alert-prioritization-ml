import pytest
from django.core.exceptions import ValidationError

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
