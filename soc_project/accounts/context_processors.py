from .models import UserProfile

_VALID_THEMES = {value for value, _ in UserProfile.THEME_CHOICES}


def theme(request):
    """Expone `ui_theme` para <html data-theme> en base.html.

    Cae en oscuro para anónimos, usuarios sin perfil o un valor inválido en la BD:
    un data-theme vacío o desconocido dejaría la página sin ningún tema aplicado.
    """
    user = getattr(request, 'user', None)
    if user is None or not user.is_authenticated:
        return {'ui_theme': UserProfile.THEME_DARK}

    try:
        value = user.profile.theme
    except UserProfile.DoesNotExist:
        return {'ui_theme': UserProfile.THEME_DARK}

    return {'ui_theme': value if value in _VALID_THEMES else UserProfile.THEME_DARK}
