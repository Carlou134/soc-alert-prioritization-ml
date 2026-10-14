from .faults import SHORT_SESSION_SECONDS, is_active

# Clave interna donde Django guarda una expiración propia de la sesión
# (la que fija request.session.set_expiry).
_SESSION_EXPIRY_KEY = '_session_expiry'


class ShortSessionMiddleware:
    """CP005-B sin reiniciar la app: con el fallo "short_session" activo, cada
    sesión autenticada expira tras SHORT_SESSION_SECONDS de inactividad.

    Se renueva en cada request (igual que SESSION_SAVE_EVERY_REQUEST), así que
    sigue contando por inactividad. Al desactivarlo — o al vencer su TTL — la
    sesión vuelve a SESSION_COOKIE_AGE en el siguiente request."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            if is_active('short_session'):
                request.session.set_expiry(SHORT_SESSION_SECONDS)
            elif _SESSION_EXPIRY_KEY in request.session:
                request.session.set_expiry(None)
        return self.get_response(request)
