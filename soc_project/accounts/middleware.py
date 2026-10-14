from functools import wraps

from django.contrib.sessions.middleware import SessionMiddleware as DjangoSessionMiddleware
from django.utils.cache import add_never_cache_headers


def passive_session(view_func):
    """Marca una vista de polling en segundo plano (campanita, progreso de un
    lote): sus requests no cuentan como actividad del usuario.

    Sin esto, con SESSION_SAVE_EVERY_REQUEST el polling cada pocos segundos
    renovaba la sesión sin parar y nunca expiraba por inactividad (CP005-B)
    mientras hubiera una pestaña abierta."""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        request.passive_session = True
        return view_func(request, *args, **kwargs)
    return wrapper


class SessionMiddleware(DjangoSessionMiddleware):
    """El SessionMiddleware de Django, salvo en los requests marcados con
    @passive_session: ahí la sesión se lee y se valida igual (si expiró, el
    usuario es anónimo), pero no se guarda ni se renueva su expiración."""

    def process_response(self, request, response):
        if getattr(request, 'passive_session', False):
            return response
        return super().process_response(request, response)


class NoCacheForAuthenticatedMiddleware:
    """CP005-A: las páginas servidas a un usuario logueado no se guardan en la
    caché del navegador. Sin esto, tras el logout el botón "Atrás" mostraba la
    página protegida desde la caché, sin pasar por el servidor (ni por el login).

    Los estáticos no llegan hasta acá: WhiteNoise los responde antes."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        user = getattr(request, 'user', None)
        if user is not None and user.is_authenticated:
            add_never_cache_headers(response)
        return response
