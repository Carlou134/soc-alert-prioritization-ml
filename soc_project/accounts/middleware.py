from django.utils.cache import add_never_cache_headers


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
