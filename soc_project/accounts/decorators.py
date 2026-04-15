from functools import wraps

from django.contrib import messages
from django.shortcuts import redirect


def admin_required(view_func):
    """Restrict access to users with role='admin'."""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('login')
        profile = getattr(request.user, 'profile', None)
        if profile is None or not profile.is_admin:
            messages.error(request, 'No tienes permisos para acceder a esta sección.')
            return redirect('dashboard')
        return view_func(request, *args, **kwargs)
    return wrapper
