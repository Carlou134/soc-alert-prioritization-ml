from functools import wraps

from django.contrib import messages
from django.shortcuts import redirect

# Roles con capacidades de analista (excluye practicante)
ANALYST_ROLES = ('admin', 'analyst_n3', 'analyst_n2', 'analyst_n1')


def role_required(*roles):
    """Restrict access to users whose role is in the given list. Requires @login_required above it."""
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            profile = getattr(request.user, 'profile', None)
            if profile is None or profile.role not in roles:
                messages.error(request, 'No tienes permisos para acceder a esta sección.')
                return redirect('dashboard')
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


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


def analyst_required(view_func):
    """Restrict access to analyst_n1, analyst_n2, analyst_n3 and admin. Excludes trainee."""
    return role_required(*ANALYST_ROLES)(view_func)
