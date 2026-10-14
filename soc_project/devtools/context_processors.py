from .faults import active_fault_labels, is_enabled


def fault_injection(request):
    """Expone el link del panel y el banner de fallos activos en base.html.

    El banner lo ven TODOS los usuarios autenticados, no solo el admin: quien
    ejecuta el caso de prueba (N1, N2) tiene que saber que el fallo es simulado.
    """
    if not is_enabled():
        return {}
    user = getattr(request, 'user', None)
    if user is None or not user.is_authenticated:
        return {}
    return {
        'fault_injection_enabled': True,
        'active_faults': active_fault_labels(),
    }
