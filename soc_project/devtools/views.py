from functools import wraps

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import Http404
from django.shortcuts import redirect, render
from django.utils import timezone

from accounts.decorators import admin_required
from accounts.models import ACTION_FAULT_TOGGLED, log_action

from .faults import FAULT_HELP, FAULT_TTL, FAULTS, is_enabled
from .models import FaultFlag


def fault_injection_required(view_func):
    """404 si el módulo está apagado. Va por fuera de admin_required para que,
    en producción, ni un admin pueda saber que el panel existe."""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not is_enabled():
            raise Http404
        return view_func(request, *args, **kwargs)
    return wrapper


@fault_injection_required
@login_required
@admin_required
def fault_panel_view(request):
    if request.method == 'POST':
        key    = request.POST.get('key', '')
        action = request.POST.get('action', '')

        if key not in FAULTS or action not in ('enable', 'disable'):
            messages.error(request, 'Solicitud inválida.')
            return redirect('fault_panel')

        label = FAULTS[key][0]
        if action == 'enable':
            FaultFlag.objects.update_or_create(
                key=key,
                defaults={'expires_at': timezone.now() + FAULT_TTL, 'enabled_by': request.user},
            )
            minutes = int(FAULT_TTL.total_seconds() // 60)
            log_action(request.user, ACTION_FAULT_TOGGLED,
                       f'Activó el fallo simulado "{label}" por {minutes} minutos.')
            messages.success(request, f'Fallo "{label}" activado por {minutes} minutos.')
        else:
            FaultFlag.objects.filter(key=key).delete()
            log_action(request.user, ACTION_FAULT_TOGGLED, f'Desactivó el fallo simulado "{label}".')
            messages.success(request, f'Fallo "{label}" desactivado.')

        return redirect('fault_panel')

    now   = timezone.now()
    flags = {f.key: f for f in FaultFlag.objects.filter(expires_at__gt=now).select_related('enabled_by')}
    rows  = [
        {
            'key':        key,
            'label':      label,
            'help':       FAULT_HELP.get(key, ''),
            'cases':      cases,
            'flag':       flags.get(key),
        }
        for key, (label, cases) in FAULTS.items()
    ]
    return render(request, 'devtools/fault_panel.html', {
        'rows':        rows,
        'ttl_minutes': int(FAULT_TTL.total_seconds() // 60),
    })
