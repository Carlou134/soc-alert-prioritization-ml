from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.core.paginator import Paginator
from django.shortcuts import get_object_or_404, redirect, render

from .decorators import admin_required
from .forms import RegisterForm, UserRoleForm
from .models import (
    ACTION_LABELS,
    ACTION_USER_ACTIVATED,
    ACTION_USER_DEACTIVATED,
    ACTION_USER_ROLE_CHANGED,
    UserActionLog,
    UserProfile,
    log_action,
)


# ── Authentication ────────────────────────────────────────────────────────────

def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')

    error = None

    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '').strip()

        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            return redirect('dashboard')
        else:
            # Check if the account exists but is inactive to give a clearer message
            try:
                existing = User.objects.get(username=username)
                if not existing.is_active:
                    error = 'Tu cuenta está desactivada. Contacta al administrador.'
                else:
                    error = 'Usuario o contraseña incorrectos.'
            except User.DoesNotExist:
                error = 'Usuario o contraseña incorrectos.'

    return render(request, 'accounts/login.html', {'error': error})


def register_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')

    form = RegisterForm()

    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('login')

    return render(request, 'accounts/register.html', {'form': form})


def logout_view(request):
    if request.method == 'POST':
        logout(request)
    return redirect('login')


# ── User Management (admin only) ──────────────────────────────────────────────

@login_required
@admin_required
def user_list_view(request):
    users = User.objects.select_related('profile').order_by('username')
    # Ensure every user has a profile (covers users created before the signal)
    for user in users:
        UserProfile.objects.get_or_create(user=user)
    users = User.objects.select_related('profile').order_by('username')
    return render(request, 'accounts/user_list.html', {'users': users})


@login_required
@admin_required
def user_edit_view(request, user_id):
    target_user = get_object_or_404(User, id=user_id)
    profile, _ = UserProfile.objects.get_or_create(user=target_user)

    if request.method == 'POST':
        form = UserRoleForm(request.POST)
        if form.is_valid():
            prev_role = profile.role
            prev_active = target_user.is_active

            new_role = form.cleaned_data['role']
            new_active = form.cleaned_data['is_active']

            profile.role = new_role
            profile.save()
            target_user.is_active = new_active
            target_user.save(update_fields=['is_active'])

            if prev_active != new_active:
                if new_active:
                    log_action(
                        request.user,
                        ACTION_USER_ACTIVATED,
                        f'Usuario "{target_user.username}" activado por {request.user.username}.',
                    )
                else:
                    log_action(
                        request.user,
                        ACTION_USER_DEACTIVATED,
                        f'Usuario "{target_user.username}" desactivado por {request.user.username}.',
                    )

            if prev_role != new_role:
                log_action(
                    request.user,
                    ACTION_USER_ROLE_CHANGED,
                    f'Rol de "{target_user.username}" cambiado de "{prev_role}" a "{new_role}" por {request.user.username}.',
                )

            messages.success(
                request,
                f'Usuario "{target_user.username}" actualizado correctamente.'
            )
            return redirect('user_list')
    else:
        form = UserRoleForm(initial={
            'role': profile.role,
            'is_active': target_user.is_active,
        })

    return render(request, 'accounts/user_edit.html', {
        'form': form,
        'target_user': target_user,
        'profile': profile,
    })


# ── Auditoría ─────────────────────────────────────────────────────────────────

@login_required
def audit_list_view(request):
    is_admin = request.user.profile.is_admin

    if is_admin:
        qs = UserActionLog.objects.select_related('user').all()
    else:
        qs = UserActionLog.objects.filter(user=request.user)

    user_filter = request.GET.get('user', '').strip()
    if user_filter and is_admin:
        qs = qs.filter(user__username__icontains=user_filter)

    action_filter = request.GET.get('action', '').strip()
    if action_filter:
        qs = qs.filter(action=action_filter)

    date_from = request.GET.get('date_from', '').strip()
    if date_from:
        qs = qs.filter(created_at__date__gte=date_from)

    date_to = request.GET.get('date_to', '').strip()
    if date_to:
        qs = qs.filter(created_at__date__lte=date_to)

    paginator = Paginator(qs, 20)
    page_obj = paginator.get_page(request.GET.get('page'))

    context = {
        'page_obj': page_obj,
        'is_admin': is_admin,
        'user_filter': user_filter,
        'action_filter': action_filter,
        'date_from': date_from,
        'date_to': date_to,
        'action_choices': ACTION_LABELS,
        'total_count': qs.count(),
    }
    return render(request, 'accounts/audit_list.html', context)
