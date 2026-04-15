from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404, redirect, render

from .decorators import admin_required
from .forms import RegisterForm, UserRoleForm
from .models import UserProfile


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
            profile.role = form.cleaned_data['role']
            profile.save()
            target_user.is_active = form.cleaned_data['is_active']
            target_user.save(update_fields=['is_active'])
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
