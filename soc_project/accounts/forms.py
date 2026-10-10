from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import PasswordChangeForm, UserCreationForm

from .models import UserProfile

INPUT_CLASS = (
    'w-full bg-surface-overlay border border-line-strong text-fg-strong '
    'placeholder:text-fg-subtle rounded-md px-3 py-2 text-sm '
    'focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500'
)
SELECT_CLASS = (
    'w-full bg-surface-overlay border border-line-strong text-fg-strong '
    'rounded-md px-3 py-2 text-sm '
    'focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500'
)


class RegisterForm(UserCreationForm):
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={'class': INPUT_CLASS, 'data-testid': 'register-email'}),
    )

    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']
        widgets = {
            'username': forms.TextInput(attrs={'class': INPUT_CLASS, 'data-testid': 'register-username'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['username'].widget.attrs.update({'class': INPUT_CLASS})
        self.fields['password1'].widget.attrs.update({'class': INPUT_CLASS, 'data-testid': 'register-password1'})
        self.fields['password2'].widget.attrs.update({'class': INPUT_CLASS, 'data-testid': 'register-password2'})

    def clean_email(self):
        email = self.cleaned_data['email'].strip().lower()
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError('Este correo ya está registrado.')
        return email


class AdminCreateUserForm(UserCreationForm):
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={'class': INPUT_CLASS, 'data-testid': 'user-create-email'}),
    )
    role = forms.ChoiceField(
        choices=UserProfile.ROLE_CHOICES,
        label='Rol',
        widget=forms.Select(attrs={'class': SELECT_CLASS, 'data-testid': 'user-create-role'}),
    )
    is_active = forms.BooleanField(
        required=False,
        initial=True,
        label='Cuenta activa',
        widget=forms.CheckboxInput(
            attrs={'class': 'w-4 h-4 text-blue-500 bg-surface-overlay border-line-strong rounded', 'data-testid': 'user-create-is-active'}
        ),
    )

    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']
        widgets = {
            'username': forms.TextInput(attrs={'class': INPUT_CLASS, 'data-testid': 'user-create-username'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['username'].widget.attrs.update({'class': INPUT_CLASS})
        self.fields['password1'].widget.attrs.update({'class': INPUT_CLASS, 'data-testid': 'user-create-password1'})
        self.fields['password2'].widget.attrs.update({'class': INPUT_CLASS, 'data-testid': 'user-create-password2'})

    def clean_email(self):
        email = self.cleaned_data['email'].strip().lower()
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError('Este correo ya está registrado.')
        return email


class ProfileForm(forms.ModelForm):
    """Datos que el propio usuario puede editar. Rol, estado y username quedan
    fuera a propósito: solo el admin los gestiona desde user_edit."""

    email = forms.EmailField(
        required=True,
        label='Correo electrónico',
        widget=forms.EmailInput(attrs={'class': INPUT_CLASS, 'data-testid': 'profile-email'}),
    )

    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email']
        labels = {
            'first_name': 'Nombre',
            'last_name': 'Apellido',
        }
        widgets = {
            'first_name': forms.TextInput(attrs={'class': INPUT_CLASS, 'data-testid': 'profile-first-name'}),
            'last_name': forms.TextInput(attrs={'class': INPUT_CLASS, 'data-testid': 'profile-last-name'}),
        }

    def clean_email(self):
        email = self.cleaned_data['email'].strip().lower()
        if User.objects.filter(email__iexact=email).exclude(pk=self.instance.pk).exists():
            raise forms.ValidationError('Este correo ya está registrado.')
        return email


class ProfilePasswordForm(PasswordChangeForm):
    """PasswordChangeForm de Django (valida la contraseña actual) con el estilo del sistema."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        labels = {
            'old_password': 'Contraseña actual',
            'new_password1': 'Nueva contraseña',
            'new_password2': 'Confirmar nueva contraseña',
        }
        for name, label in labels.items():
            self.fields[name].label = label
            self.fields[name].help_text = ''
            self.fields[name].widget.attrs.update({
                'class': INPUT_CLASS,
                'data-testid': f'profile-{name.replace("_", "-")}',
            })


class UserRoleForm(forms.Form):
    role = forms.ChoiceField(
        choices=UserProfile.ROLE_CHOICES,
        label='Rol',
        widget=forms.Select(attrs={'class': SELECT_CLASS, 'data-testid': 'user-edit-role'}),
    )
    is_active = forms.BooleanField(
        required=False,
        label='Usuario activo',
        widget=forms.CheckboxInput(
            attrs={'class': 'w-4 h-4 text-blue-500 bg-surface-overlay border-line-strong rounded', 'data-testid': 'user-edit-is-active'}
        ),
    )
