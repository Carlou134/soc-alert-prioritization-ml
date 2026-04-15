from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm

from .models import UserProfile

INPUT_CLASS = (
    'w-full bg-slate-700 border border-slate-600 text-slate-100 '
    'placeholder:text-slate-500 rounded-md px-3 py-2 text-sm '
    'focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500'
)
SELECT_CLASS = (
    'w-full bg-slate-700 border border-slate-600 text-slate-100 '
    'rounded-md px-3 py-2 text-sm '
    'focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500'
)


class RegisterForm(UserCreationForm):
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={'class': INPUT_CLASS}),
    )

    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']
        widgets = {
            'username': forms.TextInput(attrs={'class': INPUT_CLASS}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['username'].widget.attrs.update({'class': INPUT_CLASS})
        self.fields['password1'].widget.attrs.update({'class': INPUT_CLASS})
        self.fields['password2'].widget.attrs.update({'class': INPUT_CLASS})

    def clean_email(self):
        email = self.cleaned_data['email'].strip().lower()
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError('Este correo ya está registrado.')
        return email


class UserRoleForm(forms.Form):
    role = forms.ChoiceField(
        choices=UserProfile.ROLE_CHOICES,
        label='Rol',
        widget=forms.Select(attrs={'class': SELECT_CLASS}),
    )
    is_active = forms.BooleanField(
        required=False,
        label='Usuario activo',
        widget=forms.CheckboxInput(
            attrs={'class': 'w-4 h-4 text-blue-500 bg-slate-700 border-slate-600 rounded'}
        ),
    )
