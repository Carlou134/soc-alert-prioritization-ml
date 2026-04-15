from django.db import models
from django.contrib.auth.models import User


class UserProfile(models.Model):
    ROLE_CHOICES = [
        ('admin', 'Administrador'),
        ('analyst_n1', 'Analista Nivel 1'),
        ('analyst_n2', 'Analista Nivel 2'),
    ]

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='analyst_n1')

    class Meta:
        verbose_name = 'Perfil de Usuario'
        verbose_name_plural = 'Perfiles de Usuario'

    def __str__(self):
        return f'{self.user.username} — {self.get_role_display()}'

    @property
    def is_admin(self):
        return self.role == 'admin'
