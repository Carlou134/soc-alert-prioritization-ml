from django.db import models
from django.contrib.auth.models import User


ACTION_UPLOAD_ALERTS = 'upload_alerts'
ACTION_PREDICT_MANUAL = 'predict_manual'
ACTION_PREDICT_JSON = 'predict_json'
ACTION_USER_ACTIVATED = 'user_activated'
ACTION_USER_DEACTIVATED = 'user_deactivated'
ACTION_USER_ROLE_CHANGED = 'user_role_changed'
ACTION_PIPELINE_NORMALIZATION = 'pipeline_normalization'
ACTION_PIPELINE_EXPORT = 'pipeline_export'

ACTION_LABELS = {
    ACTION_UPLOAD_ALERTS: 'Subida de alertas',
    ACTION_PREDICT_MANUAL: 'Predicción manual',
    ACTION_PREDICT_JSON: 'Predicción por JSON',
    ACTION_USER_ACTIVATED: 'Activación de usuario',
    ACTION_USER_DEACTIVATED: 'Desactivación de usuario',
    ACTION_USER_ROLE_CHANGED: 'Cambio de rol',
    ACTION_PIPELINE_NORMALIZATION: 'Pipeline de normalización',
    ACTION_PIPELINE_EXPORT: 'Exportación de dataset',
}


class UserActionLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='action_logs')
    action = models.CharField(max_length=255)
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Registro de Auditoría'
        verbose_name_plural = 'Registros de Auditoría'

    def __str__(self):
        return f"{self.user.username} — {self.action} — {self.created_at:%Y-%m-%d %H:%M}"

    def get_action_label(self):
        return ACTION_LABELS.get(self.action, self.action)


def log_action(user, action, description):
    """Registra una acción de usuario en el log de auditoría."""
    UserActionLog.objects.create(user=user, action=action, description=description)


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
