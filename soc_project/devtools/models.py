from django.contrib.auth.models import User
from django.db import models


class FaultFlag(models.Model):
    """Fallo simulado activo. Vive en la BD (no en caché) porque lo leen dos
    procesos distintos: gunicorn y qcluster (las tareas en background)."""

    key        = models.CharField(max_length=40, unique=True)
    expires_at = models.DateTimeField()
    enabled_by = models.ForeignKey(User, null=True, on_delete=models.SET_NULL, related_name='+')

    def __str__(self):
        return f'{self.key} (hasta {self.expires_at:%Y-%m-%d %H:%M})'
