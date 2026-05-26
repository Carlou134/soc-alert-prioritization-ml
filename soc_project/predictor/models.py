from django.db import models
from django.contrib.auth.models import User


class ErrorLog(models.Model):
    """Registro de errores del sistema durante la ingesta o predicción de alertas."""

    user = models.ForeignKey(
        User, null=True, blank=True, on_delete=models.SET_NULL, related_name='error_logs'
    )
    context = models.CharField(max_length=100, default='', help_text='Vista o proceso que generó el error')
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Registro de Error'
        verbose_name_plural = 'Registros de Errores'

    def __str__(self):
        username = self.user.username if self.user else 'anónimo'
        return f'[{self.context}] {username} — {self.created_at:%Y-%m-%d %H:%M}'


def log_error(user, context: str, message: str) -> None:
    """Guarda un error en DB sin propagar excepciones."""
    try:
        ErrorLog.objects.create(user=user, context=context, message=message)
    except Exception:
        pass


class Alert(models.Model):
    # Campos requeridos por el modelo ML
    event_category        = models.CharField(max_length=100)
    protocol              = models.CharField(max_length=50)
    traffic_type          = models.CharField(max_length=100)
    mitre_tactic          = models.CharField(max_length=100)
    kill_chain_stage      = models.CharField(max_length=100)
    failed_login_attempts = models.IntegerField(default=0)
    request_rate_per_min  = models.FloatField(default=0.0)
    ids_ips_alert         = models.CharField(max_length=100)
    asset_criticality     = models.CharField(max_length=100)
    log_source            = models.CharField(max_length=100)
    firewall_action       = models.CharField(max_length=100)
    severity              = models.CharField(max_length=50)

    # Campos opcionales que mejoran la predicción
    has_threat_family = models.IntegerField(default=0)          # 1 si hay familia de malware conocida
    evidence_role     = models.CharField(max_length=50, blank=True, default='unknown')
    os_family         = models.CharField(max_length=50, blank=True, default='unknown')
    correlation_id    = models.CharField(max_length=200, blank=True, default='unknown')
    mitre_techniques  = models.CharField(max_length=500, blank=True, default='')

    # Campos de contexto — para display/búsqueda, no usados por el modelo ML
    attack_type       = models.CharField(max_length=100, blank=True, default='')
    attack_signature  = models.CharField(max_length=200, blank=True, default='')
    malware_indicator = models.CharField(max_length=100, blank=True, default='')
    label             = models.CharField(max_length=100, blank=True, default='')

    # Resultados ML — vacío ('') significa "pendiente de clasificar"
    predicted_class = models.CharField(max_length=100, blank=True, default='')
    risk_score = models.FloatField(null=True, blank=True)
    probabilities = models.JSONField(null=True, blank=True)
    shap_values = models.JSONField(null=True, blank=True)
    shap_explanation = models.TextField(null=True, blank=True)

    # Estado de investigación — gestionado por analista nivel 1
    INVESTIGATION_STATUS_CHOICES = [
        ('new',            'Nueva'),
        ('investigating',  'En investigación'),
        ('investigated',   'Investigada'),
        ('false_positive', 'Falso positivo'),
    ]
    investigation_status = models.CharField(
        max_length=20,
        choices=INVESTIGATION_STATUS_CHOICES,
        default='new',
    )
    investigation_notes  = models.TextField(blank=True, default='')
    investigated_by      = models.ForeignKey(
        User, null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name='investigated_alerts',
    )
    investigated_at      = models.DateTimeField(null=True, blank=True)

    # Ajuste manual de prioridad por analista nivel 2
    ANALYST_PRIORITY_CHOICES = [
        ('critical', 'Crítica'),
        ('high',     'Alta'),
        ('medium',   'Media'),
        ('low',      'Baja'),
    ]
    analyst_priority = models.CharField(max_length=20, blank=True, default='')
    analyst_note     = models.TextField(blank=True, default='')

    # Evaluación de la decisión ML — analista nivel 2
    ML_EVALUATION_CHOICES = [
        ('correct',           'Correcta'),
        ('partially_correct', 'Parcialmente correcta'),
        ('incorrect',         'Incorrecta'),
    ]
    ml_evaluation       = models.CharField(max_length=20, blank=True, default='', choices=ML_EVALUATION_CHOICES)
    ml_evaluation_notes = models.TextField(blank=True, default='')
    ml_evaluated_by     = models.ForeignKey(
        User, null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name='evaluated_alerts',
    )
    ml_evaluated_at     = models.DateTimeField(null=True, blank=True)

    # Asignación — analista responsable de la alerta
    assigned_to = models.ForeignKey(
        User, null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name='assigned_alerts',
    )

    # Escalado a incidente — gestionado por analista nivel 2
    is_incident  = models.BooleanField(default=False)
    escalated_at = models.DateTimeField(null=True, blank=True)
    escalated_by = models.ForeignKey(
        User, null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name='escalated_alerts',
    )

    # Cierre del incidente — gestionado por analista nivel 3
    ROOT_CAUSE_CHOICES = [
        ('phishing',         'Phishing'),
        ('unpatched_vuln',   'Vulnerabilidad no parchada'),
        ('malware',          'Malware / Ransomware'),
        ('misconfig',        'Error de configuración'),
        ('insider_threat',   'Amenaza interna'),
        ('other',            'Otro'),
    ]
    is_resolved      = models.BooleanField(default=False)
    resolved_at      = models.DateTimeField(null=True, blank=True)
    resolved_by      = models.ForeignKey(
        User, null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name='resolved_alerts',
    )
    root_cause       = models.CharField(max_length=30, blank=True, default='', choices=ROOT_CAUSE_CHOICES)
    lessons_learned  = models.TextField(blank=True, default='')

    # Trazabilidad
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='alerts')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"[{self.severity}] {self.attack_type} — {self.created_at:%Y-%m-%d %H:%M}"


class TurnoNota(models.Model):
    contenido  = models.TextField()
    autor      = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='turno_notas')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        username = self.autor.username if self.autor else 'anónimo'
        return f'[{self.created_at:%Y-%m-%d %H:%M}] {username}'


