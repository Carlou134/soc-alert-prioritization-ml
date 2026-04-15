from django.db import models
from django.contrib.auth.models import User


class Alert(models.Model):
    # 16 campos del dataset
    event_category = models.CharField(max_length=100)
    attack_type = models.CharField(max_length=100)
    attack_signature = models.CharField(max_length=200)
    protocol = models.CharField(max_length=50)
    traffic_type = models.CharField(max_length=100)
    mitre_tactic = models.CharField(max_length=100)
    kill_chain_stage = models.CharField(max_length=100)
    failed_login_attempts = models.IntegerField(default=0)
    request_rate_per_min = models.FloatField(default=0.0)
    ids_ips_alert = models.CharField(max_length=100)
    malware_indicator = models.CharField(max_length=100)
    asset_criticality = models.CharField(max_length=100)
    log_source = models.CharField(max_length=100)
    firewall_action = models.CharField(max_length=100)
    severity = models.CharField(max_length=50)
    label = models.CharField(max_length=100, blank=True, default='')

    # Trazabilidad
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='alerts')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"[{self.severity}] {self.attack_type} — {self.created_at:%Y-%m-%d %H:%M}"


class PredictionLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    input_data = models.JSONField()
    predicted_class = models.CharField(max_length=100)
    probabilities = models.JSONField(null=True, blank=True)
    source = models.CharField(max_length=20, default='manual')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.predicted_class} - {self.created_at:%Y-%m-%d %H:%M}"