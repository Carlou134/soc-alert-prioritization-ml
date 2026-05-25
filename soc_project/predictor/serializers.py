from rest_framework import serializers


class PredictionRequestSerializer(serializers.Serializer):
    # ── Campos requeridos — mínimo para una predicción válida ────────────────
    event_category        = serializers.CharField()
    protocol              = serializers.CharField()
    traffic_type          = serializers.CharField()
    mitre_tactic          = serializers.CharField()
    kill_chain_stage      = serializers.CharField()
    severity              = serializers.CharField()
    ids_ips_alert         = serializers.CharField()
    asset_criticality     = serializers.CharField()
    log_source            = serializers.CharField()
    firewall_action       = serializers.CharField()
    failed_login_attempts = serializers.IntegerField(min_value=0)
    request_rate_per_min  = serializers.FloatField(min_value=0.0)

    # ── Campos opcionales — mejoran la predicción significativamente ─────────
    # has_threat_family: 1 si hay nombre de malware conocido (ThreatFamily presente)
    has_threat_family = serializers.IntegerField(min_value=0, max_value=1, default=0, allow_null=True)
    # evidence_role: rol de la entidad en el incidente (attacker/impacted/related)
    evidence_role = serializers.CharField(default='unknown', allow_null=True)
    # os_family: sistema operativo del activo afectado
    os_family = serializers.CharField(default='unknown', allow_null=True)
    # correlation_id: agrupa alertas del mismo incidente — habilita incident_* features
    correlation_id = serializers.CharField(default='unknown', allow_null=True)
    # mitre_techniques: técnicas separadas por ";" ej: "T1110;T1078.004"
    mitre_techniques = serializers.CharField(default='', allow_blank=True, allow_null=True)

    def validate(self, attrs):
        required = [
            'event_category', 'protocol', 'traffic_type', 'mitre_tactic',
            'kill_chain_stage', 'severity', 'ids_ips_alert', 'asset_criticality',
            'log_source', 'firewall_action', 'failed_login_attempts', 'request_rate_per_min',
        ]
        missing = [f for f in required if attrs.get(f) is None]
        if missing:
            raise serializers.ValidationError({'missing_fields': missing})

        # Campos opcionales con null → coerce a default para no romper Alert.objects.create()
        _null_defaults = {
            'has_threat_family': 0,
            'evidence_role'    : 'unknown',
            'os_family'        : 'unknown',
            'correlation_id'   : 'unknown',
            'mitre_techniques' : '',
        }
        for field, default in _null_defaults.items():
            if attrs.get(field) is None:
                attrs[field] = default
        return attrs
