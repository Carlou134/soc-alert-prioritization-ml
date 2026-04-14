from rest_framework import serializers
from .models import PredictionLog


class PredictionRequestSerializer(serializers.Serializer):
    # Campos categóricos — el modelo acepta cualquier string válido.
    # No se restringen choices porque get_dummies + reindex manejan valores
    # desconocidos rellenando con 0, y los valores reales del dataset microsoft
    # incluyen "monitored", "blocked", "unknown", etc.
    event_category = serializers.CharField()
    attack_type = serializers.CharField()
    attack_signature = serializers.CharField()
    protocol = serializers.CharField()
    traffic_type = serializers.CharField()
    mitre_tactic = serializers.CharField()
    kill_chain_stage = serializers.CharField()
    ids_ips_alert = serializers.CharField()
    malware_indicator = serializers.CharField()
    asset_criticality = serializers.CharField()
    log_source = serializers.CharField()
    firewall_action = serializers.CharField()
    severity = serializers.CharField()

    # Campos numéricos — sí se validan rangos porque son restricciones del dominio
    failed_login_attempts = serializers.IntegerField(min_value=0)
    request_rate_per_min = serializers.FloatField(min_value=0.0)

    def validate(self, attrs):
        required = [
            'event_category', 'attack_type', 'attack_signature', 'protocol',
            'traffic_type', 'mitre_tactic', 'kill_chain_stage', 'ids_ips_alert',
            'malware_indicator', 'asset_criticality', 'log_source',
            'firewall_action', 'severity', 'failed_login_attempts',
            'request_rate_per_min',
        ]
        missing = [f for f in required if attrs.get(f) is None]
        if missing:
            raise serializers.ValidationError({'missing_fields': missing})
        return attrs


class PredictionLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = PredictionLog
        fields = ['id', 'predicted_class', 'probabilities', 'source', 'created_at', 'input_data']
