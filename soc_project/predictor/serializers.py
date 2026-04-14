from rest_framework import serializers
from .models import PredictionLog


VALID_SEVERITY = {'low', 'medium', 'high', 'critical'}
VALID_FIREWALL_ACTIONS = {'allow', 'deny', 'drop', 'reject'}
VALID_ASSET_CRITICALITY = {'low', 'medium', 'high', 'critical'}


class PredictionRequestSerializer(serializers.Serializer):
    # Campos categóricos de la alerta
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

    # Campos numéricos
    failed_login_attempts = serializers.IntegerField(min_value=0)
    request_rate_per_min = serializers.FloatField(min_value=0.0)

    def validate_severity(self, value):
        normalized = value.strip().lower()
        if normalized not in VALID_SEVERITY:
            raise serializers.ValidationError(
                f"Valor inválido. Opciones: {sorted(VALID_SEVERITY)}"
            )
        return normalized

    def validate_firewall_action(self, value):
        normalized = value.strip().lower()
        if normalized not in VALID_FIREWALL_ACTIONS:
            raise serializers.ValidationError(
                f"Valor inválido. Opciones: {sorted(VALID_FIREWALL_ACTIONS)}"
            )
        return normalized

    def validate_asset_criticality(self, value):
        normalized = value.strip().lower()
        if normalized not in VALID_ASSET_CRITICALITY:
            raise serializers.ValidationError(
                f"Valor inválido. Opciones: {sorted(VALID_ASSET_CRITICALITY)}"
            )
        return normalized

    def validate(self, attrs):
        required = [
            'event_category', 'attack_type', 'attack_signature', 'protocol',
            'traffic_type', 'mitre_tactic', 'kill_chain_stage', 'failed_login_attempts',
            'request_rate_per_min', 'ids_ips_alert', 'malware_indicator',
            'asset_criticality', 'log_source', 'firewall_action', 'severity',
        ]
        missing = [f for f in required if attrs.get(f) is None]
        if missing:
            raise serializers.ValidationError({'missing_fields': missing})
        return attrs


class PredictionLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = PredictionLog
        fields = ['id', 'predicted_class', 'probabilities', 'source', 'created_at', 'input_data']
