from rest_framework import serializers
from .models import PredictionLog
from .utils import EXPECTED_FIELDS

class PredictionRequestSerializer(serializers.Serializer):
    source_port = serializers.IntegerField()
    destination_port = serializers.IntegerField()
    protocol = serializers.CharField()
    traffic_type = serializers.CharField()
    host_affected = serializers.CharField()
    event_category = serializers.CharField()
    mitre_tactic = serializers.CharField()
    kill_chain_stage = serializers.CharField()
    log_source = serializers.CharField()
    firewall_action = serializers.CharField()
    anomaly_score = serializers.FloatField()
    failed_login_attempts = serializers.IntegerField()
    request_rate_per_min = serializers.IntegerField()
    asset_criticality = serializers.CharField()
    hour = serializers.IntegerField(min_value=0, max_value=23)
    day = serializers.IntegerField(min_value=1, max_value=31)
    month = serializers.IntegerField(min_value=1, max_value=12)
    day_of_week = serializers.IntegerField(min_value=0, max_value=6)


class PredictionLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = PredictionLog
        fields = ['id', 'predicted_class', 'probabilities', 'source', 'created_at', 'input_data']