import pytest
from django.contrib.auth.models import User


@pytest.fixture
def make_user(db):
    """Crea un User con su UserProfile (via señal) en el rol pedido."""
    def _make(username, role='analyst_n1', password='Testpass@2025'):
        user = User.objects.create_user(username=username, password=password, email=f'{username}@test.local')
        user.profile.role = role
        user.profile.save(update_fields=['role'])
        return user
    return _make


@pytest.fixture
def admin_user(make_user):
    return make_user('admin_test', role='admin')


@pytest.fixture
def analyst_n1_user(make_user):
    return make_user('n1_test', role='analyst_n1')


@pytest.fixture
def analyst_n2_user(make_user):
    return make_user('n2_test', role='analyst_n2')


@pytest.fixture
def analyst_n3_user(make_user):
    return make_user('n3_test', role='analyst_n3')


@pytest.fixture
def trainee_user(make_user):
    return make_user('trainee_test', role='trainee')


@pytest.fixture
def model_version(db):
    from django.utils import timezone
    from predictor.models import ModelVersion
    return ModelVersion.objects.create(
        version_label='test-v1',
        trained_at=timezone.now(),
        artifact_path='predictor/ml/soc_model.pkl',
        is_active=True,
    )


VALID_RECORD = {
    'event_category': 'malware_activity',
    'protocol': 'tcp',
    'traffic_type': 'https',
    'mitre_tactic': 'command and control',
    'kill_chain_stage': 'exfiltration',
    'severity': 'critical',
    'ids_ips_alert': 'confirmed malicious indicator',
    'asset_criticality': 'high',
    'log_source': 'edr',
    'firewall_action': 'blocked',
    'failed_login_attempts': 25,
    'request_rate_per_min': 500.0,
    'has_threat_family': 1,
    'evidence_role': 'attacker',
    'os_family': 'windows',
    'correlation_id': 'INC-TEST-1',
    'mitre_techniques': 'T1110;T1078.004',
}

BENIGN_RECORD = {
    'event_category': 'other',
    'protocol': 'tcp',
    'traffic_type': 'https',
    'mitre_tactic': 'unknown',
    'kill_chain_stage': 'unknown',
    'severity': 'unknown',
    'ids_ips_alert': 'no alert',
    'asset_criticality': 'low',
    'log_source': 'firewall',
    'firewall_action': 'allowed',
    'failed_login_attempts': 0,
    'request_rate_per_min': 1.0,
    'has_threat_family': 0,
    'evidence_role': 'unknown',
    'os_family': 'linux',
    'correlation_id': 'unknown',
    'mitre_techniques': '',
}


@pytest.fixture
def valid_record():
    return dict(VALID_RECORD)


@pytest.fixture
def benign_record():
    return dict(BENIGN_RECORD)


@pytest.fixture
def make_alert(model_version):
    """Crea un Alert con su AlertWorkflow pareado (invariante 1:1 del Track 1)
    y, opcionalmente, una PredictionLog — para tests de transiciones de estado
    sin pasar por todo el pipeline de predicción."""
    from predictor.models import Alert, AlertWorkflow, PredictionLog

    def _make(creator, predicted_class='malicioso', correlation_id='unknown', **overrides):
        defaults = dict(
            event_category='malware_activity', protocol='tcp', traffic_type='https',
            mitre_tactic='command and control', kill_chain_stage='exfiltration',
            failed_login_attempts=10, request_rate_per_min=50.0,
            ids_ips_alert='confirmed malicious indicator', asset_criticality='high',
            log_source='edr', firewall_action='blocked', severity='critical',
            correlation_id=correlation_id, created_by=creator,
        )
        defaults.update(overrides)
        alert = Alert.objects.create(**defaults)
        AlertWorkflow.objects.create(alert=alert, created_by=creator)
        if predicted_class is not None:
            risk = {'benigno': 0.0, 'a_investigar': 0.5, 'malicioso': 1.0}.get(predicted_class, 0.5)
            PredictionLog.objects.create(
                alert=alert, model_version=model_version,
                predicted_class=predicted_class,
                risk_score=risk,
                probabilities={'benigno': 0.1, 'a_investigar': 0.1, 'malicioso': 0.8},
            )
        return alert
    return _make
