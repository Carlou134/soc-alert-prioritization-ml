import pytest

from predictor.models import ModelVersion
from predictor.utils import (
    calculate_risk_score,
    get_active_model_version,
    normalize_input,
    predict_alert,
    predict_batch,
)

CLASSES = {'benigno', 'a_investigar', 'malicioso'}


def test_predict_alert_returns_valid_class_and_probabilities(valid_record):
    predicted_class, probabilities = predict_alert(valid_record)
    assert predicted_class in CLASSES
    assert set(probabilities.keys()) == CLASSES
    assert abs(sum(probabilities.values()) - 1.0) < 0.01
    for v in probabilities.values():
        assert 0.0 <= v <= 1.0


def test_predict_alert_malicious_pattern_scores_higher_than_benign(valid_record, benign_record):
    """No fija una clase exacta (acoplaría el test al pickle entrenado) —
    valida la propiedad que sí debe cumplirse siempre: un patrón con IDS
    confirmado + severidad crítica + firewall bloqueando puntúa más riesgoso
    que tráfico limpio."""
    _, probs_risky = predict_alert(valid_record)
    _, probs_benign = predict_alert(benign_record)
    assert calculate_risk_score(probs_risky) > calculate_risk_score(probs_benign)


def test_predict_batch_matches_length_and_shape(valid_record, benign_record):
    results = predict_batch([valid_record, benign_record, valid_record])
    assert len(results) == 3
    for predicted_class, probabilities in results:
        assert predicted_class in CLASSES
        assert abs(sum(probabilities.values()) - 1.0) < 0.01


def test_predict_batch_handles_shared_correlation_id(valid_record):
    """Tres alertas del mismo incidente no deben romper preprocess_batch al
    calcular las incident_* features agrupadas por correlation_id."""
    same_incident = [dict(valid_record, correlation_id='INC-SHARED') for _ in range(3)]
    results = predict_batch(same_incident)
    assert len(results) == 3
    assert {r[0] for r in results}.issubset(CLASSES)


def test_calculate_risk_score_weights():
    assert calculate_risk_score({'benigno': 1.0, 'a_investigar': 0.0, 'malicioso': 0.0}) == 0.0
    assert calculate_risk_score({'benigno': 0.0, 'a_investigar': 0.0, 'malicioso': 1.0}) == 1.0
    assert calculate_risk_score({'benigno': 0.0, 'a_investigar': 1.0, 'malicioso': 0.0}) == 0.5


def test_normalize_input_maps_synonyms_case_insensitive():
    raw = {
        'event_category': 'Initial Access',
        'severity': 'CRITICAL',
        'firewall_action': 'Denied',
        'ids_ips_alert': 'Malicious',
    }
    clean = normalize_input(raw)
    assert clean['event_category'] == 'intrusion_attempt'
    assert clean['severity'] == 'critical'
    assert clean['firewall_action'] == 'blocked'
    assert clean['ids_ips_alert'] == 'confirmed malicious indicator'


def test_normalize_input_defaults_unknown_values_safely():
    clean = normalize_input({'event_category': 'nonsense_value_xyz'})
    assert clean['event_category'] == 'other'
    assert clean['severity'] == 'unknown'
    assert clean['anomaly_score'] == 0.0


@pytest.mark.django_db
def test_get_active_model_version_self_heals_when_none_active():
    """Regresión del bug real encontrado en producción: una migración sobre
    una BD vacía no deja ningún ModelVersion activo, y la primera predicción
    nueva no debe explotar con DoesNotExist."""
    assert ModelVersion.objects.count() == 0
    version = get_active_model_version()
    assert version.is_active
    assert version.version_label == 'initial'
    assert ModelVersion.objects.filter(is_active=True).count() == 1


@pytest.mark.django_db
def test_get_active_model_version_returns_existing_active(model_version):
    version = get_active_model_version()
    assert version.pk == model_version.pk
    assert ModelVersion.objects.count() == 1
