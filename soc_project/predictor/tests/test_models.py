import pytest
from django.db import IntegrityError, transaction
from django.utils import timezone

from predictor.models import Alert, AlertWorkflow, Incident, ModelVersion, PredictionLog


@pytest.mark.django_db
def test_alertworkflow_enforces_one_to_one_per_alert(admin_user, make_alert):
    """Invariante de diseño del Track 1: 1 AlertWorkflow por Alert, garantizado
    por el OneToOneField — una segunda fila para el mismo alert debe fallar."""
    alert = make_alert(admin_user)
    with pytest.raises(IntegrityError):
        with transaction.atomic():
            AlertWorkflow.objects.create(alert=alert, created_by=admin_user)


@pytest.mark.django_db
def test_incident_correlation_id_is_unique(admin_user):
    Incident.objects.create(correlation_id='INC-DUP', escalated_by=admin_user)
    with pytest.raises(IntegrityError):
        with transaction.atomic():
            Incident.objects.create(correlation_id='INC-DUP', escalated_by=admin_user)


@pytest.mark.django_db
def test_modelversion_version_label_is_unique():
    ModelVersion.objects.create(version_label='v1', trained_at=timezone.now(), artifact_path='x.pkl')
    with pytest.raises(IntegrityError):
        with transaction.atomic():
            ModelVersion.objects.create(version_label='v1', trained_at=timezone.now(), artifact_path='y.pkl')


@pytest.mark.django_db
def test_predictionlog_allows_multiple_per_alert(admin_user, make_alert, model_version):
    """A propósito no hay unique en PredictionLog.alert — una alerta puede
    tener varias predicciones en el tiempo (insumo del feedback loop)."""
    alert = make_alert(admin_user, predicted_class='benigno')
    PredictionLog.objects.create(
        alert=alert, model_version=model_version,
        predicted_class='malicioso', risk_score=1.0,
        probabilities={'benigno': 0.05, 'a_investigar': 0.05, 'malicioso': 0.9},
    )
    assert PredictionLog.objects.filter(alert=alert).count() == 2


@pytest.mark.django_db
def test_alert_latest_prediction_returns_most_recent(admin_user, make_alert, model_version):
    alert = make_alert(admin_user, predicted_class='benigno')
    newer = PredictionLog.objects.create(
        alert=alert, model_version=model_version,
        predicted_class='malicioso', risk_score=1.0,
        probabilities={'benigno': 0.0, 'a_investigar': 0.0, 'malicioso': 1.0},
    )
    alert = Alert.objects.get(pk=alert.pk)  # instancia fresca, sin cached_property
    assert alert.latest_prediction.pk == newer.pk
    assert alert.latest_prediction.predicted_class == 'malicioso'


@pytest.mark.django_db
def test_alert_latest_prediction_returns_none_without_predictions(admin_user, model_version):
    alert = Alert.objects.create(
        event_category='malware', protocol='tcp', traffic_type='https',
        mitre_tactic='execution', kill_chain_stage='delivery',
        ids_ips_alert='no alert', asset_criticality='low',
        log_source='edr', firewall_action='allowed', severity='low',
        created_by=admin_user,
    )
    assert alert.latest_prediction is None


@pytest.mark.django_db
def test_alert_latest_prediction_is_cached_across_accesses(django_assert_num_queries, admin_user, make_alert):
    alert = make_alert(admin_user, predicted_class='malicioso')
    alert = Alert.objects.get(pk=alert.pk)  # instancia fresca, cached_property vacía
    with django_assert_num_queries(1):
        alert.latest_prediction
        alert.latest_prediction
        alert.latest_prediction
