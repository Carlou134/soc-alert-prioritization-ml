from django.db import migrations
from django.utils import timezone


def split_alert_data(apps, schema_editor):
    Alert = apps.get_model('predictor', 'Alert')
    AlertWorkflow = apps.get_model('predictor', 'AlertWorkflow')
    Incident = apps.get_model('predictor', 'Incident')
    PredictionLog = apps.get_model('predictor', 'PredictionLog')
    ModelVersion = apps.get_model('predictor', 'ModelVersion')

    alerts = list(Alert.objects.all())
    if not alerts:
        return

    # ModelVersion "legacy" — todas las predicciones ya existentes (y las nuevas,
    # hasta que exista un pipeline de reentrenamiento real) quedan asociadas acá.
    legacy_version, _ = ModelVersion.objects.get_or_create(
        version_label='legacy-pre-migration',
        defaults={
            'trained_at': timezone.now(),
            'metrics': None,
            'artifact_path': 'predictor/ml/soc_model.pkl',
            'is_active': True,
        },
    )

    workflows = []
    predictions = []
    # correlation_id real -> Incident ya creado en esta corrida (evita duplicados)
    incidents_by_correlation = {}

    for alert in alerts:
        workflows.append(AlertWorkflow(
            alert=alert,
            investigation_status=alert.investigation_status,
            investigation_notes=alert.investigation_notes,
            investigated_by_id=alert.investigated_by_id,
            investigated_at=alert.investigated_at,
            analyst_priority=alert.analyst_priority,
            analyst_note=alert.analyst_note,
            ml_evaluation=alert.ml_evaluation,
            ml_evaluation_notes=alert.ml_evaluation_notes,
            ml_evaluated_by_id=alert.ml_evaluated_by_id,
            ml_evaluated_at=alert.ml_evaluated_at,
            assigned_to_id=alert.assigned_to_id,
            created_by_id=alert.created_by_id,
        ))

        if alert.is_incident:
            raw_correlation = (alert.correlation_id or '').strip()
            is_real = bool(raw_correlation) and raw_correlation.lower() != 'unknown'

            if is_real:
                incident = incidents_by_correlation.get(raw_correlation)
                if incident is None:
                    incident, _ = Incident.objects.get_or_create(
                        correlation_id=raw_correlation,
                        defaults={
                            'escalated_at': alert.escalated_at,
                            'escalated_by_id': alert.escalated_by_id,
                            'is_resolved': alert.is_resolved,
                            'resolved_at': alert.resolved_at,
                            'resolved_by_id': alert.resolved_by_id,
                            'root_cause': alert.root_cause,
                            'lessons_learned': alert.lessons_learned,
                        },
                    )
                    incidents_by_correlation[raw_correlation] = incident
            else:
                # correlation_id no real (vacío/'unknown') — no se agrupa, cada
                # alerta escalada arma su propio Incident con un id sintético
                # para no chocar con el UNIQUE ni fusionar incidentes distintos.
                incident = Incident.objects.create(
                    correlation_id=f'legacy-alert-{alert.id}',
                    escalated_at=alert.escalated_at,
                    escalated_by_id=alert.escalated_by_id,
                    is_resolved=alert.is_resolved,
                    resolved_at=alert.resolved_at,
                    resolved_by_id=alert.resolved_by_id,
                    root_cause=alert.root_cause,
                    lessons_learned=alert.lessons_learned,
                )

            alert.incident_id = incident.id
            alert.save(update_fields=['incident'])

        if alert.predicted_class:
            predictions.append(PredictionLog(
                alert=alert,
                model_version=legacy_version,
                predicted_class=alert.predicted_class,
                risk_score=alert.risk_score,
                probabilities=alert.probabilities,
                shap_values=alert.shap_values,
                shap_explanation=alert.shap_explanation,
            ))

    AlertWorkflow.objects.bulk_create(workflows, batch_size=500)
    if predictions:
        PredictionLog.objects.bulk_create(predictions, batch_size=500)


def reverse_split_alert_data(apps, schema_editor):
    AlertWorkflow = apps.get_model('predictor', 'AlertWorkflow')
    Incident = apps.get_model('predictor', 'Incident')
    PredictionLog = apps.get_model('predictor', 'PredictionLog')
    ModelVersion = apps.get_model('predictor', 'ModelVersion')

    PredictionLog.objects.all().delete()
    AlertWorkflow.objects.all().delete()
    Incident.objects.all().delete()
    ModelVersion.objects.filter(version_label='legacy-pre-migration').delete()


class Migration(migrations.Migration):

    dependencies = [
        ('predictor', '0017_split_alert_schema'),
    ]

    operations = [
        migrations.RunPython(split_alert_data, reverse_split_alert_data),
    ]
