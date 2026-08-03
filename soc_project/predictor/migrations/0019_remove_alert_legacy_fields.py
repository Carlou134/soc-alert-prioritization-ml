from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('predictor', '0018_migrate_alert_data'),
    ]

    operations = [
        migrations.RemoveField(model_name='alert', name='predicted_class'),
        migrations.RemoveField(model_name='alert', name='risk_score'),
        migrations.RemoveField(model_name='alert', name='probabilities'),
        migrations.RemoveField(model_name='alert', name='shap_values'),
        migrations.RemoveField(model_name='alert', name='shap_explanation'),
        migrations.RemoveField(model_name='alert', name='investigation_status'),
        migrations.RemoveField(model_name='alert', name='investigation_notes'),
        migrations.RemoveField(model_name='alert', name='investigated_by'),
        migrations.RemoveField(model_name='alert', name='investigated_at'),
        migrations.RemoveField(model_name='alert', name='analyst_priority'),
        migrations.RemoveField(model_name='alert', name='analyst_note'),
        migrations.RemoveField(model_name='alert', name='ml_evaluation'),
        migrations.RemoveField(model_name='alert', name='ml_evaluation_notes'),
        migrations.RemoveField(model_name='alert', name='ml_evaluated_by'),
        migrations.RemoveField(model_name='alert', name='ml_evaluated_at'),
        migrations.RemoveField(model_name='alert', name='assigned_to'),
        migrations.RemoveField(model_name='alert', name='is_incident'),
        migrations.RemoveField(model_name='alert', name='escalated_at'),
        migrations.RemoveField(model_name='alert', name='escalated_by'),
        migrations.RemoveField(model_name='alert', name='is_resolved'),
        migrations.RemoveField(model_name='alert', name='resolved_at'),
        migrations.RemoveField(model_name='alert', name='resolved_by'),
        migrations.RemoveField(model_name='alert', name='root_cause'),
        migrations.RemoveField(model_name='alert', name='lessons_learned'),
    ]
