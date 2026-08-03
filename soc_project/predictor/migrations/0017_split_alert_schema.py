from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('predictor', '0016_incident_resolution_fields'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Dataset',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('filename', models.CharField(max_length=255)),
                ('row_count', models.IntegerField(default=0)),
                ('status', models.CharField(
                    choices=[('pending', 'Pendiente'), ('processed', 'Procesado'), ('failed', 'Fallido')],
                    default='pending', max_length=20,
                )),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('uploaded_by', models.ForeignKey(
                    blank=True, null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='datasets',
                    to=settings.AUTH_USER_MODEL,
                )),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
        migrations.CreateModel(
            name='Incident',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('correlation_id', models.CharField(max_length=200, unique=True)),
                ('escalated_at', models.DateTimeField(blank=True, null=True)),
                ('is_resolved', models.BooleanField(default=False)),
                ('resolved_at', models.DateTimeField(blank=True, null=True)),
                ('root_cause', models.CharField(
                    blank=True, default='', max_length=30,
                    choices=[
                        ('phishing', 'Phishing'),
                        ('unpatched_vuln', 'Vulnerabilidad no parchada'),
                        ('malware', 'Malware / Ransomware'),
                        ('misconfig', 'Error de configuración'),
                        ('insider_threat', 'Amenaza interna'),
                        ('other', 'Otro'),
                    ],
                )),
                ('lessons_learned', models.TextField(blank=True, default='')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('escalated_by', models.ForeignKey(
                    blank=True, null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='escalated_incidents',
                    to=settings.AUTH_USER_MODEL,
                )),
                ('resolved_by', models.ForeignKey(
                    blank=True, null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='resolved_incidents',
                    to=settings.AUTH_USER_MODEL,
                )),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
        migrations.CreateModel(
            name='ModelVersion',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('version_label', models.CharField(max_length=50, unique=True)),
                ('trained_at', models.DateTimeField()),
                ('metrics', models.JSONField(blank=True, null=True)),
                ('artifact_path', models.CharField(max_length=500)),
                ('is_active', models.BooleanField(default=False)),
            ],
        ),
        migrations.AddField(
            model_name='alert',
            name='dataset',
            field=models.ForeignKey(
                blank=True, null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='alerts',
                to='predictor.dataset',
            ),
        ),
        migrations.AddField(
            model_name='alert',
            name='incident',
            field=models.ForeignKey(
                blank=True, null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='alerts',
                to='predictor.incident',
            ),
        ),
        migrations.CreateModel(
            name='AlertWorkflow',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('investigation_status', models.CharField(
                    choices=[
                        ('new', 'Nueva'),
                        ('investigating', 'En investigación'),
                        ('investigated', 'Investigada'),
                        ('false_positive', 'Falso positivo'),
                    ],
                    default='new', max_length=20,
                )),
                ('investigation_notes', models.TextField(blank=True, default='')),
                ('investigated_at', models.DateTimeField(blank=True, null=True)),
                ('analyst_priority', models.CharField(blank=True, default='', max_length=20)),
                ('analyst_note', models.TextField(blank=True, default='')),
                ('ml_evaluation', models.CharField(
                    blank=True, default='', max_length=20,
                    choices=[
                        ('correct', 'Correcta'),
                        ('partially_correct', 'Parcialmente correcta'),
                        ('incorrect', 'Incorrecta'),
                    ],
                )),
                ('ml_evaluation_notes', models.TextField(blank=True, default='')),
                ('ml_evaluated_at', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('alert', models.OneToOneField(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='workflow',
                    to='predictor.alert',
                )),
                ('assigned_to', models.ForeignKey(
                    blank=True, null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='assigned_alerts',
                    to=settings.AUTH_USER_MODEL,
                )),
                ('created_by', models.ForeignKey(
                    on_delete=django.db.models.deletion.RESTRICT,
                    related_name='created_workflows',
                    to=settings.AUTH_USER_MODEL,
                )),
                ('investigated_by', models.ForeignKey(
                    blank=True, null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='investigated_alerts',
                    to=settings.AUTH_USER_MODEL,
                )),
                ('ml_evaluated_by', models.ForeignKey(
                    blank=True, null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='evaluated_alerts',
                    to=settings.AUTH_USER_MODEL,
                )),
            ],
        ),
        migrations.CreateModel(
            name='PredictionLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('predicted_class', models.CharField(max_length=100)),
                ('risk_score', models.FloatField(blank=True, null=True)),
                ('probabilities', models.JSONField(blank=True, null=True)),
                ('shap_values', models.JSONField(blank=True, null=True)),
                ('shap_explanation', models.TextField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('alert', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    to='predictor.alert',
                )),
                ('model_version', models.ForeignKey(
                    on_delete=django.db.models.deletion.RESTRICT,
                    related_name='predictions',
                    to='predictor.modelversion',
                )),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
    ]
