from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('predictor', '0011_alert_assigned_to'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name='alert',
            name='ml_evaluation',
            field=models.CharField(
                blank=True,
                choices=[
                    ('correct', 'Correcta'),
                    ('partially_correct', 'Parcialmente correcta'),
                    ('incorrect', 'Incorrecta'),
                ],
                default='',
                max_length=20,
            ),
        ),
        migrations.AddField(
            model_name='alert',
            name='ml_evaluation_notes',
            field=models.TextField(blank=True, default=''),
        ),
        migrations.AddField(
            model_name='alert',
            name='ml_evaluated_by',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='evaluated_alerts',
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.AddField(
            model_name='alert',
            name='ml_evaluated_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
