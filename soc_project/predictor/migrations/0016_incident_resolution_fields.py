from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('predictor', '0015_turnonota'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name='alert',
            name='is_resolved',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='alert',
            name='resolved_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='alert',
            name='resolved_by',
            field=models.ForeignKey(
                blank=True, null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='resolved_alerts',
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.AddField(
            model_name='alert',
            name='root_cause',
            field=models.CharField(
                blank=True, default='', max_length=30,
                choices=[
                    ('phishing', 'Phishing'),
                    ('unpatched_vuln', 'Vulnerabilidad no parchada'),
                    ('malware', 'Malware / Ransomware'),
                    ('misconfig', 'Error de configuración'),
                    ('insider_threat', 'Amenaza interna'),
                    ('other', 'Otro'),
                ],
            ),
        ),
        migrations.AddField(
            model_name='alert',
            name='lessons_learned',
            field=models.TextField(blank=True, default=''),
        ),
    ]
