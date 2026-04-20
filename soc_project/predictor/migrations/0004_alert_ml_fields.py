from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('predictor', '0003_add_error_log'),
    ]

    operations = [
        migrations.AddField(
            model_name='alert',
            name='predicted_class',
            field=models.CharField(blank=True, default='', max_length=100),
        ),
        migrations.AddField(
            model_name='alert',
            name='risk_score',
            field=models.FloatField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='alert',
            name='probabilities',
            field=models.JSONField(blank=True, null=True),
        ),
    ]
