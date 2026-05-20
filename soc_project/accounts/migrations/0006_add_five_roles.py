from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0005_user_action_log'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userprofile',
            name='role',
            field=models.CharField(
                choices=[
                    ('admin', 'Administrador'),
                    ('analyst_n3', 'Analista Nivel 3'),
                    ('analyst_n2', 'Analista Nivel 2'),
                    ('analyst_n1', 'Analista Nivel 1'),
                    ('trainee', 'Practicante'),
                ],
                default='analyst_n1',
                max_length=20,
            ),
        ),
    ]
