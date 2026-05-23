from django.contrib.auth.hashers import make_password
from django.db import migrations


NEW_USERS = [
    {
        'username': 'gian',
        'password': 'Gian@2025',
        'email': 'gian@soc.local',
        'is_staff': False,
        'role': 'analyst_n2',
    },
    {
        'username': 'senior',
        'password': 'Senior@2025',
        'email': 'senior@soc.local',
        'is_staff': False,
        'role': 'analyst_n3',
    },
    {
        'username': 'practicante_rios',
        'password': 'Practicante@2025',
        'email': 'practicante_rios@soc.local',
        'is_staff': False,
        'role': 'trainee',
    },
]


def seed_users(apps, schema_editor):
    User = apps.get_model('auth', 'User')
    UserProfile = apps.get_model('accounts', 'UserProfile')

    for data in NEW_USERS:
        user, created = User.objects.get_or_create(username=data['username'])
        if created:
            user.password = make_password(data['password'])
            user.email = data['email']
            user.is_staff = data['is_staff']
            user.is_active = True
            user.save()

        UserProfile.objects.update_or_create(
            user=user,
            defaults={'role': data['role']},
        )


def unseed_users(apps, schema_editor):
    User = apps.get_model('auth', 'User')
    User.objects.filter(username__in=[d['username'] for d in NEW_USERS]).delete()


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0006_add_five_roles'),
    ]

    operations = [
        migrations.RunPython(seed_users, reverse_code=unseed_users),
    ]
