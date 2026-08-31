import logging

from django.apps import AppConfig
from django.db.models.signals import post_migrate

logger = logging.getLogger(__name__)


def _register_sync_schedule(sender, **kwargs):
    """Registro idempotente de la tarea programada de ingesta (Schedule de
    django-q2) — corre después de post_migrate, cuando la tabla
    django_q_schedule ya existe de verdad, en vez de en AppConfig.ready()
    (Django desaconseja tocar la BD ahí — corre en cada manage.py, incluido
    el propio "migrate" antes de que la tabla exista)."""
    from django_q.models import Schedule
    Schedule.objects.get_or_create(
        func='connectors.tasks.sync_due_connectors',
        defaults={
            'name': 'Sync conectores SIEM/XDR',
            'schedule_type': Schedule.MINUTES,
            'minutes': 1,
            'repeats': -1,
        },
    )


class ConnectorsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'connectors'
    verbose_name = 'Conectores SIEM'

    def ready(self):
        post_migrate.connect(_register_sync_schedule, sender=self)
