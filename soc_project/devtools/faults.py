"""Inyección de fallos para los casos de prueba de QA.

Cada punto del código que QA necesita ver fallar llama a raise_if_active(key).
Con ENABLE_FAULT_INJECTION apagado (producción) es un no-op: ni siquiera
consulta la BD.
"""
from datetime import timedelta

from django.conf import settings
from django.utils import timezone

# Un fallo olvidado se apaga solo — nunca deja la app rota de forma indefinida.
FAULT_TTL = timedelta(minutes=15)

# CP005-B: con "Sesión corta" activo, la sesión expira tras este tiempo sin
# actividad. 3 y no 1 minuto: el admin que lo activa necesita margen para
# volver al panel y desactivarlo antes de que expire su propia sesión.
SHORT_SESSION_SECONDS = 3 * 60

# key → (nombre visible, casos de prueba que lo usan)
FAULTS = {
    'db_save':           ('Fallo al guardar en la base de datos', 'CP008-B, CP025'),
    'model_unavailable': ('Modelo ML no disponible',               'CP014-B'),
    'shap_unavailable':  ('Cálculo SHAP no disponible',            'CP013, CP015'),
    'export_pdf':        ('Fallo al generar el PDF',               'CP027-A'),
    'export_excel':      ('Fallo al generar el Excel',             'CP027-B'),
    'ingest_critical':   ('Error crítico de ingesta',              'CP010-B'),
    'short_session':     ('Sesión corta (3 minutos)',              'CP005-B'),
}

# Qué hace cada fallo, tal como se muestra en el panel.
FAULT_HELP = {
    'db_save': (
        'Falla el guardado de un lote subido y el cambio de estado de una alerta. '
        'No quedan registros parciales.'
    ),
    'model_unavailable': (
        'Las alertas que se suban se guardan sin clasificar (pendientes) y '
        '"Clasificar pendientes" se detiene.'
    ),
    'shap_unavailable': (
        'El detalle de una alerta que todavía no tiene SHAP calculado se muestra '
        'sin gráficos ni explicación.'
    ),
    'export_pdf':   'Fallan "PDF Alertas" y "PDF Incidentes" en Reportes.',
    'export_excel': 'Falla "Exportar Excel" en Reportes.',
    'ingest_critical': (
        'El procesamiento de un lote subido falla por completo y se notifica en la campanita.'
    ),
    'short_session': (
        'La sesión de cada usuario expira tras 3 minutos sin actividad (en vez de 60) '
        'y la siguiente acción pide iniciar sesión. Afecta también a tu sesión: '
        'desactívalo antes de quedarte 3 minutos sin actividad.'
    ),
}


class InjectedFault(Exception):
    """Excepción por defecto de un fallo simulado."""


def is_enabled():
    return settings.ENABLE_FAULT_INJECTION


def is_active(key):
    if not is_enabled():
        return False
    from .models import FaultFlag
    return FaultFlag.objects.filter(key=key, expires_at__gt=timezone.now()).exists()


def raise_if_active(key, exc=None):
    """Lanza `exc` (o InjectedFault) si el fallo `key` está activo. Cada punto de
    enganche pasa la excepción que el código real lanzaría (ej. DatabaseError),
    así se ejercita el mismo manejo de errores que en un fallo verdadero."""
    if is_active(key):
        raise exc or InjectedFault(f'Fallo simulado: {FAULTS[key][0]}')


def active_fault_labels():
    if not is_enabled():
        return []
    from .models import FaultFlag
    keys = FaultFlag.objects.filter(expires_at__gt=timezone.now()).values_list('key', flat=True)
    return [FAULTS[key][0] for key in keys if key in FAULTS]
