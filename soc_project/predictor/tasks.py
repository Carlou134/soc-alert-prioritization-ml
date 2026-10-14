import logging

from django.contrib.auth.models import User

from devtools.faults import raise_if_active

from .models import Dataset, log_error
from .utils import ModelUnavailableError, predict_alert, predict_batch

logger = logging.getLogger(__name__)

STORAGE_ERROR_MESSAGE = (
    'No se pudieron guardar las alertas en la base de datos. '
    'El incidente quedó registrado; intenta nuevamente.'
)

INGEST_ERROR_MESSAGE = (
    'Ocurrió un error crítico al procesar el archivo. '
    'El incidente quedó registrado para su revisión.'
)

MODEL_UNAVAILABLE_NOTICE = (
    'El modelo de clasificación no está disponible. '
    'Las alertas se guardaron como pendientes de clasificación.'
)


def process_alert_batch(dataset_id, records, user_id):
    """Tarea async (django-q2): predice y guarda un lote de alertas ya limpias.

    Compartida por upload_alerts_view y pipeline_normalize_view (Track 5) —
    lo lento (predict_batch + bulk_create) se movió aquí para que el navegador
    ya no tenga que quedarse en la página mientras procesa. Cualquier
    excepción no prevista deja el Dataset en 'failed' con error_message, así
    el polling del frontend nunca queda esperando un estado que no llega.
    """
    from .views import _build_alert_instance, _bulk_create_alerts

    try:
        dataset = Dataset.objects.get(pk=dataset_id)
    except Dataset.DoesNotExist:
        return

    dataset.status = 'processing'
    dataset.save(update_fields=['status'])

    try:
        user = User.objects.get(pk=user_id)
    except User.DoesNotExist:
        dataset.status = 'failed'
        dataset.error_message = 'El usuario que subió el archivo ya no existe.'
        dataset.save(update_fields=['status', 'error_message'])
        return

    try:
        # Devtools (CP010-B): error no previsto en medio del procesamiento.
        raise_if_active('ingest_critical')

        model_unavailable = False
        try:
            batch_results = predict_batch(records)
        except ModelUnavailableError as exc:
            # CP014-B: sin modelo no tiene sentido reintentar alerta por alerta.
            # Se guardan sin PredictionLog (pendientes) para clasificarlas después.
            logger.error('Modelo ML no disponible al procesar el dataset #%s', dataset_id)
            log_error(user, 'process_alert_batch_model', str(exc))
            batch_results = None
            model_unavailable = True
        except Exception as exc:
            log_error(user, 'process_alert_batch_predict', str(exc))
            batch_results = None

        instances = []
        failed_count = 0
        for i, record in enumerate(records):
            try:
                if model_unavailable:
                    predicted_class, probabilities = None, None
                elif batch_results is not None:
                    predicted_class, probabilities = batch_results[i]
                else:
                    predicted_class, probabilities = predict_alert(record)
                alert, kwargs = _build_alert_instance(record, predicted_class, probabilities, user)
                alert.dataset_id = dataset_id
                instances.append((alert, kwargs))
            except Exception as exc:
                log_error(user, 'process_alert_batch_build', str(exc))
                failed_count += 1

        saved_count = 0
        storage_failed = False
        if instances:
            try:
                _bulk_create_alerts(instances, user)
                saved_count = len(instances)
            except Exception as exc:
                # _bulk_create_alerts es atómico: no quedan registros parciales.
                # log_error escribe en la misma BD que acaba de fallar, así que el
                # incidente también va al log del proceso (CP008-B).
                logger.exception('No se pudieron guardar las alertas del dataset #%s', dataset_id)
                log_error(user, 'process_alert_batch_bulk', str(exc))
                failed_count += len(instances)
                instances = []
                storage_failed = True

        dataset.saved_count = saved_count
        dataset.failed_count = failed_count
        if storage_failed:
            dataset.status = 'failed'
            dataset.error_message = STORAGE_ERROR_MESSAGE
        else:
            dataset.status = 'processed'
            if model_unavailable:
                dataset.error_message = MODEL_UNAVAILABLE_NOTICE
        dataset.save(update_fields=['saved_count', 'failed_count', 'status', 'error_message'])
    except Exception as exc:
        # CP010-B: el detalle técnico va al log; el usuario ve un mensaje claro
        # y el lote fallido le aparece en la campanita.
        logger.exception('Error crítico al procesar el dataset #%s', dataset_id)
        log_error(user, 'process_alert_batch', str(exc))
        dataset.status = 'failed'
        dataset.error_message = INGEST_ERROR_MESSAGE
        dataset.save(update_fields=['status', 'error_message'])
