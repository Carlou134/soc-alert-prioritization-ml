from django.contrib.auth.models import User

from .models import Dataset, log_error
from .utils import predict_alert, predict_batch


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
        try:
            batch_results = predict_batch(records)
        except Exception as exc:
            log_error(user, 'process_alert_batch_predict', str(exc))
            batch_results = None

        instances = []
        failed_count = 0
        for i, record in enumerate(records):
            try:
                if batch_results is not None:
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
        if instances:
            try:
                _bulk_create_alerts(instances, user)
                saved_count = len(instances)
            except Exception as exc:
                log_error(user, 'process_alert_batch_bulk', str(exc))
                failed_count += len(instances)
                instances = []

        dataset.saved_count = saved_count
        dataset.failed_count = failed_count
        dataset.status = 'processed'
        dataset.save(update_fields=['saved_count', 'failed_count', 'status'])
    except Exception as exc:
        dataset.status = 'failed'
        dataset.error_message = str(exc)
        dataset.save(update_fields=['status', 'error_message'])
