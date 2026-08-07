# -*- coding: utf-8 -*-
"""
Ingesta real (polling, no push) de alertas desde Splunk hacia la BD.

Flujo: sync_due_connectors() corre cada 1 minuto (Schedule registrado en
apps.py.ready()) y decide, por cada conector Splunk activo, si ya toca
sincronizar según su propio poll_interval_minutes. Si toca,
sync_splunk_connector() hace un oneshot search real contra la REST API
(earliest_time = último checkpoint), limpia los resultados con el MISMO
pipeline que ya usan las cargas manuales (clean_records) y encola
process_alert_batch — el mismo camino que upload_alerts_view /
pipeline_normalize_view (Track 5). No se duplica ninguna lógica de
limpieza/predicción/guardado, solo se agrega el origen de los datos.
"""
import httpx
from django.utils import timezone
from django_q.tasks import async_task

from predictor.models import Dataset, log_error
from predictor.pipeline import clean_records

from .models import SIEMConnector

REQUEST_TIMEOUT = 15.0  # una búsqueda real tarda más que el simple health-check de test_connection


def sync_due_connectors():
    """
    Dispatcher — barato en el caso común (nada debido todavía): solo compara
    timestamps en memoria, no hace ninguna llamada de red salvo que algún
    conector esté realmente vencido según su poll_interval_minutes.
    """
    now = timezone.now()
    for connector in SIEMConnector.objects.filter(is_active=True, source_type='splunk'):
        last_checkpoint = connector.last_synced_at or connector.created_at
        seconds_since_last = (now - last_checkpoint).total_seconds()
        if seconds_since_last >= connector.poll_interval_minutes * 60:
            sync_splunk_connector(connector.pk)


def sync_splunk_connector(connector_id):
    """Un ciclo de sincronización real para un conector Splunk puntual."""
    try:
        connector = SIEMConnector.objects.get(pk=connector_id)
    except SIEMConnector.DoesNotExist:
        return

    earliest = connector.last_synced_at or connector.created_at
    port = connector.port or 8089
    url = f'https://{connector.host}:{port}/services/search/jobs'

    headers = {}
    auth = None
    if connector.auth_type == 'bearer_token':
        headers['Authorization'] = f"Bearer {connector.credentials.get('api_token', '')}"
    else:
        auth = (connector.credentials.get('username', ''), connector.credentials.get('password', ''))

    payload = {
        'search': connector.custom_query or 'search index=soc_alerts',
        # Epoch timestamp — inequívoco sin importar timezone/locale de la instancia Splunk,
        # a diferencia de modificadores relativos ("-1h") o ISO8601.
        'earliest_time': str(int(earliest.timestamp())),
        'latest_time': 'now',
        'exec_mode': 'oneshot',
        'output_mode': 'json',
    }

    try:
        resp = httpx.post(
            url, data=payload, headers=headers, auth=auth,
            verify=connector.verify_ssl, timeout=REQUEST_TIMEOUT,
        )
    except httpx.RequestError as exc:
        _mark_error(connector, f'Error de red en la sincronización: {exc}')
        return

    if resp.status_code != 200:
        _mark_error(connector, f'Splunk respondió {resp.status_code} durante la sincronización.')
        return

    try:
        raw_results = resp.json().get('results', [])
    except ValueError:
        _mark_error(connector, 'La respuesta de Splunk no fue JSON válido.')
        return

    if not raw_results:
        _mark_synced(connector)
        return

    # clean_records ya sabe descartar cualquier campo que no reconozca —
    # los metadatos propios de Splunk en cada resultado (_time, _raw, host,
    # source, sourcetype, index) se ignoran solos, no hace falta filtrarlos
    # a mano aquí.
    clean, _stats = clean_records(raw_results)
    if not clean:
        _mark_synced(connector)
        return

    dataset = Dataset.objects.create(
        filename=f'Splunk — {connector.name}',
        row_count=len(clean),
        uploaded_by=connector.created_by,
    )
    async_task('predictor.tasks.process_alert_batch', dataset.pk, clean, connector.created_by_id)

    _mark_synced(connector)


def _mark_synced(connector):
    connector.last_synced_at = timezone.now()
    connector.status = 'connected'
    connector.save(update_fields=['last_synced_at', 'status'])


def _mark_error(connector, message):
    connector.status = 'error'
    connector.last_test_message = message
    connector.save(update_fields=['status', 'last_test_message'])
    log_error(connector.created_by, 'splunk_sync', message)
