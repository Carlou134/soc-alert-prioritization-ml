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
import json
from datetime import timedelta

import httpx
from django.utils import timezone
from django_q.tasks import async_task

from predictor.models import Dataset, log_error
from predictor.pipeline import clean_records

from .models import IngestedSplunkEvent, SIEMConnector

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

    # Sin checkpoint todavía (primer sync de este conector): en vez de
    # arrancar en created_at (cero historial), se mira 24h hacia atrás para
    # que conectar Splunk traiga de una lo que ya había en el índice, no
    # solo lo que llegue de ahí en adelante. Ventana acotada a propósito
    # (no "todo el índice") para no arrastrar un backlog sin control.
    earliest = connector.last_synced_at or (connector.created_at - timedelta(hours=24))
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
        # Sin novedades — NO se avanza el checkpoint. Si se avanzara igual aquí,
        # cualquier evento que Splunk todavía no había terminado de indexar
        # (o que llegó con un _time levemente anterior a este intento) queda
        # excluido para siempre de las próximas búsquedas, que solo miran
        # hacia adelante desde el último checkpoint. Bug real encontrado en
        # producción: el checkpoint avanzaba en cada sync "vacío", y para
        # cuando el worker realmente empezó a mandar eventos, ya los había
        # dejado atrás — earliest_time=0 los encontraba, el checkpoint no.
        _mark_connected(connector, 'Sin alertas nuevas — no se avanzó el checkpoint.')
        return

    # Deduplicación real contra lo ya procesado: clean_records() solo
    # dedupea DENTRO del mismo lote, no contra lo que ya está guardado en la
    # BD. Sin esto, "Resetear checkpoint completo" (o incluso un solape de
    # 60s entre syncs consecutivos) vuelve a traer y a guardar eventos que
    # Splunk ya había devuelto antes. `_cd` es el identificador interno de
    # Splunk (bucket_id:offset), único por evento dentro del índice — sirve
    # de clave estable sin depender de ningún campo propio del worker .NET.
    raw_by_id = {r['_cd']: r for r in raw_results if r.get('_cd')}
    already_ingested = set(IngestedSplunkEvent.objects.filter(
        connector=connector, event_id__in=raw_by_id.keys(),
    ).values_list('event_id', flat=True))
    new_raw_results = [r for r in raw_results if r.get('_cd') not in already_ingested]

    if not new_raw_results:
        # Splunk sí tenía datos para esta ventana — no es un caso de "todavía
        # no indexado" como el de arriba, ya se procesaron antes. Es seguro
        # avanzar el checkpoint para no repetir esta misma consulta cada vez.
        _mark_synced(connector, f'{len(raw_results)} evento(s) recibidos, ya estaban guardados de una sincronización anterior — sin alertas nuevas.')
        return

    # Un oneshot search plano ("search index=soc_alerts") no siempre aplana
    # los campos del evento al nivel superior del resultado, aunque el
    # sourcetype sea _json — Splunk puede devolver solo los metadatos propios
    # (_time, host, source, sourcetype, _indextime, etc.) más _raw con el
    # JSON original del worker sin parsear. Se parsea _raw directo en vez de
    # depender de que Splunk extraiga los campos por su cuenta — confirmado
    # con una respuesta real de Splunk (2026-08-09) que traía exactamente
    # este caso. clean_records ya descarta solo cualquier campo que no
    # reconozca, así que no hace falta filtrar los metadatos a mano.
    events = [_extract_event_fields(r) for r in new_raw_results]
    clean, stats = clean_records(events)

    # Se marcan como procesados TODOS los eventos nuevos recibidos, hayan
    # pasado o no la limpieza — el contenido de un `_cd` ya indexado en
    # Splunk no cambia, así que reintentar uno inválido va a fallar siempre
    # de la misma forma. ignore_conflicts por las dudas de una carrera con
    # otro sync del mismo conector (no debería pasar, pero es gratis).
    IngestedSplunkEvent.objects.bulk_create(
        [IngestedSplunkEvent(connector=connector, event_id=eid) for eid in raw_by_id if eid not in already_ingested],
        ignore_conflicts=True,
    )

    if not clean:
        _mark_connected(connector, _diagnose_empty_clean(events, stats))
        return

    dataset = Dataset.objects.create(
        filename=f'Splunk — {connector.name}',
        row_count=len(clean),
        uploaded_by=connector.created_by,
    )
    async_task('predictor.tasks.process_alert_batch', dataset.pk, clean, connector.created_by_id)

    _mark_synced(connector, f'{len(clean)} alerta(s) nueva(s) encoladas para procesar.')


def _extract_event_fields(result):
    """Un resultado de Splunk a veces no trae los campos del evento aplanados
    al nivel superior (depende de si el search dispara extracción de campos)
    — pero _raw siempre tiene el JSON original que mandó el worker, sin
    parsear. Se prioriza _raw cuando es JSON válido; si no, se usa el
    resultado tal cual (por si algún día Splunk sí lo aplana)."""
    raw = result.get('_raw')
    if raw:
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return parsed
        except (ValueError, TypeError):
            pass
    return result


def _diagnose_empty_clean(events, stats):
    """Splunk trajo eventos pero clean_records() los descartó todos — arma
    un mensaje concreto en vez de dejarlo como caja negra, usando lo que
    clean_records ya calculó (stats) más las claves reales del primer
    evento YA extraído de _raw (para comparar contra REQUIRED_COLUMNS sin
    adivinar)."""
    parts = [f'Splunk devolvió {len(events)} evento(s), pero ninguno pasó la validación.']

    if stats.get('columns_missing'):
        parts.append(f"Faltan columnas obligatorias por completo: {', '.join(stats['columns_missing'])}.")

    if stats.get('invalid_rows_removed'):
        parts.append(f"{stats['invalid_rows_removed']} fila(s) descartada(s) por rango numérico inválido (failed_login_attempts/request_rate_per_min negativos, o anomaly_score fuera de 0-1).")

    if events:
        parts.append(f"Claves reales del primer evento: {', '.join(sorted(events[0].keys()))}.")

    return ' '.join(parts)


def _mark_connected(connector, message):
    """Conexión sana, búsqueda ejecutada, pero sin resultados nuevos (o
    descartados en la limpieza) — el checkpoint (last_synced_at) queda
    intacto a propósito."""
    connector.status = 'connected'
    connector.last_test_message = message
    connector.save(update_fields=['status', 'last_test_message'])


def _mark_synced(connector, message):
    """Hubo resultados y se guardaron — aquí sí se avanza el checkpoint, con
    un margen de solape de 60s hacia atrás por las dudas (lag de indexación
    de Splunk o pequeño desfase de reloj entre el worker y el servidor).
    El margen puede reprocesar el mismo evento dos veces en un caso límite,
    pero eso es preferible a perderlo — clean_records no dedupea contra lo
    ya guardado, así que un solape muy grande sí crearía Alert duplicados.
    60s es un margen chico a propósito."""
    connector.last_synced_at = timezone.now() - timedelta(seconds=60)
    connector.status = 'connected'
    connector.last_test_message = message
    connector.save(update_fields=['last_synced_at', 'status', 'last_test_message'])


def _mark_error(connector, message):
    connector.status = 'error'
    connector.last_test_message = message
    connector.save(update_fields=['status', 'last_test_message'])
    log_error(connector.created_by, 'splunk_sync', message)
