# -*- coding: utf-8 -*-
"""
Pipeline de normalización y limpieza para uploads de alertas SOC.
Maneja CSV/JSON subidos por el analista antes de pasarlos al predictor.
"""

import io
import csv
import json

import numpy as np
import pandas as pd

# Campos mínimos para que una predicción sea válida
REQUIRED_COLUMNS = [
    'event_category',
    'protocol',
    'traffic_type',
    'mitre_tactic',
    'kill_chain_stage',
    'severity',
    'ids_ips_alert',
    'asset_criticality',
    'log_source',
    'firewall_action',
    'failed_login_attempts',
    'request_rate_per_min',
]

# Campos opcionales que mejoran la calidad de predicción
# correlation_id → permite calcular incident_* reales (regla 4 del predictor)
# mitre_techniques → habilita las columnas binarias MITRE
# has_threat_family, evidence_role, os_family → features del Stage 2
OPTIONAL_COLUMNS = [
    'correlation_id',
    'mitre_techniques',
    'has_threat_family',
    'evidence_role',
    'os_family',
    'anomaly_score',
]

# Campos de visualización — no los usa el modelo ML, pero se guardan en Alert
DISPLAY_COLUMNS = [
    'attack_type',
    'attack_signature',
    'malware_indicator',
    'label',
]

ALL_KNOWN_COLUMNS = REQUIRED_COLUMNS + OPTIONAL_COLUMNS + DISPLAY_COLUMNS

# Metadatos por columna: descripción, ejemplo de valores y tipo de dato esperado
COLUMN_METADATA = {
    'event_category':        {'desc': 'Categoría del evento de seguridad detectado.',               'example': 'malware_activity, intrusion_attempt, command_and_control', 'type': 'str'},
    'protocol':              {'desc': 'Protocolo de red del tráfico analizado.',                    'example': 'tcp, udp, icmp',                                           'type': 'str'},
    'traffic_type':          {'desc': 'Tipo de tráfico de red.',                                    'example': 'ssh, https, dns',                                          'type': 'str'},
    'mitre_tactic':          {'desc': 'Táctica MITRE ATT&CK asociada al evento.',                   'example': 'initial access, lateral movement, command and control',    'type': 'str'},
    'kill_chain_stage':      {'desc': 'Etapa del kill chain en la que se encuentra el ataque.',      'example': 'initial access, command & control, exfiltration',          'type': 'str'},
    'severity':              {'desc': 'Nivel de severidad del evento.',                             'example': 'low, medium, high, critical, unknown',                     'type': 'str'},
    'ids_ips_alert':         {'desc': 'Veredicto del IDS/IPS sobre el tráfico.',                    'example': 'no alert, suspicious pattern, confirmed malicious indicator','type': 'str'},
    'asset_criticality':     {'desc': 'Criticidad del activo afectado por el evento.',              'example': 'low, medium, high',                                        'type': 'str'},
    'log_source':            {'desc': 'Fuente del log de seguridad.',                               'example': 'edr, siem, ips, firewall',                                 'type': 'str'},
    'firewall_action':       {'desc': 'Acción tomada por el firewall ante el tráfico.',             'example': 'allowed, blocked, monitored, unknown',                     'type': 'str'},
    'failed_login_attempts': {'desc': 'Cantidad de intentos de inicio de sesión fallidos (entero ≥ 0).',     'example': '0, 3, 10',                                         'type': 'int'},
    'request_rate_per_min':  {'desc': 'Tasa de peticiones por minuto observada en el tráfico (decimal ≥ 0).','example': '0.0, 15.5, 120.0',                                'type': 'float'},
    'has_threat_family':     {'desc': '1 si se detectó una familia de malware conocida, 0 si no.',  'example': '0, 1',                                                     'type': 'int'},
    'evidence_role':         {'desc': 'Rol de la entidad en el incidente.',                         'example': 'attacker, impacted, related',                              'type': 'str'},
    'os_family':             {'desc': 'Sistema operativo del activo afectado.',                     'example': 'windows, linux, macos',                                    'type': 'str'},
    'correlation_id':        {'desc': 'ID que agrupa alertas del mismo incidente. Activa features de incidente en el modelo.', 'example': '12345, INC-001',               'type': 'str'},
    'mitre_techniques':      {'desc': 'Técnicas MITRE ATT&CK separadas por ";". Solo técnicas del vocabulario de entrenamiento.', 'example': 'T1110;T1078.004',          'type': 'str'},
    'anomaly_score':         {'desc': 'Score de anomalía (0.0-1.0). Si no se incluye, se calcula automáticamente.',             'example': '0.0, 0.45, 1.0',            'type': 'float'},
    'attack_type':           {'desc': 'Tipo de ataque (solo visualización, no afecta la predicción ML).',    'example': 'Brute Force, Phishing, DDoS',                   'type': 'str'},
    'attack_signature':      {'desc': 'Firma o nombre del ataque detectado (solo visualización).',           'example': 'SSH Login Failure, CVE-2021-44228',             'type': 'str'},
    'malware_indicator':     {'desc': 'Indicador de malware — nombre, hash o familia (solo visualización).', 'example': 'Cobalt Strike, Mimikatz',                       'type': 'str'},
    'label':                 {'desc': 'Etiqueta real del registro. Útil para comparar contra la predicción ML.', 'example': 'benigno, a_investigar, malicioso',          'type': 'str'},
}

NUMERIC_COLUMNS = [
    'failed_login_attempts',
    'request_rate_per_min',
    'has_threat_family',
    'anomaly_score',
]

# Solo columnas que el modelo ML requiere en minúsculas para el vocabulario de entrenamiento.
# correlation_id → identificador de incidente, preservar case (INC-001 ≠ inc-001 para el usuario)
# mitre_techniques → _parse_mitre_techniques llama .lower() internamente; preservar case para display
# attack_type, attack_signature, malware_indicator, label → campos de visualización, preservar case
CATEGORICAL_COLUMNS = [
    'event_category', 'protocol', 'traffic_type', 'mitre_tactic',
    'kill_chain_stage', 'severity', 'ids_ips_alert', 'asset_criticality',
    'log_source', 'firewall_action', 'evidence_role', 'os_family',
]


def _normalize_key(key: str) -> str:
    return key.strip().lower().replace(' ', '_')


def validate_column_types(records: list, mapping: dict) -> dict:
    """
    Valida que las columnas mapeadas tengan el tipo de dato esperado.
    mapping: {target_col: source_col_in_file}
    Returns: {target_col: {'source': source_col, 'bad_samples': [(row_num, value)]}}
    Solo valida columnas int/float — los string siempre son válidos.
    """
    warnings = {}
    for target, source in mapping.items():
        if not source:
            continue
        meta = COLUMN_METADATA.get(target, {})
        if meta.get('type', 'str') not in ('int', 'float'):
            continue
        bad = []
        for i, rec in enumerate(records[:30], start=1):
            val = rec.get(source, '')
            if val is None or str(val).strip().lower() in ('', 'none', 'nan', 'null', 'unknown'):
                continue
            try:
                float(str(val))
            except (ValueError, TypeError):
                bad.append((i, str(val)[:25]))
        if bad:
            warnings[target] = {'source': source, 'bad_samples': bad[:3]}
    return warnings


def parse_file(file):
    """
    Parsea un archivo CSV o JSON.
    Devuelve (records: list[dict], error: str | None).
    """
    filename = file.name.lower()
    if filename.endswith('.json'):
        return _parse_json(file)
    if filename.endswith('.csv'):
        return _parse_csv(file)
    return None, f'Tipo de archivo no soportado: "{file.name}". Use .json o .csv.'


def _parse_json(file):
    try:
        content = file.read().decode('utf-8')
        data = json.loads(content)
    except UnicodeDecodeError:
        return None, 'El archivo no tiene codificación UTF-8 válida.'
    except json.JSONDecodeError:
        return None, 'El contenido del archivo no es JSON válido.'

    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        return None, 'El JSON debe ser un array de objetos o un único objeto.'
    if not all(isinstance(item, dict) for item in data):
        return None, 'Cada elemento del JSON debe ser un objeto (clave-valor).'

    records = [{_normalize_key(k): v for k, v in item.items()} for item in data]
    return records, None


def _parse_csv(file):
    try:
        raw = file.read()
        # pandas.read_csv maneja todos los line endings (\r\n, \r, \n), campos citados
        # con separadores internos, y encodings con BOM — mucho más robusto que csv.DictReader.
        df = pd.read_csv(
            io.BytesIO(raw),
            encoding='utf-8-sig',
            dtype=str,
            keep_default_na=False,
        )
    except UnicodeDecodeError:
        return None, 'El archivo CSV no tiene codificación UTF-8 válida.'
    except Exception:
        return None, 'El archivo CSV tiene un formato incorrecto.'

    if df.empty:
        return None, 'El CSV no contiene filas de datos (solo encabezado o vacío).'

    if df.shape[1] == 1:
        return None, (
            'El CSV se parseó como 1 columna. Verificá que use coma (,) como separador '
            'y que los campos con comas internas estén entre comillas dobles.'
        )

    df.columns = [_normalize_key(col) for col in df.columns]

    # Convertir celdas vacías a None para que clean_records() pueda rellenarlas
    records = [
        {k: (v if v != '' else None) for k, v in row.items()}
        for row in df.to_dict(orient='records')
    ]
    return records, None


def validate_columns(records: list) -> tuple:
    """
    Devuelve (detected_columns: list, missing_required: list).
    Los OPTIONAL_COLUMNS ausentes no se reportan como error.
    """
    if not records:
        return [], list(REQUIRED_COLUMNS)
    detected = list(records[0].keys())
    missing = [col for col in REQUIRED_COLUMNS if col not in detected]
    return detected, missing


def apply_mapping(records: list, mapping: dict) -> list:
    """
    Renombra columnas del archivo según el mapping proporcionado.
    mapping = { 'required_col': 'source_col_in_file', ... }
    """
    result = []
    for record in records:
        new_rec = dict(record)
        for target, source in mapping.items():
            if source and source in new_rec and source != target:
                new_rec[target] = new_rec.pop(source)
        result.append(new_rec)
    return result


def clean_records(records: list) -> tuple:
    """
    Pipeline de limpieza alineado con train_model.py:
      1. Normalizar nombres de columnas
      2. Eliminar duplicados
      3. Strip de strings
      4. Normalizar columnas categóricas (lowercase)
      5. Convertir columnas numéricas
      6. Rellenar nulos (mediana para numéricos, 'unknown' para categóricos)
      7. Validar rangos numéricos (≥ 0)
      8. Retener columnas conocidas (required + optional) presentes en el archivo

    Devuelve (cleaned_records: list[dict], stats: dict).
    """
    df = pd.DataFrame(records)

    # 1. Normalizar nombres de columnas
    df.columns = df.columns.str.strip().str.lower().str.replace(' ', '_', regex=False)

    # 2. Eliminar duplicados
    initial_count = len(df)
    df = df.drop_duplicates()
    duplicates_removed = initial_count - len(df)

    # 3. Strip de columnas de texto
    for col in df.select_dtypes(include=['object']).columns:
        df[col] = df[col].astype(str).str.strip()

    # 4. Normalizar columnas categóricas a minúsculas
    for col in CATEGORICAL_COLUMNS:
        if col in df.columns:
            df[col] = df[col].astype(str).str.lower().str.strip()

    # 5. Convertir columnas numéricas
    for col in NUMERIC_COLUMNS:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce')

    # Reemplazar strings 'nan' residuales
    for col in df.select_dtypes(include=['object']).columns:
        df[col] = df[col].replace('nan', np.nan)

    # 6. Rellenar nulos
    nulls_before = int(df.isnull().sum().sum())

    for col in df.select_dtypes(include=[np.number]).columns:
        if df[col].isnull().any():
            df[col] = df[col].fillna(df[col].median())

    for col in df.select_dtypes(include=['object']).columns:
        df[col] = df[col].fillna('unknown')

    nulls_after  = int(df.isnull().sum().sum())
    nulls_filled = nulls_before - nulls_after

    # 7. Validar rangos numéricos
    invalid_removed = 0
    for col in ('failed_login_attempts', 'request_rate_per_min', 'has_threat_family'):
        if col in df.columns:
            before = len(df)
            df = df[df[col] >= 0]
            invalid_removed += before - len(df)

    if 'anomaly_score' in df.columns:
        before = len(df)
        df = df[(df['anomaly_score'] >= 0) & (df['anomaly_score'] <= 1)]
        invalid_removed += before - len(df)

    # Castear tipos nativos
    if 'failed_login_attempts' in df.columns:
        df['failed_login_attempts'] = df['failed_login_attempts'].astype(int)
    if 'has_threat_family' in df.columns:
        df['has_threat_family'] = df['has_threat_family'].clip(0, 1).astype(int)
    if 'request_rate_per_min' in df.columns:
        df['request_rate_per_min'] = df['request_rate_per_min'].astype(float)

    # 8. Retener columnas conocidas presentes (required + optional + display)
    available_required = [c for c in REQUIRED_COLUMNS if c in df.columns]
    available_optional = [c for c in OPTIONAL_COLUMNS  if c in df.columns]
    available_display  = [c for c in DISPLAY_COLUMNS   if c in df.columns]
    available = available_required + available_optional + available_display
    df = df[available]

    stats = {
        'total_original'       : initial_count,
        'duplicates_removed'   : duplicates_removed,
        'nulls_filled'         : nulls_filled,
        'invalid_rows_removed' : invalid_removed,
        'total_clean'          : len(df),
        'columns_present'      : available,
        'columns_missing'      : [c for c in REQUIRED_COLUMNS if c not in available],
        'optional_present'     : available_optional,
        'display_present'      : available_display,
    }

    # Serializar a tipos Python nativos
    clean = []
    for row in df.where(pd.notnull(df), None).to_dict(orient='records'):
        serialized = {}
        for k, v in row.items():
            if isinstance(v, np.integer):
                serialized[k] = int(v)
            elif isinstance(v, np.floating):
                serialized[k] = float(v)
            else:
                serialized[k] = v
        clean.append(serialized)

    return clean, stats


def export_to_csv(records: list) -> str:
    """Exporta los registros limpios a string CSV (solo columnas conocidas presentes)."""
    if not records:
        return ''
    fieldnames = [c for c in ALL_KNOWN_COLUMNS if c in records[0]]
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
    writer.writeheader()
    for record in records:
        writer.writerow({col: record.get(col, '') for col in fieldnames})
    return output.getvalue()


def export_to_json(records: list) -> str:
    """Exporta los registros limpios a string JSON (solo columnas conocidas presentes)."""
    if not records:
        return '[]'
    fieldnames = [c for c in ALL_KNOWN_COLUMNS if c in records[0]]
    export = [
        {col: record.get(col, '') for col in fieldnames}
        for record in records
    ]
    return json.dumps(export, ensure_ascii=False, indent=2)
