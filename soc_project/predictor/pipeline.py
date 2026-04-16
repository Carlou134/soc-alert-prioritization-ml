# -*- coding: utf-8 -*-
"""
Pipeline de normalización y limpieza de datos para el modelo ML SOC.
Sigue la misma lógica de limpieza definida en train_model.py.
"""

import io
import csv
import json

import numpy as np
import pandas as pd

REQUIRED_COLUMNS = [
    'event_category',
    'attack_type',
    'attack_signature',
    'protocol',
    'traffic_type',
    'mitre_tactic',
    'kill_chain_stage',
    'failed_login_attempts',
    'request_rate_per_min',
    'ids_ips_alert',
    'malware_indicator',
    'asset_criticality',
    'log_source',
    'firewall_action',
    'severity',
    'label',
]

NUMERIC_COLUMNS = ['failed_login_attempts', 'request_rate_per_min']

CATEGORICAL_COLUMNS = [
    'event_category', 'attack_type', 'attack_signature', 'protocol',
    'traffic_type', 'mitre_tactic', 'kill_chain_stage', 'ids_ips_alert',
    'malware_indicator', 'asset_criticality', 'log_source',
    'firewall_action', 'severity', 'label',
]


def _normalize_key(key: str) -> str:
    return key.strip().lower().replace(' ', '_')


def parse_file(file):
    """
    Parsea un archivo CSV o JSON subido por el usuario.
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
        content = file.read().decode('utf-8-sig')
        reader = csv.DictReader(io.StringIO(content))
        records = [{_normalize_key(k): v for k, v in row.items()} for row in reader]
    except UnicodeDecodeError:
        return None, 'El archivo CSV no tiene codificación UTF-8 válida.'
    except csv.Error:
        return None, 'El archivo CSV tiene un formato incorrecto.'

    if not records:
        return None, 'El CSV no contiene filas de datos (solo encabezado o vacío).'
    return records, None


def validate_columns(records: list) -> tuple:
    """
    Devuelve (detected_columns: list, missing_required: list).
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
    Pipeline completo de limpieza siguiendo train_model.py:
      1. Normalizar nombres de columnas
      2. Eliminar duplicados
      3. Strip de strings
      4. Normalizar columnas categóricas (lowercase)
      5. Convertir columnas numéricas
      6. Rellenar nulos (mediana para numéricos, 'unknown' para categóricos)
      7. Validar rangos numéricos (≥ 0)
      8. Retener sólo columnas requeridas presentes

    Devuelve (cleaned_records: list[dict], stats: dict).
    """
    df = pd.DataFrame(records)

    # 1. Normalizar nombres de columnas
    df.columns = df.columns.str.strip().str.lower().str.replace(' ', '_')

    # 2. Eliminar duplicados
    initial_count = len(df)
    df = df.drop_duplicates()
    duplicates_removed = initial_count - len(df)

    # 3. Strip de columnas de texto
    for col in df.select_dtypes(include='object').columns:
        df[col] = df[col].astype(str).str.strip()

    # 4. Normalizar columnas categóricas a minúsculas
    for col in CATEGORICAL_COLUMNS:
        if col in df.columns:
            df[col] = df[col].astype(str).str.lower().str.strip()

    # 5. Convertir columnas numéricas
    for col in NUMERIC_COLUMNS:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce')

    # Reemplazar strings 'nan' que quedaron de conversiones anteriores
    for col in df.select_dtypes(include='object').columns:
        df[col] = df[col].replace('nan', np.nan)

    # 6. Contar nulos antes de rellenar
    nulls_before = int(df.isnull().sum().sum())

    num_cols = df.select_dtypes(include=[np.number]).columns
    obj_cols = df.select_dtypes(include=['object']).columns

    for col in num_cols:
        if df[col].isnull().any():
            df[col] = df[col].fillna(df[col].median())

    for col in obj_cols:
        df[col] = df[col].fillna('unknown')

    nulls_after = int(df.isnull().sum().sum())
    nulls_filled = nulls_before - nulls_after

    # 7. Validar rangos numéricos (eliminar filas con valores negativos)
    invalid_removed = 0
    if 'failed_login_attempts' in df.columns:
        before = len(df)
        df = df[df['failed_login_attempts'] >= 0]
        invalid_removed += before - len(df)

    if 'request_rate_per_min' in df.columns:
        before = len(df)
        df = df[df['request_rate_per_min'] >= 0]
        invalid_removed += before - len(df)

    # Convertir a tipos nativos correctos
    for col in NUMERIC_COLUMNS:
        if col in df.columns:
            if col == 'failed_login_attempts':
                df[col] = df[col].astype(int)
            else:
                df[col] = df[col].astype(float)

    # 8. Retener sólo columnas requeridas presentes
    available = [col for col in REQUIRED_COLUMNS if col in df.columns]
    df = df[available]

    stats = {
        'total_original': initial_count,
        'duplicates_removed': duplicates_removed,
        'nulls_filled': nulls_filled,
        'invalid_rows_removed': invalid_removed,
        'total_clean': len(df),
        'columns_present': available,
        'columns_missing': [col for col in REQUIRED_COLUMNS if col not in available],
    }

    # Serializar a tipos Python nativos (para almacenar en sesión JSON)
    clean = []
    for row in df.where(pd.notnull(df), None).to_dict(orient='records'):
        serialized = {}
        for k, v in row.items():
            if isinstance(v, (np.integer,)):
                serialized[k] = int(v)
            elif isinstance(v, (np.floating,)):
                serialized[k] = float(v)
            else:
                serialized[k] = v
        clean.append(serialized)

    return clean, stats


def export_to_csv(records: list) -> str:
    """Exporta los registros limpios a string CSV."""
    if not records:
        return ''
    output = io.StringIO()
    writer = csv.DictWriter(
        output, fieldnames=REQUIRED_COLUMNS, extrasaction='ignore'
    )
    writer.writeheader()
    for record in records:
        writer.writerow({col: record.get(col, '') for col in REQUIRED_COLUMNS})
    return output.getvalue()


def export_to_json(records: list) -> str:
    """Exporta los registros limpios a string JSON."""
    export = [
        {col: record.get(col, '') for col in REQUIRED_COLUMNS}
        for record in records
    ]
    return json.dumps(export, ensure_ascii=False, indent=2)
