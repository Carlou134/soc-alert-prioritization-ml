# -*- coding: utf-8 -*-
import re
import logging
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

BASE_DIR   = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / 'ml' / 'soc_model.pkl'


# Lazy-loaded — se inicializan en _load_model() al primer uso
rf_s1            = None
rf_s2_cal        = None
training_columns = None
s2_columns       = None
_t1              = None
_t2              = None
_idx_mal_s1      = None
_idx_inv_s2      = None
_idx_ben_s2      = None
_model_loaded    = False


def _load_model() -> bool:
    """Carga el artefacto ML la primera vez que se invoca. Thread-unsafe pero aceptable para uso en servidor único."""
    global rf_s1, rf_s2_cal, training_columns, s2_columns
    global _t1, _t2, _idx_mal_s1, _idx_inv_s2, _idx_ben_s2, _model_loaded

    if _model_loaded:
        return True
    if not MODEL_PATH.exists():
        logger.critical('soc_model.pkl no encontrado — modelo ML no disponible.')
        return False
    try:
        artifact         = joblib.load(MODEL_PATH)
        rf_s1            = artifact['model_s1']
        rf_s2_cal        = artifact['model_s2']
        training_columns = artifact['training_columns']
        s2_columns       = artifact['s2_columns']
        _t1              = artifact['thresholds']['t1']
        _t2              = artifact['thresholds']['t2']
        _idx_mal_s1      = artifact['idx_mal_s1']
        _idx_inv_s2      = artifact['idx_inv_s2']
        _idx_ben_s2      = artifact['idx_ben_s2']
        _model_loaded    = True
        logger.info('Modelo ML cargado correctamente.')
        return True
    except Exception as e:
        logger.critical(f'Model load failed: {e}')
        return False

CLASS_LABELS = {0: 'benigno', 1: 'a_investigar', 2: 'malicioso'}

# ---------------------------------------------------------------------------
# Vocabulary maps
# ---------------------------------------------------------------------------

MAP_SEVERITY = {
    'critical'     : 'critical',
    'high'         : 'high',
    'medium'       : 'medium',
    'low'          : 'unknown',
    'informational': 'unknown',
    'unknown'      : 'unknown',
    '15': 'critical', '12': 'critical',
    '10': 'medium',   '7' : 'medium',
    '3' : 'unknown',  '1' : 'unknown',
}

SEVERITY_ORDINAL = {"unknown": 0, "medium": 1, "high": 2, "critical": 3}

MAP_EVENT_CATEGORY = {
    'malware'             : 'malware_activity',
    'malwareactivity'     : 'malware_activity',
    'malware_activity'    : 'malware_activity',
    'intrusionattempt'    : 'intrusion_attempt',
    'intrusion_attempt'   : 'intrusion_attempt',
    'initialaccess'       : 'intrusion_attempt',
    'initial_access'      : 'intrusion_attempt',
    'lateralmovement'     : 'lateral_movement',
    'lateral_movement'    : 'lateral_movement',
    'reconnaissance'      : 'reconnaissance',
    'commandandcontrol'   : 'command_and_control',
    'command_and_control' : 'command_and_control',
    'dataexfiltration'    : 'data_exfiltration',
    'data_exfiltration'   : 'data_exfiltration',
    'exfiltration'        : 'data_exfiltration',
    'suspiciousactivity'  : 'suspicious_activity',
    'suspicious_activity' : 'suspicious_activity',
    'credentialaccess'    : 'credential_access',
    'credential_access'   : 'credential_access',
    'impact'              : 'impact',
    'execution'           : 'execution',
    'persistence'         : 'persistence',
    'privilegeescalation' : 'privilege_escalation',
    'privilege_escalation': 'privilege_escalation',
    'defenseevasion'      : 'evasion',
    'defense_evasion'     : 'evasion',
    'evasion'             : 'evasion',
    'web_attack'          : 'web_attack',
    'webattack'           : 'web_attack',
    'datacollection'      : 'data_collection',
    'data_collection'     : 'data_collection',
    'collection'          : 'data_collection',
    'resourcedevelopment' : 'resource_development',
    'resource_development': 'resource_development',
}

MAP_FIREWALL = {
    'allow'              : 'allowed',
    'allowed'            : 'allowed',
    'deny'               : 'blocked',
    'denied'             : 'blocked',
    'block'              : 'blocked',
    'blocked'            : 'blocked',
    'quarantine'         : 'blocked',
    'alertandblock'      : 'blocked',
    'containaccount'     : 'blocked',
    'isolatedevice'      : 'blocked',
    'stopvirtualmachines': 'blocked',
    'alert'              : 'monitored',
    'monitor'            : 'monitored',
    'monitored'          : 'monitored',
    'unknown'            : 'unknown',
}

MAP_IDS_ALERT = {
    'yes'                          : 'suspicious pattern',
    'no'                           : 'no alert',
    'nothreatsfound'               : 'no alert',
    'noalert'                      : 'no alert',
    'no alert'                     : 'no alert',
    'benign'                       : 'no alert',
    'suspicious'                   : 'suspicious pattern',
    'suspiciouspattern'            : 'suspicious pattern',
    'suspicious pattern'           : 'suspicious pattern',
    'behavioranomaly'              : 'suspicious pattern',
    'behavior anomaly'             : 'suspicious pattern',
    'malicious'                    : 'confirmed malicious indicator',
    'confirmedmaliciousindicator'  : 'confirmed malicious indicator',
    'confirmed malicious indicator': 'confirmed malicious indicator',
    'unknown'                      : 'unknown',
}

MAP_MITRE_TACTIC = {
    'initialaccess'       : 'initial access',
    'initial_access'      : 'initial access',
    'lateralmovement'     : 'lateral movement',
    'lateral_movement'    : 'lateral movement',
    'commandandcontrol'   : 'command and control',
    'command_and_control' : 'command and control',
    'credentialaccess'    : 'credential access',
    'credential_access'   : 'credential access',
    'execution'           : 'execution',
    'exfiltration'        : 'exfiltration',
    'impact'              : 'impact',
    'reconnaissance'      : 'reconnaissance',
    'discovery'           : 'discovery',
    'persistence'         : 'persistence',
    'privilegeescalation' : 'privilege escalation',
    'privilege_escalation': 'privilege escalation',
    'defenseevasion'      : 'defense evasion',
    'defense_evasion'     : 'defense evasion',
    'collection'          : 'collection',
    'resourcedevelopment' : 'resource development',
    'resource_development': 'resource development',
    'unknown'             : 'unknown',
}

MAP_EVIDENCE_ROLE = {
    'attacker': 'attacker',
    'impacted': 'impacted',
    'related' : 'related',
    'caller'  : 'related',
    'receiver': 'related',
    'victim'  : 'impacted',
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _norm(val: str) -> str:
    """strip + lowercase + quita espacios — para lookup en diccionarios (regla 1)."""
    return str(val).strip().lower().replace(' ', '')


def _parse_mitre_techniques(raw: str) -> list:
    """
    'T1110;T1078.004;T1003' → ['mitre_t1110', 'mitre_t1078_004', 'mitre_t1003']
    Solo retorna columnas que existan en training_columns.
    """
    if not raw or str(raw).strip().lower() in ('', 'none', 'nan', 'unknown'):
        return []
    mitre_in_train = {c for c in training_columns if c.startswith('mitre_t')}
    cols = []
    for part in str(raw).split(';'):
        m = re.search(r't\d{4}(?:\.\d{3})?', part.strip().lower())
        if m:
            col = 'mitre_' + m.group(0).replace('.', '_')
            if col in mitre_in_train:
                cols.append(col)
    return cols


def _compute_anomaly_score(ids_ips_alert: str, severity: str, firewall_action: str) -> float:
    """
    Réplica exacta de la fórmula del pipeline de entrenamiento (regla 7).
    Opera sobre valores ya normalizados (post-mapeo).

    Equivalencia con training (verificada contra dataset_soc_alertas_train.csv):
      0.40 * (LastVerdict == "Malicious")       → ids == "confirmed malicious indicator"
      0.20 * (LastVerdict == "Suspicious")      → ids == "suspicious pattern"
      0.25 * (SuspicionLevel == "Incriminated") → severity == "high"   ← NOT "critical"
      0.10 * (SuspicionLevel == "Suspicious")   → severity == "medium"
      0.05 * (ActionGrouped in [block, ...])    → firewall_action == "blocked"

    Nota: severity="critical" en el dataset no corresponde a "Incriminated" —
    contribuye 0 al anomaly_score, aunque sí aporta como feature categórica/ordinal.
    """
    return float(min(
        0.40 * (ids_ips_alert == 'confirmed malicious indicator') +
        0.20 * (ids_ips_alert == 'suspicious pattern') +
        0.25 * (severity == 'high') +
        0.10 * (severity == 'medium') +
        0.05 * (firewall_action == 'blocked'),
        1.0,
    ))


# ---------------------------------------------------------------------------
# Input fields
# ---------------------------------------------------------------------------

EXPECTED_FIELDS = [
    'event_category', 'protocol', 'traffic_type', 'mitre_tactic',
    'kill_chain_stage', 'severity', 'ids_ips_alert', 'asset_criticality',
    'log_source', 'firewall_action', 'failed_login_attempts', 'request_rate_per_min',
    'has_threat_family', 'evidence_role', 'os_family',
    'correlation_id', 'mitre_techniques',
]


def extract_valid_fields(data: dict) -> dict:
    return {field: data.get(field) for field in EXPECTED_FIELDS}


# ---------------------------------------------------------------------------
# Normalization (regla 1: strip + lower + no-spaces antes de cada lookup)
# ---------------------------------------------------------------------------

def normalize_input(data: dict) -> dict:
    """
    Traduce valores crudos al vocabulario de entrenamiento.
    malware_indicator excluido del output (regla 2).
    anomaly_score siempre se computa con la fórmula del training (regla 7).
    """
    raw = {k: str(v).strip() for k, v in data.items() if v is not None}

    ids_mapped = MAP_IDS_ALERT.get(_norm(raw.get('ids_ips_alert', '')), 'unknown')
    sev_mapped = MAP_SEVERITY.get(_norm(raw.get('severity', '')), 'unknown')
    fw_mapped  = MAP_FIREWALL.get(_norm(raw.get('firewall_action', '')), 'unknown')

    return {
        'event_category'        : MAP_EVENT_CATEGORY.get(_norm(raw.get('event_category', '')), 'other'),
        'protocol'              : raw.get('protocol', 'tcp').lower(),
        'traffic_type'          : raw.get('traffic_type', 'tcp').lower(),
        'mitre_tactic'          : MAP_MITRE_TACTIC.get(_norm(raw.get('mitre_tactic', '')), 'unknown'),
        'kill_chain_stage'      : raw.get('kill_chain_stage', 'unknown').strip().lower(),
        'failed_login_attempts' : int(float(raw.get('failed_login_attempts', 0))),
        'request_rate_per_min'  : float(raw.get('request_rate_per_min', 0.0)),
        'ids_ips_alert'         : ids_mapped,
        'asset_criticality'     : raw.get('asset_criticality', 'medium').strip().lower(),
        'log_source'            : raw.get('log_source', 'unknown').strip().lower(),
        'firewall_action'       : fw_mapped,
        'severity'              : sev_mapped,
        'has_threat_family'     : int(bool(int(float(raw.get('has_threat_family', 0))))),
        'evidence_role'         : MAP_EVIDENCE_ROLE.get(_norm(raw.get('evidence_role', '')), 'unknown'),
        'os_family'             : raw.get('os_family', 'unknown').strip().lower(),
        'anomaly_score'         : _compute_anomaly_score(ids_mapped, sev_mapped, fw_mapped),
        # privados — no entran al DataFrame del modelo
        '_correlation_id'       : raw.get('correlation_id', 'unknown'),
        '_mitre_techniques_raw' : raw.get('mitre_techniques', ''),
    }


# ---------------------------------------------------------------------------
# Feature engineering + encoding
# ---------------------------------------------------------------------------

def preprocess_input(data: dict) -> pd.DataFrame:
    """
    Pipeline completo para una alerta individual.

    Regla 3: failed_login_attempts/request_rate_per_min se usan tal cual.
             Si el caller no los tiene, pasan como 0 (señal débil pero válida).
    Regla 4: incident_* se inicializan con defaults conservadores (1 alerta = 1 incidente).
             Para batch con correlation_id, usar preprocess_batch().
    Regla 5: reindex(training_columns, fill_value=0) alinea el encoding.
    Regla 6: Stage 2 se llama con X[s2_columns], no con training_columns completo.
    """
    clean = normalize_input(data)
    mitre_raw      = clean.pop('_mitre_techniques_raw')
    correlation_id = clean.pop('_correlation_id')
    anomaly_score  = clean['anomaly_score']
    asset_crit     = clean.get('asset_criticality', 'unknown')
    ids_val        = clean.get('ids_ips_alert', 'unknown')

    df = pd.DataFrame([clean])

    # Columnas MITRE binarias — solo técnicas presentes en training (regla 5)
    for col in _parse_mitre_techniques(mitre_raw):
        df[col] = 1

    # n_mitre_techniques — solo columnas binarias de técnicas (mitre_tNNNN), no mitre_tactic
    mitre_present = [c for c in df.columns if re.match(r'^mitre_t\d', c)]
    df['n_mitre_techniques'] = df[mitre_present].sum(axis=1).astype(int) if mitre_present else 0

    # severity_num — ordinal encoding, espejea SEVERITY_ORDINAL de train_model.py
    if 'severity' in df.columns:
        df['severity_num'] = df['severity'].map(SEVERITY_ORDINAL).fillna(0).astype(int)

    # One-hot encoding → alinear con training_columns (regla 5)
    df_enc = pd.get_dummies(df, drop_first=False)
    df_enc = df_enc.reindex(columns=training_columns, fill_value=0)

    # anomaly_x_asset_high — feature cruzada, requiere dummies ya aplicados
    if 'anomaly_score' in df_enc.columns and 'asset_criticality_high' in df_enc.columns:
        df_enc['anomaly_x_asset_high'] = (
            df_enc['anomaly_score'] * df_enc['asset_criticality_high']
        ).astype(float)

    # Incident features — defaults para alerta individual (regla 4)
    # Para batch con CorrelationId completo, usar preprocess_batch().
    _defaults = {
        'incident_evidence_count'  : 1,
        'incident_max_anomaly'     : anomaly_score,
        'incident_mean_anomaly'    : anomaly_score,
        'incident_category_count'  : 1,
        'incident_log_source_count': 1,
        'incident_has_high_asset'  : 1 if asset_crit == 'high' else 0,
        'incident_has_confirmed'   : 1 if ids_val == 'confirmed malicious indicator' else 0,
    }
    for col, val in _defaults.items():
        if col in df_enc.columns:
            df_enc[col] = val

    # evidence_density y confirmed_x_evidence — requieren incident features ya seteadas
    if 'incident_evidence_count' in df_enc.columns and 'incident_log_source_count' in df_enc.columns:
        df_enc['evidence_density'] = (
            df_enc['incident_evidence_count'] / (df_enc['incident_log_source_count'] + 1)
        ).astype(float)
    if 'incident_has_confirmed' in df_enc.columns and 'incident_evidence_count' in df_enc.columns:
        df_enc['confirmed_x_evidence'] = (
            df_enc['incident_has_confirmed'] * np.log1p(df_enc['incident_evidence_count'])
        ).astype(float)

    # anomaly_z_score y anomaly_vs_max — espeja train_model.py; requieren incident features ya seteadas
    if 'anomaly_z_score' in df_enc.columns:
        inc_mean = float(df_enc['incident_mean_anomaly'].iloc[0]) if 'incident_mean_anomaly' in df_enc.columns else anomaly_score
        inc_std  = float(df_enc['incident_std_anomaly'].iloc[0])  if 'incident_std_anomaly' in df_enc.columns else 0.0
        df_enc['anomaly_z_score'] = float((anomaly_score - inc_mean) / (inc_std + 0.001))

    if 'anomaly_vs_max' in df_enc.columns:
        inc_max = float(df_enc['incident_max_anomaly'].iloc[0]) if 'incident_max_anomaly' in df_enc.columns else anomaly_score
        df_enc['anomaly_vs_max'] = float(anomaly_score / (inc_max + 0.001))

    return df_enc


def preprocess_batch(records: list) -> pd.DataFrame:
    """
    Feature engineering para un lote de alertas agrupadas por correlation_id.
    Calcula incident_* reales desde el contexto del incidente completo (regla 4).
    Cada alerta recibe las features del incidente al que pertenece.
    """
    normalized = []
    for rec in records:
        clean = normalize_input(rec)
        clean['correlation_id'] = clean.pop('_correlation_id')
        clean['_mitre_raw'] = clean.pop('_mitre_techniques_raw')
        normalized.append(clean)

    df_base = pd.DataFrame(normalized)

    # Incident features por correlation_id
    agg = (
        df_base.groupby('correlation_id')
        .agg(
            incident_evidence_count   = ('anomaly_score', 'count'),
            incident_max_anomaly      = ('anomaly_score', 'max'),
            incident_mean_anomaly     = ('anomaly_score', 'mean'),
            incident_std_anomaly      = ('anomaly_score', 'std'),
            incident_category_count   = ('event_category', 'nunique'),
            incident_log_source_count = ('log_source', 'nunique'),
            incident_has_high_asset   = ('asset_criticality',
                                         lambda x: int((x == 'high').any())),
            incident_has_confirmed    = ('ids_ips_alert',
                                         lambda x: int(
                                             (x == 'confirmed malicious indicator').any()
                                         )),
        )
        .reset_index()
    )
    agg['incident_std_anomaly'] = agg['incident_std_anomaly'].fillna(0.0)
    df_base = df_base.merge(agg, on='correlation_id', how='left')

    # Columnas MITRE binarias
    mitre_in_train = {c for c in training_columns if c.startswith('mitre_t')}
    for i, row in df_base.iterrows():
        for col in _parse_mitre_techniques(row.get('_mitre_raw', '')):
            if col in mitre_in_train:
                df_base.loc[i, col] = 1

    mitre_present = [c for c in df_base.columns if re.match(r'^mitre_t\d', c)]
    df_base['n_mitre_techniques'] = df_base[mitre_present].sum(axis=1).astype(int) if mitre_present else 0

    # severity_num — ordinal encoding, espejea SEVERITY_ORDINAL de train_model.py
    if 'severity' in df_base.columns:
        df_base['severity_num'] = df_base['severity'].map(SEVERITY_ORDINAL).fillna(0).astype(int)

    # Limpiar columnas auxiliares antes del encoding
    df_base = df_base.drop(columns=['correlation_id', '_mitre_raw'], errors='ignore')

    df_enc = pd.get_dummies(df_base, drop_first=False)
    df_enc = df_enc.reindex(columns=training_columns, fill_value=0)

    if 'anomaly_score' in df_enc.columns and 'asset_criticality_high' in df_enc.columns:
        df_enc['anomaly_x_asset_high'] = (
            df_enc['anomaly_score'] * df_enc['asset_criticality_high']
        ).astype(float)

    # Sobreescribir incident features con los valores reales (ya están en df_enc desde agg)
    for col in ['incident_evidence_count', 'incident_max_anomaly', 'incident_mean_anomaly',
                'incident_std_anomaly', 'incident_category_count', 'incident_log_source_count',
                'incident_has_high_asset', 'incident_has_confirmed']:
        if col in df_base.columns and col in df_enc.columns:
            df_enc[col] = df_base[col].values

    # evidence_density y confirmed_x_evidence — requieren incident features reales ya aplicadas
    if 'incident_evidence_count' in df_enc.columns and 'incident_log_source_count' in df_enc.columns:
        df_enc['evidence_density'] = (
            df_enc['incident_evidence_count'] / (df_enc['incident_log_source_count'] + 1)
        ).astype(float)
    if 'incident_has_confirmed' in df_enc.columns and 'incident_evidence_count' in df_enc.columns:
        df_enc['confirmed_x_evidence'] = (
            df_enc['incident_has_confirmed'] * np.log1p(df_enc['incident_evidence_count'])
        ).astype(float)

    # anomaly_z_score y anomaly_vs_max — espeja train_model.py; requieren incident features reales
    if all(c in df_enc.columns for c in ['anomaly_z_score', 'anomaly_score', 'incident_mean_anomaly', 'incident_std_anomaly']):
        df_enc['anomaly_z_score'] = (
            (df_enc['anomaly_score'] - df_enc['incident_mean_anomaly']) /
            (df_enc['incident_std_anomaly'] + 0.001)
        ).astype(float)

    if all(c in df_enc.columns for c in ['anomaly_vs_max', 'anomaly_score', 'incident_max_anomaly']):
        df_enc['anomaly_vs_max'] = (
            df_enc['anomaly_score'] / (df_enc['incident_max_anomaly'] + 0.001)
        ).astype(float)

    return df_enc


# ---------------------------------------------------------------------------
# Predicción jerárquica
# ---------------------------------------------------------------------------

def _composite_proba(X: pd.DataFrame) -> np.ndarray:
    """
    Probabilidades compuestas siguiendo composite_proba() de train_model.py.
    Stage 2 usa s2_columns, no training_columns (regla 6).
    """
    p_mal = rf_s1.predict_proba(X)[:, _idx_mal_s1]
    p_s2  = rf_s2_cal.predict_proba(X[s2_columns])
    out   = np.zeros((len(X), 3))
    out[:, 2] = p_mal
    out[:, 0] = (1 - p_mal) * p_s2[:, _idx_ben_s2]
    out[:, 1] = (1 - p_mal) * p_s2[:, _idx_inv_s2]
    return out


def predict_alert(data: dict) -> tuple:
    """Predicción jerárquica sobre una alerta individual."""
    if not _load_model():
        raise RuntimeError('Modelo ML no disponible. Verificá los logs para más detalles.')
    X = preprocess_input(data)

    p_mal  = rf_s1.predict_proba(X)[:, _idx_mal_s1]
    is_mal = p_mal >= _t1
    p_inv  = rf_s2_cal.predict_proba(X[s2_columns])[:, _idx_inv_s2]
    is_inv = p_inv >= _t2

    raw_pred   = int(np.where(is_mal, 2, np.where(is_inv, 1, 0))[0])
    prediction = CLASS_LABELS[raw_pred]

    proba = _composite_proba(X)[0]
    probabilities = {
        'benigno'     : round(float(proba[0]), 4),
        'a_investigar': round(float(proba[1]), 4),
        'malicioso'   : round(float(proba[2]), 4),
    }

    return prediction, probabilities


def predict_batch(records: list) -> list:
    """
    Predicción jerárquica sobre un lote de alertas.
    Usa preprocess_batch() para calcular incident features reales por correlation_id.
    Retorna lista de (predicted_class, probabilities) en el mismo orden que records.
    """
    if not _load_model():
        raise RuntimeError('Modelo ML no disponible. Verificá los logs para más detalles.')
    X = preprocess_batch(records)

    p_mal  = rf_s1.predict_proba(X)[:, _idx_mal_s1]
    is_mal = p_mal >= _t1
    p_inv  = rf_s2_cal.predict_proba(X[s2_columns])[:, _idx_inv_s2]
    is_inv = p_inv >= _t2

    raw_preds = np.where(is_mal, 2, np.where(is_inv, 1, 0))
    probas    = _composite_proba(X)

    results = []
    for raw_pred, proba in zip(raw_preds, probas):
        results.append((
            CLASS_LABELS[int(raw_pred)],
            {
                'benigno'     : round(float(proba[0]), 4),
                'a_investigar': round(float(proba[1]), 4),
                'malicioso'   : round(float(proba[2]), 4),
            },
        ))
    return results


# ---------------------------------------------------------------------------
# SHAP Explainability
# ---------------------------------------------------------------------------

_shap_exp_s1 = None
_shap_exp_s2 = None


def _get_shap_explainers():
    global _shap_exp_s1, _shap_exp_s2
    if _shap_exp_s1 is None:
        import shap
        _shap_exp_s1 = shap.TreeExplainer(rf_s1)
        _shap_exp_s2 = shap.TreeExplainer(rf_s2_cal)
    return _shap_exp_s1, _shap_exp_s2


def _display_feature_name(name: str) -> str:
    categorical_prefixes = {
        'event_category_': 'Event Category',
        'protocol_': 'Protocol',
        'traffic_type_': 'Traffic Type',
        'mitre_tactic_': 'MITRE Tactic',
        'kill_chain_stage_': 'Kill Chain Stage',
        'ids_ips_alert_': 'IDS/IPS Alert',
        'asset_criticality_': 'Asset Criticality',
        'log_source_': 'Log Source',
        'firewall_action_': 'Firewall Action',
        'severity_': 'Severity',
        'evidence_role_': 'Evidence Role',
        'os_family_': 'OS Family',
    }
    for prefix, label in categorical_prefixes.items():
        if name.startswith(prefix):
            value = name[len(prefix):].replace('_', ' ').title()
            return f'{label} = {value}'
    _named = {
        'severity_num'          : 'Severity Level (0-3)',
        'n_mitre_techniques'    : 'MITRE Techniques Count',
        'anomaly_score'         : 'Anomaly Score',
        'anomaly_x_asset_high'  : 'Anomaly × High Asset',
        'evidence_density'      : 'Evidence Density (per log source)',
        'confirmed_x_evidence'  : 'Confirmed × Evidence Count',
        'failed_login_attempts' : 'Failed Login Attempts',
        'request_rate_per_min'  : 'Request Rate (per min)',
        'has_threat_family'     : 'Known Threat Family',
    }
    if name in _named:
        return _named[name]
    if name.startswith('mitre_t') and len(name) > 7:
        return f'MITRE {name[6:].upper()}'
    return name.replace('_', ' ').title()


def _shap_row(sv, class_idx: int) -> np.ndarray:
    """Normaliza los tres formatos que SHAP puede devolver:
    - list of 2D arrays (nuevo, binario): sv[class_idx][0, :]
    - ndarray 2D (n_samples, n_features): sv[0, :]  — clase positiva implícita
    - ndarray 3D (n_samples, n_features, n_classes): sv[0, :, class_idx]
    """
    if isinstance(sv, list):
        return np.asarray(sv[class_idx])[0, :]
    sv = np.asarray(sv)
    if sv.ndim == 2:
        return sv[0, :]
    return sv[0, :, class_idx]


def _shap_base(expected_value, class_idx: int) -> float:
    ev = np.asarray(expected_value)
    if ev.ndim == 0:
        return float(ev)
    return float(ev.flat[class_idx])


def calculate_shap_values(data: dict, top_n: int = 15) -> dict:
    if not _load_model():
        raise RuntimeError('Modelo ML no disponible. Verificá los logs para más detalles.')
    X = preprocess_input(data)
    exp_s1, exp_s2 = _get_shap_explainers()

    sv_s1  = exp_s1.shap_values(X)
    sv_mal = _shap_row(sv_s1, _idx_mal_s1)
    base_s1 = _shap_base(exp_s1.expected_value, _idx_mal_s1)

    s1_features = sorted(
        [{'name': _display_feature_name(n), 'value': float(v), 'shap': float(s)}
         for n, v, s in zip(training_columns, X.iloc[0].values, sv_mal)],
        key=lambda x: abs(x['shap']),
        reverse=True,
    )[:top_n]

    X_s2   = X[s2_columns]
    sv_s2  = exp_s2.shap_values(X_s2)
    sv_inv = _shap_row(sv_s2, _idx_inv_s2)
    base_s2 = _shap_base(exp_s2.expected_value, _idx_inv_s2)

    s2_features = sorted(
        [{'name': _display_feature_name(n), 'value': float(v), 'shap': float(s)}
         for n, v, s in zip(s2_columns, X_s2.iloc[0].values, sv_inv)],
        key=lambda x: abs(x['shap']),
        reverse=True,
    )[:top_n]

    return {
        's1': {'features': s1_features, 'base_value': base_s1},
        's2': {'features': s2_features, 'base_value': base_s2},
    }


def compute_shap_safe(data: dict):
    """Wrapper seguro — devuelve el dict de SHAP o None si falla. Nunca propaga excepciones."""
    try:
        return calculate_shap_values(data)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Risk score
# ---------------------------------------------------------------------------

_RISK_WEIGHTS = {'benigno': 0.0, 'a_investigar': 0.5, 'malicioso': 1.0}


def calculate_risk_score(probabilities: dict) -> float:
    return round(
        sum(probabilities.get(cls, 0.0) * w for cls, w in _RISK_WEIGHTS.items()),
        4,
    )


# ---------------------------------------------------------------------------
# ModelVersion — versionado del modelo (Track 1)
# ---------------------------------------------------------------------------

def get_active_model_version():
    """Versión del modelo a asociar con las nuevas PredictionLog.

    Hasta que exista un pipeline de reentrenamiento real, todas las
    predicciones nuevas quedan asociadas a la misma versión activa
    (normalmente la 'legacy' que crea la migración 0018_migrate_alert_data
    al migrar datos existentes).

    Auto-reparable a propósito: si la base arrancó vacía (instalación fresca,
    o alguien corrió las migraciones sin datos previos), 0018 no tiene nada
    que migrar y no crea la versión 'legacy' — sin este fallback, la primera
    predicción nueva explota con DoesNotExist. Acá se crea una versión
    placeholder al vuelo la primera vez que hace falta.
    """
    from django.utils import timezone
    from .models import ModelVersion

    version = ModelVersion.objects.filter(is_active=True).first()
    if version is not None:
        return version

    version, _ = ModelVersion.objects.get_or_create(
        version_label='initial',
        defaults={
            'trained_at': timezone.now(),
            'artifact_path': str(MODEL_PATH),
            'is_active': True,
        },
    )
    return version
