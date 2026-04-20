from pathlib import Path
import joblib
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / 'ml' / 'soc_model.pkl'

artifact = joblib.load(MODEL_PATH)
model = artifact['model']
training_columns = artifact['training_columns']

# Campos que el analista envía en cada alerta (validados por el serializer)
EXPECTED_FIELDS = [
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
]

# Campos que el modelo usa para predecir.
# Origen: train_model.py línea 141-143:
#   cols_excluir = ["label", "attack_type", "attack_signature", "malware_indicator"]
#   X = df_clean.drop(columns=cols_excluir, errors="ignore")
# → attack_type, attack_signature y malware_indicator fueron excluidos del entrenamiento.
# → ids_ips_alert y severity SÍ fueron incluidos en X (no están en cols_excluir).
MODEL_FIELDS = [
    'event_category',
    'protocol',
    'traffic_type',
    'mitre_tactic',
    'kill_chain_stage',
    'failed_login_attempts',
    'request_rate_per_min',
    'ids_ips_alert',
    'asset_criticality',
    'log_source',
    'firewall_action',
    'severity',
]

# ---------------------------------------------------------------------------
# Mapeos de vocabulario: traducen valores del SOC real al esquema de entrenamiento
# ---------------------------------------------------------------------------

# El modelo fue entrenado con: unknown (74%), medium (26%), critical (0.04%)
# high y low no existen en el dataset de entrenamiento → se mapean a unknown
MAP_SEVERITY = {
    'critical'     : 'critical',
    'high'         : 'unknown',
    'medium'       : 'medium',
    'low'          : 'unknown',
    'informational': 'unknown',
    'unknown'      : 'unknown',
    # Wazuh numérico
    '15': 'critical', '12': 'critical',
    '10': 'medium',   '7' : 'medium',
    '3' : 'unknown',  '1' : 'unknown',
}

MAP_EVENT_CATEGORY = {
    'malware'              : 'malware_activity',
    'malware_activity'     : 'malware_activity',
    'intrusion_attempt'    : 'intrusion_attempt',
    'lateral_movement'     : 'lateral_movement',
    'lateral movement'     : 'lateral_movement',
    'reconnaissance'       : 'reconnaissance',
    'command_and_control'  : 'command_and_control',
    'command and control'  : 'command_and_control',
    'data_exfiltration'    : 'data_exfiltration',
    'exfiltration'         : 'data_exfiltration',
    'suspicious_activity'  : 'suspicious_activity',
    'suspicious activity'  : 'suspicious_activity',
    'credential_access'    : 'credential_access',
    'impact'               : 'impact',
    'execution'            : 'execution',
    'persistence'          : 'persistence',
    'privilege_escalation' : 'privilege_escalation',
    'evasion'              : 'evasion',
    'web_attack'           : 'web_attack',
}

# firewall_action: el modelo solo vio allowed, blocked, monitored, unknown
MAP_FIREWALL = {
    'allow'     : 'allowed',
    'allowed'   : 'allowed',
    'deny'      : 'blocked',
    'denied'    : 'blocked',
    'block'     : 'blocked',
    'blocked'   : 'blocked',
    'quarantine': 'blocked',
    'alert'     : 'monitored',
    'monitor'   : 'monitored',
    'monitored' : 'monitored',
    'unknown'   : 'unknown',
}

# ids_ips_alert: el SOC real envía yes/no; el modelo conoce los valores textuales
MAP_IDS_ALERT = {
    'yes'                          : 'suspicious pattern',
    'no'                           : 'no alert',
    'suspicious pattern'           : 'suspicious pattern',
    'no alert'                     : 'no alert',
    'confirmed malicious indicator': 'confirmed malicious indicator',
    'behavior anomaly'             : 'suspicious pattern',
    'unknown'                      : 'unknown',
}

MAP_MITRE_TACTIC = {
    'initial access'      : 'initial access',
    'initialaccess'       : 'initial access',
    'lateral movement'    : 'lateral movement',
    'lateralmovement'     : 'lateral movement',
    'command and control' : 'command and control',
    'commandandcontrol'   : 'command and control',
    'credential access'   : 'credential access',
    'credentialaccess'    : 'credential access',
    'execution'           : 'execution',
    'exfiltration'        : 'exfiltration',
    'impact'              : 'impact',
    'reconnaissance'      : 'reconnaissance',
    'discovery'           : 'discovery',
    'persistence'         : 'persistence',
    'privilege escalation': 'privilege escalation',
    'privilegeescalation' : 'privilege escalation',
    'defense evasion'     : 'defense evasion',
    'defenseevasion'      : 'defense evasion',
    'collection'          : 'collection',
    'unknown'             : 'unknown',
}


def normalize_input(data: dict) -> dict:
    """
    Traduce los valores crudos del SOC real al vocabulario que usó el modelo
    durante el entrenamiento, luego retorna solo los MODEL_FIELDS.
    """
    raw = {k: str(v).strip().lower() for k, v in data.items() if v is not None}

    return {
        'event_category'       : MAP_EVENT_CATEGORY.get(
                                     raw.get('event_category', ''), 'other'),
        'protocol'             : raw.get('protocol', 'tcp'),
        'traffic_type'         : raw.get('traffic_type', 'tcp'),
        'mitre_tactic'         : MAP_MITRE_TACTIC.get(
                                     raw.get('mitre_tactic', ''), 'unknown'),
        'kill_chain_stage'     : raw.get('kill_chain_stage', 'unknown'),
        'failed_login_attempts': int(float(raw.get('failed_login_attempts', 0))),
        'request_rate_per_min' : float(raw.get('request_rate_per_min', 0.0)),
        'ids_ips_alert'        : MAP_IDS_ALERT.get(
                                     raw.get('ids_ips_alert', ''), 'unknown'),
        'asset_criticality'    : raw.get('asset_criticality', 'medium'),
        'log_source'           : raw.get('log_source', 'unknown'),
        'firewall_action'      : MAP_FIREWALL.get(
                                     raw.get('firewall_action', ''), 'unknown'),
        'severity'             : MAP_SEVERITY.get(
                                     raw.get('severity', ''), 'unknown'),
    }


def preprocess_input(data: dict) -> pd.DataFrame:
    clean_data = normalize_input(data)
    df = pd.DataFrame([clean_data])

    for col in df.select_dtypes(include=['object', 'str']).columns:
        df[col] = df[col].astype(str).str.strip().str.lower()

    df_encoded = pd.get_dummies(df, drop_first=False)
    df_encoded = df_encoded.reindex(columns=training_columns, fill_value=0)

    return df_encoded


# Mapeo de clases numéricas del modelo a etiquetas legibles.
# El modelo fue entrenado con labels 0, 1, 2 (columna numérica en el CSV).
CLASS_LABELS = {0: 'benigno', 1: 'a_investigar', 2: 'malicioso'}


def predict_alert(data: dict):
    X = preprocess_input(data)
    prediction_raw = model.predict(X)[0]
    prediction = CLASS_LABELS.get(int(prediction_raw), str(prediction_raw))

    probabilities = {}
    if hasattr(model, 'predict_proba'):
        probs = model.predict_proba(X)[0]
        for cls, prob in zip(model.classes_, probs):
            label = CLASS_LABELS.get(int(cls), str(cls))
            probabilities[label] = float(prob)

    return prediction, probabilities


def extract_valid_fields(data: dict) -> dict:
    return {field: data.get(field) for field in EXPECTED_FIELDS}


# Pesos por clase para el cálculo del risk_score (0.0 → 1.0).
# benigno = 0, a_investigar = 0.5, malicioso = 1.0
_RISK_WEIGHTS = {'benigno': 0.0, 'a_investigar': 0.5, 'malicioso': 1.0}


def calculate_risk_score(probabilities: dict) -> float:
    """Devuelve un puntaje de riesgo entre 0.0 y 1.0 basado en las
    probabilidades del modelo. A mayor probabilidad de 'malicioso', mayor score."""
    return round(
        sum(probabilities.get(cls, 0.0) * w for cls, w in _RISK_WEIGHTS.items()),
        4,
    )
