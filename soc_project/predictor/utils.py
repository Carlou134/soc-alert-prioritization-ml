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

# Campos que el modelo usa para predecir (los que quedaron en X tras el entrenamiento)
# attack_type, attack_signature, ids_ips_alert, malware_indicator, severity
# fueron descartados en train_model.py (drop_cols). El modelo usa los restantes
# más las features temporales derivadas del timestamp.
MODEL_FIELDS = [
    'protocol',
    'traffic_type',
    'event_category',
    'mitre_tactic',
    'kill_chain_stage',
    'log_source',
    'firewall_action',
    'asset_criticality',
    'failed_login_attempts',
    'request_rate_per_min',
]


def normalize_input(data: dict) -> dict:
    normalized = {}
    for field in MODEL_FIELDS:
        value = data.get(field)
        if isinstance(value, str):
            value = value.strip().lower()
        normalized[field] = value
    return normalized


def preprocess_input(data: dict) -> pd.DataFrame:
    clean_data = normalize_input(data)
    df = pd.DataFrame([clean_data])

    for col in df.select_dtypes(include='object').columns:
        df[col] = df[col].astype(str).str.strip().str.lower()

    df_encoded = pd.get_dummies(df, drop_first=True)
    df_encoded = df_encoded.reindex(columns=training_columns, fill_value=0)

    return df_encoded


def predict_alert(data: dict):
    X = preprocess_input(data)
    prediction = model.predict(X)[0]

    probabilities = {}
    if hasattr(model, 'predict_proba'):
        probs = model.predict_proba(X)[0]
        for cls, prob in zip(model.classes_, probs):
            probabilities[cls] = float(prob)

    return prediction, probabilities


def extract_valid_fields(data: dict) -> dict:
    return {field: data.get(field) for field in EXPECTED_FIELDS}
