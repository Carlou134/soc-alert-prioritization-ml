import pandas as pd
import numpy as np
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier

CSV_PATH = "soc_alerts_dataset_10000_realista.csv"

df = pd.read_csv(CSV_PATH)

df_clean = df.copy()
df_clean.columns = (
    df_clean.columns
    .str.strip()
    .str.lower()
    .str.replace(" ", "_")
)

df_clean = df_clean.drop_duplicates()

for col in df_clean.select_dtypes(include="object").columns:
    df_clean[col] = df_clean[col].astype(str).str.strip()

df_clean["timestamp"] = pd.to_datetime(df_clean["timestamp"], errors="coerce")
df_clean = df_clean.dropna(subset=["timestamp"])

df_clean["hour"] = df_clean["timestamp"].dt.hour
df_clean["day"] = df_clean["timestamp"].dt.day
df_clean["month"] = df_clean["timestamp"].dt.month
df_clean["day_of_week"] = df_clean["timestamp"].dt.dayofweek

for col in [
    "severity", "class_label", "priority_level", "protocol",
    "traffic_type", "event_category", "attack_type",
    "mitre_tactic", "kill_chain_stage", "log_source",
    "ids_ips_alert", "firewall_action", "malware_indicator",
    "asset_criticality", "host_affected"
]:
    if col in df_clean.columns:
        df_clean[col] = df_clean[col].astype(str).str.lower().str.strip()

valid_class = ["benigno", "a_investigar", "malicioso"]
valid_priority = ["baja", "media", "alta", "critica"]
valid_severity = ["low", "medium", "high", "critical"]

df_clean = df_clean[df_clean["class_label"].isin(valid_class)]
df_clean = df_clean[df_clean["priority_level"].isin(valid_priority)]
df_clean = df_clean[df_clean["severity"].isin(valid_severity)]

num_cols = df_clean.select_dtypes(include=[np.number]).columns
cat_cols = df_clean.select_dtypes(include=["object"]).columns

for col in num_cols:
    df_clean[col] = df_clean[col].fillna(df_clean[col].median())

for col in cat_cols:
    df_clean[col] = df_clean[col].fillna("unknown")

df_clean = df_clean[(df_clean["risk_score"] >= 0) & (df_clean["risk_score"] <= 100)]

if "anomaly_score" in df_clean.columns:
    df_clean = df_clean[(df_clean["anomaly_score"] >= 0) & (df_clean["anomaly_score"] <= 1)]

if "failed_login_attempts" in df_clean.columns:
    df_clean = df_clean[df_clean["failed_login_attempts"] >= 0]

if "request_rate_per_min" in df_clean.columns:
    df_clean = df_clean[df_clean["request_rate_per_min"] >= 0]

drop_cols = [
    "alert_id",
    "timestamp",
    "class_label",
    "risk_score",
    "priority_level",
    "attack_type",
    "attack_signature",
    "ids_ips_alert",
    "malware_indicator",
    "severity"
]

drop_cols = [c for c in drop_cols if c in df_clean.columns]

X = df_clean.drop(columns=drop_cols)
y = df_clean["class_label"]

X_encoded = pd.get_dummies(X, drop_first=True)

X_train, X_test, y_train, y_test = train_test_split(
    X_encoded, y, test_size=0.2, random_state=42, stratify=y
)

model = RandomForestClassifier(
    n_estimators=200,
    max_depth=15,
    min_samples_split=5,
    min_samples_leaf=2,
    random_state=42,
    class_weight="balanced",
    n_jobs=-1
)

model.fit(X_train, y_train)

artifact = {
    "model": model,
    "training_columns": X_encoded.columns.tolist(),
    "target_classes": model.classes_.tolist()
}

joblib.dump(artifact, "soc_model.pkl")

print("Modelo guardado como soc_model.pkl")