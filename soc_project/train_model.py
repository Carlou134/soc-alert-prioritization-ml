# -*- coding: utf-8 -*-
"""
Modelo final — adaptado para ejecución local en VSCode
Original: Google Colab
"""

import pandas as pd
import numpy as np
import os

# ── Carga de datos ──────────────────────────────────────────────────────────

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
file_path = os.path.join(BASE_DIR, 'train_dataset_final.csv')
df = pd.read_csv(file_path)
print("Dimensiones iniciales:", df.shape)
print(df.head())
print(df.columns.tolist())

print("\nTipos de datos:")
print(df.dtypes)

print("\nValores nulos por columna:")
print(df.isnull().sum())

print("\nDuplicados exactos:", df.duplicated().sum())

print("\nDistribución de label:")
print(df["label"].value_counts(dropna=False))

# ── Limpieza de datos ────────────────────────────────────────────────────────

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

print("Dimensiones luego de limpieza básica:", df_clean.shape)

# ── Feature engineering ──────────────────────────────────────────────────────

cols_clave = [
    "severity",
    "mitre_tactic",
    "attack_type",
    "event_category",
    "label"
]

for col in cols_clave:
    print(f"\n--- {col} ---")
    print(df_clean[col].value_counts(dropna=False).head(20))

for col in [
    "severity", "protocol", "traffic_type", "event_category",
    "attack_type", "mitre_tactic", "kill_chain_stage",
    "log_source", "ids_ips_alert", "firewall_action",
    "malware_indicator", "asset_criticality"
]:
    if col in df_clean.columns:
        df_clean[col] = df_clean[col].astype(str).str.lower().str.strip()

print("Dimensiones luego de validar etiquetas:", df_clean.shape)
print(df_clean["label"].value_counts())

num_cols = df_clean.select_dtypes(include=[np.number]).columns
cat_cols = df_clean.select_dtypes(include=["object"]).columns

for col in num_cols:
    df_clean[col] = df_clean[col].fillna(df_clean[col].median())

for col in cat_cols:
    df_clean[col] = df_clean[col].fillna("unknown")

print(df_clean.isnull().sum().sum(), "valores nulos restantes")

if "failed_login_attempts" in df_clean.columns:
    df_clean = df_clean[df_clean["failed_login_attempts"] >= 0]

if "request_rate_per_min" in df_clean.columns:
    df_clean = df_clean[df_clean["request_rate_per_min"] >= 0]

print("Dimensiones luego de validar rangos:", df_clean.shape)

# ── Preparación de features ──────────────────────────────────────────────────

cols_excluir = ["label", "attack_type", "attack_signature", "malware_indicator"]

X = df_clean.drop(columns=cols_excluir, errors="ignore")
y = df_clean["label"]

X_encoded = pd.get_dummies(X, drop_first=False)

# Filtrar columnas MITRE de baja presencia (≥200 ocurrencias / 30k filas ≈ 0.67%)
mitre_cols = [c for c in X_encoded.columns if c.startswith("mitre_t")]
mitre_keep = [c for c in mitre_cols if X_encoded[c].sum() >= 200]
non_mitre  = [c for c in X_encoded.columns if not c.startswith("mitre_t")]
X_encoded  = X_encoded[non_mitre + mitre_keep]
print(f"MITRE features: {len(mitre_cols)} total → {len(mitre_keep)} retenidas (presencia ≥200)")

print("Features:", X_encoded.shape)
print("Target distribution:")
print(y.value_counts())

# ── Feature engineering adicional ────────────────────────────────────────────

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, classification_report,
                              f1_score, recall_score,
                              confusion_matrix, ConfusionMatrixDisplay,
                              roc_curve, auc)
from sklearn.preprocessing import label_binarize
from sklearn.linear_model import LogisticRegression
from sklearn.dummy import DummyClassifier
from sklearn.tree import DecisionTreeClassifier
from lightgbm import LGBMClassifier
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import joblib

# n_mitre_techniques: cuántas técnicas MITRE tiene el evento (señal de complejidad)
mitre_bin_cols = [c for c in X_encoded.columns if c.startswith("mitre_t")]
X_encoded["n_mitre_techniques"] = X_encoded[mitre_bin_cols].sum(axis=1).astype(int)
print(f"\nn_mitre_techniques: media={X_encoded['n_mitre_techniques'].mean():.2f}, "
      f"max={X_encoded['n_mitre_techniques'].max()}")

# Feature cruzada: anomaly_score × asset_criticality_high
if "anomaly_score" in X_encoded.columns and "asset_criticality_high" in X_encoded.columns:
    X_encoded["anomaly_x_asset_high"] = (
        X_encoded["anomaly_score"] * X_encoded["asset_criticality_high"]
    ).astype(float)
    print("Feature cruzada anomaly_x_asset_high creada")

print("Features finales:", X_encoded.shape)

X_train, X_test, y_train, y_test = train_test_split(
    X_encoded, y, test_size=0.2, random_state=42, stratify=y)

print("X_train:", X_train.shape)
print("X_test :", X_test.shape)

# ── Stage 1: Malicioso vs (Benigno + A_Investigar) ───────────────────────────

y_train_s1 = (y_train == 2).astype(int)
y_test_s1  = (y_test  == 2).astype(int)

rf_s1 = RandomForestClassifier(
    n_estimators=500,
    max_depth=20,
    min_samples_split=5,
    min_samples_leaf=1,
    max_features="sqrt",
    random_state=42,
    class_weight="balanced_subsample",
    oob_score=True,
    n_jobs=-1
)
rf_s1.fit(X_train, y_train_s1)
print(f"\nStage 1 OOB Score: {rf_s1.oob_score_:.4f}")

# ── Stage 2: Benigno vs A_Investigar ─────────────────────────────────────────
# Solo sobre muestras donde Stage 1 no clasifica como Malicioso

mask_s2    = y_train != 2
X_train_s2 = X_train[mask_s2]
y_train_s2 = y_train[mask_s2]    # 0=Benigno, 1=A_Investigar

rf_s2 = RandomForestClassifier(
    n_estimators=500,
    max_depth=15,
    min_samples_split=5,
    min_samples_leaf=2,
    max_features="sqrt",
    random_state=42,
    class_weight="balanced_subsample",
    oob_score=True,
    n_jobs=-1
)
rf_s2.fit(X_train_s2, y_train_s2)
print(f"Stage 2 OOB Score: {rf_s2.oob_score_:.4f}")

# ── Calibración Platt (sigmoid) sobre OOB probs de Stage 2 ───────────────────
# Las probabilidades OOB son out-of-sample para cada árbol → sin leakage.
# LogisticRegression aprende a corregir el sesgo de las probs raw del RF.
oob_s2_raw = rf_s2.oob_decision_function_
_ok         = ~np.isnan(oob_s2_raw).any(axis=1)
_oob_p      = oob_s2_raw[_ok]
_y_oob      = y_train_s2.values[_ok]

platt_s2 = LogisticRegression(max_iter=1000, C=1.0, random_state=42)
platt_s2.fit(_oob_p, _y_oob)
print(f"Stage 2 Platt calibration fitted ({_ok.sum()} muestras OOB)")

class _CalibratedS2:
    """Wrapper: raw RF probs → Platt sigmoid → calibrated probs."""
    def __init__(self, rf, lr):
        self.rf = rf; self.lr = lr
        self.classes_ = lr.classes_
    def predict_proba(self, X):
        return self.lr.predict_proba(self.rf.predict_proba(X))

rf_s2_cal = _CalibratedS2(rf_s2, platt_s2)

# Índices de clase — se fijan aquí para no asumir orden en todo el script
idx_mal_s1 = list(rf_s1.classes_).index(1)
idx_inv_s2 = list(rf_s2_cal.classes_).index(1) if 1 in rf_s2_cal.classes_ else 1
idx_ben_s2 = list(rf_s2_cal.classes_).index(0) if 0 in rf_s2_cal.classes_ else 0

# ── Predicción jerárquica ─────────────────────────────────────────────────────

def predict_hierarchical(X, t1=0.5, t2=0.5):
    """Stage 1 → Malicioso si P(Malicioso) >= t1. Stage 2 calibrado → A_Investigar si P >= t2."""
    is_mal = rf_s1.predict_proba(X)[:, idx_mal_s1] >= t1
    is_inv = rf_s2_cal.predict_proba(X)[:, idx_inv_s2] >= t2
    return np.where(is_mal, 2, np.where(is_inv, 1, 0))


def composite_proba(X):
    """Probabilidades compuestas: P(clase) = P(Stage1) * P(Stage2_calibrado|no-Malicioso)."""
    p_mal = rf_s1.predict_proba(X)[:, idx_mal_s1]
    p_s2  = rf_s2_cal.predict_proba(X)
    out   = np.zeros((len(X), 3))
    out[:, 2] = p_mal
    out[:, 0] = (1 - p_mal) * p_s2[:, idx_ben_s2]
    out[:, 1] = (1 - p_mal) * p_s2[:, idx_inv_s2]
    return out


y_pred_base = predict_hierarchical(X_test)
print("\n── RF Jerárquico — baseline (t1=0.5, t2=0.5) ──")
print("Accuracy:", accuracy_score(y_test, y_pred_base))
print("F1 Macro:", f1_score(y_test, y_pred_base, average="macro"))
print(classification_report(y_test, y_pred_base,
      target_names=["Benigno", "A_Investigar", "Malicioso"]))

cm_base = confusion_matrix(y_test, y_pred_base, labels=[0, 1, 2])
disp_base = ConfusionMatrixDisplay(confusion_matrix=cm_base,
            display_labels=["Benigno", "A_Investigar", "Malicioso"])
disp_base.plot(cmap="Blues", xticks_rotation=45)
plt.title("Matriz de Confusión — RF Jerárquico baseline")
plt.show()

# ── Optimización de umbrales por etapa (OOB, sin data leakage) ───────────────

MIN_RECALL_S1 = 0.85   # Malicioso recall mínimo aceptable para el SOC
MIN_RECALL_S2 = 0.70   # recall mínimo para ambas clases en Stage 2
grid          = np.arange(0.30, 0.71, 0.01)

# Stage 1: maximizar F1 macro con recall(Malicioso) >= MIN_RECALL_S1
oob_s1   = rf_s1.oob_decision_function_
ok_s1    = ~np.isnan(oob_s1).any(axis=1)
oob_s1_c = oob_s1[ok_s1]
y_s1_c   = y_train_s1.values[ok_s1]

best_t1, best_f1_s1 = 0.5, 0.0
for t1 in grid:
    p = (oob_s1_c[:, idx_mal_s1] >= t1).astype(int)
    if recall_score(y_s1_c, p, pos_label=1, zero_division=0) < MIN_RECALL_S1:
        continue
    f = f1_score(y_s1_c, p, average="macro", zero_division=0)
    if f > best_f1_s1:
        best_f1_s1, best_t1 = f, round(float(t1), 2)

# Stage 2: optimizar t2 sobre probabilidades calibradas OOB (sin leakage)
cal_probs_s2 = platt_s2.predict_proba(_oob_p)

best_t2, best_f1_s2 = 0.5, 0.0
for t2 in grid:
    p  = (cal_probs_s2[:, idx_inv_s2] >= t2).astype(int)
    rs = recall_score(_y_oob, p, average=None, zero_division=0)
    f  = f1_score(_y_oob, p, average="macro", zero_division=0)
    if len(rs) >= 2 and min(rs) >= MIN_RECALL_S2 and f > best_f1_s2:
        best_f1_s2, best_t2 = f, round(float(t2), 2)

print(f"\n── Umbrales optimos (OOB) ──")
print(f"t1 (Malicioso, recall>={MIN_RECALL_S1}):    {best_t1}  — F1 Macro OOB Stage 1: {best_f1_s1:.4f}")
print(f"t2 (A_Investigar, recall>={MIN_RECALL_S2}): {best_t2}  — F1 Macro OOB Stage 2: {best_f1_s2:.4f}")

y_pred_opt = predict_hierarchical(X_test, best_t1, best_t2)
print("\n── RF Jerárquico + Umbrales Optimizados (test) ──")
print("Accuracy:", accuracy_score(y_test, y_pred_opt))
print("F1 Macro:", f1_score(y_test, y_pred_opt, average="macro"))
print(classification_report(y_test, y_pred_opt,
      target_names=["Benigno", "A_Investigar", "Malicioso"]))

cm_opt = confusion_matrix(y_test, y_pred_opt, labels=[0, 1, 2])
disp_opt = ConfusionMatrixDisplay(confusion_matrix=cm_opt,
           display_labels=["Benigno", "A_Investigar", "Malicioso"])
disp_opt.plot(cmap="Greens", xticks_rotation=45)
plt.title("Matriz de Confusión — RF Jerárquico + Umbrales")
plt.show()

fp_real      = (y_test == 0).sum()
fp_correctos = ((y_pred_opt == 0) & (y_test == 0)).sum()
fp_escapados = ((y_pred_opt != 0) & (y_test == 0)).sum()
falsa_alarma = ((y_pred_opt == 0) & (y_test != 0)).sum()
print(f"\n── Detección de alertas benignas (FP del SOC) ──")
print(f"Benignas reales en test  : {fp_real}")
print(f"Detectadas correctamente : {fp_correctos} ({fp_correctos/fp_real*100:.1f}%)")
print(f"No detectadas            : {fp_escapados} ({fp_escapados/fp_real*100:.1f}%)")
print(f"Falsas alarmas           : {falsa_alarma}")

# ── Feature importance (ambas etapas) ────────────────────────────────────────

fi_s1 = pd.DataFrame({
    "feature"   : X_encoded.columns,
    "importance": rf_s1.feature_importances_
}).sort_values("importance", ascending=False)

fi_s2 = pd.DataFrame({
    "feature"   : X_encoded.columns,
    "importance": rf_s2.feature_importances_
}).sort_values("importance", ascending=False)

print("\n── Top 15 features — Stage 1 (Malicioso vs resto) ──")
print(fi_s1.head(15).to_string(index=False))
print("\n── Top 15 features — Stage 2 (Benigno vs A_Investigar) ──")
print(fi_s2.head(15).to_string(index=False))

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))
top1 = fi_s1.head(15)
ax1.barh(top1["feature"][::-1], top1["importance"][::-1])
ax1.set_title("Top 15 — Stage 1 (Malicioso vs resto)")
ax1.set_xlabel("Importancia")

top2 = fi_s2.head(15)
ax2.barh(top2["feature"][::-1], top2["importance"][::-1])
ax2.set_title("Top 15 — Stage 2 (Benigno vs A_Investigar)")
ax2.set_xlabel("Importancia")
plt.tight_layout()
plt.show()

# ── Curvas ROC ────────────────────────────────────────────────────────────────

classes  = [0, 1, 2]
nombres  = ["Benigno", "A_Investigar", "Malicioso"]
colores  = ["#1D9E75", "#7F77DD", "#D85A30"]

y_test_bin     = label_binarize(y_test, classes=classes)
prob_comp_test = composite_proba(X_test)

plt.figure(figsize=(8, 6))
for i, (nombre, color) in enumerate(zip(nombres, colores)):
    fpr, tpr, _ = roc_curve(y_test_bin[:, i], prob_comp_test[:, i])
    roc_auc     = auc(fpr, tpr)
    plt.plot(fpr, tpr, color=color, lw=2,
             label=f"{nombre} (AUC = {roc_auc:.3f})")

plt.plot([0,1],[0,1], "k--", lw=1, label="Aleatorio (AUC = 0.5)")
plt.xlabel("False Positive Rate")
plt.ylabel("True Positive Rate")
plt.title("Curvas ROC — RF Jerárquico SOC")
plt.legend(loc="lower right")
plt.tight_layout()
plt.show()

# ── Comparación con modelos baseline ─────────────────────────────────────────

baselines = {
    "Dummy (majority)"  : DummyClassifier(strategy="most_frequent", random_state=42),
    "Árbol de decisión" : DecisionTreeClassifier(max_depth=10, random_state=42),
    "LightGBM"          : LGBMClassifier(
                              n_estimators=500, learning_rate=0.05,
                              num_leaves=63, class_weight="balanced",
                              random_state=42, n_jobs=-1, verbose=-1),
    "RF Jerárquico"     : None,
}

print("\n── Comparación con modelos baseline ──")
print(f"{'Modelo':<22} {'Accuracy':>10} {'F1 Macro':>10} {'F1 Weighted':>12}")
print("-" * 58)

for nombre, modelo in baselines.items():
    if modelo is not None:
        modelo.fit(X_train, y_train)
        pred = modelo.predict(X_test)
    else:
        pred = y_pred_opt
    acc = accuracy_score(y_test, pred)
    f1m = f1_score(y_test, pred, average="macro")
    f1w = f1_score(y_test, pred, average="weighted")
    print(f"{nombre:<22} {acc:>10.4f} {f1m:>10.4f} {f1w:>12.4f}")

# ── Predicción con 10 alertas reales de GUIDE_Test.csv ───────────────────────
# Registros extraídos del test set y transformados con la misma lógica del pipeline.
# Fuente GUIDE_Test.csv: filas 2,5,9,34,7,12,66,13,42,61 (1-indexed desde header)
#
#   #  IncidentGrade     Category            SuspicionLevel  LastVerdict   Label
#   1  BenignPositive    LateralMovement     Suspicious      Suspicious    → Benigno
#   2  FalsePositive     InitialAccess       —               —             → Benigno
#   3  BenignPositive    Impact              —               —             → Benigno
#   4  BenignPositive    CredentialAccess    —               —             → Benigno
#   5  TruePositive      InitialAccess       —               —             → A_Investigar
#   6  TruePositive      InitialAccess       —               —             → A_Investigar
#   7  TruePositive      Impact              —               —             → A_Investigar
#   8  TruePositive      CredentialAccess    Suspicious      Suspicious    → Malicioso
#   9  TruePositive      Malware             Suspicious      Malicious     → Malicioso
#  10  TruePositive      CommandAndControl   Suspicious      Suspicious    → Malicioso

alertas_test = pd.DataFrame([
    # ── Benigno (0) ──────────────────────────────────────────────────────────
    {"event_category":"lateral_movement", "protocol":"tcp",  "traffic_type":"smb",
     "mitre_tactic":"lateral movement",   "kill_chain_stage":"lateral movement",
     "failed_login_attempts":0, "request_rate_per_min":20.0,
     "ids_ips_alert":"suspicious pattern","asset_criticality":"medium",
     "log_source":"siem",  "firewall_action":"unknown","severity":"medium",  "anomaly_score":0.30},

    {"event_category":"intrusion_attempt","protocol":"tcp",  "traffic_type":"ssh",
     "mitre_tactic":"initial access",     "kill_chain_stage":"initial access",
     "failed_login_attempts":0, "request_rate_per_min":20.0,
     "ids_ips_alert":"unknown",           "asset_criticality":"medium",
     "log_source":"edr",   "firewall_action":"unknown","severity":"unknown", "anomaly_score":0.0},

    {"event_category":"impact",           "protocol":"tcp",  "traffic_type":"tcp",
     "mitre_tactic":"impact",             "kill_chain_stage":"impact",
     "failed_login_attempts":0, "request_rate_per_min":20.0,
     "ids_ips_alert":"unknown",           "asset_criticality":"low",
     "log_source":"ips",   "firewall_action":"unknown","severity":"unknown", "anomaly_score":0.0},

    {"event_category":"credential_access","protocol":"tcp",  "traffic_type":"ldap",
     "mitre_tactic":"credential access",  "kill_chain_stage":"credential access",
     "failed_login_attempts":0, "request_rate_per_min":20.0,
     "ids_ips_alert":"unknown",           "asset_criticality":"medium",
     "log_source":"siem",  "firewall_action":"unknown","severity":"unknown", "anomaly_score":0.0},

    # ── A_Investigar (1) ─────────────────────────────────────────────────────
    {"event_category":"intrusion_attempt","protocol":"tcp",  "traffic_type":"ssh",
     "mitre_tactic":"initial access",     "kill_chain_stage":"initial access",
     "failed_login_attempts":0, "request_rate_per_min":20.0,
     "ids_ips_alert":"unknown",           "asset_criticality":"medium",
     "log_source":"edr",   "firewall_action":"unknown","severity":"unknown", "anomaly_score":0.0},

    {"event_category":"intrusion_attempt","protocol":"tcp",  "traffic_type":"ssh",
     "mitre_tactic":"initial access",     "kill_chain_stage":"initial access",
     "failed_login_attempts":0, "request_rate_per_min":20.0,
     "ids_ips_alert":"unknown",           "asset_criticality":"medium",
     "log_source":"ips",   "firewall_action":"unknown","severity":"unknown", "anomaly_score":0.0},

    {"event_category":"impact",           "protocol":"tcp",  "traffic_type":"tcp",
     "mitre_tactic":"impact",             "kill_chain_stage":"impact",
     "failed_login_attempts":0, "request_rate_per_min":20.0,
     "ids_ips_alert":"unknown",           "asset_criticality":"high",
     "log_source":"siem",  "firewall_action":"unknown","severity":"unknown", "anomaly_score":0.0},

    # ── Malicioso (2) ────────────────────────────────────────────────────────
    {"event_category":"credential_access","protocol":"tcp",  "traffic_type":"ldap",
     "mitre_tactic":"credential access",  "kill_chain_stage":"credential access",
     "failed_login_attempts":0, "request_rate_per_min":20.0,
     "ids_ips_alert":"suspicious pattern","asset_criticality":"low",
     "log_source":"siem",  "firewall_action":"unknown","severity":"medium",  "anomaly_score":0.30},

    {"event_category":"malware_activity", "protocol":"tcp",  "traffic_type":"http",
     "mitre_tactic":"execution",          "kill_chain_stage":"exploitation",
     "failed_login_attempts":0, "request_rate_per_min":20.0,
     "ids_ips_alert":"confirmed malicious indicator","asset_criticality":"low",
     "log_source":"waf",   "firewall_action":"unknown","severity":"medium",  "anomaly_score":0.50},

    {"event_category":"command_and_control","protocol":"tcp","traffic_type":"https",
     "mitre_tactic":"command and control","kill_chain_stage":"command & control",
     "failed_login_attempts":0, "request_rate_per_min":20.0,
     "ids_ips_alert":"suspicious pattern","asset_criticality":"low",
     "log_source":"edr",   "firewall_action":"unknown","severity":"medium",  "anomaly_score":0.30},
])

labels_test   = [0, 0, 0, 0, 1, 1, 1, 2, 2, 2]
grades_test   = ["BenignPositive","FalsePositive","BenignPositive","BenignPositive",
                 "TruePositive","TruePositive","TruePositive",
                 "TruePositive","TruePositive","TruePositive"]
_NL = ["Benigno", "A_Investigar", "Malicioso"]
_NG = {0: "Benigno", 1: "A_Investigar", 2: "Malicioso"}

alertas_enc = pd.get_dummies(alertas_test, drop_first=False)
alertas_enc = alertas_enc.reindex(columns=X_encoded.columns, fill_value=0)

_mc_t = [c for c in alertas_enc.columns if c.startswith("mitre_t")]
alertas_enc["n_mitre_techniques"] = alertas_enc[_mc_t].sum(axis=1).astype(int)
if "anomaly_score" in alertas_enc.columns and "asset_criticality_high" in alertas_enc.columns:
    alertas_enc["anomaly_x_asset_high"] = (
        alertas_enc["anomaly_score"] * alertas_enc["asset_criticality_high"]
    ).astype(float)

predicciones   = predict_hierarchical(alertas_enc, best_t1, best_t2)
probabilidades = composite_proba(alertas_enc)

print("\n── Predicción con alertas reales de GUIDE_Test (10 registros) ──")
print(f"{'#':>3}  {'IncidentGrade':<18} {'Real':<14} {'Predicho':<14} {'Conf':>6}    {'B':>5} {'I':>5} {'M':>5}")
print("-" * 78)
correctas = 0
for i, (pred, prob, real, grade) in enumerate(
        zip(predicciones, probabilidades, labels_test, grades_test)):
    ok = "✓" if pred == real else "✗"
    if pred == real: correctas += 1
    print(f"{i+1:>3}  {grade:<18} {_NG[real]:<14} {_NL[pred]:<14} "
          f"{max(prob)*100:>5.1f}% {ok}   {prob[0]:>5.2f} {prob[1]:>5.2f} {prob[2]:>5.2f}")

print(f"\nCorrectas  : {correctas}/10 ({correctas*10:.0f}%)")
print(f"Incorrectas: {10-correctas}/10")
print("\nClassification Report:")
print(classification_report(labels_test, predicciones,
      target_names=["Benigno", "A_Investigar", "Malicioso"], zero_division=0))

# ── Exportar modelo ───────────────────────────────────────────────────────────
# IMPORTANTE: la app Django necesita actualizar su carga para usar
# model_s1/model_s2 en lugar de model, y llamar a predict_hierarchical.

artifact = {
    "model_s1"         : rf_s1,
    "model_s2"         : rf_s2_cal,
    "training_columns" : X_encoded.columns.tolist(),
    "target_classes"   : [0, 1, 2],
    "thresholds"       : {"t1": best_t1, "t2": best_t2},
    "stage1_classes"   : rf_s1.classes_.tolist(),
    "stage2_classes"   : rf_s2_cal.classes_.tolist(),
    "idx_mal_s1"       : idx_mal_s1,
    "idx_inv_s2"       : idx_inv_s2,
    "idx_ben_s2"       : idx_ben_s2,
}

joblib.dump(artifact, "soc_model.pkl")
print("\nModelo guardado como soc_model.pkl")
print(f"Umbrales exportados: t1 (Malicioso)={best_t1}, t2 (A_Investigar)={best_t2}")
