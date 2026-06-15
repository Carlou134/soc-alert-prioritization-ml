# -*- coding: utf-8 -*-
# Modelo final — adaptado para ejecución local en VSCode
# Original: Google Colab

import pandas as pd
import numpy as np
import os

# -- Carga de datos ----------------------------------------------------------

BASE_DIR  = os.path.dirname(os.path.abspath(__file__))
file_path = os.path.join(BASE_DIR, 'dataset_soc_alertas_train.csv')
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

# -- Limpieza de datos --------------------------------------------------------

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

# -- Feature engineering ------------------------------------------------------

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

# -- Preparación de features --------------------------------------------------

cols_excluir = ["label", "attack_type", "attack_signature", "malware_indicator", "correlation_id"]

X = df_clean.drop(columns=cols_excluir, errors="ignore")
y = df_clean["label"]


SEVERITY_ORDINAL = {"unknown": 0, "medium": 1, "high": 2, "critical": 3}
if "severity" in X.columns:
    X = X.copy()
    X["severity_num"] = X["severity"].map(SEVERITY_ORDINAL).fillna(0).astype(int)

X_encoded = pd.get_dummies(X, drop_first=False)

# Filtrar columnas MITRE de baja presencia (>=200 ocurrencias / 30k filas ~ 0.67%)
mitre_cols = [c for c in X_encoded.columns if c.startswith("mitre_t")]
mitre_keep = [c for c in mitre_cols if X_encoded[c].sum() >= 200]
non_mitre  = [c for c in X_encoded.columns if not c.startswith("mitre_t")]
X_encoded  = X_encoded[non_mitre + mitre_keep]
print(f"MITRE features: {len(mitre_cols)} total -> {len(mitre_keep)} retenidas (presencia >=200)")

print("Features:", X_encoded.shape)
print("Target distribution:")
print(y.value_counts())

# -- Feature engineering adicional --------------------------------------------

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, classification_report, f1_score,
                              confusion_matrix, ConfusionMatrixDisplay,
                              roc_curve, auc)
from sklearn.preprocessing import label_binarize
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

if "incident_evidence_count" in X_encoded.columns and "incident_log_source_count" in X_encoded.columns:
    X_encoded["evidence_density"] = (
        X_encoded["incident_evidence_count"] / (X_encoded["incident_log_source_count"] + 1)
    ).astype(float)
    print("Feature cruzada evidence_density creada")

if "incident_has_confirmed" in X_encoded.columns and "incident_evidence_count" in X_encoded.columns:
    X_encoded["confirmed_x_evidence"] = (
        X_encoded["incident_has_confirmed"] * np.log1p(X_encoded["incident_evidence_count"])
    ).astype(float)
    print("Feature cruzada confirmed_x_evidence creada")

# anomaly_z_score: cuánto se desvía el evento del promedio de anomalía de su incidente
if all(c in X_encoded.columns for c in ["anomaly_score", "incident_mean_anomaly", "incident_std_anomaly"]):
    X_encoded["anomaly_z_score"] = (
        (X_encoded["anomaly_score"] - X_encoded["incident_mean_anomaly"]) /
        (X_encoded["incident_std_anomaly"] + 0.001)
    ).astype(float)
    print("Feature anomaly_z_score creada")

# anomaly_vs_max: qué tan cerca está el evento del pico de anomalía del incidente
if all(c in X_encoded.columns for c in ["anomaly_score", "incident_max_anomaly"]):
    X_encoded["anomaly_vs_max"] = (
        X_encoded["anomaly_score"] / (X_encoded["incident_max_anomaly"] + 0.001)
    ).astype(float)
    print("Feature anomaly_vs_max creada")

print("Features finales:", X_encoded.shape)

all_idx = np.arange(len(X_encoded))
train_idx, test_idx = train_test_split(
    all_idx, test_size=0.2, random_state=42, stratify=y
)
X_train = X_encoded.iloc[train_idx]
X_test  = X_encoded.iloc[test_idx]
y_train = y.iloc[train_idx]
y_test  = y.iloc[test_idx]
print("Split: train_test_split estratificado")

print("X_train:", X_train.shape)
print("X_test :", X_test.shape)
print("Distribución train:", y_train.value_counts().to_dict())
print("Distribución test :", y_test.value_counts().to_dict())

# -- Stage 1: Malicioso vs (Benigno + A_Investigar) --------------------------─

y_train_s1 = (y_train == 2).astype(int)
y_test_s1  = (y_test  == 2).astype(int)

rf_s1 = RandomForestClassifier(
    n_estimators=500,
    max_depth=20,
    min_samples_split=5,
    min_samples_leaf=1,
    max_features="sqrt",
    random_state=42,
    class_weight={0: 1, 1: 2},
    oob_score=True,
    n_jobs=-1
)
rf_s1.fit(X_train, y_train_s1)
print(f"\nStage 1 OOB Score: {rf_s1.oob_score_:.4f}")

# -- Stage 2: Benigno vs A_Investigar ----------------------------------------─
# Solo sobre muestras donde Stage 1 no clasifica como Malicioso

mask_s2    = y_train != 2
X_train_s2 = X_train[mask_s2]
y_train_s2 = y_train[mask_s2]

# Feature pruning: primer LightGBM para detectar features de baja importancia
_lgbm_s2_full = LGBMClassifier(
    n_estimators=700, learning_rate=0.05, num_leaves=63,
    class_weight={0: 1.5, 1: 1}, random_state=42, n_jobs=-1, verbose=-1
)
_lgbm_s2_full.fit(X_train_s2, y_train_s2)

_fi_s2 = pd.Series(_lgbm_s2_full.feature_importances_, index=X_encoded.columns)
s2_cols = _fi_s2[_fi_s2 > 0.003].index.tolist()
print(f"Stage 2 feature pruning: {len(X_encoded.columns)} -> {len(s2_cols)} features (importancia > 0.003)")

# LightGBM final con features seleccionadas
lgbm_s2 = LGBMClassifier(
    n_estimators=700, learning_rate=0.05, num_leaves=63,
    class_weight={0: 1.5, 1: 1}, random_state=42, n_jobs=-1, verbose=-1
)
lgbm_s2.fit(X_train_s2[s2_cols], y_train_s2)
print(f"Stage 2 LightGBM entrenado — clases: {lgbm_s2.classes_}")

# Índices de clase — se fijan aquí para no asumir orden en todo el script
idx_mal_s1 = list(rf_s1.classes_).index(1)
idx_inv_s2 = list(lgbm_s2.classes_).index(1) if 1 in lgbm_s2.classes_ else 1
idx_ben_s2 = list(lgbm_s2.classes_).index(0) if 0 in lgbm_s2.classes_ else 0

# -- Predicción jerárquica ----------------------------------------------------─

def predict_hierarchical(X, t1=0.5, t2=0.5):
    """Stage 1 -> Malicioso si P(Malicioso) >= t1. Stage 2 calibrado -> A_Investigar si P >= t2."""
    is_mal = rf_s1.predict_proba(X)[:, idx_mal_s1] >= t1
    is_inv = lgbm_s2.predict_proba(X[s2_cols])[:, idx_inv_s2] >= t2
    return np.where(is_mal, 2, np.where(is_inv, 1, 0))


def composite_proba(X):
    """Probabilidades compuestas: P(clase) = P(Stage1) * P(Stage2_calibrado|no-Malicioso)."""
    p_mal = rf_s1.predict_proba(X)[:, idx_mal_s1]
    p_s2  = lgbm_s2.predict_proba(X[s2_cols])
    out   = np.zeros((len(X), 3))
    out[:, 2] = p_mal
    out[:, 0] = (1 - p_mal) * p_s2[:, idx_ben_s2]
    out[:, 1] = (1 - p_mal) * p_s2[:, idx_inv_s2]
    return out


best_t1, best_t2 = 0.50, 0.50

# -- Reportes visuales ---------------------------------------------------------

REPORTS_DIR = os.path.join(BASE_DIR, "reports", "figures")
os.makedirs(REPORTS_DIR, exist_ok=True)

y_pred = predict_hierarchical(X_test, best_t1, best_t2)

print("\n-- RF Jerárquico (t1=0.5, t2=0.5) --")
print("Accuracy    :", accuracy_score(y_test, y_pred))
print("F1 Macro    :", f1_score(y_test, y_pred, average="macro"))
print("F1 Weighted :", f1_score(y_test, y_pred, average="weighted"))
print(classification_report(y_test, y_pred,
      target_names=["Benigno", "A_Investigar", "Malicioso"]))

cm = confusion_matrix(y_test, y_pred, labels=[0, 1, 2])
ConfusionMatrixDisplay(confusion_matrix=cm,
    display_labels=["0", "1", "2"]
).plot(cmap="Blues", xticks_rotation=45)
plt.title("Matriz de Confusión — RF Jerárquico SOC")
plt.savefig(os.path.join(REPORTS_DIR, "cm_baseline.png"), dpi=150, bbox_inches='tight')
plt.close()

fi_s1 = pd.DataFrame({
    "feature"   : X_encoded.columns,
    "importance": rf_s1.feature_importances_,
}).sort_values("importance", ascending=False)
fi_s2 = pd.DataFrame({
    "feature"   : s2_cols,
    "importance": lgbm_s2.feature_importances_,
}).sort_values("importance", ascending=False)

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
plt.savefig(os.path.join(REPORTS_DIR, "feature_importance.png"), dpi=150, bbox_inches='tight')
plt.close()

y_test_bin     = label_binarize(y_test, classes=[0, 1, 2])
prob_comp_test = composite_proba(X_test)
nombres = ["Benigno", "A_Investigar", "Malicioso"]
colores = ["#1D9E75", "#7F77DD", "#D85A30"]
plt.figure(figsize=(8, 6))
for i, (nombre, color) in enumerate(zip(nombres, colores)):
    fpr, tpr, _ = roc_curve(y_test_bin[:, i], prob_comp_test[:, i])
    plt.plot(fpr, tpr, color=color, lw=2, label=f"{nombre} (AUC = {auc(fpr, tpr):.3f})")
plt.plot([0, 1], [0, 1], "k--", lw=1, label="Aleatorio (AUC = 0.5)")
plt.xlabel("False Positive Rate")
plt.ylabel("True Positive Rate")
plt.title("Curvas ROC — RF Jerárquico SOC")
plt.legend(loc="lower right")
plt.tight_layout()
plt.savefig(os.path.join(REPORTS_DIR, "roc_curves.png"), dpi=150, bbox_inches='tight')
plt.close()

print(f"\nReportes guardados en {REPORTS_DIR}")

# -- Predicción sobre 10 muestras reales del test set (estratificado por severity) ---
# Cubre los 4 niveles reales del dataset: unknown, medium, critical, high.
# Incluye casos Canvia (high) para mostrar patrones del SOC peruano.
# Features tomadas directamente de X_test: sin valores aproximados.

_rng_demo  = np.random.RandomState(42)
_sev_test  = df_clean.iloc[test_idx]["severity"].values   # severidad de cada fila del test

# Índices por severidad dentro del test set
_i_unk  = np.where(_sev_test == "unknown" )[0]
_i_low  = np.where(_sev_test == "low"     )[0]
_i_med  = np.where(_sev_test == "medium"  )[0]
_i_crit = np.where(_sev_test == "critical")[0]
_i_high = np.where(_sev_test == "high"    )[0]  # casi todo Canvia

# 2 unknown + 2 low + 2 medium + 2 critical + 2 high (Canvia)
_parts = [
    _rng_demo.choice(_i_unk,  size=min(2, len(_i_unk)),  replace=False),
    _rng_demo.choice(_i_low,  size=min(2, len(_i_low)),  replace=False),
    _rng_demo.choice(_i_med,  size=min(2, len(_i_med)),  replace=False),
    _rng_demo.choice(_i_crit, size=min(2, len(_i_crit)), replace=False),
    _rng_demo.choice(_i_high, size=min(2, len(_i_high)), replace=False),
]
_sel = np.concatenate([p for p in _parts if len(p) > 0])

_X_demo     = X_test.iloc[_sel]
_preds_demo = predict_hierarchical(_X_demo, best_t1, best_t2)
_probs_demo = composite_proba(_X_demo)
_labels_demo = y_test.values[_sel].tolist()

_pos_demo  = test_idx[_sel]
_meta_demo = df_clean.iloc[_pos_demo][
    ["correlation_id", "event_category", "severity",
     "anomaly_score", "incident_evidence_count"]
].reset_index(drop=True)
_meta_demo["fuente"] = _meta_demo["correlation_id"].apply(
    lambda x: "Canvia" if x >= 700_001 else "Microsoft"
)
_NG_D = {0: "Benigno", 1: "A_Investigar", 2: "Malicioso"}

print("\n-- 10 muestras reales del test set (unknown/medium/critical/high) --")
print(f"{'#':>2}  {'Fuente':<10} {'Categoria':<24} {'Sev':<9} {'Anom':>5} "
      f"{'Evid':>5}  {'Real':<14} {'Predicho':<14} {'Conf':>6}")
print("-" * 100)
_correctas_demo = 0
for i, (pred, prob, real) in enumerate(zip(_preds_demo, _probs_demo, _labels_demo)):
    ok = "OK" if pred == real else "XX"
    if pred == real: _correctas_demo += 1
    m = _meta_demo.iloc[i]
    print(f"{i+1:>2}  {m['fuente']:<10} {m['event_category']:<24} "
          f"{m['severity']:<9} {m['anomaly_score']:>5.2f} {int(m['incident_evidence_count']):>5}  "
          f"{_NG_D[real]:<14} {_NG_D[pred]:<14} "
          f"{max(prob)*100:>5.1f}% {ok}   P:{prob[0]:.2f} I:{prob[1]:.2f} M:{prob[2]:.2f}")

print(f"\nCorrectas: {_correctas_demo}/10 ({_correctas_demo*10:.0f}%)")
print(f"Incorrectas: {10 - _correctas_demo}/10")
print("\nClassification Report:")
print(classification_report(_labels_demo, list(_preds_demo),
      labels=[0, 1, 2], target_names=["Benigno", "A_Investigar", "Malicioso"], zero_division=0))

# -- Exportar modelo ----------------------------------------------------------─
# IMPORTANTE: la app Django necesita actualizar su carga para usar
# model_s1/model_s2 en lugar de model, y llamar a predict_hierarchical.

artifact = {
    "model_s1"         : rf_s1,
    "model_s2"         : lgbm_s2,
    "training_columns" : X_encoded.columns.tolist(),
    "s2_columns"       : s2_cols,
    "target_classes"   : [0, 1, 2],
    "thresholds"       : {"t1": best_t1, "t2": best_t2},
    "stage1_classes"   : rf_s1.classes_.tolist(),
    "stage2_classes"   : lgbm_s2.classes_.tolist(),
    "idx_mal_s1"       : idx_mal_s1,
    "idx_inv_s2"       : idx_inv_s2,
    "idx_ben_s2"       : idx_ben_s2,
}

model_path = os.path.join(BASE_DIR, "predictor", "ml", "soc_model.pkl")
os.makedirs(os.path.dirname(model_path), exist_ok=True)
joblib.dump(artifact, model_path)
print(f"\nModelo guardado en {model_path}")
print(f"Umbrales exportados: t1 (Malicioso)={best_t1}, t2 (A_Investigar)={best_t2}")
