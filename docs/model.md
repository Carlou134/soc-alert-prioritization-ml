# Model

This describes the ML classifier that scores every alert: architecture, features, real evaluation metrics against a held-out test set, and how explainability (SHAP) is produced. Training code: `soc_project/train_model.py`. Inference code: `soc_project/predictor/utils.py`. Dataset: [dataset.md](dataset.md).

## Why a two-stage hierarchical classifier, not a single 3-class model

The target has three classes — `benigno` (0), `a_investigar` (1), `malicioso` (2) — but they aren't symmetric in cost: missing a real attack (a false negative on `malicioso`) is far more expensive for a SOC than an analyst spending a minute dismissing a false alarm. A single multiclass model treats all misclassifications the same. Instead:

- **Stage 1** — `RandomForestClassifier`, binary: is this `malicioso` or not. Trained with `class_weight={0: 1, 1: 2}` (the malicious class is weighted 2×), explicitly biasing the model toward **recall** on malicious alerts over precision.
- **Stage 2** — `LGBMClassifier` (LightGBM), only trained on and applied to alerts Stage 1 did **not** flag as malicious: distinguishes `a_investigar` from `benigno`.

An alert is only ever scored by Stage 2 if Stage 1 didn't already flag it malicious — the two models are not independent voters, they're a pipeline.

## Hyperparameters (as trained, from `train_model.py`)

| | Stage 1 (RandomForest) | Stage 2 (LightGBM) |
|---|---|---|
| Estimators | 500 trees | 700 |
| Depth / leaves | `max_depth=20` | `num_leaves=63` |
| Learning rate | — | 0.05 |
| `class_weight` | `{benigno+investigar: 1, malicioso: 2}` | `{benigno: 1.5, investigar: 1}` |
| `min_samples_split` / `min_samples_leaf` | 5 / 1 | — |
| `max_features` | `sqrt` | — |
| `random_state` | 42 (both stages, and the train/test split) |
| Decision threshold | `t1 = 0.5` (P(malicioso) ≥ t1) | `t2 = 0.5` (P(a_investigar) ≥ t2, calibrated) |

Stage 2 is trained twice: once on the full feature set purely to rank feature importances, then retrained on only the features with importance > 0.003 (**102 → 63 features**) — a pruning step, not a separate model.

## Features

Raw categorical fields (`event_category`, `protocol`, `severity`, `mitre_tactic`, etc.) are one-hot encoded. Engineered features on top of that:

- **`severity_num`** — ordinal encoding (`unknown=0, medium=1, high=2, critical=3`), since severity has a real order that one-hot throws away.
- **MITRE ATT&CK technique flags** — the dataset has 52 raw binary `mitre_t####` columns; only techniques present in **≥ 200 rows (~0.67%)** are kept as training features, to avoid near-empty binary columns the model can't learn anything from.
- **`n_mitre_techniques`** — count of active technique flags per alert (complexity signal).
- **`anomaly_score`** — computed once per alert (not learned), a weighted rule: `0.40×(confirmed malicious) + 0.20×(suspicious pattern) + 0.25×(severity=high) + 0.10×(severity=medium) + 0.05×(firewall blocked)`, capped at 1.0. This same formula lives in `predictor/utils.py::_compute_anomaly_score` and is re-applied identically at inference time.
- **`incident_*` aggregates** — evidence count, max/mean/std of `anomaly_score`, category/log-source/protocol diversity, all aggregated **per `correlation_id`** (i.e. per real-world incident, not per row). At batch-inference time (`predict_batch`), these are computed from the actual batch; at single-alert inference (`predict_alert`), conservative single-alert defaults are used instead (see `preprocess_input` vs `preprocess_batch` in `predictor/utils.py`).
- **Cross features** — `anomaly_x_asset_high`, `evidence_density` (`evidence_count / (log_source_count + 1)`), `confirmed_x_evidence`, `anomaly_z_score`, `anomaly_vs_max` — all derived from `anomaly_score` × the `incident_*` aggregates above.

## Evaluation

**Verified against the actual production artifact** (`predictor/ml/soc_model.pkl`), evaluated on the same held-out 20% stratified split the training script uses (`random_state=42` → deterministic, reproducible) — not self-reported numbers copied from a training log.

- Test set: **6,600 alerts** (of 32,999 after deduplication), stratified: 3,000 `benigno` / 1,800 `a_investigar` / 1,800 `malicioso`.
- **Accuracy: 0.8291** · **F1 macro: 0.8316** · **F1 weighted: 0.8271**
- Stage 1 out-of-bag score (train-time internal estimate): **0.9144**

| Class | Precision | Recall | F1 |
|---|---|---|---|
| Benigno | 0.8282 | 0.7873 | 0.8072 |
| A investigar | 0.9229 | 0.7383 | 0.8204 |
| **Malicioso** | 0.7717 | **0.9894** | 0.8671 |

Confusion matrix (rows = true, columns = predicted, order `[benigno, a_investigar, malicioso]`):

```
              pred_benigno  pred_investigar  pred_malicioso
true_benigno          2362              111             527
true_investigar         471             1329               0
true_malicioso            19                0            1781
```

**Reading this correctly for a SOC tool**: Stage 1 misses only **19 of 1,800** real malicious alerts (98.9% recall) — that's the number that matters most for a triage system. The cost is precision: **527 benign alerts get escalated as malicious** (false positives an analyst has to dismiss). This is the direct, intended consequence of `class_weight={0:1, 1:2}` on Stage 1 — the model was deliberately tuned to rarely miss a real attack, accepting more false alarms in exchange. Whether that tradeoff is correctly calibrated for this specific SOC's alert volume is worth stating explicitly in a thesis defense, not left implicit.

No `a_investigar` alert is ever predicted `malicioso` or vice versa in this run — structurally guaranteed by the pipeline (Stage 2 never runs on anything Stage 1 already flagged malicious), not a coincidence of this particular split.

## Top features (combined importance, both stages, normalized)

| Rank | Feature | Combined importance |
|---|---|---|
| 1 | `request_rate_per_min` | 0.294 |
| 2 | `incident_evidence_count` | 0.134 |
| 3 | `severity_unknown` | 0.133 |
| 4 | `anomaly_score` | 0.121 |
| 5 | `evidence_density` | 0.120 |
| 6 | `severity_num` | 0.114 |
| 7 | `anomaly_vs_max` | 0.103 |
| 8 | `incident_mean_anomaly` | 0.099 |
| 9 | `incident_mitre_total` | 0.093 |
| 10 | `failed_login_attempts` | 0.078 |

Pre-generated plots (confusion matrix, feature importance bar chart, ROC curves) are saved by `train_model.py` to `soc_project/reports/figures/`.

## Explainability (SHAP)

`predictor/utils.py::calculate_shap_values` builds a `shap.TreeExplainer` for each stage (built lazily, cached in module-level globals — not per request) and returns the top-15 features by `|SHAP value|` for each stage, with the feature's raw value and its SHAP contribution. This is computed **once per alert, on first view**, not for the whole ingested batch — see [technical.md](technical.md#key-decisions) for why.

## Model versioning and the feedback loop

Every prediction is stored as a `PredictionLog` row tied to a `ModelVersion` (`version_label`, `trained_at`, `metrics` JSON, `is_active`). `get_active_model_version()` self-heals — if no version is marked active (e.g. a fresh install), it creates an `'initial'` placeholder rather than raising `DoesNotExist`. This is what makes a future feedback loop possible: an alert can have several `PredictionLog` rows over time (one per model version that ever scored it), which can eventually be compared against the `root_cause` an N3 analyst logs when closing the `Incident` it was escalated into.

## Retraining

```bash
cd soc_project
python train_model.py
```

Regenerates `predictor/ml/soc_model.pkl` and the figures in `reports/figures/`. `python manage.py migrate` also auto-triggers a training run if `soc_model.pkl` doesn't exist yet (first-time setup) — see the [README](../README.md).
