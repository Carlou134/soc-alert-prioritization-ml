# Dataset

Describes the training data behind the model in [model.md](model.md): `soc_project/dataset_soc_alertas_train.csv`. All numbers on this page were pulled directly from the file, not estimated.

## Size and provenance

- **33,000 rows, 83 raw columns**, 1 exact duplicate row (32,999 after dedup).
- `train_model.py`'s demo/reporting section labels rows by `correlation_id` (`>= 700,001` → `"Canvia"`, otherwise `"Microsoft"`), implying the dataset schema was designed to eventually blend alerts from more than one SOC source. **In the current file, every row falls in the `"Microsoft"` range** — verified directly (`0` rows with `correlation_id >= 700,001`). If a second, real-data source (e.g. an actual Canvia export) gets merged in later, this split logic already exists in the training script — but as of today the training data is single-source.
- **Zero missing values** in any column.

## Class balance (target: `label`)

| Class | Count | % |
|---|---|---|
| `benigno` (0) | 15,000 | 45.5% |
| `a_investigar` (1) | 9,000 | 27.3% |
| `malicioso` (2) | 9,000 | 27.3% |

Moderately imbalanced toward benign — handled via `class_weight` in both model stages (see [model.md](model.md#hyperparameters-as-trained-from-train_modelpy)), not via oversampling/undersampling.

## Notable field distributions

- **`severity`**: `unknown` 20,559 (62%) · `medium` 9,497 (29%) · `critical` 2,941 (9%) · `high` **3** rows. There is no `low` tier at all in this dataset — worth knowing before assuming the four-way severity scale is evenly represented anywhere.
- **`protocol`**: TCP 28,498 (86%) vs UDP 4,502 (14%).
- **`ids_ips_alert`**: `unknown` 19,582 · `Suspicious pattern` 8,980 · `Confirmed malicious indicator` 3,399 · `No alert` 1,039.
- **`asset_criticality`**: Low 17,112 · Medium 12,926 · High 2,962.
- **`firewall_action`**: `unknown` 32,843 vs `Blocked` **157** — the vast majority of alerts arrive with no firewall verdict attached at all.
- **`has_threat_family`**: only 452 rows (1.4%) have a known malware family tagged.
- **`event_category`** (top 4 of the observed values): `intrusion_attempt` 14,214 · `suspicious_activity` 5,582 · `data_exfiltration` 3,874 · `command_and_control` 3,650.
- **52 binary MITRE ATT&CK technique columns** (`mitre_t####`) in the raw file — see [model.md](model.md#features) for which ones actually make it into training.

## Fields excluded from training

`label` (the target), `attack_type`, `attack_signature`, `malware_indicator`, `correlation_id`. The first three are display-only fields shown in the UI but not fed to the model; `correlation_id` isn't used as a row-level feature directly — it's the grouping key for the `incident_*` aggregated features instead (see [model.md](model.md#features)), so feeding it in raw would just leak an identifier with no generalizable signal.

## Cleaning pipeline (`train_model.py`)

1. Strip + lowercase column names (`" Column Name "` → `column_name`).
2. Drop exact duplicate rows.
3. Strip and lowercase categorical values across all `object` columns.
4. Fill numeric nulls with the column median, categorical nulls with `"unknown"` — a no-op on this specific file today since there are no nulls, but the pipeline is defensive against future data that does have gaps.
5. Drop rows with negative `failed_login_attempts` or `request_rate_per_min` (invalid by definition).

This is conceptually — not code-path — the same philosophy as `predictor/pipeline.py::clean_records()`, which runs the equivalent cleaning at inference time for analyst-uploaded alert batches.

## Where it's used

- `train_model.py` reads it directly to produce `predictor/ml/soc_model.pkl`.
- It ships in the repo so a fresh clone can train the model itself (`python manage.py migrate` auto-triggers training on first run if the `.pkl` is missing) without needing external data access — see the [README](../README.md).
