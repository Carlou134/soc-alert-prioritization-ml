# API Reference

REST API for programmatic/external clients — JWT-authenticated, independent from the session-based web UI (see [architecture.md](architecture.md#authentication)). This is the surface the planned Splunk ingestion worker will consume.

Base URL in production: `https://<your-azure-app>.azurewebsites.net`. Locally: `http://127.0.0.1:8000`.

All authenticated endpoints expect:
```
Authorization: Bearer <access_token>
```

## ⚠️ Known gap — read before integrating

**`POST /api/predict/` and `POST /api/upload-alerts/` do not persist anything.** They score the payload and return the prediction in the response body, but never create an `Alert` or a `Dataset`. If an external system (e.g. the planned Splunk worker) calls these endpoints today, the alert gets classified but never shows up in the dashboard or the analyst queue — see [architecture.md](architecture.md#planned-extension-soc-connector). This is a known, tracked gap, not an oversight you need to rediscover.

---

## Auth

### `POST /api/token/`
Obtain a JWT pair (`djangorestframework-simplejwt`).

**Body**
```json
{ "username": "admin_soc", "password": "..." }
```
**200**
```json
{ "access": "<jwt>", "refresh": "<jwt>" }
```
- Access token lifetime: 60 minutes. Refresh token lifetime: 7 days, rotated on use, old refresh tokens blacklisted after rotation.

### `POST /api/token/refresh/`
**Body:** `{ "refresh": "<jwt>" }` → **200:** `{ "access": "<jwt>" }`

### `POST /api/accounts/register/`
No auth required.

**Body**
```json
{ "username": "new_user", "email": "new_user@example.com", "password": "..." }
```
**201**
```json
{
  "message": "Usuario registrado correctamente.",
  "user": { "id": 12, "username": "new_user", "email": "new_user@example.com" },
  "refresh": "<jwt>",
  "access": "<jwt>"
}
```
**400** — missing fields, duplicate `username`, or duplicate `email`.

> Note: a user created this way gets a `UserProfile` via signal with the default role (`analyst_n1`) — there's no `role` field in this payload. Role assignment is an admin-only web action (`accounts.views.user_create_view`), not exposed on this API endpoint.

### `POST /api/accounts/login/`
No auth required. **Body:** `{ "username": "...", "password": "..." }`
**200:** same shape as register. **400:** missing fields. **401:** invalid credentials.

### `POST /api/accounts/logout/`
Auth required. **Body:** `{ "refresh": "<jwt>" }` → **200:** `{ "message": "Sesión cerrada correctamente." }` — blacklists the refresh token (it can no longer be used at `/api/token/refresh/`). **400:** missing or already-invalid refresh token.

---

## Prediction

### `POST /api/predict/`
Auth required. Scores a single alert. Does **not** persist it (see gap above).

**Body** (`PredictionRequestSerializer`)

| Field | Required | Notes |
|---|---|---|
| `event_category`, `protocol`, `traffic_type`, `mitre_tactic`, `kill_chain_stage`, `severity`, `ids_ips_alert`, `asset_criticality`, `log_source`, `firewall_action` | ✅ | free-text, normalized server-side (see `predictor/utils.py::normalize_input`) |
| `failed_login_attempts` | ✅ | integer ≥ 0 |
| `request_rate_per_min` | ✅ | float ≥ 0 |
| `has_threat_family` | optional | 0 or 1, default 0 |
| `evidence_role`, `os_family`, `correlation_id` | optional | default `"unknown"` |
| `mitre_techniques` | optional | `;`-separated, e.g. `"T1110;T1078.004"`, default `""` |

```json
{
  "event_category": "intrusion_attempt",
  "protocol": "tcp",
  "traffic_type": "https",
  "mitre_tactic": "command and control",
  "kill_chain_stage": "exfiltration",
  "severity": "critical",
  "ids_ips_alert": "confirmed malicious indicator",
  "asset_criticality": "high",
  "log_source": "edr",
  "firewall_action": "blocked",
  "failed_login_attempts": 25,
  "request_rate_per_min": 500.0,
  "correlation_id": "INC-4471"
}
```

**200**
```json
{
  "message": "Predicción realizada correctamente.",
  "predicted_class": "malicioso",
  "probabilities": { "benigno": 0.0512, "a_investigar": 0.1023, "malicioso": 0.8465 },
  "source": "api"
}
```
**400** — any required field missing (`{"missing_fields": [...]}`), wrapped in DRF's standard validation error shape.

### `POST /api/upload-alerts/`
Auth required, `multipart/form-data`, field name `file` (`.json` or `.csv`, max **10 MB**). Batch-scores every record; does **not** persist anything (see gap above). Validates each record independently — a batch with some invalid rows still processes the valid ones.

**200**
```json
{
  "success": true,
  "message": "3 alerta(s) procesada(s) correctamente.",
  "file": "alerts.json",
  "total_records": 4,
  "processed": 3,
  "failed": 1,
  "results": [
    { "record": 1, "predicted_class": "benigno" },
    { "record": 2, "predicted_class": "a_investigar" },
    { "record": 4, "predicted_class": "malicioso" }
  ],
  "errors": [
    { "record": 3, "errors": { "missing_fields": ["severity"] } }
  ]
}
```
**400** — no file, empty file, unsupported extension, or no records in the file.

> ⚠️ **Known inconsistency:** the enforced size limit is 10 MB (`MAX_FILE_SIZE`), but the error message on an oversized file says *"El archivo supera el límite de 5 MB."* — the limit itself is correct, only the message text is stale. Don't build a client that parses that number out of the message.

---

## What this API is *not*

There is no endpoint here for the alert lifecycle actions (`alert_set_status`, `alert_evaluate`, `alert_escalate`, `incident_resolve`, priority, assignment) — those only exist as session-authenticated Django views under `/alerts/...` and `/incidents/...`, not on `/api/...`. This API's current surface is auth + scoring only.
