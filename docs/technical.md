# Technical Notes

This is the *why* behind the code — decisions, tradeoffs, and gotchas that aren't obvious from reading the source once. For the *what* (system components, data model, deployment), see [architecture.md](architecture.md). For setup, see the [README](../README.md).

## Project layout

```
soc_project/
├── accounts/         # auth, roles, user management, audit log
├── predictor/        # ML pipeline, alerts, reports, background tasks
│   ├── ml/            # trained model artifact (soc_model.pkl)
│   ├── migrations/
│   └── tests/
├── theme/            # Tailwind CSS integration
├── templates/
├── conftest.py       # shared pytest fixtures (roles, alerts, static storage override)
└── pytest.ini
```

## Key decisions

**Splitting the `Alert` god-table (schema normalization).**
The original `Alert` model mixed ML input fields, prediction output, investigation state, analyst priority, ML evaluation, and incident closure in one 45+ column table. It was split into `Alert` (ML core data) + `AlertWorkflow` (investigation/priority/evaluation, 1:1) + `Incident` (a real entity instead of an `is_incident` boolean) + `ModelVersion` + `PredictionLog` + `Dataset`. Migrated with a three-step data migration (`CreateModel` → `RunPython` to backfill → `RemoveField`, kept as separate migrations on purpose so a failed backfill can be retried without having already dropped the old columns). See [architecture.md](architecture.md#data-model) for the schema and the deviations from the original DDL.

**Background alert ingestion via `django-q2`, not Celery.**
The deployment budget (Azure App Service, student plan) has no room for a managed Redis instance, which Celery needs for its broker. `django-q2` supports an ORM-backed broker — the task queue lives in a Postgres table, no extra infrastructure. The tradeoff: the worker (`qcluster`) isn't independently scalable and runs backgrounded in the same container as gunicorn (see [deployment topology](architecture.md#deployment-topology)).

*Testing gotcha:* `django_q.conf.Conf.SYNC` is read from `settings.Q_CLUSTER` **once, at module import time** — overriding `settings.Q_CLUSTER['sync'] = True` at runtime (e.g. via pytest-django's `settings` fixture) has no effect, because `Conf` was already imported and cached before the test ran. To make `async_task()` run synchronously in a test, monkeypatch the class attribute directly: `monkeypatch.setattr(Conf, 'SYNC', True)` (see the `q_cluster_sync` fixture in `conftest.py`).

**Lazy SHAP computation.**
Computing SHAP values for an entire ingested batch added significant latency and was mostly wasted work — in practice an analyst opens the explainability view for a handful of alerts, not all of them. SHAP is computed on first view of an alert's detail page and cached on `PredictionLog.shap_values` from then on.

**`bulk_create(..., batch_size=500)` everywhere alerts are created.**
Row-by-row inserts (or an unbounded single `bulk_create`) don't scale for realistic SOC ingestion volumes on either SQLite or PostgreSQL.

**Short polling (2-3s) instead of WebSockets, for both dataset status and the planned notification bell.**
Django Channels' only production-supported channel layer is Redis-backed — not in budget. The alternative (a single worker process + `InMemoryChannelLayer`) isn't a real production pattern. Polling needs zero infrastructure changes and the latency is imperceptible for the use case.

**Authorization: two different failure modes for "you don't have permission" — know which one a view uses before relying on it.**
Views wrapped in `@role_required(...)` (e.g. `alert_escalate_view`, `incident_resolve_view`, `alert_set_priority_view`) redirect (`302` to `dashboard`) when the role doesn't match. Views with an inline role check in the body (e.g. `alert_evaluate_view`, or the target-role check inside `alert_assign_view`) return `403` JSON instead. This is inconsistent by history, not by design — worth checking explicitly if you're writing a client against these endpoints, or a test that asserts on status code.

## Dependencies and why

| Package | Why |
|---|---|
| `djangorestframework` + `djangorestframework-simplejwt` | REST API surface for external integrations (JWT, independent from the session-based web UI) — the future Splunk worker authenticates through this |
| `lightgbm` + `shap` | The two-stage classifier and its explainability layer |
| `django-q2` + `django-picklefield` | Background task queue with an ORM broker (no Redis) |
| `pytest-django` + `pytest-cov` | Test runner and coverage reporting — chosen over bare `TestCase`/`APITestCase` specifically because QA needed a coverage report as evidence |
| `whitenoise` | Serves static files directly from gunicorn on Azure App Service, no separate static host |
| `reportlab`, `openpyxl`, `matplotlib` | PDF/Excel report export and embedded charts (`report_export_pdf_view`) |

## MITRE ATT&CK technique metadata (`sync_mitre_attack`)

`predictor/management/commands/sync_mitre_attack.py` is a **dev-time-only, offline** command — never called from the request path or from any always-on process. It reads the `mitre_tNNNN` columns from the already-trained `training_columns` (in `soc_model.pkl`), downloads MITRE's official STIX bundle (`github.com/mitre/cti`), and caches name/description/URL for just those technique IDs into `predictor/data/mitre_technique_metadata.json` — committed to git, read at runtime with zero network calls (`predictor/mitre_metadata.py::resolve_techniques()`, used by `alert_shap_view` to render technique chips instead of raw codes). It runs automatically as the last step of `train_model.py` (see [docs/model.md](model.md#retraining)) — never before training, since it depends on the *new* `training_columns` that training just produced.

*Environment gotcha:* on machines behind a TLS-inspecting proxy/antivirus, Python's own `ssl` module can fail to verify GitHub's certificate (`SSLCertVerificationError`) even though `curl`/browsers work fine (they trust the OS certificate store; Python's `ssl`/`certifi` don't automatically). The command catches `urllib.error.URLError` and falls back to shelling out to `curl`, which sidesteps the issue entirely and works identically on the Linux Azure App Service target.

## Testing

110 tests, `pytest-django`. Coverage is intentionally uneven — the test priorities were driven by mapping directly against the QA team's 30 user-story acceptance checklist (see [testing-backlog.md](testing-backlog.md)), not by chasing 100% line coverage everywhere.

```bash
cd soc_project
DB_HOST= pytest --cov=predictor --cov=accounts --cov-report=term-missing
```

(`DB_HOST=` forces SQLite so the suite never touches a real Postgres instance; on PowerShell use `$env:DB_HOST=""` first.)

Known test-environment-only gotcha: `whitenoise`'s `CompressedManifestStaticFilesStorage` (the production static files backend) requires a `collectstatic` manifest that doesn't exist under `pytest` — any test rendering a template with `{% static %}` would otherwise fail with `ValueError`. An `autouse` fixture in `conftest.py` swaps it for a manifest-less backend during tests only.
