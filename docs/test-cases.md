# Test cases — acceptance criteria ↔ test cases (P20261086)

Maps every acceptance criterion (AC) of the 30 user stories to the QA test case (TC) that covers it, and to the automated test on our side that covers the rest.

**Sources:** `P20261086 - Historias de Usuarios y Criterios de Aceptación v.1.1.xlsx` and `P20261086_Casos_de_Prueba_v.1.1.xlsx`. The Excel files are the source of truth for QA execution; this page is the developer-side reference.

## Coverage

- 6 epics · 30 user stories · **61 AC scenarios** (HU027 has 3).
- 30 TCs · **43 test scenarios** (13 TCs have an A/B variant, 17 are single).
- QA TCs cover 43 of 61 AC scenarios. The remaining 18 — almost all scenario 1 (happy path) — are covered by the automated suite (see [Automated coverage](#automated-coverage)).

| HU | Sc. 1 (happy path) | Sc. 2 (error/alternate) | HU | Sc. 1 | Sc. 2 |
|---|---|---|---|---|---|
| HU001 | TC001-A | TC001-B | HU016 | — | TC016 |
| HU002 | TC002-A | TC002-B | HU017 | — | TC017 |
| HU003 | — | TC003 | HU018 | — | TC018 |
| HU004 | TC004-A | TC004-B | HU019 | — (by risk) | TC019 |
| HU005 | TC005-A | TC005-B | HU020 | — | TC020 |
| HU006 | — | TC006 | HU021 | — | TC021 |
| HU007 | — | TC007 | HU022 | — | TC022 |
| HU008 | TC008-A | TC008-B | HU023 | — | TC023 |
| HU009 | TC009-A | TC009-B | HU024 | — | TC024 |
| HU010 | TC010-A | TC010-B | HU025 | — | TC025 |
| HU011 | TC011-A | TC011-B | HU026 | — | TC026 |
| HU012 | TC012-A | TC012-B | HU027 | — | Sc.2 Excel → TC027-B · Sc.3 PDF → TC027-A |
| HU013 | — | TC013 | HU028 | TC028-A | TC028-B |
| HU014 | TC014-A | TC014-B | HU029 | TC029-A | TC029-B |
| HU015 | — | TC015 | HU030 | — | TC030 |

## Mapping by user story

Each AC follows **Given** (context) · **When** (event) · **Then** (expected result).

### EP01 — System access

#### HU001 — User registration · Role: Administrator · Manual · High
| Sc. | Acceptance criterion | TC |
|---|---|---|
| 1 · Successful registration | **Given** the user does not exist · **When** the admin registers them · **Then** the user is stored | TC001-A |
| 2 · Duplicate user | **Given** the user already exists · **When** the admin tries to register them · **Then** the error "user already exists" is shown | TC001-B |

**Passes if:** (A) the user appears in the list and can log in; (B) the "already exists" message is shown, no second record is created and the existing one is unchanged.

#### HU002 — Login · Role: Registered user · Manual · High
| Sc. | Acceptance criterion | TC |
|---|---|---|
| 1 · Valid credentials | **Given** correct credentials · **When** the user logs in · **Then** access is granted | TC002-A |
| 2 · Invalid credentials | **Given** incorrect credentials · **When** the user logs in · **Then** an authentication error is shown | TC002-B |

**Passes if:** (A) redirects to the main page with an active session; (B) shows the error, no session is created and the user stays on the login page.

#### HU003 — Role assignment · Role: Administrator · Manual · High
| Sc. | Acceptance criterion | TC |
|---|---|---|
| 1 · Correct assignment | **Given** the user exists · **When** the admin assigns a role · **Then** the role is updated | — |
| 2 · Nonexistent user | **Given** the user does not exist · **When** the admin tries to assign a role · **Then** the error "user does not exist" is shown | TC003 |

**Passes if:** "user does not exist" is shown, no role is assigned and the database is unchanged.

#### HU004 — User deactivation · Role: Administrator · Manual · High
| Sc. | Acceptance criterion | TC |
|---|---|---|
| 1 · Successful deactivation | **Given** an active user · **When** the admin deactivates them · **Then** their status becomes inactive | TC004-A |
| 2 · Restricted access | **Given** a deactivated user · **When** they try to log in · **Then** access is blocked with an **inactive user** message | TC004-B |

**Passes if:** (A) asks for confirmation and the status stays inactive after reload; (B) the message says the user is inactive (not "invalid credentials") and no session is created.

#### HU005 — Logout · Role: Authenticated user · Manual · Medium-High
| Sc. | Acceptance criterion | TC |
|---|---|---|
| 1 · Successful logout | **Given** an authenticated user · **When** they log out · **Then** the session is invalidated and they are redirected to login | TC005-A |
| 2 · Expired session | **Given** a session expired by inactivity · **When** the user attempts an action · **Then** they are asked to log in | TC005-B |

**Passes if:** (A) after logout, opening a protected URL (or using the browser's Back button) redirects to login; (B) after the inactivity timeout, any action asks for login.

### EP02 — Alert management

#### HU006 — Alert ingestion · Role: SOC Analyst L1 · Manual/Automated · High
| Sc. | Acceptance criterion | TC |
|---|---|---|
| 1 · Valid alert | **Given** a well-formed JSON/CSV · **When** it is submitted · **Then** it is received and stored | — |
| 2 · Invalid format | **Given** a JSON/CSV with syntax or structure errors · **When** it is submitted · **Then** it is rejected with "invalid format" | TC006 |

**Passes if:** "invalid format" is shown for both a malformed JSON and a broken CSV, and the alert is not stored nor queued.

#### HU007 — Alert validation · Role: SOC Analyst L1 · Manual · High
| Sc. | Acceptance criterion | TC |
|---|---|---|
| 1 · Correct validation | **Given** alerts with all required fields · **When** they are validated · **Then** processing continues | — |
| 2 · Missing fields | **Given** alerts missing required fields · **When** they are validated · **Then** the missing fields are detected, "incomplete data" is shown and processing stops | TC007 |

**Passes if:** the incomplete-data message is shown, no predictions are generated and the user stays in the Pipeline module able to upload again.

#### HU008 — Alert storage · Role: SOC Analyst L1 · Automated · High
| Sc. | Acceptance criterion | TC |
|---|---|---|
| 1 · Successful storage | **Given** a valid alert · **When** it is processed · **Then** it is stored in the database | TC008-A |
| 2 · Storage error | **Given** a database failure · **When** saving is attempted · **Then** an error is shown and the incident is logged | TC008-B |

**Passes if:** (A) the alert is stored with correct data and no duplicates; (B) an error is shown, the incident is logged and **no new or partial records** exist (row count before/after).

#### HU009 — Cleaning and normalization · Role: SOC Analyst L1 · Automated · High
| Sc. | Acceptance criterion | TC |
|---|---|---|
| 1 · Normalized data | **Given** inconsistent values · **When** processed · **Then** they are transformed to the expected format | TC009-A |
| 2 · Incomplete data | **Given** null/empty values · **When** processed · **Then** they are replaced or flagged per the rules | TC009-B |

**Passes if:** every input value ends up exactly as the expected normalized value and the alert continues through the pipeline.

#### HU010 — Ingestion errors · Role: SOC Analyst L1 · Automated · High
| Sc. | Acceptance criterion | TC |
|---|---|---|
| 1 · Controlled error | **Given** an ingestion failure · **When** processed · **Then** the error is logged without stopping the flow | TC010-A |
| 2 · Error notification | **Given** a critical error · **When** it occurs · **Then** an alert is shown for review | TC010-B |

**Passes if:** (A) in a batch of ≥3 alerts where one fails, the failing one is logged and the rest are processed; (B) a notification is visible to the analyst and the error is logged.

### EP03 — Alert prediction

#### HU011 — Automatic classification · Role: SOC Analyst L2 · Automated · High
| Sc. | Acceptance criterion | TC |
|---|---|---|
| 1 · Correct classification | **Given** valid data · **When** processed · **Then** Benigno, A_Investigar or Malicioso is assigned | TC011-A |
| 2 · Classification error | **Given** insufficient data · **When** classified · **Then** "could not classify" is shown | TC011-B |

**Passes if:** (A) the class is one of the three and is linked to the alert; (B) no class is assigned and the message is shown.

#### HU012 — Risk score · Role: SOC Analyst L2 · Automated · High
| Sc. | Acceptance criterion | TC |
|---|---|---|
| 1 · Risk calculation | **Given** a classified alert · **When** processed · **Then** a numeric risk value is assigned | TC012-A |
| 2 · Unclassified | **Given** an unclassified alert · **When** risk is calculated · **Then** no score is generated and a warning is shown | TC012-B |

**Passes if:** (A) the value is numeric, within range and stored; (B) no score exists and the "must be classified first" warning is shown.

#### HU013 — Explainability interpretation · Role: SOC Analyst L2 · Manual/Automated · Medium-High
| Sc. | Acceptance criterion | TC |
|---|---|---|
| 1 · Factor interpretation | **Given** an explanation is available · **When** the detail is opened · **Then** the relevant factors are shown understandably | — |
| 2 · No explanation | **Given** no explanation data · **When** the detail is opened · **Then** "no information available" is shown | TC013 |

**Passes if:** the informational message is shown, the general alert information stays visible and there are no visual errors.

#### HU014 — Random Forest execution · Role: System · Automated · High
| Sc. | Acceptance criterion | TC |
|---|---|---|
| 1 · Model execution | **Given** the model is loaded · **When** an alert is processed · **Then** it runs and produces a classification | TC014-A |
| 2 · Model error | **Given** the model is unavailable · **When** execution is attempted · **Then** the error is logged and the process stops | TC014-B |

**Passes if:** (A) a classification is stored; (B) no classification exists, the error is logged and the rest of the system keeps working. The alert from TC014-B is the test data for TC030.

#### HU015 — SHAP values · Role: System · Automated · Medium-High
| Sc. | Acceptance criterion | TC |
|---|---|---|
| 1 · SHAP calculation | **Given** a classified alert with processed data · **When** the user selects it and clicks **SHAP** · **Then** the SHAP values for that prediction are generated | — |
| 2 · Calculation error | **Given** the SHAP process fails · **When** it is calculated · **Then** the error is logged and the flow continues | TC015 |

**Passes if:** no SHAP values are generated, the error is logged, **the classification is unchanged** and navigation keeps working.

### EP04 — Visualization and monitoring

#### HU016 — Alert dashboard · Role: SOC Analyst L1 · Manual/Automated · Medium
| Sc. | Acceptance criterion | TC |
|---|---|---|
| 1 · Visualization | **Given** stored alerts · **When** the dashboard is opened · **Then** the list is shown | — |
| 2 · No alerts | **Given** no alerts · **When** the dashboard is opened · **Then** "no alerts" is shown | TC016 |

**Passes if:** the informational message is shown with no broken empty tables or errors, and navigation keeps working.

#### HU017 — Metrics and charts · Role: SOC Analyst L1 · Manual/Automated · Medium
| Sc. | Acceptance criterion | TC |
|---|---|---|
| 1 · Metrics visualization | **Given** data is available · **When** the page is opened · **Then** charts and statistics are shown | — |
| 2 · Insufficient data | **Given** insufficient data · **When** the page is opened · **Then** an informational message is shown | TC017 |

**Passes if:** the informational message is shown, empty charts render without errors and filters can be changed or refreshed.

#### HU018 — Filter by criticality · Role: SOC Analyst L1 · Manual/Automated · Medium-High
| Sc. | Acceptance criterion | TC |
|---|---|---|
| 1 · Filter applied | **Given** alerts of several levels · **When** a filter is applied · **Then** only matching alerts are shown | — |
| 2 · No matches | **Given** no alert has that level · **When** filtering · **Then** "no results" is shown | TC018 |

**Passes if:** "no results" is shown, the filter stays selected and can be cleared or changed.

#### HU019 — Alert ordering · Role: SOC Analyst L1 · Manual/Automated · Medium
| Sc. | Acceptance criterion | TC |
|---|---|---|
| 1 · By risk | **Given** several alerts · **When** ordered by risk · **Then** highest to lowest risk | — |
| 2 · By date | **Given** several alerts · **When** ordered by date · **Then** chronological order | TC019 |

**Passes if:** the order matches the actual dates (≥3 alerts inserted out of order) and persists until the criterion changes.

#### HU020 — Alert detail · Role: SOC Analyst L2 · Manual/Automated · Medium-High
| Sc. | Acceptance criterion | TC |
|---|---|---|
| 1 · Alert analysis | **Given** an existing alert · **When** it is selected · **Then** all relevant information is shown | — |
| 2 · Nonexistent alert | **Given** a nonexistent alert · **When** access is attempted · **Then** an error message is shown | TC020 |

**Passes if:** a clear message is shown (not a 500 page), there is a way back to the list, and the attempt is recorded in the audit log.

### EP05 — Operations and response

#### HU021 — Order by priority · Role: SOC Analyst L1 · Manual/Automated · Medium-High
| Sc. | Acceptance criterion | TC |
|---|---|---|
| 1 · Order by priority | **Given** several alerts · **When** the list is opened · **Then** highest to lowest priority | — |
| 2 · No high-priority alerts | **Given** no critical alerts · **When** the list is opened · **Then** the available alerts are shown without high priority | TC021 |

**Passes if:** with only Medium and Low alerts, they are listed in order (Medium before Low) without errors.

#### HU022 — Priority change · Role: SOC Analyst L2 · Manual/Automated · Medium-High
| Sc. | Acceptance criterion | TC |
|---|---|---|
| 1 · Update | **Given** an existing alert · **When** the priority is changed · **Then** it is updated | — |
| 2 · Update error | **Given** a nonexistent alert · **When** a change is attempted · **Then** an error message is shown | TC022 |

**Passes if:** an error message is shown and no priority changed in the database.

#### HU023 — Alert status · Role: SOC Analyst L1 · Manual/Automated · Medium-High
| Sc. | Acceptance criterion | TC |
|---|---|---|
| 1 · Successful marking | **Given** an available alert · **When** "Investigated" is chosen, a justification entered and saved · **Then** the status is updated | — |
| 2 · Alert unavailable | **Given** an alert already escalated to an incident · **When** saving it as "Investigated" is attempted · **Then** it is rejected with "no longer available" | TC023 |

**Sequence:** (1) analyst A opens the alert → "Investigation status" section; (2) analyst B escalates **the same** alert to an incident; (3) A chooses "Investigated", enters a justification and clicks **Save status**.

**Passes if:** the save is rejected with the expected message, the status is unchanged, the incident is unchanged and the alert no longer appears for L1/L2.

#### HU024 — Alert assignment · Role: SOC Analyst L1 · Manual/Automated · Medium-High
| Sc. | Acceptance criterion | TC |
|---|---|---|
| 1 · Correct assignment | **Given** an existing target analyst · **When** assigning · **Then** the assignment is stored | — |
| 2 · Nonexistent analyst | **Given** a nonexistent target · **When** assigning · **Then** an error message is shown | TC024 |

**Passes if:** an error message is shown and the alert's assignment is unchanged.

#### HU025 — Action logging and justification · Role: SOC Analyst L1 · Manual/Automated · Medium-High
| Sc. | Acceptance criterion | TC |
|---|---|---|
| 1 · Action logging | **Given** an existing alert · **When** an action is logged · **Then** it is stored with its justification | — |
| 2 · Logging error | **Given** a failure · **When** the action is logged · **Then** an error message is shown | TC025 |

**Passes if:** "could not log the action" is shown with a retry option, the action is not stored, prior history is unchanged and the failed attempt appears in the audit log.

### EP06 — Reports, audit and history

#### HU026 — Report generation · Role: Administrator · Manual/Automated · Medium
| Sc. | Acceptance criterion | TC |
|---|---|---|
| 1 · Report generation | **Given** stored data · **When** the report is generated · **Then** it contains the requested information | — |
| 2 · No data | **Given** no data · **When** generating · **Then** "no information" is shown | TC026 |

**Passes if:** the informational message is shown, **no file is downloaded** and the filters can be changed.

#### HU027 — Report export · Role: Administrator · Manual/Automated · Medium-High
| Sc. | Acceptance criterion | TC |
|---|---|---|
| 1 · Successful export | **Given** information is available · **When** exporting in a format · **Then** the file is generated | — |
| 2 · Excel error | **Given** a controlled failure generating Excel · **When** exporting to Excel · **Then** no file is generated and a message is shown | TC027-B |
| 3 · PDF error | **Given** a controlled failure generating PDF · **When** exporting to PDF · **Then** no file is generated and a message is shown | TC027-A |

Note the crossed order: TC027-**A** covers scenario **3** (PDF) and TC027-**B** covers scenario **2** (Excel).

**Passes if:** nothing is downloaded and exactly **"No se pudo exportar el reporte."** is shown; data is unchanged and the export can be retried.

#### HU028 — Alert history · Role: SOC Analyst L2 · Manual · Medium
| Sc. | Acceptance criterion | TC |
|---|---|---|
| 1 · History query | **Given** alerts classified by the model · **When** History is opened · **Then** it shows: date, category/attack, MITRE tactic, severity, ML class, risk, status, ML evaluation and assigned investigator | TC028-A |
| 2 · No history | **Given** no classified alerts · **When** History is opened · **Then** "no alerts in the history" is shown | TC028-B |

**Passes if:** (A) the alert appears, "View detail" opens and **all 9 columns** are visible; (B) the informational message is shown.

#### HU029 — Audit log · Role: Administrator · Manual · Medium
| Sc. | Acceptance criterion | TC |
|---|---|---|
| 1 · Audit log | **Given** logged actions · **When** Audit is opened · **Then** user, action, description and date are shown | TC029-A |
| 2 · Filtering | **Given** logged actions · **When** filters are applied · **Then** only matching records are shown | TC029-B |

**Passes if:** (A) every row has the 4 columns; (B) each filter (action type, user, from, to) and one combination return only matching records, the original log is unchanged and the filter can be cleared.

#### HU030 — Decision evaluation · Role: SOC Analyst L2 · Manual · Medium
| Sc. | Acceptance criterion | TC |
|---|---|---|
| 1 · Decision evaluation | **Given** stored results · **When** an alert is opened · **Then** classification, explanation and executed action are shown | — |
| 2 · No information | **Given** an alert whose processing did not complete · **When** its information is queried · **Then** "no information available" is shown | TC030 |

**Passes if:** the general alert information is shown along with the message, and **no made-up or default classification, explanation or action** is displayed.

## Automated coverage

The AC scenarios without a QA TC are covered by the `pytest` suite (unit + integration, runs in CI). HU001 scenario 2 is covered on both sides.

| HU | Scenario covered | Test |
|---|---|---|
| 001 | Sc.2 Duplicate user | `accounts/tests/test_api_auth.py::test_register_rejects_duplicate_username` |
| 002 | Sc.1 Valid credentials | `accounts/tests/test_api_auth.py::test_login_succeeds_with_valid_credentials` |
| 003 | Sc.1 Correct assignment | `accounts/tests/test_user_management.py::test_admin_creates_user_with_role` |
| 004 | Sc.1 Successful deactivation | `accounts/tests/test_user_management.py::test_admin_deactivates_user` |
| 005 | Sc.1 Successful logout | `accounts/tests/test_api_auth.py::test_logout_blacklists_refresh_token` |
| 006 | Sc.1 Valid alert | `predictor/tests/test_api_predict.py::test_upload_alerts_api_processes_valid_json_file` |
| 007 | Sc.1 Correct validation | `predictor/tests/test_pipeline.py::test_validate_columns_detects_missing_required` |
| 008 | Sc.1 Successful storage | `predictor/tests/test_smoke_e2e.py::test_smoke_login_upload_queue_escalate` |
| 009 | Sc.1 Normalized data | `predictor/tests/test_pipeline.py::test_clean_records_*` (5 tests) |
| 010 | Sc.1 Controlled error | `predictor/tests/test_api_predict.py::test_upload_alerts_api_rejects_empty_file` |
| 011 | Sc.1 Correct classification | `predictor/tests/test_utils.py::test_predict_alert_returns_valid_class_and_probabilities` |
| 012 | Sc.1 Risk calculation | `predictor/tests/test_utils.py::test_calculate_risk_score_weights` |
| 013 | Sc.1 Factor interpretation | `predictor/tests/test_shap.py::test_calculate_shap_values_returns_structured_explanation` |
| 014 | Sc.1 Model execution | `predictor/tests/test_utils.py::test_predict_batch_matches_length_and_shape` |
| 015 | Sc.1 SHAP calculation | `predictor/tests/test_shap.py::test_calculate_shap_values_returns_structured_explanation` |
| 016 | Sc.1 Visualization | `predictor/tests/test_dashboard_and_list.py::test_alert_list_admin_sees_everything` |
| 017 | Sc.1 Metrics visualization | `predictor/tests/test_dashboard_and_list.py::test_dashboard_counts_alerts_by_class` |
| 018 | Sc.1 Filter applied | `predictor/tests/test_dashboard_and_list.py::test_alert_list_severity_filter_matches` |
| 019 | Sc.1 By risk | `predictor/tests/test_dashboard_and_list.py::test_alert_list_order_by_risk_desc` |
| 020 | Sc.1 Alert analysis | `predictor/tests/test_dashboard_and_list.py::test_alert_shap_view_renders_and_computes_shap` |
| 021 | Sc.1 Order by priority | `predictor/tests/test_dashboard_and_list.py::test_alert_list_priority_filter` |
| 022 | Sc.1 Update | `predictor/tests/test_priority_and_assignment.py::test_set_priority_updates_workflow` |
| 023 | Sc.1 Successful marking | `predictor/tests/test_state_transitions.py::test_set_status_updates_workflow` |
| 024 | Sc.1 Correct assignment | `predictor/tests/test_priority_and_assignment.py::test_admin_assigns_alert_to_allowed_target` |
| 025 | Sc.1 Action logging | `predictor/tests/test_state_transitions.py::test_set_status_records_action_with_justification_in_audit` |
| 026 | Sc.1 Report generation | `predictor/tests/test_reports_and_history.py::test_report_view_summarizes_alerts` |
| 027 | Sc.1 Successful export | `predictor/tests/test_reports_and_history.py::test_report_export_excel_returns_xlsx_attachment` |
| 028 | Sc.1 History query | `predictor/tests/test_reports_and_history.py::test_history_shows_only_classified_alerts` |
| 029 | Sc.1 Audit log | `accounts/tests/test_audit.py::test_admin_sees_all_audit_entries` |
| 030 | Sc.1 Decision evaluation | `predictor/tests/test_state_transitions.py::test_evaluate_records_ml_evaluation` |

### Running the suite

```bash
cd soc_project
DB_HOST= ../venv/Scripts/python.exe -m pytest --cov=predictor --cov=accounts --cov-report=term-missing
```

`DB_HOST=` forces SQLite so the suite never touches the local or production Postgres database (in PowerShell: `$env:DB_HOST=""` before the command).

### Smoke E2E

`predictor/tests/test_smoke_e2e.py` chains three happy-path flows with Django's test client (no real browser), as a CI safety net — it does not replace QA's formal Selenium suite:

1. `test_smoke_login_upload_queue_escalate` — login → upload alerts → see them in the queue → escalate to an incident.
2. `test_smoke_login_pipeline_normalize_queue` — the pipeline flow (HU009): upload → map → normalize → queue.
3. `test_smoke_login_rejected_with_wrong_password` — minimal negative control.

They run with `django-q2` in synchronous mode (`Q_CLUSTER sync=True`, patched by the `q_cluster_sync` fixture) so CI does not need a running `qcluster`.

## Load testing scope

- **JMeter/BlazeMeter — only `POST /login/` plus the GET endpoints below.** Never write operations (registration, dataset upload, Splunk connection, alert CRUD): they are not idempotent, and looping them under load would create junk or corrupt data in the shared demo environment.
- **Selenium — everything that writes**, run a fixed, controlled number of times per suite to check functional correctness, not throughput.

**Concurrency ceiling: 20 virtual users** for the general flow (login + navigation) — the total headcount of SOC analysts of every level plus admin. A real SOC works in shifts, so 20 is already a generous margin over expected use.

**Exception — SHAP detail: at most 3 concurrent users.** Opening a single alert's detail is a "one assigns, another reviews" action; loading it with 20 users overstates real use and does not produce a useful measurement.

| Page | Endpoint | Weight | Concurrency |
|---|---|---|---|
| Dashboard | `/dashboard/` | Light | up to 20 |
| Alerts + filters | `/alerts/?severity=...&predicted_class=...` | Light | up to 20 |
| History + filters | `/alerts/history/?...` | Light | up to 20 |
| Incident desk | `/incidents/` | Light | up to 20 |
| **SHAP detail** | `/alerts/<id>/shap/` | **Heavy — synchronous, CPU-bound** | **max 3** |
| Reports + filters | `/reports/?...` | Light | up to 20 |
| **PDF export** | `/reports/export/pdf/`, `/reports/export/incidents/pdf/` | **Heavy — synchronous, matplotlib** | up to 20 |
| Excel export | `/reports/export/excel/` | Light | up to 20 |
| Audit | `/audit/` | Light | up to 20 |
| Connector status | `/connectors/status/` | Light | up to 20 |

Performance work already done before load testing: `bulk_create` with `batch_size=500`, model and SHAP explainers preloaded in `apps.py.ready()`, uploads moved to background tasks. Anything still slow on SHAP/PDF under load is real synchronous work, not a known inefficiency.

## Out of scope

- `predictor/claude_service.py` (natural-language SHAP explanation, incident chat) — not part of any user story in this mapping.
