# Testing backlog — entrega a QA (P20261086)

Este documento es la contraparte de nuestro lado del mapeo maestro de QA (`mapeo_maestro.json` / `Mapeo_Maestro_HU_CP.md`, 6 épicas · 30 HU · 60 criterios · 30 CP).

## Cómo se dividió el trabajo

Cada HU tiene 2 escenarios de aceptación, pero el CP de QA solo cubre 1. En 29 de las 30 HU, ese CP cubre el escenario **negativo/de error** — el camino feliz queda sin caso de prueba formal. La única excepción es HU001 (al revés: su CP cubre el éxito, falta el duplicado).

- **QA ejecuta** (Selenium/JMeter, columna izquierda de la tabla de abajo): ya está en su documento, no se repite aquí.
- **Nosotros cubrimos** (unit + integración, `pytest`): el camino feliz de cada HU + el negativo de HU001. Todo con test real, no smoke visual — corre en CI, no depende de que alguien lo ejecute a mano.

Entre ambos lados, los 60 criterios de aceptación quedan cubiertos sin duplicar esfuerzo.

## Cómo correr la suite

```bash
cd soc_project
DB_HOST= ../venv/Scripts/python.exe -m pytest --cov=predictor --cov=accounts --cov-report=term-missing
```

(`DB_HOST=` fuerza SQLite para no tocar la base de Postgres local/producción — en PowerShell es `$env:DB_HOST=""` antes del comando.)

**Estado actual: 110 tests, 0 fallos.** Cobertura por módulo: `accounts/api_views.py` 98%, `predictor/utils.py` 96%, `predictor/models.py` 89%, `accounts/views.py` 67%, `predictor/views.py` 52%, `predictor/pipeline.py` 73%, `predictor/api_views.py` 70%.

## Checklist HU por HU

| HU | QA ejecuta (su CP) | Nos toca a nosotros | Test que lo cubre |
|---|---|---|---|
| 001 | Esc.1 Registro exitoso | Esc.2 Usuario duplicado | `accounts/tests/test_api_auth.py::test_register_rejects_duplicate_username` |
| 002 | Esc.2 Credenciales inválidas | Esc.1 Credenciales válidas | `accounts/tests/test_api_auth.py::test_login_succeeds_with_valid_credentials` |
| 003 | Esc.2 Usuario inexistente | Esc.1 Asignación correcta | `accounts/tests/test_user_management.py::test_admin_creates_user_with_role` |
| 004 | Esc.2 Acceso restringido | Esc.1 Desactivación exitosa | `accounts/tests/test_user_management.py::test_admin_deactivates_user` |
| 005 | Esc.2 Sesión expirada | Esc.1 Cierre de sesión exitoso | `accounts/tests/test_api_auth.py::test_logout_blacklists_refresh_token` |
| 006 | Esc.2 Formato inválido | Esc.1 Recepción válida | `predictor/tests/test_api_predict.py::test_upload_alerts_api_processes_valid_json_file` |
| 007 | Esc.2 Campos faltantes | Esc.1 Validación correcta | `predictor/tests/test_pipeline.py::test_validate_columns_detects_missing_required` |
| 008 | Esc.2 Error de almacenamiento | Esc.1 Almacenamiento exitoso | `predictor/tests/test_smoke_e2e.py::test_smoke_login_upload_queue_escalate` |
| 009 | Esc.2 Datos incompletos | Esc.1 Datos normalizados | `predictor/tests/test_pipeline.py::test_clean_records_*` (5 tests) |
| 010 | Esc.2 Notificación de error | Esc.1 Error controlado | `predictor/tests/test_api_predict.py::test_upload_alerts_api_rejects_empty_file` |
| 011 | Esc.2 Error de clasificación | Esc.1 Clasificación correcta | `predictor/tests/test_utils.py::test_predict_alert_returns_valid_class_and_probabilities` |
| 012 | Esc.2 Alerta sin clasificación | Esc.1 Cálculo de riesgo | `predictor/tests/test_utils.py::test_calculate_risk_score_weights` |
| 013 | Esc.2 Falta de explicación | Esc.1 Interpretación de factores | `predictor/tests/test_shap.py::test_calculate_shap_values_returns_structured_explanation` |
| 014 | Esc.2 Error del modelo | Esc.1 Ejecución del modelo | `predictor/tests/test_utils.py::test_predict_batch_matches_length_and_shape` |
| 015 | Esc.2 Error en cálculo SHAP | Esc.1 Cálculo SHAP correcto | `predictor/tests/test_shap.py::test_calculate_shap_values_returns_structured_explanation` |
| 016 | Esc.2 Sin alertas disponibles | Esc.1 Visualización de alertas | `predictor/tests/test_dashboard_and_list.py::test_alert_list_admin_sees_everything` |
| 017 | Esc.2 Sin datos suficientes | Esc.1 Visualización de métricas | `predictor/tests/test_dashboard_and_list.py::test_dashboard_counts_alerts_by_class` |
| 018 | Esc.2 Sin coincidencias | Esc.1 Filtro aplicado | `predictor/tests/test_dashboard_and_list.py::test_alert_list_severity_filter_matches` |
| 019 | Esc.2 Orden por fecha | Esc.1 Orden por riesgo | `predictor/tests/test_dashboard_and_list.py::test_alert_list_order_by_risk_desc` |
| 020 | Esc.2 Alerta inexistente | Esc.1 Análisis de alerta | `predictor/tests/test_dashboard_and_list.py::test_alert_shap_view_renders_and_computes_shap` |
| 021 | Esc.2 Sin alertas prioritarias | Esc.1 Orden por prioridad | `predictor/tests/test_dashboard_and_list.py::test_alert_list_priority_filter` ⚠️ ver nota |
| 022 | Esc.2 Error de actualización | Esc.1 Actualización de prioridad | `predictor/tests/test_priority_and_assignment.py::test_set_priority_updates_workflow` |
| 023 | Esc.2 Alerta inexistente | Esc.1 Marcado exitoso | `predictor/tests/test_state_transitions.py::test_set_status_updates_workflow` |
| 024 | Esc.2 Analista inexistente | Esc.1 Asignación correcta | `predictor/tests/test_priority_and_assignment.py::test_admin_assigns_alert_to_allowed_target` |
| 025 | Esc.2 Error en registro | Esc.1 Registro de acción | `accounts/tests/test_audit.py::test_log_action_persists_entry` |
| 026 | Esc.2 Sin datos disponibles | Esc.1 Generación de reporte | `predictor/tests/test_reports_and_history.py::test_report_view_summarizes_alerts` |
| 027 | Esc.2 Error de exportación | Esc.1 Exportación exitosa | `predictor/tests/test_reports_and_history.py::test_report_export_excel_returns_xlsx_attachment` |
| 028 | Esc.2 Sin historial | Esc.1 Consulta de historial | `predictor/tests/test_reports_and_history.py::test_history_shows_only_classified_alerts` |
| 029 | Esc.2 Sin registros | Esc.1 Registro de auditoría | `accounts/tests/test_audit.py::test_admin_sees_all_audit_entries` |
| 030 | Esc.2 Sin información disponible | Esc.1 Evaluación de decisiones | `predictor/tests/test_state_transitions.py::test_evaluate_records_ml_evaluation` |

⚠️ **Nota HU021**: la UI no tiene un "orden por prioridad" literal — `alert_list_view` solo ordena por `risk_desc/risk_asc/date_desc/date_asc` (`predictor/views.py`, `_order_map`). Lo que sí existe y se testea es el **filtro** por `analyst_priority`. Si QA espera un sort real por prioridad y no un filtro, es un gap de producto, no de testing — vale la pena confirmarlo con ellos antes de dar la HU por cerrada.

## Smoke E2E (nuestro, no reemplaza el Selenium formal de QA)

`predictor/tests/test_smoke_e2e.py` — 3 casos de camino feliz encadenados con el test Client de Django (sin navegador real), pensados como red de CI propia:

1. `test_smoke_login_upload_queue_escalate` — login real → subir alertas → verlas en la cola → escalar a incidente.
2. `test_smoke_login_pipeline_normalize_queue` — el flujo del pipeline (HU009): subir → mapear → normalizar → cola.
3. `test_smoke_login_rejected_with_wrong_password` — control negativo mínimo.

Corren con `django-q2` en modo síncrono (`Q_CLUSTER sync=True` parcheado via fixture `q_cluster_sync`) para no depender de un `qcluster` real corriendo aparte durante CI.

## Fuera de alcance (documentado, no oculto)

- Carga (JMeter) — de QA. Deuda de performance conocida y ya atendida antes de que empiecen: `bulk_create` con `batch_size=500`, modelo/SHAP precargados en `apps.py.ready()`, uploads movidos a background (Track 5). El cálculo de SHAP por alerta y la generación de gráficos con matplotlib en PDF siguen siendo síncronos — riesgo real bajo concurrencia, sin medir todavía.
- E2E formal con casos documentados — de QA (Selenium), su entregable de curso.
- `predictor/claude_service.py` (explicación de SHAP en texto, chat de incidente) — 0% cobertura, no estaba en el alcance de ninguna HU de este mapeo.
