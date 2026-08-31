"""Vistas de predictor, separadas por responsabilidad (antes un único
views.py de 2300+ líneas). Este __init__ reexporta todo para que urls.py y
cualquier import externo (ej. predictor/tasks.py) sigan funcionando igual."""

from .dashboard import dashboard_view

from .predict import predict_view, predict_json_view

from .alerts import (
    ASSIGNMENT_TARGETS,
    alert_history_view,
    _build_alert_instance,
    _bulk_create_alerts,
    upload_alerts_view,
    dataset_status_view,
    notifications_unread_count_view,
    _friendly_serializer_errors,
    alert_list_view,
    predict_pending_view,
    alert_set_status_view,
    alert_set_priority_view,
    alert_shap_view,
    alert_explain_view,
    alert_assign_view,
    alert_evaluate_view,
    alert_escalate_view,
)

from .normalization import (
    pipeline_view,
    pipeline_upload_view,
    pipeline_map_view,
    pipeline_normalize_view,
    pipeline_preview_view,
    pipeline_export_view,
)

from .reports import (
    report_view,
    report_export_excel_view,
    report_export_pdf_view,
    report_export_incidents_pdf_view,
)

from .incidents import (
    incident_detail_view,
    incident_resolve_view,
    incident_chat_view,
    incident_desk_view,
)
