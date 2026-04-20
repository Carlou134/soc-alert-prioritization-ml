from django.urls import path
from .views import (
    alert_list_view,
    dashboard_view,
    history_view,
    predict_json_view,
    predict_view,
    predict_pending_view,
    upload_alerts_view,
    pipeline_view,
    pipeline_upload_view,
    pipeline_map_view,
    pipeline_normalize_view,
    pipeline_preview_view,
    pipeline_export_view,
)

urlpatterns = [
    path('', dashboard_view, name='dashboard'),
    path('dashboard/', dashboard_view, name='dashboard'),
    path('predict/', predict_view, name='predict'),
    path('predict-json/', predict_json_view, name='predict_json'),
    path('upload-alerts/', upload_alerts_view, name='upload_alerts'),
    path('history/', history_view, name='history'),
    path('alerts/', alert_list_view, name='alert_list'),
    path('alerts/predict-pending/', predict_pending_view, name='predict_pending'),
    # HU009 — Pipeline de normalización
    path('pipeline/', pipeline_view, name='pipeline'),
    path('pipeline/upload/', pipeline_upload_view, name='pipeline_upload'),
    path('pipeline/map/', pipeline_map_view, name='pipeline_map'),
    path('pipeline/normalize/', pipeline_normalize_view, name='pipeline_normalize'),
    path('pipeline/preview/', pipeline_preview_view, name='pipeline_preview'),
    path('pipeline/export/', pipeline_export_view, name='pipeline_export'),
]
