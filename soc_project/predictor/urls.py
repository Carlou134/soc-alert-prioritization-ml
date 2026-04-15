from django.urls import path
from .views import (
    alert_list_view,
    dashboard_view,
    history_view,
    predict_json_view,
    predict_view,
    upload_alerts_view,
)

urlpatterns = [
    path('', dashboard_view, name='dashboard'),
    path('dashboard/', dashboard_view, name='dashboard'),
    path('predict/', predict_view, name='predict'),
    path('predict-json/', predict_json_view, name='predict_json'),
    path('upload-alerts/', upload_alerts_view, name='upload_alerts'),
    path('history/', history_view, name='history'),
    path('alerts/', alert_list_view, name='alert_list'),
]
