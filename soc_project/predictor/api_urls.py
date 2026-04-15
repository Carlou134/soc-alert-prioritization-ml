from django.urls import path
from .api_views import PredictAPIView, HistoryAPIView, UploadAlertsAPIView

urlpatterns = [
    path('predict/', PredictAPIView.as_view(), name='api_predict'),
    path('history/', HistoryAPIView.as_view(), name='api_history'),
    path('upload-alerts/', UploadAlertsAPIView.as_view(), name='api_upload_alerts'),
]
