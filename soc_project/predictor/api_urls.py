from django.urls import path
from .api_views import PredictAPIView, UploadAlertsAPIView

urlpatterns = [
    path('predict/', PredictAPIView.as_view(), name='api_predict'),
    path('upload-alerts/', UploadAlertsAPIView.as_view(), name='api_upload_alerts'),
]
