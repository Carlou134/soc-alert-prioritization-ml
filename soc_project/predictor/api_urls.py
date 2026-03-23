from django.urls import path
from .api_views import PredictAPIView, HistoryAPIView

urlpatterns = [
    path('predict/', PredictAPIView.as_view(), name='api_predict'),
    path('history/', HistoryAPIView.as_view(), name='api_history'),
]