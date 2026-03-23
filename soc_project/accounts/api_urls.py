from django.urls import path
from .api_views import RegisterAPIView

urlpatterns = [
    path('register/', RegisterAPIView.as_view(), name='api_register'),
]