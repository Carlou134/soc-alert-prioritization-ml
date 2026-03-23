from django.urls import path
from .views import dashboard_view, predict_view, predict_json_view, history_view

urlpatterns = [
    path('', dashboard_view, name='dashboard'),
    path('dashboard/', dashboard_view, name='dashboard'),
    path('predict/', predict_view, name='predict'),
    path('predict-json/', predict_json_view, name='predict_json'),
    path('history/', history_view, name='history'),
]