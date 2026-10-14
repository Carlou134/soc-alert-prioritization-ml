from django.urls import path

from .views import fault_panel_view

urlpatterns = [
    path('devtools/faults/', fault_panel_view, name='fault_panel'),
]
