from django.urls import path

from .views import (
    connector_create_view,
    connector_delete_view,
    connector_edit_view,
    connector_force_resync_view,
    connector_list_view,
    connector_status_view,
    connector_sync_now_view,
    connector_test_view,
)

urlpatterns = [
    path('connectors/', connector_list_view, name='connector_list'),
    path('connectors/status/', connector_status_view, name='connector_status'),
    path('connectors/create/', connector_create_view, name='connector_create'),
    path('connectors/<int:pk>/edit/', connector_edit_view, name='connector_edit'),
    path('connectors/<int:pk>/delete/', connector_delete_view, name='connector_delete'),
    path('connectors/<int:pk>/test/', connector_test_view, name='connector_test'),
    path('connectors/<int:pk>/sync-now/', connector_sync_now_view, name='connector_sync_now'),
    path('connectors/<int:pk>/resync/', connector_force_resync_view, name='connector_resync'),
]
