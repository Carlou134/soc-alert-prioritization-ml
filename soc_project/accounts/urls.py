from django.urls import path

from .views import login_view, logout_view, register_view, user_edit_view, user_list_view

urlpatterns = [
    path('login/', login_view, name='login'),
    path('register/', register_view, name='register'),
    path('logout/', logout_view, name='logout'),
    # User management (admin only)
    path('users/', user_list_view, name='user_list'),
    path('users/<int:user_id>/edit/', user_edit_view, name='user_edit'),
]
