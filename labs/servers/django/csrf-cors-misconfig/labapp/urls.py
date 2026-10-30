"""
URL routes for the csrf-cors-misconfig lab server.

INTENTIONALLY VULNERABLE LAB SERVER (CWE-352). See README.md.
"""
from django.urls import path

from . import views

urlpatterns = [
    path("login", views.login_view, name="login"),
    path("api/me", views.me_view, name="api-me"),
    path("api/users/<int:id>/role", views.change_role_view, name="api-change-role"),
    path("api/admin/dashboard", views.admin_dashboard, name="api-admin-dashboard"),
]
