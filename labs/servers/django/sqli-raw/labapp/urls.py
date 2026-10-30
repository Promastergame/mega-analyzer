"""
URL routes for labapp.

INTENTIONALLY VULNERABLE LAB SERVER (CWE-89). See README.md.
"""
from django.urls import path

from . import views

urlpatterns = [
    path("search", views.search_view, name="search"),
    path("api/me", views.me_view, name="me"),
    path("api/admin/dashboard", views.admin_dashboard, name="admin_dashboard"),
]
