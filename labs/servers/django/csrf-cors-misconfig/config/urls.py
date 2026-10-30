"""
URL configuration for the csrf-cors-misconfig lab server.

INTENTIONALLY VULNERABLE LAB SERVER (CWE-352). See README.md.
"""
from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include("labapp.urls")),
]
