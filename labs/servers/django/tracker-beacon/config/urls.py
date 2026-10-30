"""URL configuration for the tracker-beacon lab server."""

from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include("labapp.urls")),
]
