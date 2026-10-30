"""
URL configuration for the `insecure-deserialize` lab.

The vulnerable `/api/session/import` route is wired up in `labapp/urls.py`
like any other route - it looks exactly like a normal "remember me" /
"import saved session" convenience feature. The bug isn't in how the route
is wired up; it's that the endpoint deserializes client-supplied bytes and
trusts a `role` field out of the result with no signature/integrity check.
"""

from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include("labapp.urls")),
]
