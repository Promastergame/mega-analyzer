"""
URL configuration for the `admin-hidden-debug` lab.

Note that the vulnerable `/_internal/become-admin` route is wired up in
`labapp/urls.py` like any other route - it is not hidden by any special
routing trick. The "hidden" part of CWE-489 is purely social: it is
undocumented and never linked from any menu/nav in the app. That is
exactly what real leftover-debug-code backdoors look like in the wild.
"""

from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include("labapp.urls")),
]
