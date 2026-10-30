from django.urls import path

from . import views

urlpatterns = [
    # NOTE: deliberately not referenced from any nav/menu/template anywhere
    # in this app. It only exists here, like any other route - that's the
    # whole point of CWE-489 "leftover debug code".
    path("_internal/become-admin", views.become_admin, name="become_admin"),
    path("login", views.login_view, name="login"),
    path("api/me", views.me_view, name="me"),
    path("api/admin/dashboard", views.admin_dashboard, name="admin_dashboard"),
]
