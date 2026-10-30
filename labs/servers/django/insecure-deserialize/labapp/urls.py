from django.urls import path

from . import views

urlpatterns = [
    path("api/session/import", views.import_session_view, name="import_session"),
    path("login", views.login_view, name="login"),
    path("api/me", views.me_view, name="me"),
    path("api/admin/dashboard", views.admin_dashboard, name="admin_dashboard"),
]
