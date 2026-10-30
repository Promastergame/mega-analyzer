from django.urls import path

from . import views

urlpatterns = [
    path("login", views.login_view, name="login"),
    path("api/notes", views.notes_list_create_view, name="notes-list-create"),
    path("api/me", views.me_view, name="me"),
]
