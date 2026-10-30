from django.conf import settings
from django.db import models


class Profile(models.Model):
    """Extra role metadata for Django's built-in `auth.User`.

    Kept deliberately simple: this lab uses `django.contrib.auth.models.User`
    directly for authentication (username/password, `is_staff`,
    `is_superuser`, sessions - all standard Django) and layers a `role`
    field on top via a one-to-one `Profile` for the app-level authorization
    check used by `admin_dashboard`.
    """

    class Role(models.TextChoices):
        USER = "user", "User"
        MODERATOR = "moderator", "Moderator"
        ADMIN = "admin", "Admin"

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="profile",
    )
    role = models.CharField(max_length=16, choices=Role.choices, default=Role.USER)

    def __str__(self):
        return f"{self.user.username} ({self.role})"
