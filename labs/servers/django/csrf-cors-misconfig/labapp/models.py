"""
Models for the csrf-cors-misconfig lab server.

INTENTIONALLY VULNERABLE LAB SERVER (CWE-352). See README.md.
"""
from django.conf import settings
from django.db import models


class UserProfile(models.Model):
    """A thin role wrapper around Django's built-in auth User, consistent
    with the UserProfile(user, role) shape used by sibling lab servers in
    this repo."""

    ROLE_CHOICES = [
        ("user", "user"),
        ("moderator", "moderator"),
        ("admin", "admin"),
    ]

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="profile",
    )
    role = models.CharField(max_length=16, choices=ROLE_CHOICES, default="user")

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.user.username} ({self.role})"
