"""
Models for the sqli-raw lab server.

INTENTIONALLY VULNERABLE LAB SERVER (CWE-89). See README.md.
"""
from django.contrib.auth.models import User
from django.db import models


class UserProfile(models.Model):
    """One-to-one profile row carrying the role used for authorization
    decisions in this lab (see labapp/views.py: admin_dashboard)."""

    ROLE_USER = "user"
    ROLE_MODERATOR = "moderator"
    ROLE_ADMIN = "admin"
    ROLE_CHOICES = [
        (ROLE_USER, "User"),
        (ROLE_MODERATOR, "Moderator"),
        (ROLE_ADMIN, "Admin"),
    ]

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="profile")
    role = models.CharField(max_length=16, choices=ROLE_CHOICES, default=ROLE_USER)

    class Meta:
        db_table = "labapp_userprofile"

    def __str__(self):
        return f"{self.user.username} ({self.role})"
