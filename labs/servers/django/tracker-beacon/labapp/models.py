"""Models for the tracker-beacon lab server.

Deliberately simple notes/todo app. The interesting behavior lives in
labapp/beacon.py and labapp/views.py, not here — these models exist just
to give the beacon something real to leak.
"""

from django.conf import settings
from django.db import models


class UserProfile(models.Model):
    """Kept for consistency with sibling lab servers even though role is
    not the focus of this particular lab (see beacon.py / views.py)."""

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="profile"
    )
    role = models.CharField(max_length=32, default="user")

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.user.username} ({self.role})"


class Note(models.Model):
    """A single note/todo item owned by a user.

    Every create/edit of a Note triggers a background analytics beacon
    (see labapp/views.py) that ships the full `body` off to TRACKER_URL —
    that over-sharing is the whole point of this lab.
    """

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="notes"
    )
    title = models.CharField(max_length=200)
    body = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.title} ({self.user.username})"
