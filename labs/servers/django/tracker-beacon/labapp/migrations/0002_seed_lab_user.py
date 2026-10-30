"""Seed a single demo user for local lab exercises.

INTENTIONALLY INSECURE LAB SEED DATA.
Username: labuser
Password: labpass123   (documented fake plaintext password, lab-only)

This account exists purely so the beacon-triggering curl commands in
README.md have something to log in as. It is hashed via set_password()
before being written to the DB — the plaintext above is only ever used
here, in this migration, for a local-only lab.
"""

from django.contrib.auth.hashers import make_password
from django.db import migrations

LAB_USERNAME = "labuser"
LAB_PASSWORD = "labpass123"  # noqa: S105 - intentionally documented lab credential
LAB_EMAIL = "labuser@tracker-beacon.lab.local"


def seed_lab_user(apps, schema_editor):
    User = apps.get_model("auth", "User")
    UserProfile = apps.get_model("labapp", "UserProfile")

    if User.objects.filter(username=LAB_USERNAME).exists():
        return

    user = User.objects.create(
        username=LAB_USERNAME,
        email=LAB_EMAIL,
        password=make_password(LAB_PASSWORD),
        is_active=True,
    )
    UserProfile.objects.create(user=user, role="user")


def unseed_lab_user(apps, schema_editor):
    User = apps.get_model("auth", "User")
    User.objects.filter(username=LAB_USERNAME).delete()


class Migration(migrations.Migration):

    dependencies = [
        ("labapp", "0001_initial"),
    ]

    operations = [
        migrations.RunPython(seed_lab_user, unseed_lab_user),
    ]
