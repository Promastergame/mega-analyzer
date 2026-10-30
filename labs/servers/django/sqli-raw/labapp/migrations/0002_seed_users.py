"""
Seed data for the sqli-raw lab: three auth.User + labapp.UserProfile rows
covering each role, so the /search endpoint (and its SQL injection) has
real rows to read/impersonate.

INTENTIONALLY VULNERABLE LAB SERVER (CWE-89). See README.md.

Fake, documented, local-lab-only plaintext passwords (never reused
anywhere real):

    username    password           role
    --------    --------           ----
    user1       user1_lab_pw       user
    moderator1  moderator1_lab_pw  moderator
    admin1      admin1_lab_pw      admin

Note: this migration intentionally imports the real `django.contrib.auth`
User model (rather than the historical `apps.get_model()` model) so that
`set_password()` is available - `auth.User` is a stable, framework-owned
model that is not expected to gain/lose fields under our own app's
migration history.
"""
from django.contrib.auth.models import User
from django.db import migrations

SEED_ACCOUNTS = [
    ("user1", "user1_lab_pw", "user"),
    ("moderator1", "moderator1_lab_pw", "moderator"),
    ("admin1", "admin1_lab_pw", "admin"),
]


def seed_users(apps, schema_editor):
    UserProfile = apps.get_model("labapp", "UserProfile")

    for username, password, role in SEED_ACCOUNTS:
        user, _ = User.objects.get_or_create(
            username=username,
            defaults={"email": f"{username}@example.invalid"},
        )
        user.set_password(password)
        user.save()

        # Assign via user_id (not user=user) because `user` is a real
        # django.contrib.auth.models.User instance while UserProfile here
        # is the historical migration-state model, whose `user` FK
        # descriptor expects an instance of the historical User model.
        UserProfile.objects.get_or_create(user_id=user.pk, defaults={"role": role})


def unseed_users(apps, schema_editor):
    usernames = [username for username, _, _ in SEED_ACCOUNTS]
    User.objects.filter(username__in=usernames).delete()


class Migration(migrations.Migration):

    dependencies = [
        ("labapp", "0001_initial"),
    ]

    operations = [
        migrations.RunPython(seed_users, unseed_users),
    ]
