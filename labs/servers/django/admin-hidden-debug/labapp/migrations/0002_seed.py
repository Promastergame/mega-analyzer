"""Data migration: seed demo user/moderator/admin accounts.

These are intentionally fake, publicly-documented lab credentials - not a
bug, this is standard Django practice for seeding demo/fixture data via a
data migration. See README.md for the full, documented account list.

Note: data migrations receive *historical* model classes from
`apps.get_model(...)`, which only carry fields, not the custom methods
defined on the real model class (e.g. `AbstractBaseUser.set_password`).
We therefore hash passwords with `django.contrib.auth.hashers.make_password`
directly, which is the standard, documented way to set a password in a
data migration. For the same seeding logic against real model instances
(so `set_password()` itself can be used), see the equivalent
`python manage.py seed_lab_users` management command.
"""

from django.contrib.auth.hashers import make_password
from django.db import migrations

# (username, plaintext password, role, is_staff, is_superuser)
SEED_ACCOUNTS = [
    ("alice", "alice_lab_pw", "user", False, False),
    ("mod_bob", "mod_bob_lab_pw", "moderator", False, False),
    ("root_admin", "root_admin_lab_pw", "admin", True, True),
]


def seed_users(apps, schema_editor):
    User = apps.get_model("auth", "User")
    Profile = apps.get_model("labapp", "Profile")

    for username, password, role, is_staff, is_superuser in SEED_ACCOUNTS:
        user, _ = User.objects.get_or_create(
            username=username,
            defaults={
                "email": f"{username}@lab.local",
                "is_staff": is_staff,
                "is_superuser": is_superuser,
                "password": make_password(password),
            },
        )
        Profile.objects.get_or_create(user=user, defaults={"role": role})


def unseed_users(apps, schema_editor):
    User = apps.get_model("auth", "User")
    User.objects.filter(username__in=[account[0] for account in SEED_ACCOUNTS]).delete()


class Migration(migrations.Migration):

    dependencies = [
        ("labapp", "0001_initial"),
    ]

    operations = [
        migrations.RunPython(seed_users, unseed_users),
    ]
