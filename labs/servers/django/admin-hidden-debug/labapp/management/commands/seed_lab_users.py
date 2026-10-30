"""Idempotently (re)seed the lab's demo user/moderator/admin accounts.

`labapp/migrations/0002_seed.py` already seeds these accounts automatically
on `python manage.py migrate`. This command does the same seeding against
*real* model instances (not historical migration state), so it can use
`User.set_password(...)` directly and is handy for resetting the demo
passwords without a full migrate/reset cycle.

Intentionally fake, publicly-documented lab credentials - never do this in
production.
"""

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from django.db import transaction

from labapp.models import Profile

# (username, plaintext password, role, is_staff, is_superuser)
SEED_ACCOUNTS = [
    ("alice", "alice_lab_pw", Profile.Role.USER, False, False),
    ("mod_bob", "mod_bob_lab_pw", Profile.Role.MODERATOR, False, False),
    ("root_admin", "root_admin_lab_pw", Profile.Role.ADMIN, True, True),
]


class Command(BaseCommand):
    help = (
        "Seed lab demo accounts (user/moderator/admin) with documented, "
        "intentionally fake plaintext passwords. Lab-only, never for "
        "production use."
    )

    @transaction.atomic
    def handle(self, *args, **options):
        User = get_user_model()
        for username, password, role, is_staff, is_superuser in SEED_ACCOUNTS:
            user, created = User.objects.get_or_create(
                username=username,
                defaults={
                    "email": f"{username}@lab.local",
                    "is_staff": is_staff,
                    "is_superuser": is_superuser,
                },
            )
            user.set_password(password)
            user.is_staff = is_staff
            user.is_superuser = is_superuser
            user.save()

            Profile.objects.update_or_create(user=user, defaults={"role": role})

            state = "created" if created else "updated"
            self.stdout.write(
                self.style.SUCCESS(
                    f"{state} {username} (role={role}, password={password!r})"
                )
            )
