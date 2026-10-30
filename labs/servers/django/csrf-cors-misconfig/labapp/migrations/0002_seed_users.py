"""
Data migration seeding the lab's user/moderator/admin accounts.

Seed users. Plaintext seed passwords (FAKE, LOCAL-LAB-ONLY credentials --
never used anywhere else, safe to document in plaintext here for lab
setup):

    user:      alice-user  / alice-plaintext-pw123
    moderator: mod-morgan  / morgan-plaintext-pw123
    admin:     root-admin  / admin-plaintext-pw123

NOTE: this migration intentionally imports the *real*
django.contrib.auth.models.User (rather than the historical
apps.get_model("auth", "User")) so it can call the real set_password()
hasher method as requested for this lab's seed data. Using the concrete
model instead of the historical migration state is a known anti-pattern
for large/long-lived projects (a future change to auth.User's schema could
break this migration when replayed from scratch), but it's safe and
simplest for this small, static lab fixture.
"""
from django.contrib.auth.models import User
from django.db import migrations

SEED_USERS = [
    ("alice-user", "alice-plaintext-pw123", "user"),
    ("mod-morgan", "morgan-plaintext-pw123", "moderator"),
    ("root-admin", "admin-plaintext-pw123", "admin"),
]


def seed_users(apps, schema_editor):
    UserProfile = apps.get_model("labapp", "UserProfile")

    for username, password, role in SEED_USERS:
        user, created = User.objects.get_or_create(username=username)
        if created or not user.has_usable_password():
            user.set_password(password)
            user.save()
        UserProfile.objects.get_or_create(user_id=user.id, defaults={"role": role})


def unseed_users(apps, schema_editor):
    usernames = [username for username, _password, _role in SEED_USERS]
    User.objects.filter(username__in=usernames).delete()


class Migration(migrations.Migration):

    dependencies = [
        ("labapp", "0001_initial"),
    ]

    operations = [
        migrations.RunPython(seed_users, unseed_users),
    ]
