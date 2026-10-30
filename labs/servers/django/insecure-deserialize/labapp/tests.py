import json

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from .models import UserProfile
from .session_blob import SessionBlob, deserialize_session, make_session_blob_b64

User = get_user_model()


class SessionBlobRoundTripTests(TestCase):
    """(a) Pure unit test, no DB involved: proves the trust boundary is
    broken by the (de)serialization helpers alone, with zero login."""

    def test_round_trip_preserves_forged_admin_role(self):
        blob_b64 = make_session_blob_b64("attacker", "admin")
        blob = deserialize_session(blob_b64)

        self.assertIsInstance(blob, SessionBlob)
        self.assertEqual(blob.username, "attacker")
        self.assertEqual(blob.role, "admin")


class NormalLoginTests(TestCase):
    """A normal, non-admin user logs in through legitimate auth and is
    correctly denied access to the admin dashboard."""

    def setUp(self):
        self.user = User.objects.create_user(username="normal_user", password="normal_pw")
        UserProfile.objects.create(user=self.user, role=UserProfile.Role.USER)

    def test_login_view_then_dashboard_denied(self):
        response = self.client.post(
            reverse("login"),
            data=json.dumps({"username": "normal_user", "password": "normal_pw"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["username"], "normal_user")

        me_response = self.client.get(reverse("me"))
        self.assertEqual(me_response.status_code, 200)
        me_data = me_response.json()
        self.assertTrue(me_data["authenticated"])
        self.assertEqual(me_data["role"], "user")

        dashboard_response = self.client.get(reverse("admin_dashboard"))
        self.assertEqual(dashboard_response.status_code, 403)


class SessionImportBackdoorTests(TestCase):
    """(b) DB-backed: POSTing a forged admin session blob to
    /api/session/import grants admin access with zero prior authentication.
    """

    def test_forged_admin_blob_grants_admin_with_zero_prior_login(self):
        # No self.client.login() and no prior request of any kind - this is
        # the very first request this client makes.
        forged_blob_b64 = make_session_blob_b64("attacker", "admin")

        response = self.client.post(
            reverse("import_session"),
            data=forged_blob_b64,
            content_type="text/plain",
        )
        self.assertEqual(response.status_code, 200)
        response_data = response.json()
        self.assertEqual(response_data["status"], "ok")
        self.assertEqual(response_data["username"], "attacker")
        self.assertEqual(response_data["role"], "admin")

        me_response = self.client.get(reverse("me"))
        self.assertEqual(me_response.status_code, 200)
        me_data = me_response.json()
        self.assertTrue(me_data["authenticated"])
        self.assertEqual(me_data["username"], "attacker")
        self.assertEqual(me_data["role"], "admin")

        dashboard_response = self.client.get(reverse("admin_dashboard"))
        self.assertEqual(dashboard_response.status_code, 200)
        self.assertEqual(dashboard_response.json()["status"], "ok")

        forged_user = User.objects.get(username="attacker")
        self.assertEqual(forged_user.profile.role, UserProfile.Role.ADMIN)

    def test_forged_moderator_blob_denied_admin_dashboard(self):
        forged_blob_b64 = make_session_blob_b64("attacker2", "moderator")

        response = self.client.post(
            reverse("import_session"),
            data=forged_blob_b64,
            content_type="text/plain",
        )
        self.assertEqual(response.status_code, 200)

        dashboard_response = self.client.get(reverse("admin_dashboard"))
        self.assertEqual(dashboard_response.status_code, 403)

    def test_garbage_blob_is_rejected(self):
        response = self.client.post(
            reverse("import_session"),
            data="not-valid-base64-pickle-data!!!",
            content_type="text/plain",
        )
        self.assertEqual(response.status_code, 400)

        me_response = self.client.get(reverse("me"))
        self.assertEqual(me_response.status_code, 401)
