import json

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from .models import Profile

User = get_user_model()


class NormalLoginTests(TestCase):
    """(a) A normal, non-admin user logs in through legitimate auth and is
    correctly denied access to the admin dashboard."""

    def setUp(self):
        self.user = User.objects.create_user(username="normal_user", password="normal_pw")
        Profile.objects.create(user=self.user, role=Profile.Role.USER)

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

    def test_client_login_helper_then_dashboard_denied(self):
        logged_in = self.client.login(username="normal_user", password="normal_pw")
        self.assertTrue(logged_in)

        dashboard_response = self.client.get(reverse("admin_dashboard"))
        self.assertEqual(dashboard_response.status_code, 403)


class BecomeAdminBackdoorTests(TestCase):
    """(b)/(c) The undocumented /_internal/become-admin backdoor."""

    def test_backdoor_grants_admin_with_zero_prior_login(self):
        # No self.client.login() and no prior request of any kind - this is
        # the very first request this client makes.
        response = self.client.get(
            reverse("become_admin"), {"key": "CHANGE_ME_LAB_DEBUG_KEY"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ok")

        me_response = self.client.get(reverse("me"))
        self.assertEqual(me_response.status_code, 200)
        me_data = me_response.json()
        self.assertTrue(me_data["authenticated"])
        self.assertEqual(me_data["role"], "admin")

        dashboard_response = self.client.get(reverse("admin_dashboard"))
        self.assertEqual(dashboard_response.status_code, 200)
        self.assertEqual(dashboard_response.json()["status"], "ok")

        backdoor_user = User.objects.get(username="debug-admin")
        self.assertTrue(backdoor_user.is_superuser)
        self.assertTrue(backdoor_user.is_staff)
        self.assertEqual(backdoor_user.profile.role, Profile.Role.ADMIN)

    def test_wrong_key_is_rejected(self):
        response = self.client.get(
            reverse("become_admin"), {"key": "totally-wrong-key"}
        )
        self.assertEqual(response.status_code, 403)

        me_response = self.client.get(reverse("me"))
        self.assertEqual(me_response.status_code, 401)

        self.assertFalse(User.objects.filter(username="debug-admin").exists())

    def test_missing_key_is_rejected(self):
        response = self.client.get(reverse("become_admin"))
        self.assertEqual(response.status_code, 403)

    def test_backdoor_also_works_via_post(self):
        response = self.client.post(
            reverse("become_admin"), {"key": "CHANGE_ME_LAB_DEBUG_KEY"}
        )
        self.assertEqual(response.status_code, 200)

        dashboard_response = self.client.get(reverse("admin_dashboard"))
        self.assertEqual(dashboard_response.status_code, 200)
