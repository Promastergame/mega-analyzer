"""
Tests for the csrf-cors-misconfig lab server.

INTENTIONALLY VULNERABLE LAB SERVER (CWE-352). See README.md.

These tests document the two halves of the vulnerability this lab exists to
demonstrate:

  (a) ChangeRoleCsrfExemptTest -- the KEY proof. A Client with
      enforce_csrf_checks=True behaves like a real browser: any POST
      missing a valid CSRF token is normally rejected with 403. Here it
      succeeds anyway, because change_role_view is decorated @csrf_exempt.
      This test needs a real database (it creates a User + UserProfile and
      asserts the row actually changed).

  (b) PermissiveCorsHeaderTest -- a lighter test asserting that
      Access-Control-Allow-Origin: * and Access-Control-Allow-Credentials:
      true appear TOGETHER on a response. That specific header pairing is
      the actual browser-exploitable CORS misconfiguration: it is what
      lets a credentialed cross-origin request be sent (and its
      side-effects take place) from any origin in the first place.
"""
import json

from django.contrib.auth.models import User
from django.test import Client, TestCase

from labapp.models import UserProfile


class ChangeRoleCsrfExemptTest(TestCase):
    """KEY PROOF of the CWE-352 bug: change_role_view is reachable via POST
    with a real, CSRF-enforcing client and NO CSRF token at all -- exactly
    what a forged cross-site <form>/fetch() request would send. A properly
    protected endpoint would reject this with 403 "CSRF verification
    failed"; instead it succeeds and the role change is persisted.
    """

    def setUp(self):
        # The 0002_seed_users migration already seeds alice-user, so
        # get_or_create keeps this idempotent instead of colliding.
        self.user, _ = User.objects.get_or_create(username="alice-user")
        self.user.set_password("alice-plaintext-pw123")
        self.user.save()
        self.profile, _ = UserProfile.objects.get_or_create(
            user=self.user, defaults={"role": "user"}
        )
        self.profile.role = "user"
        self.profile.save()
        # enforce_csrf_checks=True makes this Client behave like a real
        # browser instead of the (CSRF-blind) default test Client.
        self.client = Client(enforce_csrf_checks=True)
        self.client.force_login(self.user)

    def test_change_role_succeeds_without_csrf_token(self):
        self.assertEqual(self.profile.role, "user")

        resp = self.client.post(
            f"/api/users/{self.user.id}/role",
            data=json.dumps({"role": "admin"}),
            content_type="application/json",
            # Deliberately NOT sending an X-CSRFToken header or csrfmiddlewaretoken
            # field -- a correctly-CSRF-protected view would 403 this.
        )

        self.assertEqual(resp.status_code, 200, resp.content)
        self.profile.refresh_from_db()
        self.assertEqual(self.profile.role, "admin")

    def test_control_other_endpoints_still_enforce_csrf(self):
        """Sanity control: a hypothetical CSRF-protected POST endpoint on
        this same project (login_view is also intentionally exempted here,
        so we can't use it as the control -- but Django's CSRF middleware
        is demonstrably active) will reject an unrelated admin POST made
        without a token, showing CsrfViewMiddleware is on and would have
        blocked change_role_view too had it not been @csrf_exempt.
        """
        resp = self.client.post(
            "/admin/login/",
            data={"username": "alice-user", "password": "alice-plaintext-pw123"},
        )
        # Django admin login enforces CSRF; without a token this is a 403,
        # in contrast with the 200 change_role_view returned above.
        self.assertEqual(resp.status_code, 403)


class PermissiveCorsHeaderTest(TestCase):
    """The actual browser-exploitable misconfiguration is this exact header
    PAIR appearing together on a response:

        Access-Control-Allow-Origin: *
        Access-Control-Allow-Credentials: true

    Per the Fetch/CORS spec this combination is supposed to be invalid for
    credentialed requests (a wildcard origin should never be paired with
    Allow-Credentials: true), but labapp/middleware.py sets both anyway --
    that is the literal misconfiguration this lab exists to reproduce, and
    is what a network-capture pipeline should be able to flag directly from
    response headers alone, no request body needed.
    """

    def test_cors_headers_present_together(self):
        client = Client()
        resp = client.get("/api/me", HTTP_ORIGIN="https://evil.example")

        self.assertEqual(resp["Access-Control-Allow-Origin"], "*")
        self.assertEqual(resp["Access-Control-Allow-Credentials"], "true")

    def test_cors_headers_present_on_state_changing_endpoint_too(self):
        """Same header pair on the vulnerable POST endpoint itself -- this
        is the response an attacker's cross-origin fetch() would actually
        receive (even if, per spec, a strict browser might refuse to let
        the attacker's JS *read* the body; the state change already
        happened server-side by the time this response is produced)."""
        user, _ = User.objects.get_or_create(username="mod-morgan")
        user.set_password("morgan-plaintext-pw123")
        user.save()
        UserProfile.objects.get_or_create(user=user, defaults={"role": "user"})

        client = Client()
        client.force_login(user)
        resp = client.post(
            f"/api/users/{user.id}/role",
            data=json.dumps({"role": "admin"}),
            content_type="application/json",
            HTTP_ORIGIN="https://evil.example",
        )

        self.assertEqual(resp.status_code, 200, resp.content)
        self.assertEqual(resp["Access-Control-Allow-Origin"], "*")
        self.assertEqual(resp["Access-Control-Allow-Credentials"], "true")
