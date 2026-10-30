"""Tests for the tracker-beacon lab server.

These tests exist to document and pin down the intentional vulnerability:
undisclosed telemetry fired on login and on note creation. They mock the
network boundary (`labapp.beacon.send_beacon` / `urllib.request.urlopen`)
so the suite never makes a real network call and never depends on the
trackercollector service actually running.
"""

import json
from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import Client, TestCase

from labapp.beacon import _post_beacon
from labapp.models import Note


class LoginBeaconTests(TestCase):
    def setUp(self):
        self.password = "correct horse battery staple"
        self.user = User.objects.create_user(
            username="alice", password=self.password
        )
        self.client = Client()

    @patch("labapp.views.send_beacon")
    def test_login_triggers_exactly_one_login_beacon(self, mock_send_beacon):
        response = self.client.post(
            "/login",
            data=json.dumps({"username": "alice", "password": self.password}),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        mock_send_beacon.assert_called_once()

        event, payload = mock_send_beacon.call_args.args
        self.assertEqual(event, "login")
        self.assertEqual(payload["username"], "alice")
        self.assertIn("ip", payload)
        self.assertIn("user_agent", payload)

    @patch("labapp.views.send_beacon")
    def test_failed_login_does_not_beacon(self, mock_send_beacon):
        response = self.client.post(
            "/login",
            data=json.dumps({"username": "alice", "password": "wrong"}),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 401)
        mock_send_beacon.assert_not_called()


class NoteBeaconTests(TestCase):
    def setUp(self):
        self.password = "correct horse battery staple"
        self.user = User.objects.create_user(
            username="bob", password=self.password
        )
        self.client = Client()
        self.client.force_login(self.user)

    @patch("labapp.views.send_beacon")
    def test_creating_note_beacons_full_note_body(self, mock_send_beacon):
        secret_body = "meet me at the docks at midnight, tell no one"

        response = self.client.post(
            "/api/notes",
            data=json.dumps({"title": "reminder", "body": secret_body}),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(Note.objects.count(), 1)

        mock_send_beacon.assert_called_once()
        event, payload = mock_send_beacon.call_args.args
        self.assertEqual(event, "note_created")
        # Documents the over-sharing: the full note body is present in
        # the telemetry payload, undisclosed to the user.
        self.assertEqual(payload["body"], secret_body)
        self.assertEqual(payload["username"], "bob")

    def test_notes_list_requires_authentication(self):
        anon_client = Client()
        response = anon_client.get("/api/notes")
        self.assertEqual(response.status_code, 401)


class BeaconDegradesGracefullyTests(TestCase):
    """Proves the beacon transport never raises even when the collector
    is unreachable — e.g. because labdns has sinkholed tracker.lab.local
    or the collector process is simply down. No real network or DB use
    beyond what TestCase already sets up."""

    @patch("urllib.request.urlopen", side_effect=OSError("connection refused"))
    def test_post_beacon_swallows_connection_errors(self, mock_urlopen):
        try:
            _post_beacon(
                "http://tracker.lab.local:18099/beacon/tracker-beacon",
                "login",
                {"username": "alice"},
            )
        except Exception as exc:  # pragma: no cover - failure path
            self.fail(f"_post_beacon raised unexpectedly: {exc}")

        mock_urlopen.assert_called_once()

    @patch(
        "urllib.request.urlopen",
        side_effect=TimeoutError("timed out"),
    )
    def test_post_beacon_swallows_timeouts(self, mock_urlopen):
        try:
            _post_beacon(
                "http://tracker.lab.local:18099/beacon/tracker-beacon",
                "note_created",
                {"body": "irrelevant"},
            )
        except Exception as exc:  # pragma: no cover - failure path
            self.fail(f"_post_beacon raised unexpectedly: {exc}")
