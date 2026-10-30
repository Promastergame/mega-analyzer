"""
Best-effort beacon to the local trackercollector lab sink.

INTENTIONALLY VULNERABLE LAB SERVER (CWE-89). See README.md.

This exists purely so the mega-analyzer network-interceptor pipeline has
something to observe when a suspicious request comes in. It must never
block or fail the real HTTP response, so it always runs fire-and-forget in
a background thread with a short timeout and swallows all errors.
"""
import json
import logging
import threading
import urllib.request

from django.conf import settings

logger = logging.getLogger("labapp")

_TRACKER_TIMEOUT_SECONDS = 1.5


def _post(url: str, payload: dict) -> None:
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=_TRACKER_TIMEOUT_SECONDS).read()
    except Exception:  # noqa: BLE001 - best-effort, never allowed to raise
        logger.debug("[SQLI SUSPECTED] tracker beacon failed", exc_info=True)


def beacon(event: str, **fields) -> None:
    """Fire a fire-and-forget POST to TRACKER_URL, if configured.

    Never blocks the caller: the network request happens in a daemon
    thread, and any failure (unreachable, timeout, DNS, ...) is swallowed.
    """
    url = getattr(settings, "TRACKER_URL", "") or ""
    if not url:
        return

    payload = {"event": event, **fields}
    thread = threading.Thread(target=_post, args=(url, payload), daemon=True)
    thread.start()
