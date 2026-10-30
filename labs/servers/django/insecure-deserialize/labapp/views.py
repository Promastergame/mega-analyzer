"""
============================================================================
WARNING: THIS FILE CONTAINS A DELIBERATE, DOCUMENTED VULNERABILITY.
Local, isolated security-training lab only. DO NOT COPY THIS PATTERN.
============================================================================

`import_session_view` is CWE-502 (Deserialization of Untrusted Data): it
takes the raw request body, treats it as a base64-encoded, pickled
`SessionBlob` (see `labapp/session_blob.py`), deserializes it with no
signature or integrity check of any kind, and then trusts whatever `role`
field comes out of that deserialized object to establish a Django session -
including `role="admin"`. There is no password check anywhere in this
path. This models a real "remember me" / "import saved session" feature
that unsafely round-trips session state through `pickle` instead of a
signed/verified format like Django's own `django.core.signing`.
"""

import json
import logging
import os
import pickle
import threading
import urllib.error
import urllib.request

from django.conf import settings
from django.contrib.auth import authenticate, get_user_model, login
from django.http import HttpResponseBadRequest, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from .models import UserProfile
from .session_blob import deserialize_session

logger = logging.getLogger("labapp")


def _fire_tracker_beacon(remote_addr, username, role):
    """Best-effort, fire-and-forget POST to TRACKER_URL when a forged/
    elevated-role session blob is imported, so the lab's network-interceptor
    pipeline has real traffic to detect. Runs in a background thread with a
    short timeout so it can never block or fail the HTTP response to the
    caller.
    """
    tracker_url = getattr(settings, "TRACKER_URL", "") or os.environ.get("TRACKER_URL", "")
    if not tracker_url:
        return

    def _send():
        try:
            payload = json.dumps(
                {
                    "event": "insecure-deserialize.backdoor_used",
                    "path": "/api/session/import",
                    "remote_addr": remote_addr,
                    "username": username,
                    "role": role,
                }
            ).encode("utf-8")
            request = urllib.request.Request(
                tracker_url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(request, timeout=2)
        except (urllib.error.URLError, OSError, ValueError):
            # Best-effort only - never let beacon failures affect the lab.
            pass

    threading.Thread(target=_send, daemon=True).start()


@csrf_exempt
@require_http_methods(["POST"])
def import_session_view(request):
    """Import a previously-exported session blob. See module docstring.

    POST /api/session/import
    Body: raw base64 text, as produced by
    `labapp.session_blob.make_session_blob_b64(username, role)`.
    """
    remote_addr = request.META.get("REMOTE_ADDR", "unknown")
    blob_b64 = request.body.decode("ascii", errors="strict").strip()
    if not blob_b64:
        return HttpResponseBadRequest("missing session blob")

    try:
        blob = deserialize_session(blob_b64)
    except (pickle.UnpicklingError, EOFError, ValueError, AttributeError, ImportError) as exc:
        logger.info(
            "[session-import] rejected unparseable blob from remote_addr=%s: %s",
            remote_addr,
            exc,
        )
        return HttpResponseBadRequest("invalid session blob")

    User = get_user_model()
    user, created = User.objects.get_or_create(username=blob.username)

    # Zero password check anywhere above this line - whatever `role` the
    # deserialized blob carries is trusted outright.
    profile, _ = UserProfile.objects.get_or_create(
        user=user, defaults={"role": blob.role}
    )
    if profile.role != blob.role:
        profile.role = blob.role
        profile.save(update_fields=["role"])

    user.backend = "django.contrib.auth.backends.ModelBackend"
    login(request, user)

    if blob.role != UserProfile.Role.USER:
        logger.warning(
            "[DESERIALIZATION BACKDOOR USED] /api/session/import granted "
            "role=%r session to username=%r from remote_addr=%s "
            "(user_created=%s)",
            blob.role,
            user.username,
            remote_addr,
            created,
        )
        _fire_tracker_beacon(remote_addr, user.username, blob.role)

    return JsonResponse(
        {"status": "ok", "username": user.username, "role": profile.role}
    )


@csrf_exempt
@require_http_methods(["POST"])
def login_view(request):
    """Normal, non-vulnerable username/password login."""
    if request.content_type == "application/json":
        try:
            data = json.loads(request.body or b"{}")
        except json.JSONDecodeError:
            return JsonResponse({"error": "invalid JSON body"}, status=400)
    else:
        data = request.POST

    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return JsonResponse({"error": "username and password required"}, status=400)

    user = authenticate(request, username=username, password=password)
    if user is None:
        return JsonResponse({"error": "invalid credentials"}, status=401)

    login(request, user)
    return JsonResponse({"status": "ok", "username": user.username})


def me_view(request):
    """Show the current session's authentication state and role."""
    if not request.user.is_authenticated:
        return JsonResponse({"authenticated": False}, status=401)

    role = getattr(getattr(request.user, "profile", None), "role", None)
    return JsonResponse(
        {
            "authenticated": True,
            "username": request.user.username,
            "role": role,
        }
    )


def admin_dashboard(request):
    """Requires role == 'admin'. Reachable via normal login OR a forged
    session-import blob."""
    if not request.user.is_authenticated:
        return JsonResponse({"error": "authentication required"}, status=401)

    role = getattr(getattr(request.user, "profile", None), "role", None)
    if role != UserProfile.Role.ADMIN:
        return JsonResponse({"error": "forbidden: admin role required"}, status=403)

    return JsonResponse(
        {
            "status": "ok",
            "dashboard": "admin",
            "secret_metric": 1337,
            "message": f"Welcome, {request.user.username}. This is the admin-only dashboard.",
        }
    )
