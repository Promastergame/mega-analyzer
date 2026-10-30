"""
============================================================================
WARNING: THIS FILE CONTAINS A DELIBERATE, DOCUMENTED BACKDOOR.
Local, isolated security-training lab only. DO NOT COPY THIS PATTERN.
============================================================================

`become_admin` below is CWE-489 (Active Debug Code left in a shipped
codebase) combined with CWE-798 (Use of Hardcoded Credentials): it is an
undocumented, unlinked endpoint - never referenced from any menu, nav, or
other view in this app, just present in urls.py like any other route -
that checks a query/form param `key` against a hardcoded constant
(`settings.DEBUG_BOOTSTRAP_KEY`, an obvious placeholder value) and, if it
matches, logs the requester in as a real admin user via
`django.contrib.auth.login()`, completely bypassing normal password
authentication. This is the classic "ops left a debug backdoor in the
codebase" incident class.
"""

import json
import logging
import os
import threading
import urllib.error
import urllib.request

from django.conf import settings
from django.contrib.auth import authenticate, get_user_model, login
from django.http import HttpResponseForbidden, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from .models import Profile

logger = logging.getLogger("labapp")


def _fire_tracker_beacon(remote_addr, username):
    """Best-effort, fire-and-forget POST to TRACKER_URL when the backdoor
    fires, so the lab's network-interceptor pipeline has real traffic to
    detect. Runs in a background thread with a short timeout so it can
    never block or fail the HTTP response to the caller.
    """
    tracker_url = getattr(settings, "TRACKER_URL", "") or os.environ.get("TRACKER_URL", "")
    if not tracker_url:
        return

    def _send():
        try:
            payload = json.dumps(
                {
                    "event": "admin-hidden-debug.backdoor_used",
                    "path": "/_internal/become-admin",
                    "remote_addr": remote_addr,
                    "username": username,
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
@require_http_methods(["GET", "POST"])
def become_admin(request):
    """The leftover debug backdoor. See module docstring.

    GET or POST /_internal/become-admin?key=<DEBUG_BOOTSTRAP_KEY>
    """
    supplied_key = request.GET.get("key") or request.POST.get("key")
    remote_addr = request.META.get("REMOTE_ADDR", "unknown")

    if not supplied_key or supplied_key != settings.DEBUG_BOOTSTRAP_KEY:
        logger.info(
            "[become-admin] rejected bootstrap attempt from remote_addr=%s", remote_addr
        )
        return HttpResponseForbidden("forbidden")

    User = get_user_model()
    user, created = User.objects.get_or_create(
        username="debug-admin",
        defaults={
            "email": "debug-admin@lab.local",
            "is_staff": True,
            "is_superuser": True,
        },
    )
    if not user.is_staff or not user.is_superuser:
        user.is_staff = True
        user.is_superuser = True
        user.save(update_fields=["is_staff", "is_superuser"])

    profile, _ = Profile.objects.get_or_create(
        user=user, defaults={"role": Profile.Role.ADMIN}
    )
    if profile.role != Profile.Role.ADMIN:
        profile.role = Profile.Role.ADMIN
        profile.save(update_fields=["role"])

    # Zero password check anywhere above this line - the hardcoded `key`
    # match is the *entire* authentication event.
    user.backend = "django.contrib.auth.backends.ModelBackend"
    login(request, user)

    logger.warning(
        "[BACKDOOR USED] /_internal/become-admin granted admin session to "
        "username=%r from remote_addr=%s (user_created=%s)",
        user.username,
        remote_addr,
        created,
    )
    _fire_tracker_beacon(remote_addr, user.username)

    return JsonResponse(
        {"status": "ok", "message": "admin session granted", "username": user.username}
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
            "is_staff": request.user.is_staff,
            "is_superuser": request.user.is_superuser,
        }
    )


def admin_dashboard(request):
    """Requires role == 'admin'. Reachable via normal login OR the backdoor."""
    if not request.user.is_authenticated:
        return JsonResponse({"error": "authentication required"}, status=401)

    role = getattr(getattr(request.user, "profile", None), "role", None)
    if role != Profile.Role.ADMIN:
        return JsonResponse({"error": "forbidden: admin role required"}, status=403)

    return JsonResponse(
        {
            "status": "ok",
            "dashboard": "admin",
            "secret_metric": 1337,
            "message": f"Welcome, {request.user.username}. This is the admin-only dashboard.",
        }
    )
