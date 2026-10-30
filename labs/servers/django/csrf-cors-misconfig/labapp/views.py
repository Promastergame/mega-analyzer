"""
Views for the csrf-cors-misconfig lab server.

============================================================================
INTENTIONALLY VULNERABLE LAB SERVER (CWE-352) -- see README.md.
============================================================================

The bug lives in change_role_view below: it is decorated @csrf_exempt (with
the classic "just get it working" excuse comment right above it) even
though it performs a sensitive, state-changing privilege escalation. Paired
with labapp/middleware.py's wide-open CORS policy and this project's
weakened cookie flags (config/settings.py), a malicious page on ANY origin
can make an authenticated cross-site request -- riding the victim's
ambient session cookie -- to self-promote the victim (or, if the victim
happens to already be an admin, any account) to admin. No CSRF token is
ever checked.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import urllib.request
from datetime import datetime, timezone
from functools import wraps

from django.contrib.auth import authenticate, login
from django.contrib.auth.models import User
from django.http import HttpResponseForbidden, JsonResponse
from django.shortcuts import get_object_or_404
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST

from .models import UserProfile

logger = logging.getLogger("labapp")

# Fire-and-forget beacon POST must never block or fail the real HTTP
# response, so it always gets a short timeout and runs on its own thread.
BEACON_TIMEOUT_SECONDS = 2


def _beacon(event: dict) -> None:
    """Best-effort, non-blocking POST of `event` to TRACKER_URL, if set.

    Mirrors the beacon pattern used by sibling lab servers in this repo
    (e.g. labs/servers/go/admin-idor-role's `beacon` helper): always runs in
    its own daemon thread, short timeout, all errors swallowed. This is
    telemetry for the lab's own detection pipeline, never something the
    lab server's actual behavior should depend on.
    """
    url = os.environ.get("TRACKER_URL", "")
    if not url:
        return

    def _send() -> None:
        try:
            data = json.dumps(event).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=data,
                headers={
                    "Content-Type": "application/json",
                    "X-Beacon-Source": "labs-csrf-cors-misconfig",
                },
                method="POST",
            )
            urllib.request.urlopen(req, timeout=BEACON_TIMEOUT_SECONDS).close()
        except Exception:
            # Telemetry only; must never raise into the caller.
            pass

    threading.Thread(target=_send, daemon=True).start()


def _is_foreign_origin(request) -> bool:
    """True if the request carries an Origin header that is NOT our own
    127.0.0.1/localhost origin -- i.e. the request shape a real cross-site
    CSRF exploit produces (a browser only sends an Origin header at all for
    cross-origin/cross-site requests)."""
    origin = request.META.get("HTTP_ORIGIN", "")
    if not origin:
        return False
    return "127.0.0.1" not in origin and "localhost" not in origin


def json_login_required(view_func):
    """Like django.contrib.auth.decorators.login_required, but returns a
    plain 401 JSON body instead of redirecting to a login page -- this is a
    JSON API, not a server-rendered site."""

    @wraps(view_func)
    def _wrapped(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({"error": "authentication required"}, status=401)
        return view_func(request, *args, **kwargs)

    return _wrapped


def _get_or_create_profile(user: User) -> UserProfile:
    profile, _ = UserProfile.objects.get_or_create(user=user, defaults={"role": "user"})
    return profile


# NOTE: login_view is also exempted from CSRF. Unlike change_role_view
# below, that's a defensible, common pattern for a credential-based
# "obtain a session" endpoint on a pure JSON API with no prior page load to
# have handed out a CSRF token in the first place -- an attacker still
# needs the victim's real password to use it, CSRF alone gets them
# nothing. It is NOT the bug this lab is about.
@csrf_exempt
@require_POST
def login_view(request):
    """POST /login -- {"username": ..., "password": ...}. On success, logs
    the user in (Django sets the sessionid cookie) and returns their role.
    """
    try:
        body = json.loads(request.body or b"{}")
    except json.JSONDecodeError:
        return JsonResponse({"error": "bad request"}, status=400)

    username = body.get("username", "")
    password = body.get("password", "")

    user = authenticate(request, username=username, password=password)
    if user is None:
        return JsonResponse({"error": "invalid credentials"}, status=401)

    login(request, user)  # sets the (weakly-flagged, see settings.py) session cookie
    profile = _get_or_create_profile(user)

    return JsonResponse({"id": user.id, "username": user.username, "role": profile.role})


@json_login_required
@require_GET
def me_view(request):
    """GET /api/me -- returns the caller's own id/username/role."""
    profile = _get_or_create_profile(request.user)
    return JsonResponse({"id": request.user.id, "username": request.user.username, "role": profile.role})


# TEMP: exempted for the mobile app, TODO remove
#
# THIS is the bug (CWE-352). change_role_view performs a sensitive,
# state-changing privilege escalation (it can promote an account to
# "admin"), yet it never validates a CSRF token. Combined with
# labapp/middleware.py's wide-open CORS policy and this project's
# SESSION_COOKIE_SAMESITE=None (config/settings.py), a page on ANY origin
# can POST here with the victim's browser attaching their real session
# cookie automatically, and the request will be honored exactly as if the
# victim had clicked a legitimate "change my role" button themselves.
@csrf_exempt
@json_login_required
@require_POST
def change_role_view(request, id):
    """POST /api/users/<id>/role -- {"role": "user"|"moderator"|"admin"}.

    Authorization model: a caller may always change their OWN role (this
    endpoint doubles as innocuous self-service, e.g. imagine a "switch to
    limited mode" toggle), and an admin caller may change ANYONE's role.
    That's a reasonable-looking rule in isolation -- the vulnerability is
    NOT missing authorization, it's that @csrf_exempt above means none of
    this requires the caller to have actually intended the request:

      - If the victim is a normal user, a forged cross-site request
        promotes THEM (the "self" the request executes as) straight to
        admin -- a classic self-CSRF privilege escalation.
      - If the victim already happens to be logged in as an admin, the
        same forged request can retarget ANY account's role, because the
        admin branch of the authorization check is satisfied by the
        victim's ambient session.
    """
    try:
        body = json.loads(request.body or b"{}")
    except json.JSONDecodeError:
        return JsonResponse({"error": "bad request"}, status=400)

    new_role = body.get("role")
    if new_role not in dict(UserProfile.ROLE_CHOICES):
        return JsonResponse({"error": "invalid role"}, status=400)

    target_user = get_object_or_404(User, pk=id)
    caller_profile = _get_or_create_profile(request.user)

    is_self = target_user.id == request.user.id
    if not is_self and caller_profile.role != "admin":
        return JsonResponse({"error": "forbidden"}, status=403)

    target_profile = _get_or_create_profile(target_user)
    target_profile.role = new_role
    target_profile.save(update_fields=["role"])

    privileged = new_role in ("moderator", "admin")
    foreign_origin = _is_foreign_origin(request)

    if privileged and foreign_origin:
        origin = request.META.get("HTTP_ORIGIN", "")
        logger.warning(
            "[CSRF/CORS PRIVESC USED] origin=%s caller=%s(id=%s,role=%s) "
            "target=%s(id=%s) new_role=%s",
            origin,
            request.user.username,
            request.user.id,
            caller_profile.role,
            target_user.username,
            target_user.id,
            new_role,
        )
        _beacon(
            {
                "event": "csrf_cors_privesc",
                "origin": origin,
                "caller_id": request.user.id,
                "caller_username": request.user.username,
                "caller_role": caller_profile.role,
                "target_id": target_user.id,
                "target_username": target_user.username,
                "new_role": new_role,
                "self_change": is_self,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

    return JsonResponse({"id": target_user.id, "username": target_user.username, "role": new_role})


@json_login_required
@require_GET
def admin_dashboard(request):
    """GET /api/admin/dashboard -- role-gated: requires role == "admin"."""
    profile = _get_or_create_profile(request.user)
    if profile.role != "admin":
        return HttpResponseForbidden(
            json.dumps({"error": "forbidden"}), content_type="application/json"
        )

    users = [
        {"id": p.user.id, "username": p.user.username, "role": p.role}
        for p in UserProfile.objects.select_related("user").order_by("user__username")
    ]
    return JsonResponse({"dashboard": "admin", "users": users})
