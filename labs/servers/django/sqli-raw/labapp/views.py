"""
Views for the sqli-raw lab server.

INTENTIONALLY VULNERABLE LAB SERVER (CWE-89). See README.md.

`search_view` is the vulnerable endpoint: it hands attacker-controlled
`username` straight to labapp.queries.build_search_query(), which splices
it into a raw SQL string with an f-string instead of using .raw(sql,
params). A UNION-based payload lets an attacker force role='admin' into
the first result row, which this view then treats as "the account the
caller searched for / is now acting as" and stores in the session.
"""
import logging

from django.contrib.auth.models import User
from django.http import JsonResponse

from .models import UserProfile
from .queries import build_search_query
from .tracker import beacon

logger = logging.getLogger("labapp")

# Crude signature used only to decide whether to log/beacon loudly; it is
# NOT a defense and does not affect whether the query below is vulnerable.
_SQLI_SIGNATURES = ("'", "--", "union")


def _looks_like_sqli(value: str) -> bool:
    lowered = (value or "").lower()
    return any(sig in lowered for sig in _SQLI_SIGNATURES)


def _maybe_report_sqli(request, username: str) -> None:
    if not _looks_like_sqli(username):
        return
    logger.warning(
        "[SQLI SUSPECTED] suspicious username parameter on /search: %r "
        "(remote_addr=%s)",
        username,
        request.META.get("REMOTE_ADDR"),
    )
    beacon(
        "sqli_suspected",
        endpoint="/search",
        param="username",
        value=username,
        remote_addr=request.META.get("REMOTE_ADDR"),
    )


def search_view(request):
    """GET /search?username=<value>

    # INTENTIONALLY VULNERABLE: executes an unparameterized raw SQL string
    # built by labapp.queries.build_search_query(). See that module for the
    # full explanation and exploit payload.
    """
    username = request.GET.get("username", "")
    _maybe_report_sqli(request, username)

    sql = build_search_query(username)
    if _looks_like_sqli(username):
        logger.info("[SQLI SUSPECTED] executing raw SQL: %s", sql)

    try:
        rows = list(UserProfile.objects.raw(sql))
    except Exception as exc:  # noqa: BLE001 - surfaced to the caller on purpose
        logger.warning("[SQLI SUSPECTED] raw query failed: %s", exc)
        return JsonResponse({"error": "query failed", "detail": str(exc)}, status=400)

    if not rows:
        return JsonResponse({"found": False}, status=404)

    row = rows[0]
    result = {
        "id": row.id,
        "username": row.username,
        "role": row.role,
    }

    # Simulate "logging in as" whatever the raw query returned first - this
    # is what lets the SQL injection above escalate to impersonation/role
    # forgery: the session below trusts row.role verbatim.
    request.session["username"] = result["username"]
    request.session["role"] = result["role"]

    return JsonResponse({"found": True, "user": result})


def me_view(request):
    """GET /api/me - returns the identity currently stored in the session
    (as set by search_view), or 401 if nobody has "searched"/"logged in"
    yet in this session."""
    username = request.session.get("username")
    role = request.session.get("role")
    if not username:
        return JsonResponse({"error": "not authenticated"}, status=401)
    return JsonResponse({"username": username, "role": role})


def admin_dashboard(request):
    """GET /api/admin/dashboard - role-gated on the session role set by
    search_view. Because that role can be forged via the SQL injection in
    search_view, this endpoint is reachable by any anonymous caller who
    supplies the right UNION payload to /search first."""
    role = request.session.get("role")
    if role != UserProfile.ROLE_ADMIN:
        return JsonResponse({"error": "forbidden"}, status=403)

    usernames = list(User.objects.values_list("username", flat=True))
    return JsonResponse(
        {
            "dashboard": "admin",
            "message": "welcome, admin",
            "all_usernames": usernames,
        }
    )
