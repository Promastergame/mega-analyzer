"""Views for the tracker-beacon lab server.

INTENTIONALLY VULNERABLE LAB CODE. `login_view` and
`notes_list_create_view` both fire an async "analytics" beacon (see
labapp/beacon.py) carrying more data than the user consented to —
username, IP, User-Agent, and (for notes) the full note body. That
undisclosed telemetry is the vulnerability under test in this lab.
"""

from __future__ import annotations

import json

from django.contrib.auth import authenticate, login
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from .beacon import send_beacon
from .models import Note


def _client_ip(request) -> str:
    # Deliberately naive: trusts X-Forwarded-For if present, otherwise
    # falls back to REMOTE_ADDR. Fine for a local lab.
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "")


@csrf_exempt
@require_http_methods(["POST"])
def login_view(request):
    """Authenticate a user and log them in.

    On success, fires a beacon reporting the username, source IP, and
    User-Agent of the login — none of which the user was told would be
    shipped to a third-party analytics endpoint.
    """
    try:
        data = json.loads(request.body or b"{}")
    except json.JSONDecodeError:
        data = request.POST

    username = data.get("username", "")
    password = data.get("password", "")

    user = authenticate(request, username=username, password=password)
    if user is None:
        return JsonResponse({"error": "invalid credentials"}, status=401)

    login(request, user)

    # This is the "phone home" beacon the lab's DNS-blocking exercise
    # targets — it over-shares on every successful login.
    send_beacon(
        "login",
        {
            "username": user.username,
            "ip": _client_ip(request),
            "user_agent": request.META.get("HTTP_USER_AGENT", ""),
        },
    )

    return JsonResponse({"status": "ok", "username": user.username})


@require_http_methods(["GET", "POST"])
def notes_list_create_view(request):
    """GET: list the current user's notes. POST: create a note.

    Note creation fires a beacon that includes the full note body —
    deliberately over-sharing private note content to the analytics
    endpoint. That's the point of this lab.
    """
    if not request.user.is_authenticated:
        return JsonResponse({"error": "authentication required"}, status=401)

    if request.method == "GET":
        notes = Note.objects.filter(user=request.user).values(
            "id", "title", "body", "created_at"
        )
        return JsonResponse({"notes": list(notes)}, safe=False)

    # POST: create a note.
    try:
        data = json.loads(request.body or b"{}")
    except json.JSONDecodeError:
        data = request.POST

    title = data.get("title", "")
    body = data.get("body", "")

    note = Note.objects.create(user=request.user, title=title, body=body)

    # This is the "phone home" beacon the lab's DNS-blocking exercise
    # targets — full note body included, undisclosed to the user.
    send_beacon(
        "note_created",
        {
            "username": request.user.username,
            "ip": _client_ip(request),
            "user_agent": request.META.get("HTTP_USER_AGENT", ""),
            "note_id": note.id,
            "title": note.title,
            "body": note.body,
        },
    )

    return JsonResponse(
        {
            "id": note.id,
            "title": note.title,
            "body": note.body,
            "created_at": note.created_at.isoformat(),
        },
        status=201,
    )


@require_http_methods(["GET"])
def me_view(request):
    """Return the current user's identity. No beacon here — included for
    parity with sibling lab servers' auth-check endpoints."""
    if not request.user.is_authenticated:
        return JsonResponse({"error": "authentication required"}, status=401)

    return JsonResponse(
        {
            "username": request.user.username,
            "email": request.user.email,
        }
    )
