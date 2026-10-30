"""
labapp/middleware.py

INTENTIONALLY VULNERABLE: permissive CORS + credentials.
============================================================================
This middleware hand-rolls the equivalent of `django-cors-headers`'
`CORS_ALLOW_ALL_ORIGINS = True` combined with `CORS_ALLOW_CREDENTIALS =
True`, without pulling in the extra dependency (kept out of
requirements.txt on purpose to stay self-contained). It exists purely to
reproduce a common, real-world CORS misconfiguration: allowing ANY origin
to make credentialed (cookie-bearing) cross-origin requests against this
API.

Why this matters for the lab's CWE-352 (CSRF) story: browsers only send a
site's cookies along with a cross-origin `fetch()`/XHR if the request is
made `credentials: "include"` AND the server's CORS response headers say
that's allowed. A tightly-scoped CORS policy (specific allow-listed
origins, no wildcard-plus-credentials) is one of the defenses that can
blunt cross-origin abuse even when CSRF tokens are missing. This lab
removes that defense entirely: every response gets

    Access-Control-Allow-Origin: *
    Access-Control-Allow-Credentials: true

Note for readers: per the Fetch/CORS spec, a literal "*" for
Access-Control-Allow-Origin is technically supposed to be incompatible with
Access-Control-Allow-Credentials: true for *reading* the response body from
JavaScript (the spec says the origin must be echoed back specifically, not
wildcarded, whenever credentials are involved) -- some real, misconfigured
deployments get exactly this combination wrong anyway, as reproduced here.
Even in browsers that strictly enforce that rule and refuse to let
attacker JS read the response, that does NOT stop the browser from SENDING
the cross-origin request with the victim's ambient session cookie
attached, and it does NOT stop this server from acting on it. That's the
actual exploit path this lab demonstrates: the attacker's page never needs
to read the JSON response, it only needs the state-changing side effect
(the role change performed by change_role_view) to happen. Combined with
`@csrf_exempt` on that view, this header pair is the second half of the
misconfiguration this lab is built to surface.
"""
from __future__ import annotations

from django.http import HttpResponse


class PermissiveCorsMiddleware:
    """Adds "allow everything" CORS headers to every response and
    short-circuits CORS preflight (OPTIONS) requests.

    INTENTIONALLY VULNERABLE: permissive CORS + credentials.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Short-circuit CORS preflight requests instead of running them
        # through the rest of the app -- a real browser sends one of these
        # ahead of a "non-simple" cross-origin request (e.g. one with a
        # JSON Content-Type), and it expects a fast 2xx with CORS headers,
        # not the actual view logic.
        if request.method == "OPTIONS" and "HTTP_ACCESS_CONTROL_REQUEST_METHOD" in request.META:
            response = HttpResponse(status=200)
        else:
            response = self.get_response(request)

        # INTENTIONALLY VULNERABLE: permissive CORS + credentials.
        # A correctly configured server would echo back a specific,
        # allow-listed Origin (never a literal "*") and would only ever set
        # Allow-Credentials for origins it actually trusts. This lab does
        # neither, on purpose, so the "wide open CORS" half of the
        # CWE-352 story is real, observable network traffic.
        response["Access-Control-Allow-Origin"] = "*"
        response["Access-Control-Allow-Credentials"] = "true"
        response["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
        response["Access-Control-Allow-Headers"] = request.META.get(
            "HTTP_ACCESS_CONTROL_REQUEST_HEADERS",
            "Content-Type, Authorization, X-Requested-With",
        )
        return response
