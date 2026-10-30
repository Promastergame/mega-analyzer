"""
============================================================================
WARNING: THIS FILE CONTAINS A DELIBERATE, DOCUMENTED VULNERABILITY.
Local, isolated security-training lab only. DO NOT COPY THIS PATTERN.
============================================================================

`SessionBlob` is a tiny two-field value object (`username`, `role`) that a
trusted client is meant to use to export and later re-import its own
session - a "remember me" / "import saved session" convenience feature.

`make_session_blob_b64` is the "legit-looking" helper: it pickles a
`SessionBlob` and base64-encodes the result, exactly the kind of small
serialization helper a real codebase would write for this feature.

`deserialize_session` is the vulnerable half: it reverses that encoding by
calling `pickle.loads()` directly on client-controlled bytes, with no
signature or integrity check of any kind (contrast with Django's own
`django.core.signing`, which HMAC-signs cookie data specifically so it
cannot be tampered with client-side). Whatever `SessionBlob.role` comes out
of that call is later trusted as-is by `labapp/views.py::import_session_view`
to establish a session - including `role="admin"`. This is CWE-502
(Deserialization of Untrusted Data), and it is the entire scope of this
lab: a `role` field arriving via untrusted deserialized data with no
integrity check, used to escalate privilege.
"""

import base64
import pickle


class SessionBlob:
    """Plain value object: username + role. No other behavior."""

    def __init__(self, username: str, role: str):
        self.username = username
        self.role = role


def make_session_blob_b64(username: str, role: str) -> str:
    """Build a base64-encoded, pickled `SessionBlob`.

    This is the helper a trusted client is meant to call to export its own
    session for later re-import. It is also, unmodified, exactly what an
    attacker uses to forge an arbitrary-role blob - see README.md.
    """
    blob = SessionBlob(username=username, role=role)
    return base64.b64encode(pickle.dumps(blob)).decode("ascii")


def deserialize_session(blob_b64: str) -> SessionBlob:
    """Decode and deserialize a client-supplied session blob.

    Takes a base64 string straight from the request body and pickle-loads
    it with no signing, no HMAC, no allow-list, no validation of any kind
    before trusting the result.
    """
    raw = base64.b64decode(blob_b64)
    # INTENTIONALLY VULNERABLE: pickle.loads on untrusted client input with no integrity check (CWE-502), see README
    return pickle.loads(raw)
