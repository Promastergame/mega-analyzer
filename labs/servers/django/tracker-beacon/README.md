# tracker-beacon (Django lab server)

> **INTENTIONALLY INSECURE — LOCAL LAB USE ONLY.**
> This server binds to `127.0.0.1` by default and exists purely to give the
> mega-analyzer network-interceptor / ncer pipeline real traffic to detect
> and **block**. Never deploy this anywhere near production, never point it
> at a real database with real users.

## Vulnerability class: undisclosed telemetry / data exfiltration (CWE-359-ish)

This looks like an ordinary, boring notes app: register/login, list your
notes, create a note. Nothing here is SQL-injectable, nothing has a broken
auth check, nothing deserializes attacker input unsafely. The vulnerability
is different in kind from this lab suite's other servers:

**On every successful login, and on every note create/edit, the app fires a
background "analytics" beacon that ships far more data than any reasonable
user would expect** — username, source IP, User-Agent, and (for notes) the
**full note body** — to a third-party collector endpoint. Nothing in the UI
or API response discloses that this happens. The user typed a private note;
the app quietly copied its full contents to `TRACKER_URL` anyway.

This is the "where does my data actually go" example in the lab: it's not
here to be exploited by a `curl` payload, it's here to be **caught in the
network layer** by the pipeline this repo is built to test.

- `labapp/beacon.py` — `send_beacon(event, payload)` builds a JSON body and
  POSTs it to `TRACKER_URL` on a background daemon thread (via stdlib
  `urllib.request`, 2s timeout). It swallows/logs every error so a
  blocked/unreachable collector is invisible to the app and the user —
  exactly like a real telemetry backdoor would behave.
- `labapp/views.py` — `login_view` beacons `{username, ip, user_agent}` on
  every successful login; `notes_list_create_view` beacons
  `{username, ip, user_agent, note_id, title, body}` on every note
  creation, deliberately including the full note body.
- Every beacon attempt logs loudly to stdout:
  `[TRACKER BEACON SENT] event=<event> url=<url>` — so it's easy to see in
  server logs even though it's invisible in the HTTP response the user
  actually gets back.

## Layout

```
tracker-beacon/
  manage.py
  config/            settings.py, urls.py, wsgi.py
  labapp/
    models.py         Note, UserProfile
    beacon.py         send_beacon() — the phone-home beacon
    views.py          login_view, notes_list_create_view, me_view
    urls.py
    migrations/       0001_initial, 0002_seed_lab_user (seeds `labuser`)
    tests.py
  Dockerfile
  requirements.txt
```

## Running it

```sh
cd labs/servers/django/tracker-beacon
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver 127.0.0.1:18010
```

Environment variables (all optional, defaults shown):

| Var | Default |
|---|---|
| `DB_HOST` | `127.0.0.1` |
| `DB_PORT` | `33306` |
| `DB_NAME` | `labs_tracker_beacon` |
| `DB_USER` | `labs` |
| `DB_PASSWORD` | `labs_lab_pw` |
| `TRACKER_URL` | `http://tracker.lab.local:18099/beacon/tracker-beacon` |

A demo account is seeded by migration `0002_seed_lab_user`:

- username: `labuser`
- password: `labpass123` (documented fake plaintext password, lab-only —
  see the migration file for the disclaimer, it's stored hashed via
  `set_password()`/`make_password()`, never in plaintext in the DB)

## Triggering a beacon

Login (fires the `login` beacon — username, IP, User-Agent):

```sh
curl -i -c /tmp/tb-cookies.txt -X POST http://127.0.0.1:18010/login \
  -H 'Content-Type: application/json' \
  -d '{"username": "labuser", "password": "labpass123"}'
```

Create a note (fires the `note_created` beacon — the full note body
included, undisclosed to the caller):

```sh
curl -i -b /tmp/tb-cookies.txt -X POST http://127.0.0.1:18010/api/notes \
  -H 'Content-Type: application/json' \
  -d '{"title": "reminder", "body": "meet me at the docks at midnight, tell no one"}'
```

Watch the server's stdout for:

```
[TRACKER BEACON SENT] event=login url=http://tracker.lab.local:18099/beacon/tracker-beacon
[TRACKER BEACON SENT] event=note_created url=http://tracker.lab.local:18099/beacon/tracker-beacon
```

## `tracker.lab.local` — the intended blocking target

`TRACKER_URL` deliberately defaults to a **hostname**, not a bare IP:
`http://tracker.lab.local:18099/beacon/tracker-beacon`. This is a fake,
local-only hostname that does not resolve anywhere by default — that's on
purpose. It exists so the exercise can demonstrate **DNS-level
sinkholing/blocking**, not just IP/port blocking:

- Resolving `tracker.lab.local` normally requires either an `/etc/hosts`
  entry (e.g. `127.0.0.1 tracker.lab.local`) or running it through the
  repo's local DNS sinkhole, `pkg/internal/labdns.LabDNS`. `LabDNS` matches
  domains/wildcards via its `SinkholeRules` engine and resolves matches to a
  configured target IP (default `127.0.0.1`) — see
  `pkg/internal/labdns/rules.go` and `pkg/internal/labdns/server.go`.
- The integration exercise (`pkg/ncer/labtest`, built separately from this
  server) is expected to: point resolution of `tracker.lab.local` at the
  shared `trackercollector` service via `LabDNS`, drive this app through a
  login + note-create flow, and assert that the beacon traffic is (a)
  observed by the mitm/ncer pipeline and (b) blockable — e.g. by having
  `LabDNS` sinkhole `tracker.lab.local` to a dead address, or by having the
  mitm layer drop requests to it, and then asserting the `trackercollector`
  never sees the hit.
- Without any DNS setup at all, `tracker.lab.local` simply fails to
  resolve, `send_beacon()` swallows the resulting `URLError`/`OSError`, and
  the app behaves exactly as if telemetry were successfully blocked — which
  is realistic: this is what a well-behaved DNS sinkhole should produce.

## The shared collector (`labs/servers/trackercollector`)

The default `TRACKER_URL` points at the shared local sink already built at
`labs/servers/trackercollector/`. It is a minimal Go HTTP server
(`trackercollector.New()` / `StartBackground("127.0.0.1:18099")` by
default, or run standalone via `labs/servers/trackercollector/cmd`) that:

- Accepts any request on any path (`/`) and records it (method, path,
  remote address, a SHA-256 of the body, body length, and a few
  interesting headers) into an in-memory ring buffer.
- Exposes `GET /_hits` — returns the recorded hits as JSON — so tests can
  assert whether a beacon actually arrived.
- Exposes `GET /_health` for a liveness check.

`labs/servers/trackercollector/` does not currently have its own README;
the above describes its relevant surface for this lab's purposes.

## Tests

```sh
python manage.py test labapp
```

`labapp/tests.py` mocks the network boundary
(`labapp.views.send_beacon` / `urllib.request.urlopen`) — it never makes a
real network call and never depends on `trackercollector` actually
running:

- `test_login_triggers_exactly_one_login_beacon` — asserts `login_view`
  fires exactly one `"login"` beacon carrying username/IP/User-Agent.
- `test_creating_note_beacons_full_note_body` — asserts creating a note
  fires a `"note_created"` beacon whose payload contains the full note
  body (documents the over-sharing).
- `test_post_beacon_swallows_connection_errors` /
  `test_post_beacon_swallows_timeouts` — call `labapp.beacon._post_beacon`
  directly against a mocked, failing `urllib.request.urlopen` to prove the
  beacon degrades gracefully (never raises) when the collector is
  unreachable — i.e. exactly what should happen once `labdns` sinkholes
  `tracker.lab.local`.
