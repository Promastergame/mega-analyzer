# admin-hidden-debug

> WARNING: Intentionally vulnerable - local lab only. Requires
> `pip install -r requirements.txt` plus a live MySQL instance to actually
> run. Never deploy this, never expose it beyond `127.0.0.1`, never reuse
> this pattern in real code.

Part of `mega-analyzer`'s intentionally-vulnerable lab server collection,
used to generate real, detectable traffic for the network-interceptor /
NCER pipeline to analyze.

## Vulnerability

- **CWE-489** - Active Debug Code: an undocumented, unlinked endpoint,
  `GET/POST /_internal/become-admin`, is wired up in `labapp/urls.py` next
  to every other route but is never referenced from any menu, nav,
  template, or other view in the app. It's "hidden" only in the sense that
  real leftover-debug-code backdoors are hidden: nobody links to it, so it
  only shows up if you read the source or fuzz the URL space.
- **CWE-798** - Use of Hardcoded Credentials: the endpoint checks a `key`
  query/form parameter against a hardcoded constant,
  `DEBUG_BOOTSTRAP_KEY = "CHANGE_ME_LAB_DEBUG_KEY"` (see
  `config/settings.py`, overridable via the `DEBUG_BOOTSTRAP_KEY` env var
  but shipped with an obvious, loudly-documented placeholder default).

If the key matches, `labapp/views.become_admin` calls
`django.contrib.auth.login()` and grants the requester a fully
authenticated admin session (`is_staff=True`, `is_superuser=True`,
`Profile.role="admin"`) with **zero password check anywhere in the
request** - the hardcoded key match is the entire authentication event.
This models the classic real-world incident: "ops left a debug/bootstrap
backdoor in the codebase, and it shipped with a hardcoded key."

On successful use, the view:

1. Logs a `[BACKDOOR USED]` line via Python's `logging` module, including
   the remote address and the username granted, at `WARNING` level.
2. Fires a best-effort, non-blocking POST to `TRACKER_URL` (if set) on a
   background thread with a short timeout, so it never delays the HTTP
   response even if the tracker endpoint is slow or unreachable.

## Exploit

```bash
curl "http://127.0.0.1:18006/_internal/become-admin?key=CHANGE_ME_LAB_DEBUG_KEY"
```

That single unauthenticated GET request returns a session cookie for a
freshly-created (or reused) `debug-admin` account with full admin rights.
Confirm it with the cookie jar:

```bash
curl -c cookies.txt "http://127.0.0.1:18006/_internal/become-admin?key=CHANGE_ME_LAB_DEBUG_KEY"
curl -b cookies.txt "http://127.0.0.1:18006/api/admin/dashboard"
```

The second call succeeds even though no `/login` request was ever made.

## What legitimate traffic looks like, for comparison

- `POST /login` with `{"username": ..., "password": ...}` - normal
  password auth via `django.contrib.auth.authenticate()`.
- `GET /api/me` - shows the current session's username/role.
- `GET /api/admin/dashboard` - requires `Profile.role == "admin"`, reached
  legitimately only by an account seeded/promoted through normal means.

## Endpoints

| Method | Path                          | Auth required | Notes                                   |
|--------|-------------------------------|----------------|------------------------------------------|
| GET/POST | `/_internal/become-admin`   | none (backdoor)| CWE-489 / CWE-798 - see above           |
| POST   | `/login`                      | none           | normal username/password login          |
| GET    | `/api/me`                     | session        | current user + role                     |
| GET    | `/api/admin/dashboard`        | session, role=admin | 403 unless `Profile.role == "admin"` |

## Running it

This project needs a real Django install and a live MySQL server; neither
is available in every environment, so it can't be exercised everywhere -
run it on a machine with both.

```bash
cd labs/servers/django/admin-hidden-debug
pip install -r requirements.txt

# Point at your MySQL instance (defaults shown match the docker-compose
# lab network / db/mysql/init/06-admin-hidden-debug.sql):
export DB_HOST=127.0.0.1
export DB_PORT=33306
export DB_NAME=labs_admin_hidden_debug
export DB_USER=labs
export DB_PASSWORD=labs_lab_pw

python manage.py migrate      # creates tables AND seeds demo accounts
                               # (labapp/migrations/0002_seed.py)
python manage.py runserver 127.0.0.1:18006
```

`python manage.py migrate` both creates the `labapp_profile` table and
seeds three demo accounts via the `0002_seed` data migration (equivalent
seeding is also available on demand via
`python manage.py seed_lab_users`, which uses `User.set_password(...)`
directly on real model instances):

| username     | password           | role      |
|--------------|--------------------|-----------|
| `alice`      | `alice_lab_pw`     | user      |
| `mod_bob`    | `mod_bob_lab_pw`   | moderator |
| `root_admin` | `root_admin_lab_pw`| admin     |

These are intentionally fake, published-in-this-README plaintext
passwords for lab use only.

### Docker

```bash
docker build -t admin-hidden-debug .
docker run --rm -p 127.0.0.1:18006:18006 \
  -e DB_HOST=host.docker.internal \
  admin-hidden-debug
```

The container's own `runserver` binds `0.0.0.0:18006` *inside* the
container - that's expected and fine. The guarantee that this lab is only
reachable from `127.0.0.1` on the host comes from the docker-compose /
`docker run` port mapping (`127.0.0.1:18006:18006`), not from the bind
address inside the container.

## Database schema

`labs/servers/db/mysql/init/06-admin-hidden-debug.sql` only provisions the
empty `labs_admin_hidden_debug` database (and the `labs` user/grant) at
container-init time. Django owns the actual schema: `python manage.py
migrate` creates `labapp_profile` (plus Django's own `auth_user`,
`django_session`, etc. tables) and seeds the demo accounts above.

## Evidence / what NCER should flag

The signal here is almost entirely in **request metadata, not payload**:

- A `GET`/`POST` to `/_internal/become-admin` is a **first-seen endpoint**
  with no prior navigation event leading to it in the session - no link
  click, no form render referencing it, nothing in the app's own HTML/JS
  ever mentions the path. NCER's novelty scoring should flag this as an
  undocumented URL path hit out of nowhere.
- The response sets a session cookie and grants elevated privileges
  (`is_staff`/`is_superuser`) despite the request carrying no prior
  authenticated session and no password.
- Immediately following that request, the same session/cookie is able to
  reach `/api/admin/dashboard`, which normally requires a `role=admin`
  account reached only via `/login` - a privilege escalation with no
  intervening credential-bearing request.
- Server-side, the `[BACKDOOR USED]` log line and (if `TRACKER_URL` is
  configured) the outbound beacon are additional, deliberately loud
  corroborating signals for detection tooling.

## Tests

`labapp/tests.py` covers:

1. A normal user logging in through `/login` (or Django's test-client
   `login()` helper) and being correctly denied (`403`) at
   `/api/admin/dashboard`.
2. `GET /_internal/become-admin?key=CHANGE_ME_LAB_DEBUG_KEY` granting an
   admin session with **zero prior login of any kind**, and that session
   then succeeding at `/api/admin/dashboard`.
3. Wrong/missing `key` values being rejected (`403`, no session, no
   account created).

Run with:

```bash
python manage.py test labapp
```

> This sandbox has no Django, MySQL, or `pip` available, so these tests
> were written and syntax-checked (`ast.parse`) but **not executed** here.
> Run `python manage.py test labapp` yourself on a machine with the
> dependencies installed and a reachable MySQL instance before relying on
> them.
