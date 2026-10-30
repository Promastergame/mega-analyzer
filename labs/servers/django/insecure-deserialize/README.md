# insecure-deserialize

> ⚠️ Intentionally vulnerable — local lab only. Requires
> `pip install -r requirements.txt` plus a live MySQL instance to actually
> run. Never deploy this, never expose it beyond `127.0.0.1`, never reuse
> this pattern in real code.

Part of `mega-analyzer`'s intentionally-vulnerable lab server collection,
used to generate real, detectable traffic for the network-interceptor /
NCER pipeline to analyze.

## Vulnerability

- **CWE-502** — Deserialization of Untrusted Data: `POST
  /api/session/import` is a "remember me" / "import saved session"
  convenience feature. It takes the raw request body — a base64-encoded,
  `pickle`-serialized `SessionBlob(username, role)` — and calls
  `pickle.loads()` directly on it (see
  `labapp/session_blob.py::deserialize_session`) with **no signature or
  integrity check of any kind**, unlike Django's own signed cookies
  (`django.core.signing`), which HMAC-sign session data specifically so it
  cannot be tampered with client-side.

`labapp/views.py::import_session_view` then trusts whatever `role` field
comes out of that deserialized object outright and establishes a Django
session with it — including `role="admin"`. There is **zero password
check anywhere in this path**: the deserialized blob's `role` field is the
entire authorization decision. This models a real, common incident class:
session/cache data that is deserialized with `pickle` instead of a
signed/verified format, letting a client forge any field the deserialized
object carries — here, specifically the `role` field used for
authorization.

On successful import of a blob with `role != "user"`, the view:

1. Logs a `[DESERIALIZATION BACKDOOR USED]` line via Python's `logging`
   module, including the remote address, username, and role granted, at
   `WARNING` level.
2. Fires a best-effort, non-blocking POST to `TRACKER_URL` (if set) on a
   background thread with a short timeout, so it never delays the HTTP
   response even if the tracker endpoint is slow or unreachable.

## Exploit

`labapp/session_blob.py::make_session_blob_b64` is the same helper a
trusted client would use to export its own session — and, unmodified, it's
also exactly what forges an arbitrary-role blob:

```python
from labapp.session_blob import make_session_blob_b64

forged = make_session_blob_b64("attacker", "admin")
print(forged)
```

POST the resulting base64 string as the raw request body to
`/api/session/import`:

```bash
BLOB=$(python -c "
import django, os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()
from labapp.session_blob import make_session_blob_b64
print(make_session_blob_b64('attacker', 'admin'))
")

curl -c cookies.txt -X POST \
  --data "$BLOB" \
  "http://127.0.0.1:18008/api/session/import"

curl -b cookies.txt "http://127.0.0.1:18008/api/admin/dashboard"
```

The second call succeeds even though no `/login` request was ever made and
the `attacker` account did not previously exist.

## What legitimate traffic looks like, for comparison

- `POST /login` with `{"username": ..., "password": ...}` — normal
  password auth via `django.contrib.auth.authenticate()`.
- `GET /api/me` — shows the current session's username/role.
- `GET /api/admin/dashboard` — requires `UserProfile.role == "admin"`,
  reached legitimately only by an account seeded/promoted through normal
  means.

## Endpoints

| Method | Path                     | Auth required        | Notes                                    |
|--------|--------------------------|-----------------------|-------------------------------------------|
| POST   | `/api/session/import`    | none (vulnerable)     | CWE-502 — see above                       |
| POST   | `/login`                 | none                  | normal username/password login            |
| GET    | `/api/me`                | session               | current user + role                       |
| GET    | `/api/admin/dashboard`   | session, role=admin   | 403 unless `UserProfile.role == "admin"`  |

## Running it

This project needs a real Django install and a live MySQL server; neither
is available in every environment, so it can't be exercised everywhere —
run it on a machine with both.

```bash
cd labs/servers/django/insecure-deserialize
pip install -r requirements.txt

# Point at your MySQL instance (defaults shown match the docker-compose
# lab network / db/mysql/init/08-insecure-deserialize.sql):
export DB_HOST=127.0.0.1
export DB_PORT=33306
export DB_NAME=labs_insecure_deserialize
export DB_USER=labs
export DB_PASSWORD=labs_lab_pw

python manage.py migrate      # creates tables AND seeds demo accounts
                               # (labapp/migrations/0002_seed.py)
python manage.py runserver 127.0.0.1:18008
```

`python manage.py migrate` both creates the `labapp_userprofile` table and
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
docker build -t insecure-deserialize .
docker run --rm -p 127.0.0.1:18008:18008 \
  -e DB_HOST=host.docker.internal \
  insecure-deserialize
```

The container's own `runserver` binds `0.0.0.0:18008` *inside* the
container — that's expected and fine. The guarantee that this lab is only
reachable from `127.0.0.1` on the host comes from the docker-compose /
`docker run` port mapping (`127.0.0.1:18008:18008`), not from the bind
address inside the container.

## Database schema

`labs/servers/db/mysql/init/08-insecure-deserialize.sql` only provisions
the empty `labs_insecure_deserialize` database (and the `labs` user/grant)
at container-init time. Django owns the actual schema: `python manage.py
migrate` creates `labapp_userprofile` (plus Django's own `auth_user`,
`django_session`, etc. tables) and seeds the demo accounts above.

## Evidence / what NCER should flag

- A `POST` to `/api/session/import` carrying an **unusual base64-encoded
  body** on a session-import-like endpoint is itself an anomaly worth
  flagging — most JSON APIs don't accept raw base64 text as a whole
  request body.
- The response sets a session cookie and grants an elevated role
  (`role=admin`) despite the request carrying no prior authenticated
  session, no password, and no username that previously existed.
- Immediately following that request, the same session/cookie is able to
  reach `/api/admin/dashboard`, which normally requires a `role=admin`
  account reached only via `/login` — a privilege escalation with no
  intervening credential-bearing request.
- Server-side, the `[DESERIALIZATION BACKDOOR USED]` log line and (if
  `TRACKER_URL` is configured) the outbound beacon are additional,
  deliberately loud corroborating signals for detection tooling.

## Tests

`labapp/tests.py` covers:

1. A pure unit test with no DB/login involved:
   `make_session_blob_b64("attacker", "admin")` round-tripped through
   `deserialize_session()` returns a `SessionBlob` with `role == "admin"`,
   proving the trust boundary is broken at the (de)serialization layer
   alone.
2. A normal user logging in through `/login` and being correctly denied
   (`403`) at `/api/admin/dashboard`.
3. `POST /api/session/import` with a forged admin blob granting an admin
   session with **zero prior authentication of any kind**, and that
   session then succeeding at `/api/admin/dashboard`.
4. A forged `role="moderator"` blob being correctly denied at
   `/api/admin/dashboard`.
5. A garbage (non-base64/non-pickle) body being rejected with `400` and
   no session established.

Run with:

```bash
python manage.py test labapp
```

> This sandbox has no Django, MySQL, or `pip` available, so these tests
> were written and syntax-checked (`ast.parse`) but **not executed** here.
> Run `python manage.py test labapp` yourself on a machine with the
> dependencies installed and a reachable MySQL instance before relying on
> them.
