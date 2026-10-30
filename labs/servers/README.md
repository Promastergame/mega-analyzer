# labs/servers — intentionally vulnerable local lab

> ## ⚠️ INTENTIONALLY VULNERABLE — LOCAL LAB ONLY
>
> Every server in this directory contains **deliberate, documented security
> vulnerabilities**. They exist for one reason: to give this repository's own
> network interceptor / causal-reconciliation pipeline
> (`pkg/ncer` + the Rust `omnisec-mitm` crates) and DNS sinkhole
> (`pkg/internal/labdns`) real, exploitable traffic to **observe, score, and
> block**.
>
> - **Never deploy any of this.** Never expose these ports past `127.0.0.1`.
> - Every port binds to loopback only (both the servers themselves and the
>   `docker-compose.lab.yml` port mappings).
> - Every "secret", password, token, and backdoor key here is an obvious
>   **fake placeholder** (`CHANGE_ME_LAB_DEBUG_KEY`, `alice_lab_pw1`, …). None
>   is a real credential. Do not copy any pattern from these servers into
>   real code — they are the *opposite* of a secure baseline.
>
> This is the same "intentionally insecure fixture" precedent as `demo/`,
> scaled up to a live-traffic lab.

## What's here

11 standalone servers — 5 Go/Postgres, 5 Django/MySQL, and one Go/bbolt coin
shop — plus a shared beacon sink. Each server is a **fully independent project**
(its own `go.mod` / `manage.py` + `requirements.txt`); none imports
`pkg/ncer`. The integration only flows one way: the `pkg/ncer/labtest` test
package drives HTTP traffic at these servers and feeds what it observes into
the reconciliation pipeline.

Four of the servers implement the four most common **"hidden admin/moderator
without logging in"** classes specifically (hardcoded backdoor header,
JWT `alg=none`, IDOR role escalation, hidden debug route) — these mirror real
public incident classes, so the lab doubles as realistic training material.

### Vulnerability matrix

| # | Server | Lang / DB | Port | CWE | Backdoor / bug | One-line exploit |
| :- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | `go/admin-backdoor-header` | Go / Postgres | 18001 | CWE-798 | Hardcoded magic header mints an admin session, no login | `curl -H 'X-Debug-Role: admin' http://127.0.0.1:18001/api/admin/dashboard` |
| 2 | `go/admin-jwt-none` | Go / Postgres | 18002 | CWE-347 | JWT verifier trusts `alg:none`; forge `role:admin` | `curl -H 'Authorization: Bearer <alg=none token>' http://127.0.0.1:18002/api/admin/dashboard` |
| 3 | `go/admin-idor-role` | Go / Postgres | 18003 | CWE-639 | Any logged-in user can self-promote via role endpoint | login as `alice`, then `POST /api/users/{own_id}/role {"role":"admin"}` |
| 4 | `go/sqli-login` | Go / Postgres | 18004 | CWE-89 | String-concatenated login SQL → auth bypass | `curl -d "username=admin' -- &password=x" http://127.0.0.1:18004/login` |
| 5 | `go/path-traversal-download` | Go / Postgres | 18005 | CWE-22 | `?name=../` escapes the files dir; leaks an admin bootstrap token | `curl 'http://127.0.0.1:18005/files?name=../config/admin_secrets.txt'` |
| 6 | `django/admin-hidden-debug` | Django / MySQL | 18006 | CWE-489/798 | Undocumented debug route grants admin by hardcoded key | `curl 'http://127.0.0.1:18006/_internal/become-admin?key=CHANGE_ME_LAB_DEBUG_KEY'` |
| 7 | `django/sqli-raw` | Django / MySQL | 18007 | CWE-89 | `.raw()` f-string bypasses ORM parameterization (UNION) | `curl "http://127.0.0.1:18007/search?username=admin' -- "` |
| 8 | `django/insecure-deserialize` | Django / MySQL | 18008 | CWE-502 | `pickle.loads` on an unsigned client blob → forge `role:admin` | `POST /api/session/import` with a forged base64 blob |
| 9 | `django/csrf-cors-misconfig` | Django / MySQL | 18009 | CWE-352 | `@csrf_exempt` role change + wide-open CORS | cross-origin `fetch()` PoC in that server's README |
| 10 | `django/tracker-beacon` | Django / MySQL | 18010 | CWE-359 | Silently exfiltrates session/note data to a tracker host | login or create a note → beacon fires to `tracker.lab.local` |
| 11 | `go/coin-client-authoritative` | Go / bbolt | 18011 + UI 18111 | CWE-602 | Legacy wallet reconciliation trusts an unsigned cached balance | MITM rewrites `reported_balance:35` to `777`, then a server-authoritative purchase succeeds |

Support service (not itself vulnerable):

| Service | Lang | Port | Role |
| :--- | :--- | :--- | :--- |
| `trackercollector` | Go | 18099 | Records every beacon it receives; `GET /_hits` to inspect. The "where does the data go" sink servers 8–10 phone home to. |

Each server's own `README.md` has the full write-up: the planted CWE, exact
exploit steps, the fake seed credentials, and what network evidence the
ncer/mitm pipeline should be able to flag.

### `labkit` — clean, defensive test-server framework

Separately from the intentionally vulnerable fixtures above, [`labkit/`](labkit/)
is a **standalone, research-grade local test-server framework** (HTTP,
WebSocket, TCP, UDP) with a middleware pipeline, deterministic
latency/error/timeout injection, structured logging and metrics. It is *not*
vulnerable-by-design: it's the tool you use to generate controlled local
traffic, reproduce timeout/retry behaviour, and analyze custom protocols. It is
its own Go module (`labs-labkit`) and imports nothing from `pkg/internal/*`.
See [`labkit/README.md`](labkit/README.md).

## Running the lab

### Everything at once (Docker)

```bash
# From the repository root. The root compose file provides the
# mega-analyzer-net network the lab overlay attaches to.
docker compose -f docker-compose.yml -f labs/servers/docker-compose.lab.yml up -d
```

This starts `postgres-lab` (host `127.0.0.1:55432`), `mysql-lab`
(`127.0.0.1:33306`), `trackercollector`, and all 11 servers. The Postgres /
MySQL schemas and fake seed data load automatically from `db/postgres/init/`
and `db/mysql/init/` via the standard `docker-entrypoint-initdb.d` mechanism
(Go servers) and Django data migrations (`manage.py migrate`, Django
servers).

### Everything at once (no Docker — Android/Termux-style hosts)

On a host without Docker (and where PostgreSQL can't use System V shared
memory, e.g. Android), use the helper scripts under `.rundata/` instead.
They run Postgres + MariaDB under an unprivileged uid, `LD_PRELOAD` a small
`shmshim.so` that emulates SysV shared memory with file mmaps so PostgreSQL
can start, and launch every process detached (`setsid`) so it survives the
shell closing:

```bash
bash labs/servers/.rundata/lab-up.sh     # brings all 13 services up
bash labs/servers/.rundata/lab-down.sh   # stops everything
```

> Note: some sandboxes aggressively reap background processes when the
> controlling terminal closes; if the ports go quiet, just re-run
> `lab-up.sh` — it's idempotent and comes back in a few seconds.

This is the exact setup used to verify the whole lab end-to-end on this
repo's dev host: all 10 exploits return HTTP 200 live, tracker beacons reach
`trackercollector` (`GET /_hits`), and `go test ./pkg/ncer/labtest/...`
passes with every `TestLive*` case actually driving a real server.


### A single Go server, standalone

```bash
cd labs/servers/go/admin-backdoor-header
DATABASE_URL='postgres://labs:labs_lab_pw@127.0.0.1:55432/labs_admin_backdoor_header?sslmode=disable' \
  go run .          # binds 127.0.0.1:18001
```

### A single Django server, standalone

```bash
cd labs/servers/django/admin-hidden-debug
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python manage.py migrate            # creates tables + seeds fake users
python manage.py runserver 127.0.0.1:18006
```

## Tests

- **Per-server unit tests** prove each planted vulnerability is genuinely
  exploitable, and run *without* a live database (Go servers use in-memory
  fake stores in `*_test.go`; the pure vulnerable functions — e.g.
  `buildLoginQuery`, `parseAndVerify`, `resolvePath` — are tested directly):

  ```bash
  # Go servers (a go.work here ties the modules together):
  cd labs/servers/go/admin-backdoor-header && go test ./...   # per module
  # Django servers (need Django installed; DB-backed tests need MySQL):
  cd labs/servers/django/admin-hidden-debug && python manage.py test
  ```

- **Pipeline integration tests** (`pkg/ncer/labtest`, in the root module)
  are the main deliverable. They drive the real exploit traffic through
  `ncer.Collector` and assert the tracker beacon is both **detected** and
  **blocked** by the `pkg/internal/labdns` sinkhole:

  ```bash
  go test ./pkg/ncer/labtest/...
  ```

  The `TestLive*` cases auto-skip when the corresponding lab server isn't
  running (start the docker-compose lab to exercise them live); the
  self-contained cases (backdoor-pattern detection, tracker allow/block via
  LabDNS) always run.

## How the blocking exercise works

`django/tracker-beacon` phones home to the hostname `tracker.lab.local`
(not a raw IP) on every login and note write. `pkg/ncer/labtest`'s
`trackers_block_test.go` demonstrates the two states using the existing,
already-tested `labdns.LabDNS` / `SinkholeRules` engine — no new blocklist
code:

- **Allowed** — no block rule: `tracker.lab.local` resolves to the collector,
  the beacon lands, `GET /_hits` shows it, and the DNS query + HTTP exchange
  are recorded as ncer evidence.
- **Blocked** — `AddBlockRule("tracker.lab.local")` active: the query is
  sinkholed to a dead loopback address, the beacon never reaches the
  collector, and `LabDNS.Stats().SinkholeCount` increments — detection *and*
  block, proven in one test.
