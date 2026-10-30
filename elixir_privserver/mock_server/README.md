# Mock Server — programmable private backend

A small Elixir/OTP server that answers like whatever backend you point a client
at. It exists so you can run a captured client **offline**: sessions come back
authenticated, licenses come back active, feature flags come back enabled, and
you get to watch what the client does next — all without touching anybody
else's infrastructure.

Three moving parts:

| Part | Module | What it does |
| --- | --- | --- |
| Rules | `MockServer.RuleStore` | Declarative request → response rules from `priv/rules.json`, reloadable at runtime |
| Scenarios | `MockServer.Scenario` | Fault injection: `normal`, `flaky`, `offline`, `expired` |
| Stats | `MockServer.Stats` | Counters + a rolling 50-request traffic log, shown on the dashboard |

## Run it

Elixir 1.15+ / OTP 26+.

```bash
cd elixir_privserver/mock_server
mix deps.get
mix run --no-halt
```

| | |
| --- | --- |
| Fake backend | <http://localhost:9340> — point your client here |
| Dashboard | <http://localhost:9341> — live traffic, scenario switch, rule reload |

The fake backend answers **every** method on **every** path, so you never have
to guess a client's endpoints in advance — send traffic, watch the dashboard,
then write rules for the requests that actually matter.

```bash
curl localhost:9340/api/v1/session
curl localhost:9340/v2/user/subscription
curl -X POST localhost:9340/anything/at/all
```

## Rules

`priv/rules.json`, first match wins:

```json
{
  "rules": [
    {
      "name": "active-pro-license",
      "match":    { "path": "(license|subscription)" },
      "response": { "status": 200, "json": { "active": true, "plan": "professional" } }
    }
  ]
}
```

- `match` — any of `method`, `path` (regex), `path_prefix`. Omitted keys match everything.
- `response` — `status` plus a `json` body.
- Generated values usable anywhere in `json`: `"$premium_token"`, `"$free_token"`,
  `"$now"`, `"$rand_hex"`.

Edit the file and hit **Reload rules** on the dashboard (or `POST /api/reload`) —
no restart, connected clients stay connected.

If nothing matches, `MockServer.RuleEngine.builtin/1` recognises auth, license
and feature-flag endpoints by name and answers plausibly anyway, which is why an
unknown app usually works with zero configuration.

## Scenarios

A client that works against a perfect backend tells you very little. Flip a
scenario from the dashboard mid-session:

| Scenario | Behaviour |
| --- | --- |
| `normal` | Always healthy |
| `flaky` | 20–250 ms latency, ~20% of requests fail with `503` |
| `offline` | Everything fails with `503` |
| `expired` | License-shaped paths report an inactive, expired plan |

`expired` is the interesting one: does the client fall back gracefully, cache the
last good answer, or hard-lock the UI?

## Control API (port 9341)

```
GET  /              dashboard
GET  /api/status    ports, rule count, scenario, counters
GET  /api/recent    rolling traffic log
GET  /api/rules     loaded rules
POST /api/scenario  {"name": "flaky"}
POST /api/reload    re-read priv/rules.json
```

## The demo: unlocking a real game

[`../demo_game`](../demo_game) is a working multiplayer game server (Bit Arena)
with exactly one trust boundary: it asks its own `/api/v1/session` endpoint what
tier the player is, and believes the token it gets back.

Run both, then point only the *session lookup* at this server:

```bash
# terminal 1 — the honest game on :4000
cd ../demo_game && mix run --no-halt

# terminal 2 — this private server on :9340
mix run --no-halt

# terminal 3 — same account, two different backends
cd ../demo_game/client
node bot.mjs --account guest                                  # tier=free
node bot.mjs --account guest --backend http://localhost:9340   # tier=premium
```

Same game, same account, golden skin and double coins. The unlock works because
the game's tokens are **unsigned**, and `MockServer.Entitlements` mints the same
wire format. Watch the request land on the dashboard as it happens.

That is the whole lesson in one command: *an entitlement your client asks a
server for is only as trustworthy as the signature on the answer.*

## Where this fits in Mega-Analyzer

The Go side (`pkg/internal/privserver`) generates servers like this one from a
captured app: it discovers endpoints, picks a framing style, and renders a
ready-to-run Elixir project. This directory is the hand-written reference the
generator's output is modelled on — the shape you get when the pipeline decides
"Elixir, generic family, HTTP framing".

## HTTPS

Some clients refuse plain HTTP. Generate a self-signed pair:

```bash
mix gen.cert
```

Then terminate TLS in front of the mock (reverse proxy, `stunnel`,
or an `:ssl`-wrapped listener in `lib/mock_server/application.ex`):
the listeners are plain OTP (`MockServer.TcpServer` on `:gen_tcp` for
the fake backend, `MockServer.HttpServer` on `:inets` for the admin
dashboard) with zero third-party dependencies.

You will still need to trust the certificate on the client side — which, for an
Android target, is what the toolkit in `../../zig/apk_editor` is for.

## Responsible use

This is a lab tool for software you own or are authorized to analyze:
interoperability research, preservation of dead online games, security review,
and offline testing. Do not use it to defraud anyone or to strip payment from
software you have not licensed. There is no obfuscation here and no attempt to
bypass a cryptographic check — the entire point is that a *missing* check is the
vulnerability.
