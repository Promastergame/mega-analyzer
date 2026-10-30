# Bit Arena — demo game server

A tiny **authoritative real-time multiplayer** game, written in Elixir/OTP, that
exists to answer one question the rest of Mega-Analyzer keeps asking:

> *"What does the server side of a captured online game actually look like, and
> where is the seam a private server slips into?"*

Eight players roam a 1280×720 arena grabbing coins; first to 30 wins. It is
small enough to read in one sitting and complete enough to show every moving
part of a real game backend: matchmaking, one process per player, an
authoritative world tick, a leaderboard, and — the important bit — a single
**entitlement trust boundary** that the sibling [`../mock_server`](../mock_server)
private server can spoof.

```
 browser / bot                    Bit Arena (this app)
 ─────────────                   ─────────────────────
  1. GET /api/v1/session  ─────▶   Entitlements.issue/1   (free unless allow-listed)
     { token, tier }      ◀─────
  2. WS  /ws?token=...     ─────▶   PlayerSocket.init/1    (verify token ONCE)
                                       │
                                       ▼
                                   Matchmaker ─▶ Match (authoritative 20 Hz world)
  3. {"t":"input",dir}     ─────▶   cast → clamp → integrate
     {"type":"state",...}  ◀─────   broadcast snapshot every tick
```

## Run it

Elixir 1.17+ / OTP 26+.

```bash
cd elixir_privserver/demo_game
mix deps.get   # no-op: zero hex dependencies (OTP stdlib only)
mix run --no-halt          # HTTP on :4000, game WebSocket on :4001
```

Then open <http://localhost:4000> and press **play**. Open a few more tabs (or
run the bot below) to fill the arena. Move with `WASD` / arrow keys.

### Headless bot (no browser, no dependencies)

Node 22+ has a global `fetch` and `WebSocket`, so the reference client is a
single file:

```bash
cd client
node bot.mjs --account guest             # plays a normal round
node bot.mjs --account guest --duration 30
node bot.mjs --help
```

## The private-server moment

This is the whole reason the game exists. The game trusts the token the client
brings back from `/api/v1/session`; it never checks *who* issued it.

1. Start Bit Arena (`:4000`) and, in another terminal, the private server from
   [`../mock_server`](../mock_server) (`:9340`).
2. Ask the **honest** server for a session — you are `free`:
   ```bash
   node client/bot.mjs --account guest
   #  session from http://localhost:4000 -> tier=free
   ```
3. Ask the **private** server instead — same account, same game, now `premium`
   (golden skin, 1.35× speed, 2× coins):
   ```bash
   node client/bot.mjs --account guest --backend http://localhost:9340
   #  session from http://localhost:9340 -> tier=premium
   ```

In the browser client, just change the **“session server”** field to
`http://localhost:9340` before pressing play. The WebSocket still goes to the
real game on `:4001` — only the entitlement lookup was redirected, which is
exactly how a private-server unlock works in the wild.

> This works because tokens are unsigned. That is a deliberate, documented flaw,
> not an accident — see [`PROTOCOL.md`](./PROTOCOL.md) for the format and a
> step-by-step hardening guide.

## Layout

| File | Role |
| --- | --- |
| `lib/bit_arena/application.ex` | Supervision tree: leaderboard, match registry, dynamic supervisor, matchmaker, HTTP/WS listener |
| `lib/bit_arena/router.ex` | Serves the client, the `/api/v1/session` trust boundary, status + leaderboard JSON; answers `426` on `/ws` with the real WS port |
| `lib/bit_arena/ws_server.ex` + `player_conn.ex` | Zero-dep game socket on `:gen_tcp`: handshake, framing, intent in, snapshots out |
| `lib/bit_arena/entitlements.ex` | Issues/verifies the (intentionally unsigned) tier tokens |
| `lib/bit_arena/matchmaker.ex` | Puts joining players into an open match |
| `lib/bit_arena/match.ex` | The authoritative world: tick loop, movement, coins, scoring, win/timeout |
| `lib/bit_arena/leaderboard.ex` | ETS-backed cumulative wins/scores |
| `priv/static/` | Zero-build browser client (`index.html` + `app.js`) |
| `client/bot.mjs` | Headless Node reference client / bot |

## Design notes

- **Authoritative.** Clients send a *direction*, never a position. The server
  clamps it to a unit vector and integrates at a fixed step, so a patched
  client cannot teleport (there is a test that tries). This is what a private
  server has to reproduce to stay believable — faking the entitlement is easy,
  faking the physics is the hard part.
- **A process per player, a process per match.** Disconnects are just a
  monitored process going `:DOWN`; there is no bespoke session bookkeeping.
- **No client build step.** `priv/static` is plain HTML + canvas so you can read
  the whole client, which matters when the point is to reason about clients.

Authorized lab / educational use only, same as the rest of Mega-Analyzer.
