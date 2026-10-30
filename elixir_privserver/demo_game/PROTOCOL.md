# Bit Arena wire protocol (`bitarena/1`)

Everything is JSON over a single WebSocket. There are three server messages and
two client messages — small on purpose, so it is realistic to re-implement the
whole thing inside a private server.

```
HTTP  GET /api/v1/session?account=<name>   → { token, tier, perks, ws_port }   ← the trust boundary
WS    GET /ws?token=<token>                → upgrade, then JSON frames (own listener, default :4001)
```

## Handshake

The token is presented **once**, in the query string of the upgrade request.
`BitArena.PlayerConn.init/1` decodes it, resolves perks, and hands the player
to the matchmaker. Nothing the client sends afterwards can change its tier.

## Server → client

### `welcome` (once, immediately after joining)

```json
{
  "type": "welcome",
  "you": "p_9f3ac118",
  "name": "dev★-1a2b",
  "match": "arena-1",
  "skin": "golden",
  "arena": { "width": 1280, "height": 720 },
  "win_score": 30,
  "tick_hz": 20
}
```

### `state` (every tick, 20 Hz by default)

A full snapshot. No deltas, no client-side prediction — at eight players this
is a few hundred bytes and keeps the demo readable.

```json
{
  "type": "state",
  "tick": 412,
  "status": "running",
  "players": [
    { "id": "p_9f3ac118", "name": "dev★-1a2b", "x": 640.5, "y": 361.0,
      "score": 12, "skin": "golden", "trail": true }
  ],
  "coins": [ { "id": 17, "x": 233, "y": 88, "v": 2 } ]
}
```

### `game_over` (once, then the match lingers ~6 s and exits)

```json
{
  "type": "game_over",
  "match": "arena-1",
  "winner": "dev★-1a2b",
  "scores": { "dev★-1a2b": 30, "guest-77c1": 18 },
  "board": [ { "name": "dev★-1a2b", "wins": 3, "best": 30, "played": 5 } ]
}
```

## Client → server

### `input`

The only message that affects the world. `dir` is a desired direction, not a
position and not a velocity.

```json
{ "t": "input", "dir": [1, -1] }
```

Both components are clamped to `-1..1` in `PlayerSocket.sanitize_dir/1`, and the
vector is then clamped to unit length in `Match.unit/2`. Sending `[9999, 9999]`
moves you exactly as fast as `[0.7, 0.7]`. There is a test for this.

### `ping`

```json
{ "t": "ping" }        →  { "type": "pong", "ts": 1766650000000 }
```

## Why the token is forgeable (read this before copying the design)

A token is `btk_` + base64url(JSON) with **no signature**:

```
btk_eyJhY2N0IjoiZGV2IiwidGllciI6InByZW1pdW0iLCJpYXQiOjB9
→ {"acct":"dev","tier":"premium","iat":0}
```

That is deliberate. It reproduces the single most common real-world mistake in
mobile game backends: the client is trusted to *report* what the backend said,
and the game server verifies a token it never signed. It is what makes the
private-server demo work in one line instead of one afternoon.

**How you would harden it**

1. Sign the claims server-side (`:crypto.mac(:hmac, :sha256, secret, payload)`)
   and reject any token whose MAC does not verify.
2. Put `exp` in the claims and honour it.
3. Never let the client choose which host issues the token — resolve
   entitlements server-to-server, inside the game backend.
4. Pin the certificate so a lab proxy cannot sit in the middle.

Each of those steps breaks a different rung of the private-server ladder, which
is the actual lesson of the demo.
