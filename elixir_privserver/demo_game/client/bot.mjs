#!/usr/bin/env node
/*
 * Bit Arena — headless reference client (a coin-seeking bot).
 *
 * Zero dependencies: Node 22+ ships a global fetch and a global WebSocket.
 * It exists for two reasons:
 *   1. to fill an arena with traffic so the server is doing something visible;
 *   2. to be the smallest possible demonstration of the private-server swap —
 *      the same binary is free or premium depending only on --backend.
 *
 *   node bot.mjs                                        # honest server -> free
 *   node bot.mjs --backend http://localhost:9340        # private server -> premium
 */

const argv = process.argv.slice(2);

function parseArgs(list) {
  const out = {};
  for (let i = 0; i < list.length; i += 1) {
    const arg = list[i];
    if (!arg.startsWith("--")) continue;
    const key = arg.slice(2);
    const next = list[i + 1];
    if (next && !next.startsWith("--")) {
      out[key] = next;
      i += 1;
    } else {
      out[key] = true;
    }
  }
  return out;
}

const args = parseArgs(argv);

if (args.help || args.h) {
  console.log(`Bit Arena headless bot

Usage: node bot.mjs [options]

  --backend <url>    where to fetch the entitlement token   (default http://localhost:4000)
  --game <ws url>    the game websocket                     (default ws://localhost:4001/ws)
  --account <name>   account presented to the session API    (default guest)
  --duration <secs>  leave after N seconds                   (default 60)
  --quiet            only print join / game over
  --help             this text

Try it twice to see the point of the toolkit:
  node bot.mjs --account guest
  node bot.mjs --account guest --backend http://localhost:9340
`);
  process.exit(0);
}

const backend = String(args.backend || "http://localhost:4000").replace(/\/+$/, "");
const game = String(args.game || "ws://localhost:4001/ws").replace(/\/+$/, "");
const account = String(args.account || "guest");
const duration = Number(args.duration || 60);
const quiet = Boolean(args.quiet);

const say = (...m) => console.log("[bot]", ...m);

let session;
try {
  const res = await fetch(`${backend}/api/v1/session?account=${encodeURIComponent(account)}`);
  session = await res.json();
} catch (err) {
  say(`could not reach the session server at ${backend}: ${err.message}`);
  process.exit(1);
}

if (!session || !session.token) {
  say("session server returned no token");
  process.exit(1);
}

say(`session from ${backend} -> tier=${session.tier}`);
if (session.perks) {
  say(`perks: speed x${session.perks.speed_mult}, coins x${session.perks.coin_mult}, skin ${session.perks.skin}`);
}

const ws = new WebSocket(`${game}?token=${encodeURIComponent(session.token)}`);

let me = null;
let latest = null;
let lastDir = "";
let lastSent = 0;
let reporter = null;
let leaving = null;

function finish(code) {
  if (reporter) clearInterval(reporter);
  if (leaving) clearTimeout(leaving);
  try {
    ws.close();
  } catch (_err) {
    /* already closed */
  }
  process.exit(code);
}

function nearestCoin(self, coins) {
  let best = null;
  let bestDist = Infinity;
  for (const c of coins) {
    const d = (c.x - self.x) ** 2 + (c.y - self.y) ** 2;
    if (d < bestDist) {
      bestDist = d;
      best = c;
    }
  }
  return best;
}

function steer(self, coins) {
  const coin = nearestCoin(self, coins);
  if (!coin) return [0, 0];
  const vx = coin.x - self.x;
  const vy = coin.y - self.y;
  const mag = Math.hypot(vx, vy) || 1;
  return [Number((vx / mag).toFixed(3)), Number((vy / mag).toFixed(3))];
}

ws.addEventListener("open", () => say(`connected to ${game}`));

ws.addEventListener("error", (ev) => {
  say(`socket error: ${ev.message || "unknown"}`);
  finish(1);
});

ws.addEventListener("close", () => {
  say("socket closed");
  finish(0);
});

ws.addEventListener("message", (ev) => {
  let msg;
  try {
    msg = JSON.parse(ev.data);
  } catch (_err) {
    return;
  }

  if (msg.type === "welcome") {
    me = msg.you;
    say(`welcome: ${msg.name} in ${msg.match}, first to ${msg.win_score} (${msg.tick_hz} Hz)`);
    return;
  }

  if (msg.type === "game_over") {
    say(`game over — winner: ${msg.winner || "nobody"}`);
    say(`final scores: ${JSON.stringify(msg.scores)}`);
    finish(0);
    return;
  }

  if (msg.type !== "state") return;

  latest = msg;
  const self = (msg.players || []).find((p) => p.id === me);
  if (!self) return;

  const dir = steer(self, msg.coins || []);
  const key = dir.join(",");
  const now = Date.now();

  // Only talk when the intent actually changes (plus a slow keep-alive).
  if (key !== lastDir || now - lastSent > 500) {
    lastDir = key;
    lastSent = now;
    ws.send(JSON.stringify({ t: "input", dir }));
  }
});

if (!quiet) {
  reporter = setInterval(() => {
    if (!latest || !me) return;
    const self = (latest.players || []).find((p) => p.id === me);
    if (!self) return;
    const board = (latest.players || [])
      .slice()
      .sort((a, b) => b.score - a.score)
      .map((p) => `${p.name}:${p.score}`)
      .join("  ");
    say(`tick ${latest.tick} · me ${self.score} · ${board}`);
  }, 2000);
}

leaving = setTimeout(() => {
  say(`duration ${duration}s reached, leaving`);
  finish(0);
}, duration * 1000);
