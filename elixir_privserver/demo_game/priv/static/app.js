/*
 * Bit Arena — browser client.
 *
 * Deliberately dumb: it renders whatever the server says and sends nothing but
 * a desired direction. The one thing it *does* get to decide is where to fetch
 * its entitlement token from — which is exactly the hook a private server
 * abuses. Swap the "session server" field and watch the tier flip.
 */
(() => {
  "use strict";

  const qs = new URLSearchParams(location.search);
  const $ = (id) => document.getElementById(id);

  const S = {
    ws: null,
    you: null,
    match: "",
    arena: { width: 1280, height: 720 },
    winScore: 30,
    players: [],
    coins: [],
    tick: 0,
    tier: "free",
    perks: null,
    over: null,
    lastDir: "",
  };

  const keys = new Set();
  const KEYMAP = {
    ArrowUp: [0, -1],
    ArrowDown: [0, 1],
    ArrowLeft: [-1, 0],
    ArrowRight: [1, 0],
    KeyW: [0, -1],
    KeyS: [0, 1],
    KeyA: [-1, 0],
    KeyD: [1, 0],
  };

  const canvas = $("arena");
  const ctx = canvas.getContext("2d");

  function log(msg) {
    const box = $("log");
    const line = document.createElement("div");
    line.textContent = msg;
    box.prepend(line);
    while (box.childElementCount > 40) box.lastElementChild.remove();
  }

  async function play() {
    const base = ($("session").value || "").trim().replace(/\/+$/, "") || location.origin;
    const account = ($("account").value || "").trim() || "guest";

    log(`GET ${base}/api/v1/session?account=${account}`);

    let session;
    try {
      const res = await fetch(`${base}/api/v1/session?account=${encodeURIComponent(account)}`);
      session = await res.json();
    } catch (err) {
      log(`session server unreachable: ${err.message}`);
      log("if this is a private server, make sure it sends CORS headers");
      return;
    }

    if (!session || !session.token) {
      log("session server returned no token");
      return;
    }

    S.tier = session.tier || "free";
    S.perks = session.perks || null;
    paintTier(base);
    log(`tier = ${S.tier} · token ${String(session.token).slice(0, 20)}...`);

    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    // The game socket lives on its own listener (plain HTTP cannot be
    // upgraded by the stdlib server); the session tells us its port.
    const wsPort = session.ws_port || location.port || (location.protocol === "https:" ? 443 : 80);
    const url = `${proto}//${location.hostname}:${wsPort}/ws?token=${encodeURIComponent(session.token)}`;
    log(`connecting ${url}`);
    const ws = new WebSocket(url);
    S.ws = ws;
    S.over = null;

    ws.onopen = () => log("websocket open — joining a match");
    ws.onclose = () => {
      log("websocket closed");
      $("play").disabled = false;
      $("play").textContent = "play again";
    };
    ws.onerror = () => log("websocket error");
    ws.onmessage = (ev) => {
      try {
        onFrame(JSON.parse(ev.data));
      } catch (_err) {
        /* ignore malformed frame */
      }
    };

    $("play").disabled = true;
    $("play").textContent = "in match";
  }

  function onFrame(msg) {
    if (msg.type === "welcome") {
      S.you = msg.you;
      S.match = msg.match;
      S.arena = msg.arena;
      S.winScore = msg.win_score;
      canvas.width = msg.arena.width;
      canvas.height = msg.arena.height;
      log(`welcome: you are ${msg.name} in ${msg.match} — first to ${msg.win_score}`);
      return;
    }

    if (msg.type === "state") {
      S.players = msg.players || [];
      S.coins = msg.coins || [];
      S.tick = msg.tick;
      return;
    }

    if (msg.type === "game_over") {
      S.over = msg;
      log(`game over — winner: ${msg.winner || "nobody"}`);
    }
  }

  function sendDir() {
    if (!S.ws || S.ws.readyState !== 1) return;

    let dx = 0;
    let dy = 0;
    keys.forEach((code) => {
      const v = KEYMAP[code];
      if (v) {
        dx += v[0];
        dy += v[1];
      }
    });
    dx = Math.max(-1, Math.min(1, dx));
    dy = Math.max(-1, Math.min(1, dy));

    const key = `${dx},${dy}`;
    if (key === S.lastDir) return;
    S.lastDir = key;
    S.ws.send(JSON.stringify({ t: "input", dir: [dx, dy] }));
  }

  function paintTier(base) {
    const badge = $("tier");
    badge.textContent = S.tier.toUpperCase();
    badge.className = `badge ${S.tier}`;
    $("source").textContent = base;
    $("perks").textContent = S.perks
      ? `speed x${S.perks.speed_mult} · coins x${S.perks.coin_mult} · ${S.perks.skin}`
      : "—";
  }

  function colorFor(p) {
    if (p.skin === "golden") return "#fbbf24";
    return p.id === S.you ? "#22d3ee" : "#8b5cf6";
  }

  function draw() {
    const w = canvas.width;
    const h = canvas.height;
    ctx.clearRect(0, 0, w, h);

    ctx.strokeStyle = "rgba(139,92,246,0.12)";
    ctx.lineWidth = 1;
    for (let x = 0; x <= w; x += 64) {
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, h);
      ctx.stroke();
    }
    for (let y = 0; y <= h; y += 64) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(w, y);
      ctx.stroke();
    }

    for (const c of S.coins) {
      const fill = c.v >= 3 ? "#f472b6" : c.v === 2 ? "#facc15" : "#fde68a";
      ctx.beginPath();
      ctx.arc(c.x, c.y, 9 + c.v, 0, Math.PI * 2);
      ctx.fillStyle = fill;
      ctx.shadowColor = fill;
      ctx.shadowBlur = 14;
      ctx.fill();
      ctx.shadowBlur = 0;
    }

    for (const p of S.players) {
      const col = colorFor(p);

      if (p.trail) {
        ctx.beginPath();
        ctx.arc(p.x, p.y, 26, 0, Math.PI * 2);
        ctx.fillStyle = "rgba(251,191,36,0.18)";
        ctx.fill();
      }

      ctx.beginPath();
      ctx.arc(p.x, p.y, 14, 0, Math.PI * 2);
      ctx.fillStyle = col;
      ctx.shadowColor = col;
      ctx.shadowBlur = 18;
      ctx.fill();
      ctx.shadowBlur = 0;

      if (p.id === S.you) {
        ctx.beginPath();
        ctx.arc(p.x, p.y, 20, 0, Math.PI * 2);
        ctx.strokeStyle = "#ffffff";
        ctx.lineWidth = 2;
        ctx.stroke();
      }

      ctx.fillStyle = "rgba(233,231,245,0.92)";
      ctx.font = "600 13px 'Plus Jakarta Sans', system-ui, sans-serif";
      ctx.textAlign = "center";
      ctx.fillText(`${p.name} · ${p.score}`, p.x, p.y - 22);
    }

    if (S.over) {
      ctx.fillStyle = "rgba(9,6,22,0.84)";
      ctx.fillRect(0, 0, w, h);
      ctx.textAlign = "center";
      ctx.fillStyle = "#fbbf24";
      ctx.font = "700 46px 'Outfit', system-ui, sans-serif";
      ctx.fillText("GAME OVER", w / 2, h / 2 - 46);
      ctx.fillStyle = "#e9e7f5";
      ctx.font = "500 21px 'Plus Jakarta Sans', system-ui, sans-serif";
      ctx.fillText(`winner: ${S.over.winner || "nobody"}`, w / 2, h / 2 - 6);

      let y = h / 2 + 32;
      const scores = S.over.scores || {};
      for (const name of Object.keys(scores)) {
        ctx.fillText(`${name} — ${scores[name]}`, w / 2, y);
        y += 26;
      }
    }

    renderScores();
    requestAnimationFrame(draw);
  }

  function renderScores() {
    const sorted = S.players.slice().sort((a, b) => b.score - a.score);

    $("scores").innerHTML = sorted
      .map((p) => {
        const me = p.id === S.you ? " me" : "";
        const pct = Math.min(100, Math.round((p.score / S.winScore) * 100));
        return (
          `<li class="row${me}">` +
          `<span class="dot" style="background:${colorFor(p)}"></span>` +
          `<span class="nm">${escapeHtml(p.name)}</span>` +
          `<span class="bar"><i style="width:${pct}%"></i></span>` +
          `<b>${p.score}</b></li>`
        );
      })
      .join("");

    $("tickv").textContent = S.tick;
    $("matchv").textContent = S.match || "—";
  }

  function escapeHtml(s) {
    return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  window.addEventListener("keydown", (e) => {
    if (KEYMAP[e.code]) {
      keys.add(e.code);
      e.preventDefault();
    }
  });
  window.addEventListener("keyup", (e) => keys.delete(e.code));
  window.addEventListener("blur", () => keys.clear());

  $("session").value = qs.get("session") || location.origin;
  $("account").value = qs.get("account") || "guest";
  $("play").addEventListener("click", play);

  setInterval(sendDir, 50);
  requestAnimationFrame(draw);
  log("ready — pick a session server and press play");
})();
