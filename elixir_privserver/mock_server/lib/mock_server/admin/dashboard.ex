defmodule MockServer.Admin.Dashboard do
  @moduledoc """
  The control-plane UI: one self-contained HTML document, no build step, no CDN,
  no fonts fetched over the network — it has to work on an air-gapped analysis
  box like everything else in Mega-Analyzer.

  It polls `/api/status` and `/api/recent` twice a second and can flip scenarios
  or reload `priv/rules.json` while traffic is running.
  """

  @html ~S"""
  <!doctype html>
  <html lang="en">
  <head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Mock Server — control plane</title>
  <style>
    :root {
      --bg: #090616;
      --panel: rgba(24, 17, 48, 0.72);
      --border: rgba(139, 92, 246, 0.28);
      --primary: #8b5cf6;
      --accent: #d946ef;
      --gold: #fbbf24;
      --text: #e9e7f5;
      --muted: #9d95c7;
      --success: #10b981;
      --danger: #f87171;
    }

    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      min-height: 100vh;
      padding: 34px 26px 60px;
      color: var(--text);
      font-family: "Plus Jakarta Sans", "Outfit", system-ui, -apple-system, "Segoe UI", sans-serif;
      background:
        radial-gradient(900px 620px at 12% -12%, rgba(139, 92, 246, 0.24), transparent),
        radial-gradient(760px 520px at 96% 0%, rgba(217, 70, 239, 0.16), transparent),
        var(--bg);
    }

    header {
      max-width: 1080px;
      margin: 0 auto 26px;
      display: flex;
      align-items: baseline;
      gap: 14px;
      flex-wrap: wrap;
    }

    h1 {
      margin: 0;
      font-size: 27px;
      letter-spacing: -0.5px;
      background: linear-gradient(92deg, var(--primary), var(--accent), var(--gold));
      -webkit-background-clip: text;
      background-clip: text;
      color: transparent;
    }

    .sub {
      margin: 0;
      color: var(--muted);
      font-size: 13.5px;
    }

    .pill {
      margin-left: auto;
      padding: 5px 12px;
      border-radius: 999px;
      font-size: 12px;
      border: 1px solid var(--border);
      background: rgba(139, 92, 246, 0.12);
    }

    .pill.ok {
      color: var(--success);
      border-color: rgba(16, 185, 129, 0.4);
    }

    .pill.bad {
      color: var(--danger);
      border-color: rgba(248, 113, 113, 0.45);
    }

    section {
      max-width: 1080px;
      margin: 0 auto 22px;
    }

    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
      gap: 14px;
    }

    .card,
    .panel {
      border: 1px solid var(--border);
      border-radius: 16px;
      background: var(--panel);
      backdrop-filter: blur(16px);
    }

    .card {
      padding: 16px 18px;
      display: flex;
      flex-direction: column;
      gap: 7px;
    }

    .label {
      font-size: 11.5px;
      text-transform: uppercase;
      letter-spacing: 0.9px;
      color: var(--muted);
    }

    .value {
      font-size: 25px;
      font-weight: 700;
      font-variant-numeric: tabular-nums;
    }

    .value.ok {
      color: var(--success);
    }

    .value.warn {
      color: var(--gold);
    }

    .panel {
      padding: 20px 22px;
    }

    .panel-head {
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 12px;
    }

    h2 {
      margin: 0 0 4px;
      font-size: 15px;
      letter-spacing: 0.2px;
    }

    .hint {
      margin: 0 0 14px;
      font-size: 12.5px;
      color: var(--muted);
    }

    .row {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
    }

    .chip,
    .ghost {
      cursor: pointer;
      font: inherit;
      font-size: 13px;
      padding: 8px 16px;
      border-radius: 999px;
      color: var(--text);
      border: 1px solid var(--border);
      background: rgba(139, 92, 246, 0.1);
      transition: transform 0.12s ease, border-color 0.12s ease;
    }

    .chip:hover,
    .ghost:hover {
      transform: translateY(-1px);
      border-color: var(--accent);
    }

    .chip.active {
      background: linear-gradient(92deg, var(--primary), var(--accent));
      border-color: transparent;
      font-weight: 600;
    }

    .ghost {
      margin-left: auto;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }

    th {
      text-align: left;
      padding: 8px 10px;
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.9px;
      color: var(--muted);
      border-bottom: 1px solid var(--border);
    }

    td {
      padding: 9px 10px;
      border-bottom: 1px solid rgba(139, 92, 246, 0.12);
      font-variant-numeric: tabular-nums;
    }

    td.path {
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      word-break: break-all;
    }

    .muted {
      color: var(--muted);
    }

    .ok {
      color: var(--success);
    }

    .warn {
      color: var(--gold);
    }

    .bad {
      color: var(--danger);
    }

    .empty {
      padding: 22px 10px;
      text-align: center;
      color: var(--muted);
    }

    #toast {
      position: fixed;
      left: 50%;
      bottom: 26px;
      transform: translate(-50%, 24px);
      opacity: 0;
      pointer-events: none;
      padding: 10px 18px;
      border-radius: 999px;
      font-size: 13px;
      border: 1px solid var(--border);
      background: rgba(24, 17, 48, 0.94);
      transition: opacity 0.18s ease, transform 0.18s ease;
    }

    #toast.show {
      opacity: 1;
      transform: translate(-50%, 0);
    }

    @media (max-width: 720px) {
      body {
        padding: 22px 14px 44px;
      }
    }
  </style>
  </head>
  <body>
    <header>
      <h1>Mock Server</h1>
      <p class="sub">programmable private backend · <span id="ports">…</span></p>
      <span class="pill" id="conn">connecting…</span>
    </header>

    <section class="grid" id="cards"></section>

    <section class="panel">
      <h2>Scenario</h2>
      <p class="hint">Applied before any rule runs, so you can watch a client cope with a backend that stops being polite.</p>
      <div class="row" id="scenarios"></div>
    </section>

    <section class="panel">
      <div class="panel-head">
        <h2>Live traffic</h2>
        <button class="ghost" id="reload">Reload rules</button>
      </div>
      <table>
        <thead>
          <tr><th>time</th><th>method</th><th>path</th><th>status</th><th>rule</th></tr>
        </thead>
        <tbody id="log"></tbody>
      </table>
    </section>

    <div id="toast"></div>

  <script>
    var SCENARIOS = ["normal", "flaky", "offline", "expired"];

    function el(id) {
      return document.getElementById(id);
    }

    function esc(value) {
      return String(value === null || value === undefined ? "" : value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
    }

    function card(label, value, accent) {
      return '<div class="card"><span class="label">' + label + '</span><span class="value ' +
        (accent || "") + '">' + esc(value) + "</span></div>";
    }

    function uptime(startedAt) {
      if (!startedAt) return "—";
      var s = Math.max(0, Math.floor(Date.now() / 1000) - startedAt);
      var m = Math.floor(s / 60);
      var h = Math.floor(m / 60);
      if (h > 0) return h + "h " + (m % 60) + "m";
      if (m > 0) return m + "m " + (s % 60) + "s";
      return s + "s";
    }

    function statusClass(status) {
      if (status >= 500) return "bad";
      if (status >= 400) return "warn";
      return "ok";
    }

    function logRow(entry) {
      var time = new Date(entry.ts).toLocaleTimeString();
      return "<tr><td class='muted'>" + time + "</td><td><b>" + esc(entry.method) +
        "</b></td><td class='path'>" + esc(entry.path) + "</td><td class='" +
        statusClass(entry.status) + "'>" + esc(entry.status) + "</td><td class='muted'>" +
        esc(entry.rule) + "</td></tr>";
    }

    function draw(status, log) {
      el("ports").textContent = "backend :" + status.mock_port + " · dashboard :" + status.admin_port;

      el("cards").innerHTML = [
        card("requests served", status.stats.total),
        card("rules loaded", status.rules),
        card("scenario", status.scenario, status.scenario === "normal" ? "ok" : "warn"),
        card("uptime", uptime(status.stats.started_at))
      ].join("");

      el("scenarios").innerHTML = SCENARIOS.map(function (name) {
        var active = name === status.scenario ? " active" : "";
        return '<button class="chip' + active + '" data-scenario="' + name + '">' + name + "</button>";
      }).join("");

      el("log").innerHTML = log.length
        ? log.map(logRow).join("")
        : '<tr><td colspan="5" class="empty">no traffic yet — point a client at port ' +
          status.mock_port + "</td></tr>";
    }

    function flash(text) {
      var node = el("toast");
      node.textContent = text;
      node.classList.add("show");
      setTimeout(function () {
        node.classList.remove("show");
      }, 2400);
    }

    async function tick() {
      try {
        var status = await fetch("/api/status").then(function (r) { return r.json(); });
        var recent = await fetch("/api/recent").then(function (r) { return r.json(); });
        draw(status, recent.recent || []);
        el("conn").textContent = "online";
        el("conn").className = "pill ok";
      } catch (err) {
        el("conn").textContent = "unreachable";
        el("conn").className = "pill bad";
      }
    }

    document.addEventListener("click", async function (event) {
      var chip = event.target.closest("[data-scenario]");

      if (chip) {
        var name = chip.dataset.scenario;
        await fetch("/api/scenario", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ name: name })
        });
        flash("scenario: " + name);
        tick();
        return;
      }

      if (event.target.id === "reload") {
        var result = await fetch("/api/reload", { method: "POST" }).then(function (r) { return r.json(); });
        flash("reloaded " + result.rules + " rule(s)");
        tick();
      }
    });

    tick();
    setInterval(tick, 1500);
  </script>
  </body>
  </html>
  """

  @doc "The dashboard document."
  def render, do: @html
end
