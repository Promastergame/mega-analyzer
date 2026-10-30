defmodule BitArena.Router do
  @moduledoc """
  HTTP surface for Bit Arena (dependency-free dispatch, replaces
  `Plug.Router`).

  It serves the browser client, exposes the entitlement/session endpoint (the
  single trust boundary a private server spoofs), and returns status +
  leaderboard JSON. WebSocket play lives on `BitArena.WsServer` — plain
  HTTP `GET /ws` answers `426` with the real WS port, because `:inets`
  cannot upgrade connections.
  """

  alias BitArena.{Conn, Entitlements, Leaderboard}

  @static_files ~w(app.js favicon.ico)

  @spec dispatch(Conn.t()) :: Conn.t()
  def dispatch(%Conn{method: "GET", path: "/"} = conn) do
    send_static(conn, "index.html", "text/html")
  end

  def dispatch(%Conn{method: "GET", path: "/" <> file} = conn) when file in @static_files do
    send_static(conn, file, mime_type(file))
  end

  # Honest entitlement server: only known accounts are premium (see Entitlements).
  # Point a client at a *private* server instead and it will hand out premium
  # tokens to anyone — that is the whole trick the toolkit demonstrates.
  def dispatch(%Conn{method: "GET", path: "/api/v1/session"} = conn) do
    account = conn.query_params["account"] || "guest"
    token = Entitlements.issue(account)
    {:ok, claims} = Entitlements.verify(token)

    json(conn, 200, %{
      ok: true,
      account: claims.account,
      tier: claims.tier,
      token: token,
      perks: Entitlements.perks(claims.tier),
      ws_port: BitArena.config(:ws_port, 4001)
    })
  end

  def dispatch(%Conn{method: "GET", path: "/api/v1/status"} = conn) do
    json(conn, 200, %{
      ok: true,
      info: sanitize(BitArena.info()),
      matches: Registry.count(BitArena.MatchRegistry),
      ws_port: BitArena.config(:ws_port, 4001)
    })
  end

  def dispatch(%Conn{method: "GET", path: "/api/v1/leaderboard"} = conn) do
    json(conn, 200, %{ok: true, board: Leaderboard.top(10)})
  end

  def dispatch(%Conn{path: "/ws"} = conn) do
    json(conn, 426, %{
      ok: false,
      error: "use the websocket listener",
      ws_port: BitArena.config(:ws_port, 4001)
    })
  end

  def dispatch(%Conn{} = conn) do
    json(conn, 404, %{ok: false, error: "not found"})
  end

  # ── helpers ──

  defp send_static(conn, file, content_type) do
    priv = :code.priv_dir(:bit_arena) |> to_string()
    path = Path.join([priv, "static", file])
    static = Path.join(priv, "static")
    expanded = Path.expand(path)

    if (expanded == static or String.starts_with?(expanded, static <> "/")) and File.regular?(expanded) do
      Conn.send_file(conn, 200, expanded, content_type)
    else
      json(conn, 404, %{ok: false, error: "not found"})
    end
  end

  defp mime_type(path) do
    case Path.extname(path) |> String.downcase() do
      ".html" -> "text/html"
      ".js" -> "application/javascript"
      ".ico" -> "image/x-icon"
      ".json" -> "application/json"
      _ -> "application/octet-stream"
    end
  end

  defp json(conn, status, term) do
    %{conn | status: status, resp_body: BitArena.JSON.encode!(sanitize(term))}
    |> Conn.put_resp_content_type("application/json")
  end

  # Game payloads carry Elixir-only terms (e.g. `transport: :websocket`
  # in `BitArena.info/0`); coerce them so the codec never leaks a 500.
  defp sanitize(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  defp sanitize(%_{} = struct), do: inspect(struct)
  defp sanitize(map) when is_map(map), do: Map.new(map, fn {k, v} -> {k, sanitize(v)} end)
  defp sanitize(list) when is_list(list), do: Enum.map(list, &sanitize/1)
  defp sanitize(tuple) when is_tuple(tuple), do: tuple |> Tuple.to_list() |> sanitize()
  defp sanitize(true), do: true
  defp sanitize(false), do: false
  defp sanitize(nil), do: nil
  defp sanitize(atom) when is_atom(atom), do: Atom.to_string(atom)
  defp sanitize(other), do: other
end
