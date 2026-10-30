defmodule MockServer.Admin.Router do
  @moduledoc """
  Control plane, served on the admin port. Deliberately kept on a separate
  listener so admin traffic never shows up in the fake backend's statistics.

      GET  /              live dashboard
      GET  /api/status    ports, rule count, active scenario, counters
      GET  /api/recent    rolling traffic log
      GET  /api/rules     currently loaded rules
      POST /api/scenario  {"name": "flaky"}  switch fault injection
      POST /api/reload    re-read priv/rules.json
  """

  alias MockServer.Admin.Dashboard
  alias MockServer.{Conn, RuleStore, Scenario, Stats}

  @spec dispatch(Conn.t()) :: Conn.t()
  def dispatch(%Conn{method: "GET", path: "/"} = conn) do
    %{conn | status: 200, resp_body: Dashboard.render()}
    |> Conn.put_resp_content_type("text/html")
  end

  def dispatch(%Conn{method: "GET", path: "/api/status"} = conn) do
    info = MockServer.info()
    Conn.json(conn, 200, %{info | scenario: to_string(info.scenario)})
  end

  def dispatch(%Conn{method: "GET", path: "/api/recent"} = conn) do
    Conn.json(conn, 200, %{recent: Stats.recent()})
  end

  def dispatch(%Conn{method: "GET", path: "/api/rules"} = conn) do
    Conn.json(conn, 200, %{rules: RuleStore.rules()})
  end

  def dispatch(%Conn{method: "POST", path: "/api/scenario"} = conn) do
    case Scenario.set(conn.body_params["name"]) do
      {:ok, name} ->
        Conn.json(conn, 200, %{ok: true, scenario: to_string(name)})

      {:error, :unknown} ->
        Conn.json(conn, 400, %{ok: false, error: "unknown scenario", allowed: Enum.map(Scenario.all(), &to_string/1)})
    end
  end

  def dispatch(%Conn{method: "POST", path: "/api/reload"} = conn) do
    {:ok, count} = MockServer.reload_rules()
    Conn.json(conn, 200, %{ok: true, rules: count})
  end

  def dispatch(%Conn{} = conn) do
    Conn.json(conn, 404, %{error: "not found"})
  end
end
