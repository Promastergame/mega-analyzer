defmodule MockServer do
  @moduledoc """
  Mega-Analyzer Mock Server — a programmable **private backend**.

  Point a client (or a patched APK) at this server and it answers like the real
  thing: authenticated sessions, active licenses, enabled feature flags, and
  whatever else you describe in `priv/rules.json`. Together with the demo game
  in `../demo_game` it closes the loop — the honest game issues *free*
  entitlement tokens, this server issues *premium* ones, and a client that
  trusts its backend lights up every perk.

  Three moving parts:

    * `MockServer.RuleStore`  — declarative request → response rules, reloadable
      at runtime without dropping connections.
    * `MockServer.Scenario`   — fault injection (`:normal`, `:flaky`, `:offline`,
      `:expired`) so you can watch how a client copes when its backend misbehaves.
    * `MockServer.Stats`      — counters plus a rolling traffic log, rendered on
      the live dashboard.

  Authorized lab / educational use only.
  """

  alias MockServer.{RuleStore, Scenario, Stats}

  @doc "High-level status, as rendered by the dashboard and `GET /api/status`."
  def info do
    %{
      name: "Mega-Analyzer Mock Server",
      mock_port: Application.get_env(:mock_server, :mock_port, 9340),
      admin_port: Application.get_env(:mock_server, :admin_port, 9341),
      rules: RuleStore.count(),
      scenario: Scenario.current(),
      stats: Stats.summary()
    }
  end

  @doc "Reload `priv/rules.json` in place. Returns `{:ok, rule_count}`."
  defdelegate reload_rules(), to: RuleStore, as: :reload

  @doc "Switch the active fault-injection scenario."
  defdelegate set_scenario(name), to: Scenario, as: :set
end
