defmodule MockServer.Application do
  @moduledoc false

  use Application
  require Logger

  @impl true
  def start(_type, _args) do
    mock_port = Application.get_env(:mock_server, :mock_port, 9340)
    admin_port = Application.get_env(:mock_server, :admin_port, 9341)

    children = [
      # Counters + rolling traffic log (ETS).
      MockServer.Stats,
      # Active fault-injection profile.
      MockServer.Scenario,
      # Declarative rules from priv/rules.json.
      MockServer.RuleStore,
      # The fake backend itself. Plain `:gen_tcp` HTTP/1.1 (not `:inets`:
      # OTP httpd answers 501 to OPTIONS before our code runs, and this
      # backend contractually serves every method incl. CORS preflight).
      Supervisor.child_spec({MockServer.TcpServer, port: mock_port, router: MockServer.Router},
        id: :mock_tcp
      ),
      # Live dashboard + control API (plain GET/POST — `:inets` is fine).
      Supervisor.child_spec(
        {MockServer.HttpServer, port: admin_port, router: MockServer.Admin.Router},
        id: :admin_http
      )
    ]

    result = Supervisor.start_link(children, strategy: :one_for_one, name: MockServer.Supervisor)
    banner(mock_port, admin_port)
    result
  end

  defp banner(mock_port, admin_port) do
    Logger.info("""
    ─────────────────────────────────────────────────────────
     Mega-Analyzer Mock Server — authorized lab use only
     fake backend : http://localhost:#{mock_port}
     dashboard    : http://localhost:#{admin_port}
     rules        : #{MockServer.RuleStore.count()} loaded from priv/rules.json
     scenario     : #{MockServer.Scenario.current()}
    ─────────────────────────────────────────────────────────
    """)
  end
end
