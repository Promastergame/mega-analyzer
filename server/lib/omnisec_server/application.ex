defmodule OmnisecServer.Application do
  @moduledoc """
  OmniSec Server — OTP Application entry point.

  Starts the supervision tree:
    1. ResultCache — ETS-backed result caching
    2. DebugSessions — debugger session ownership registry
    3. WorkerPool — manages Rust NIF analysis workers
    4. TaskSupervisor — DynamicSupervisor for concurrent analysis tasks
    5. ClusterMonitor — multi-node health / metrics
    6. HttpServer + WsServer (optional) — REST + WebSocket API on
       OTP `:inets` / `:gen_tcp`, no third-party dependencies

  The HTTP layer is opt-in via application config. When unset, the
  server boots in headless mode with just the worker pool and NIF —
  this is the default for local dev and CI.
  """

  use Application
  require Logger

  @impl true
  def start(_type, _args) do
    children =
      [
        # Result cache (ETS)
        OmnisecServer.ResultCache,

        # Debugger session ownership registry (ETS)
        OmnisecServer.DebugSessions,

        # Worker pool for Rust NIF analysis engines
        {OmnisecServer.WorkerPool, pool_size: System.schedulers_online() * 2},

        # Dynamic task supervisor for concurrent analysis jobs
        {Task.Supervisor, name: OmnisecServer.TaskSupervisor},

        # Cluster monitor
        OmnisecServer.ClusterMonitor
      ]
      |> maybe_add_http()

    opts = [strategy: :one_for_one, name: OmnisecServer.Supervisor]

    Logger.info("""
    ╔══════════════════════════════════════════╗
    ║         OMNISEC SERVER v0.2.0            ║
    ║      Distributed Analysis Platform       ║
    ╚══════════════════════════════════════════╝

    Workers: #{System.schedulers_online() * 2}
    Node:    #{Node.self()}
    HTTP:    #{if endpoint_enabled?(), do: "ENABLED (port #{http_port()})", else: "disabled"}
    """)

    Supervisor.start_link(children, opts)
  end

  # ─── Optional children ──────────────────────────────────────────

  defp maybe_add_http(children) do
    if endpoint_enabled?() do
      http_opts = Application.get_env(:omnisec_server, OmnisecServer.HttpServer, [])
      ws_opts = Application.get_env(:omnisec_server, OmnisecServer.WsServer, [])

      http_opts =
        Keyword.merge(
          [ip: {127, 0, 0, 1}, port: http_port()],
          http_opts
        )

      ws_opts =
        Keyword.merge(
          [ip: {127, 0, 0, 1}, port: http_port() + 1],
          ws_opts
        )

      children ++
        [
          {OmnisecServer.HttpServer, http_opts},
          {OmnisecServer.WsServer, ws_opts}
        ]
    else
      children
    end
  end

  defp endpoint_enabled?, do: Application.get_env(:omnisec_server, :enable_endpoint, false)

  defp http_port do
    case Application.get_env(:omnisec_server, OmnisecServer.HttpServer, []) do
      cfg when is_list(cfg) -> Keyword.get(cfg, :port, 4000)
      _ -> 4000
    end
  end
end
