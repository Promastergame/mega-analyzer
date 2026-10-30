defmodule BitArena.Application do
  @moduledoc false

  use Application
  require Logger

  @impl true
  def start(_type, _args) do
    port = BitArena.config(:http_port, 4000)
    ws_port = BitArena.config(:ws_port, 4001)

    children = [
      # Cumulative wins/scores across every match (ETS).
      BitArena.Leaderboard,
      # One entry per live match, addressed by name.
      {Registry, keys: :unique, name: BitArena.MatchRegistry},
      # Matches are temporary GenServers spawned on demand.
      {DynamicSupervisor, name: BitArena.MatchSupervisor, strategy: :one_for_one},
      # Places joining players into an open match.
      BitArena.Matchmaker,
      # HTTP surface: client, session API (OTP :inets, no deps).
      {BitArena.HttpServer, port: port},
      # Game WebSocket (plain :gen_tcp, no deps).
      {BitArena.WsServer, port: ws_port}
    ]

    banner(port, ws_port)
    opts = [strategy: :one_for_one, name: BitArena.Supervisor]
    Supervisor.start_link(children, opts)
  end

  defp banner(port, ws_port) do
    Logger.info("""
    ─────────────────────────────────────────────────────────
     Bit Arena — authoritative demo game server
     client :  http://localhost:#{port}/
     ws     :  ws://localhost:#{ws_port}/ws
     status :  http://localhost:#{port}/api/v1/status
    ─────────────────────────────────────────────────────────
    """)
  end
end
