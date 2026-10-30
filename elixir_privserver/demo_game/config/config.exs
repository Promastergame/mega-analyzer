import Config

config :bit_arena,
  http_port: 4000,
  # Game WebSocket listener (separate port: :inets cannot upgrade to WS).
  ws_port: 4001,
  # Authoritative simulation rate (server ticks per second).
  tick_hz: 20,
  # Arena bounds in logical units.
  arena: %{width: 1280, height: 720},
  # A round ends when a player reaches win_score, or after round_ms elapses.
  win_score: 30,
  round_ms: 120_000,
  max_players_per_match: 8

config :logger, :console,
  format: "[$level] $message\n",
  level: :info
