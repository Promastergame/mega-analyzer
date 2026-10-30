import Config

config :mock_server,
  # The fake backend clients talk to.
  mock_port: 9340,
  # The live dashboard + control API.
  admin_port: 9341,
  # Loaded from priv/, hot-reloadable at runtime.
  rules_path: "rules.json"

config :logger, :console,
  format: "[$level] $message\n",
  level: :info
