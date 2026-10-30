import Config

# Default OmniSec server config — headless mode (no HTTP).
# Override per-environment in `config/{dev,test,prod}.exs` or via
# `runtime.exs` for runtime-injected secrets.

config :omnisec_server,
  # Set to `true` and configure `OmnisecServer.HttpServer` below to expose
  # the REST API on a long-running node. Default boot is headless.
  enable_endpoint: false,
  # Private mode — set via OMNISEC_PRIVATE_TOKEN env var.
  # nil/empty = mode disabled (open access).
  private_token: System.get_env("OMNISEC_PRIVATE_TOKEN"),
  # Admin/debug mode token
  admin_token: System.get_env("OMNISEC_ADMIN_TOKEN"),
  # Special folder for file uploads in debugger
  uploads_dir: System.get_env("OMNISEC_UPLOADS_DIR") || Path.expand("uploads"),
  # Project root folder for running Go CLI and commands
  project_root: System.get_env("OMNISEC_PROJECT_ROOT") || Path.expand("../"),
  # CIDR-style allowlist, empty list = allow all IPs.
  allowed_ips: []

# Dependency-free HTTP + WebSocket servers (only used when
# enable_endpoint == true). No secret key base is needed — auth is
# bearer tokens compared in constant time (see `OmnisecServer.Crypto`).
config :omnisec_server, OmnisecServer.HttpServer,
  ip: {127, 0, 0, 1},
  port: 4000

config :omnisec_server, OmnisecServer.WsServer,
  ip: {127, 0, 0, 1},
  port: 4001

# Logger
config :logger, :default_formatter,
  format: "$time [$level] $message\n",
  metadata: [:request_id]

import_config "#{config_env()}.exs"
