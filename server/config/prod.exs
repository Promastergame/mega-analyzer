import Config

# Production: the endpoint must be configured via runtime.exs (secrets
# come from env vars). This file just locks the static defaults.

config :omnisec_server,
  enable_endpoint: true

config :logger, level: :info
