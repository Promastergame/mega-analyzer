import Config

# Dev defaults: keep the endpoint off so `iex -S mix` boots straight
# into the worker pool. Flip to true to actually serve HTTP+WS.

config :omnisec_server,
  enable_endpoint: false

config :omnisec_server, OmnisecServer.HttpServer,
  ip: {127, 0, 0, 1},
  port: 4000

config :omnisec_server, OmnisecServer.WsServer,
  ip: {127, 0, 0, 1},
  port: 4001

config :logger, level: :debug
