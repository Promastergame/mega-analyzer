import Config

config :omnisec_server,
  enable_endpoint: false

config :omnisec_server, OmnisecServer.HttpServer,
  ip: {127, 0, 0, 1},
  port: 4002

config :omnisec_server, OmnisecServer.WsServer,
  ip: {127, 0, 0, 1},
  port: 4003

config :logger, level: :warning
