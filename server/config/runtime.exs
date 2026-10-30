import Config

# runtime.exs runs after release boot, so it can read env vars set by
# the deployment system. Use it to flip the endpoint on, set the
# ports, and inject tokens.

if config_env() == :prod do
  port = String.to_integer(System.get_env("PORT") || "4000")
  ws_port = String.to_integer(System.get_env("WS_PORT") || Integer.to_string(port + 1))

  private_token = System.get_env("OMNISEC_PRIVATE_TOKEN")
  if is_nil(private_token) or private_token == "" do
    raise "OMNISEC_PRIVATE_TOKEN is missing or empty! Production mode requires a valid OMNISEC_PRIVATE_TOKEN."
  end

  admin_token = System.get_env("OMNISEC_ADMIN_TOKEN")
  if is_nil(admin_token) or admin_token == "" do
    raise "OMNISEC_ADMIN_TOKEN is missing or empty! Production mode requires a valid OMNISEC_ADMIN_TOKEN."
  end

  config :omnisec_server,
    private_token: private_token,
    admin_token: admin_token

  config :omnisec_server, OmnisecServer.HttpServer,
    ip: {0, 0, 0, 0},
    port: port

  config :omnisec_server, OmnisecServer.WsServer,
    ip: {0, 0, 0, 0},
    port: ws_port
end
