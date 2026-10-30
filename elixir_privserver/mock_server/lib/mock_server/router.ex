defmodule MockServer.Router do
  @moduledoc """
  The fake backend. Every request — any method, any path — is answered by
  `MockServer.RuleEngine`, recorded in `MockServer.Stats`, and logged.

  CORS is wide open and `OPTIONS` is short-circuited on purpose: browser clients
  (like the Bit Arena demo running on another port) have to be able to point
  their session lookup here without tripping a preflight.
  """
  require Logger

  alias MockServer.{Conn, RuleEngine, Stats}

  @spec dispatch(Conn.t()) :: Conn.t()
  def dispatch(%Conn{method: "OPTIONS"} = conn) do
    %{conn | status: 204, resp_body: ""}
    |> put_cors()
  end

  def dispatch(%Conn{method: method, path: path} = conn) do
    {rule, status, body} = RuleEngine.resolve(method, path, conn.body_params)

    Stats.record(%{
      ts: System.system_time(:millisecond),
      method: method,
      path: path,
      status: status,
      rule: rule
    })

    Logger.info("#{method} #{path} -> #{status} [#{rule}]")

    %{conn | status: status, resp_body: MockServer.JSON.encode!(body)}
    |> Conn.put_resp_content_type("application/json")
    |> put_cors()
  end

  defp put_cors(conn) do
    conn
    |> Conn.put_resp_header("access-control-allow-origin", "*")
    |> Conn.put_resp_header("access-control-allow-methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
    |> Conn.put_resp_header("access-control-allow-headers", "*")
  end
end
