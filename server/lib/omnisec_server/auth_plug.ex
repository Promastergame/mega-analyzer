defmodule OmnisecServer.AuthPlug do
  @moduledoc """
  Verifies Bearer token from Authorization header.

  Skips all checks when `private_token` is nil/empty (open mode).
  On mismatch returns 401 with JSON and halts the connection.
  """

  alias OmnisecServer.{Conn, Crypto}

  def init(opts), do: opts

  def call(conn, _opts) do
    token = Application.get_env(:omnisec_server, :private_token)

    if is_nil(token) or token == "" do
      conn
    else
      check_token(conn, token)
    end
  end

  defp check_token(conn, expected) do
    case Conn.get_req_header(conn, "authorization") do
      ["Bearer " <> provided] ->
        if Crypto.secure_compare(provided, expected) do
          conn
        else
          halt_with_401(conn, "invalid token")
        end

      _ ->
        halt_with_401(conn, "missing or malformed Authorization header")
    end
  end

  defp halt_with_401(conn, reason) do
    conn
    |> Conn.put_resp_content_type("application/json")
    |> Conn.send_resp(401, ~s({"ok":false,"error":"#{reason}"}))
    |> Conn.halt()
  end
end