defmodule OmnisecServer.AllowlistPlug do
  @moduledoc """
  Blocks requests from IPs not in the allowlist.

  Skips all checks when `allowed_ips` is empty or nil (open mode).
  Uses `conn.remote_ip` directly — no X-Forwarded-For trust.
  Single IP matching only (no CIDR yet).
  """

  alias OmnisecServer.Conn

  def init(opts), do: opts

  def call(conn, _opts) do
    ips = Application.get_env(:omnisec_server, :allowed_ips) || []

    if ips == [] do
      conn
    else
      check_ip(conn, ips)
    end
  end

  defp check_ip(conn, allowed) do
    remote = conn.remote_ip

    if ip_to_string(remote) in allowed do
      conn
    else
      halt_with_403(conn)
    end
  end

  defp ip_to_string(ip) when is_binary(ip), do: ip
  defp ip_to_string({a, b, c, d}), do: "#{a}.#{b}.#{c}.#{d}"
  defp ip_to_string(addr), do: "#{:inet.ntoa(addr)}"

  defp halt_with_403(conn) do
    conn
    |> Conn.put_resp_content_type("application/json")
    |> Conn.send_resp(403, ~s({"ok":false,"error":"access denied"}))
    |> Conn.halt()
  end
end