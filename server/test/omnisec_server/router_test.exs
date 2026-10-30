defmodule OmnisecServer.RouterTest do
  use ExUnit.Case, async: false

  alias OmnisecServer.{Conn, Router}

  setup do
    old_private = Application.get_env(:omnisec_server, :private_token)
    old_admin = Application.get_env(:omnisec_server, :admin_token)
    old_ips = Application.get_env(:omnisec_server, :allowed_ips)

    on_exit(fn ->
      Application.put_env(:omnisec_server, :private_token, old_private)
      Application.put_env(:omnisec_server, :admin_token, old_admin)
      Application.put_env(:omnisec_server, :allowed_ips, old_ips)
    end)

    Application.put_env(:omnisec_server, :private_token, nil)
    Application.put_env(:omnisec_server, :admin_token, nil)
    Application.put_env(:omnisec_server, :allowed_ips, [])
    :ok
  end

  defp conn(method, path, opts \\ []) do
    {path, qs, query} = Conn.split_path(path)

    Conn.new(
      method: method,
      path: path,
      query_string: qs,
      query_params: query,
      params: query,
      headers: Keyword.get(opts, :headers, []),
      body: Keyword.get(opts, :body, ""),
      remote_ip: Keyword.get(opts, :remote_ip, "127.0.0.1")
    )
    |> Conn.parse_body()
  end

  test "GET /health returns ok envelope" do
    conn = conn("GET", "/health") |> Router.dispatch()
    assert conn.status == 200
    assert {:ok, %{"status" => "ok"}} = OmnisecServer.JSON.decode(conn.resp_body)
  end

  test "unknown route returns 404" do
    conn = conn("GET", "/nope") |> Router.dispatch()
    assert conn.status == 404
    assert {:ok, %{"ok" => false}} = OmnisecServer.JSON.decode(conn.resp_body)
  end

  test "non-JSON accept returns 406" do
    conn = conn("GET", "/health", headers: [{"accept", "text/html"}]) |> Router.dispatch()
    assert conn.status == 406
  end

  test "private mode rejects missing/wrong token with 401" do
    Application.put_env(:omnisec_server, :private_token, "secret")

    assert conn("POST", "/api/v1/analyze/apk") |> Router.dispatch() |> Map.get(:status) == 401

    bad =
      conn("POST", "/api/v1/analyze/apk", headers: [{"authorization", "Bearer wrong"}])
      |> Router.dispatch()

    assert bad.status == 401
  end

  test "private mode passes correct token through to controller" do
    Application.put_env(:omnisec_server, :private_token, "secret")

    conn =
      conn("POST", "/api/v1/analyze/apk", headers: [{"authorization", "Bearer secret"}])
      |> Router.dispatch()

    # Auth passed — controller rejects the empty body with 400.
    assert conn.status == 400
    assert {:ok, %{"ok" => false, "error" => "empty body"}} = OmnisecServer.JSON.decode(conn.resp_body)
  end

  test "invalid base64 payload returns 400" do
    conn =
      conn("POST", "/api/v1/analyze/apk",
        headers: [{"content-type", "application/json"}],
        body: ~s({"data_b64":"!!!not-base64!!!"})
      )
      |> Router.dispatch()

    assert conn.status == 400
  end

  test "allowlist blocks foreign IPs with 403" do
    Application.put_env(:omnisec_server, :allowed_ips, ["10.0.0.1"])

    conn = conn("GET", "/health") |> Router.dispatch()
    assert conn.status == 200

    blocked =
      conn("POST", "/api/v1/analyze/apk", remote_ip: "127.0.0.1", body: "x")
      |> Router.dispatch()

    assert blocked.status == 403
  end

  test "debug action without session_id returns 400" do
    conn =
      conn("GET", "/api/v1/debug/registers")
      |> Router.dispatch()

    assert conn.status == 400
  end

  test "debug action with unknown session returns 404 (ownership guard)" do
    conn = conn("GET", "/api/v1/debug/registers?session_id=999999") |> Router.dispatch()
    assert conn.status == 404
    assert {:ok, %{"ok" => false, "error" => "unknown session"}} = OmnisecServer.JSON.decode(conn.resp_body)
  end

  test "admin-only debug action without admin token configured falls back to open mode" do
    conn =
      conn("POST", "/api/v1/debug/patch",
        headers: [{"content-type", "application/json"}],
        body: ~s({"session_id":999999,"address":0,"hex":"90"})
      )
      |> Router.dispatch()

    # Open mode passes admin plug; ownership guard rejects unknown session.
    assert conn.status == 404
  end

  test "admin-only debug action rejects wrong admin token with 401" do
    Application.put_env(:omnisec_server, :private_token, "secret")
    Application.put_env(:omnisec_server, :admin_token, "admin-secret")

    conn =
      conn("POST", "/api/v1/debug/patch",
        headers: [{"content-type", "application/json"}, {"authorization", "Bearer secret"}],
        body: ~s({"session_id":1,"address":0,"hex":"90"})
      )
      |> Router.dispatch()

    assert conn.status == 401
  end
end
