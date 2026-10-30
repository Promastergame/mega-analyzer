defmodule OmnisecServer.HttpServerTest do
  @moduledoc """
  End-to-end tests for the `:inets`-based HTTP layer: real socket,
  stdlib `:httpc` client, no external dependencies.
  """
  use ExUnit.Case, async: false

  @port 4022
  @base "http://127.0.0.1:4022"

  setup do
    old_private = Application.get_env(:omnisec_server, :private_token)
    old_admin = Application.get_env(:omnisec_server, :admin_token)

    on_exit(fn ->
      Application.put_env(:omnisec_server, :private_token, old_private)
      Application.put_env(:omnisec_server, :admin_token, old_admin)
    end)

    Application.put_env(:omnisec_server, :private_token, nil)
    Application.put_env(:omnisec_server, :admin_token, nil)

    {:ok, _} = start_supervised({OmnisecServer.HttpServer, port: @port, ip: {127, 0, 0, 1}})
    :ok
  end

  defp get(path, headers \\ []) do
    :httpc.request(:get, {@base <> path |> String.to_charlist(), headers}, [], [])
  end

  defp post(path, body, content_type \\ "application/json") do
    :httpc.request(
      :post,
      {String.to_charlist(@base <> path), [], String.to_charlist(content_type), body},
      [],
      []
    )
  end

  test "GET /health returns JSON envelope" do
    {:ok, {{_, 200, _}, resp_headers, body}} = get("/health")
    assert List.keyfind(resp_headers, ~c"content-type", 0) |> elem(1) |> to_string() =~ "application/json"
    assert {:ok, %{"status" => "ok", "node" => _}} = OmnisecServer.JSON.decode(to_string(body))
  end

  test "unknown route returns 404 JSON" do
    {:ok, {{_, 404, _}, _, body}} = get("/nope")
    assert {:ok, %{"ok" => false}} = OmnisecServer.JSON.decode(to_string(body))
  end

  test "POST /api/v1/analyze/apk with empty body returns 400" do
    {:ok, {{_, 400, _}, _, body}} = post("/api/v1/analyze/apk", "")
    assert {:ok, %{"ok" => false, "error" => "empty body"}} = OmnisecServer.JSON.decode(to_string(body))
  end

  test "POST debug action with unknown session returns 404" do
    {:ok, {{_, 404, _}, _, body}} = get("/api/v1/debug/registers?session_id=777777")
    assert {:ok, %{"ok" => false, "error" => "unknown session"}} =
             OmnisecServer.JSON.decode(to_string(body))
  end

  test "private mode enforced over HTTP" do
    Application.put_env(:omnisec_server, :private_token, "secret")

    {:ok, {{_, 401, _}, _, _}} = post("/api/v1/analyze/apk", "x", "application/octet-stream")

    # Correct token passes auth and reaches the analysis pipeline (200).
    {:ok, {{_, 200, _}, _, body}} =
      :httpc.request(
        :post,
        {String.to_charlist(@base <> "/api/v1/analyze/apk"), [{~c"authorization", "Bearer secret"}],
         ~c"application/octet-stream", "x"},
        [],
        []
      )

    assert {:ok, %{"ok" => true}} = OmnisecServer.JSON.decode(to_string(body))
  end

  test "static index.html is served" do
    {:ok, {{_, 200, _}, resp_headers, body}} = get("/index.html")
    assert List.keyfind(resp_headers, ~c"content-type", 0) |> elem(1) |> to_string() =~ "text/html"
    assert to_string(body) =~ "<"
  end

  test "HEAD /health returns headers without body" do
    {:ok, {{_, 200, _}, _headers, body}} = :httpc.request(:head, {String.to_charlist(@base <> "/health"), []}, [], [])
    assert IO.iodata_to_binary(body) == ""
  end
end
