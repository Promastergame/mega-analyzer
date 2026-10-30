defmodule BitArena.HttpTest do
  @moduledoc """
  End-to-end smoke tests over the real `:inets` listener (stdlib
  `:httpc` client). The application tree already boots the listener in
  the test env on the configured HTTP port.
  """
  use ExUnit.Case, async: false

  @base "http://127.0.0.1:4000"

  defp get(path) do
    :httpc.request(:get, {String.to_charlist(@base <> path), []}, [], [])
  end

  test "session endpoint mints a token and advertises the WS port" do
    {:ok, {{_, 200, _}, _, body}} = get("/api/v1/session?account=guest")

    assert {:ok, %{"ok" => true, "tier" => "free", "token" => "btk_" <> _, "ws_port" => 4001}} =
             BitArena.JSON.decode(to_string(body))
  end

  test "status endpoint reports matches and WS port" do
    {:ok, {{_, 200, _}, _, body}} = get("/api/v1/status")

    assert {:ok, %{"ok" => true, "matches" => _, "ws_port" => 4001, "info" => %{"game" => "Bit Arena"}}} =
             BitArena.JSON.decode(to_string(body))
  end

  test "leaderboard endpoint returns a board" do
    {:ok, {{_, 200, _}, _, body}} = get("/api/v1/leaderboard")
    assert {:ok, %{"ok" => true, "board" => _}} = BitArena.JSON.decode(to_string(body))
  end

  test "browser client is served" do
    {:ok, {{_, 200, _}, headers, body}} = get("/")
    assert List.keyfind(headers, ~c"content-type", 0) |> elem(1) |> to_string() =~ "text/html"
    assert to_string(body) =~ "Bit Arena"
  end

  test "plain HTTP /ws answers 426 with the WS port" do
    {:ok, {{_, 426, _}, _, body}} = get("/ws?token=x")
    assert {:ok, %{"ok" => false, "ws_port" => 4001}} = BitArena.JSON.decode(to_string(body))
  end

  test "unknown route is a JSON 404" do
    {:ok, {{_, 404, _}, _, body}} = get("/nope")
    assert {:ok, %{"ok" => false}} = BitArena.JSON.decode(to_string(body))
  end
end
