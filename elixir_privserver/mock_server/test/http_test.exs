defmodule MockServer.HttpTest do
  @moduledoc """
  End-to-end smoke tests over the real `:inets` listeners (stdlib
  `:httpc` client). The application supervision tree already boots both
  listeners in the test env on the configured ports.
  """
  use ExUnit.Case, async: false

  alias MockServer.Scenario

  setup do
    Scenario.set(:normal)
    :ok
  end

  defp get(port, path) do
    :httpc.request(:get, {String.to_charlist("http://127.0.0.1:#{port}#{path}"), []}, [], [])
  end

  defp post(port, path, body) do
    :httpc.request(
      :post,
      {String.to_charlist("http://127.0.0.1:#{port}#{path}"), [], ~c"application/json", body},
      [],
      []
    )
  end

  test "fake backend answers any path with JSON" do
    {:ok, {{_, 200, _}, _, body}} = get(9340, "/api/v1/session?account=lab")
    assert {:ok, %{"tier" => "premium", "token" => "btk_" <> _}} = MockServer.JSON.decode(to_string(body))
  end

  test "fake backend short-circuits OPTIONS for CORS preflight" do
    {:ok, {{_, 204, _}, headers, _}} =
      :httpc.request(:options, {~c"http://127.0.0.1:9340/api/v1/session", []}, [], [])

    assert List.keyfind(headers, ~c"access-control-allow-origin", 0) != nil
  end

  test "arbitrary methods on arbitrary paths get a believable success" do
    {:ok, {{_, 200, _}, _, body}} =
      :httpc.request(
        :put,
        {~c"http://127.0.0.1:9340/totally/unknown", [], ~c"application/json", "{}"},
        [],
        []
      )

    assert {:ok, %{"error" => false}} = MockServer.JSON.decode(to_string(body))
  end

  test "admin dashboard serves HTML and status JSON" do
    {:ok, {{_, 200, _}, _, dash}} = get(9341, "/")
    assert to_string(dash) =~ "<"

    {:ok, {{_, 200, _}, _, status}} = get(9341, "/api/status")
    assert {:ok, %{"scenario" => "normal"}} = MockServer.JSON.decode(to_string(status))
  end

  test "admin scenario switch round-trips over HTTP" do
    {:ok, {{_, 200, _}, _, body}} = post(9341, "/api/scenario", ~s({"name":"flaky"}))
    assert {:ok, %{"ok" => true, "scenario" => "flaky"}} = MockServer.JSON.decode(to_string(body))

    {:ok, {{_, 200, _}, _, status}} = get(9341, "/api/status")
    assert {:ok, %{"scenario" => "flaky"}} = MockServer.JSON.decode(to_string(status))

    {:ok, {{_, 200, _}, _, _}} = post(9341, "/api/scenario", ~s({"name":"normal"}))
  end

  test "admin unknown route is a JSON 404" do
    {:ok, {{_, 404, _}, _, body}} = get(9341, "/api/nope")
    assert {:ok, %{"error" => "not found"}} = MockServer.JSON.decode(to_string(body))
  end
end
