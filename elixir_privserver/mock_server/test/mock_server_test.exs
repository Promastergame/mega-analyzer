defmodule MockServerTest do
  use ExUnit.Case, async: false

  alias MockServer.{Entitlements, RuleEngine, Scenario}

  setup do
    Scenario.set(:normal)
    :ok
  end

  test "info/0 reports the live configuration" do
    info = MockServer.info()

    assert info.mock_port == 9340
    assert info.admin_port == 9341
    assert info.scenario == :normal
    assert is_integer(info.rules)
    assert is_integer(info.stats.total)
  end

  test "minted tokens are Bit-Arena-compatible" do
    token = Entitlements.issue("lab", "premium")

    assert String.starts_with?(token, "btk_")
    assert {:ok, %{"tier" => "premium", "acct" => "lab"}} = Entitlements.peek(token)
  end

  test "the game's session endpoint is answered with a premium tier" do
    {rule, status, body} = RuleEngine.resolve("GET", "/api/v1/session", %{})

    assert status == 200
    assert body["tier"] == "premium"
    assert String.starts_with?(body["token"], "btk_")
    assert is_binary(rule)
  end

  test "license checks come back active" do
    {_rule, 200, body} = RuleEngine.resolve("GET", "/v2/user/subscription", %{})

    assert body["active"] == true
    assert body["tier"] == "premium"
  end

  test "unknown paths still fall back to a believable success" do
    {_rule, status, body} = RuleEngine.resolve("POST", "/totally/unknown", %{})

    assert status == 200
    assert body["error"] == false
  end

  test "the offline scenario short-circuits every request" do
    Scenario.set(:offline)

    {rule, status, body} = RuleEngine.resolve("GET", "/api/v1/session", %{})

    assert status == 503
    assert rule == "scenario:offline"
    assert body["error"] == true
  end

  test "the expired scenario downgrades the tier instead of failing" do
    Scenario.set(:expired)

    {_rule, 200, body} = RuleEngine.resolve("GET", "/api/v1/session", %{})

    assert body["tier"] == "free"
    assert body["expired"] == true
  end

  test "scenarios can be set by name and unknown ones are rejected" do
    assert {:ok, :flaky} = Scenario.set("flaky")
    assert {:error, :unknown} = Scenario.set("meltdown")
    assert Scenario.current() == :flaky
  end

  test "rules can be reloaded at runtime" do
    assert {:ok, count} = MockServer.reload_rules()
    assert count >= 0
  end
end
