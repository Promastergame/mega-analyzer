defmodule BitArena.EntitlementsTest do
  use ExUnit.Case, async: true

  alias BitArena.Entitlements

  test "unknown accounts get the free tier" do
    token = Entitlements.issue("some_random_player")
    assert {:ok, %{tier: "free", account: "some_random_player"}} = Entitlements.verify(token)
  end

  test "allow-listed accounts get premium" do
    token = Entitlements.issue("dev")
    assert {:ok, %{tier: "premium", account: "dev"}} = Entitlements.verify(token)
  end

  test "garbage tokens degrade to free instead of crashing the socket" do
    assert {:ok, %{tier: "free"}} = Entitlements.verify("btk_not base64 at all!!")
    assert {:ok, %{tier: "free"}} = Entitlements.verify("complete nonsense")
    assert {:ok, %{tier: "free"}} = Entitlements.verify(nil)
  end

  test "premium perks are strictly better, which is what makes the demo visible" do
    free = Entitlements.perks("free")
    premium = Entitlements.perks("premium")

    assert premium.speed_mult > free.speed_mult
    assert premium.coin_mult > free.coin_mult
    assert premium.skin == "golden"
    assert premium.trail
  end

  test "a token minted by ANY server is accepted — the flaw under demonstration" do
    # This is exactly what ../mock_server does: same wire format, no signature,
    # so the game cannot tell an honest issuer from a private one. If you ever
    # harden this, start by signing the payload and this test should fail.
    forged =
      %{"acct" => "guest", "tier" => "premium", "iat" => 0}
      |> BitArena.JSON.encode!()
      |> Base.url_encode64(padding: false)
      |> then(&("btk_" <> &1))

    assert {:ok, %{tier: "premium"}} = Entitlements.verify(forged)
  end
end
