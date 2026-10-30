defmodule BitArena.Entitlements do
  @moduledoc """
  The game's **trust boundary**, and the entire reason this demo exists.

  A token is `btk_` followed by base64url-encoded JSON claims:

      %{"acct" => "guest", "tier" => "free", "iat" => 1735689600}

  It is **not signed**. `verify/1` decodes the claims and believes the `tier`
  field, so any server that speaks this format — including the private server in
  `../mock_server` — can hand a client premium perks. That is the flaw this demo
  is built to show; see `PROTOCOL.md` for how to close it.

  `verify/1` never fails. A malformed, forged-but-broken, empty or missing token
  degrades to the free tier instead of crashing the socket, because a client
  that can crash your session process is a much worse problem than a client that
  cheats.
  """

  @prefix "btk_"
  @premium_accounts ~w(dev founder qa)
  @tiers ~w(free premium)

  @premium_perks %{skin: "golden", speed_mult: 1.35, coin_mult: 2, trail: true}
  @free_perks %{skin: "cyan", speed_mult: 1.0, coin_mult: 1, trail: false}

  @doc """
  Mint a token for `account`.

  The honest server only grants premium to allow-listed accounts — everyone else
  is free, no matter what they ask for.
  """
  def issue(account) when is_binary(account) do
    claims = %{
      "acct" => account,
      "tier" => tier_for(account),
      "iat" => System.system_time(:second)
    }

    @prefix <> Base.url_encode64(BitArena.JSON.encode!(claims), padding: false)
  end

  @doc """
  Decode a token into `{:ok, %{account: _, tier: _, issued_at: _}}`.

  Always succeeds; anything unreadable becomes an anonymous free player.
  """
  def verify(@prefix <> encoded) do
    with {:ok, json} <- Base.url_decode64(encoded, padding: false),
         {:ok, claims} <- BitArena.JSON.decode(json) do
      {:ok,
       %{
         account: string(claims["acct"], "guest"),
         tier: tier(claims["tier"]),
         issued_at: claims["iat"]
       }}
    else
      _ -> {:ok, anonymous()}
    end
  end

  def verify(_token), do: {:ok, anonymous()}

  @doc "Gameplay perks granted by a tier. Premium is deliberately, visibly better."
  def perks("premium"), do: @premium_perks
  def perks(_tier), do: @free_perks

  @doc "Accounts this server will grant premium to on its own."
  def premium_accounts, do: @premium_accounts

  defp anonymous, do: %{account: "guest", tier: "free", issued_at: nil}

  defp tier_for(account) when account in @premium_accounts, do: "premium"
  defp tier_for(_account), do: "free"

  defp tier(tier) when tier in @tiers, do: tier
  defp tier(_other), do: "free"

  defp string(value, _default) when is_binary(value), do: value
  defp string(_value, default), do: default
end
