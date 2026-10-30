defmodule MockServer.Entitlements do
  @moduledoc """
  Mints entitlement tokens in exactly the format the Bit Arena demo game
  accepts: `btk_` followed by base64url-encoded JSON claims, unsigned.

  This mirrors `BitArena.Entitlements` on purpose. Two independent applications,
  one wire format, no shared secret — which is the entire reason a private
  server can hand out premium accounts. If the game ever starts signing its
  tokens, this module is what stops working, and that is the point.
  """

  @doc "Mint a token for `account` at `tier` (\"free\" or \"premium\")."
  def issue(account, tier) when is_binary(account) and tier in ["free", "premium"] do
    %{"acct" => account, "tier" => tier, "iat" => System.system_time(:second)}
    |> MockServer.JSON.encode!()
    |> Base.url_encode64(padding: false)
    |> then(&("btk_" <> &1))
  end

  @doc "Decode a token back to its claims, for inspection in the dashboard/tests."
  def peek("btk_" <> encoded) do
    with {:ok, json} <- Base.url_decode64(encoded, padding: false),
         {:ok, claims} <- MockServer.JSON.decode(json) do
      {:ok, claims}
    else
      _ -> :error
    end
  end

  def peek(_token), do: :error
end
