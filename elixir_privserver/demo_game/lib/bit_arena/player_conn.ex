defmodule BitArena.PlayerConn do
  @moduledoc """
  Per-client game state: checks the entitlement token **once** at join,
  translates incoming JSON frames into authoritative `Match` intents, and
  renders server snapshots back down the socket. Everything else the
  client says is ignored — which is why the only interesting attack
  surface is the token.

  Transport-agnostic (replaces the `WebSock` behaviour implementation):
  `BitArena.WsServer` feeds it text frames and delivers `{:push, text}`.
  """

  require Logger
  alias BitArena.{Entitlements, Match, Matchmaker}

  @doc "Join a match for `token`. Never fails (bad tokens degrade to free)."
  @spec init(String.t() | nil) :: %{match: pid(), id: String.t(), name: String.t(), tier: String.t()}
  def init(token) do
    {:ok, claims} = Entitlements.verify(token || "")
    perks = Entitlements.perks(claims.tier)
    id = "p_" <> Base.encode16(:crypto.strong_rand_bytes(4), case: :lower)
    name = display_name(claims.account, claims.tier)

    {:ok, match} =
      Matchmaker.join(%{id: id, name: name, socket: self(), perks: perks})

    Logger.info("socket #{id} joined as #{name} (tier=#{claims.tier})")
    %{match: match, id: id, name: name, tier: claims.tier}
  end

  @doc "Handles one text frame. Returns `{:push, reply, state}` to answer."
  @spec handle_text(String.t(), map()) :: {:ok, map()} | {:push, String.t(), map()}
  def handle_text(text, state) do
    case BitArena.JSON.decode(text) do
      {:ok, %{"t" => "input", "dir" => dir}} when is_list(dir) ->
        Match.input(state.match, state.id, %{"dir" => sanitize_dir(dir)})
        {:ok, state}

      {:ok, %{"t" => "ping"}} ->
        pong = BitArena.JSON.encode!(%{type: "pong", ts: System.system_time(:millisecond)})
        {:push, pong, state}

      _ ->
        {:ok, state}
    end
  end

  @doc "Renders a `{:push, payload}` game message into a text frame."
  @spec render_push(map()) :: String.t()
  def render_push(payload), do: BitArena.JSON.encode!(payload)

  # A premium player is visibly marked, and every name gets a short suffix so
  # two guests never collide on the leaderboard.
  defp display_name(account, tier) do
    base = if tier == "premium", do: "#{account}★", else: account
    base <> "-" <> Base.encode16(:crypto.strong_rand_bytes(2), case: :lower)
  end

  defp sanitize_dir([dx, dy]) when is_number(dx) and is_number(dy), do: [clamp1(dx), clamp1(dy)]
  defp sanitize_dir(_), do: [0, 0]

  defp clamp1(n), do: n |> max(-1) |> min(1)
end
