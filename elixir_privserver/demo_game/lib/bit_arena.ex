defmodule BitArena do
  @moduledoc """
  Bit Arena — a tiny *authoritative* real-time multiplayer game, used as the
  reference "online game with a backend" for the Mega-Analyzer private-server
  toolkit.

  The point of the demo is to show, end to end, what a captured mobile-game
  backend actually is: matchmaking, one lightweight process per player, an
  authoritative world tick, and a single trust boundary (entitlements) that a
  private server can spoof. See `README.md` and `PROTOCOL.md`.
  """

  @doc "Static metadata about this server, surfaced on the status API."
  def info do
    %{
      game: "Bit Arena",
      version: version(),
      transport: :websocket,
      protocol: "bitarena/1 (JSON frames)",
      tick_hz: config(:tick_hz),
      arena: config(:arena),
      win_score: config(:win_score)
    }
  end

  @doc "Fetch a `:bit_arena` application-env value."
  def config(key, default \\ nil), do: Application.get_env(:bit_arena, key, default)

  defp version do
    case Application.spec(:bit_arena, :vsn) do
      nil -> "dev"
      vsn -> to_string(vsn)
    end
  end
end
