defmodule BitArena.MatchTest do
  use ExUnit.Case, async: false

  alias BitArena.{Entitlements, Match}

  setup do
    name = "test-#{System.unique_integer([:positive])}"

    match =
      start_supervised!(%{
        id: {Match, name},
        start: {Match, :start_link, [%{name: name}]},
        restart: :temporary
      })

    %{match: match, name: name}
  end

  test "a joining player is welcomed and then receives world snapshots", ctx do
    name = ctx.name
    assert :ok = Match.add_player(ctx.match, player("p_one"))

    assert_receive {:push, %{type: "welcome", you: "p_one", match: ^name}}, 1_000
    assert_receive {:push, %{type: "state", players: players, coins: coins}}, 1_000

    assert Enum.any?(players, &(&1.id == "p_one"))
    assert length(coins) == 6
  end

  test "a match stays open until it is full", ctx do
    assert Match.open?(ctx.match)

    for i <- 1..8 do
      assert :ok = Match.add_player(ctx.match, player("p_#{i}"))
    end

    refute Match.open?(ctx.match)
    assert :full = Match.add_player(ctx.match, player("p_nine"))
  end

  test "movement is authoritative: a wild direction cannot teleport a player", ctx do
    assert :ok = Match.add_player(ctx.match, player("p_cheat"))

    assert_receive {:push, %{type: "welcome"}}, 1_000
    assert_receive {:push, %{type: "state", players: [before_input]}}, 1_000

    # A patched client screaming "move me 9999 units to the right".
    Match.input(ctx.match, "p_cheat", %{"dir" => [9_999, 0]})

    assert_receive {:push, %{type: "state", players: [after_input]}}, 1_000

    # 260 units/s at 20 Hz is 13 units per tick, so the unit-vector clamp held.
    assert after_input.x - before_input.x <= 20
  end

  defp player(id) do
    %{id: id, name: id, socket: self(), perks: Entitlements.perks("free")}
  end
end
