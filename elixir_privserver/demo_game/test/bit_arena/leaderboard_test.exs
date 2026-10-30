defmodule BitArena.LeaderboardTest do
  use ExUnit.Case, async: false

  alias BitArena.Leaderboard

  test "records wins and keeps the best single-match score" do
    a = "alpha-#{System.unique_integer([:positive])}"
    b = "beta-#{System.unique_integer([:positive])}"

    Leaderboard.record(%{a => 30, b => 12}, a)
    Leaderboard.record(%{a => 7, b => 25}, b)

    # record/2 is a cast; a synchronous call flushes everything queued before it.
    :sys.get_state(Leaderboard)

    board = Leaderboard.top(100)
    entry_a = Enum.find(board, &(&1.name == a))
    entry_b = Enum.find(board, &(&1.name == b))

    assert entry_a.wins == 1
    assert entry_a.best == 30
    assert entry_a.played == 2

    assert entry_b.wins == 1
    assert entry_b.best == 25
    assert entry_b.played == 2
  end
end
