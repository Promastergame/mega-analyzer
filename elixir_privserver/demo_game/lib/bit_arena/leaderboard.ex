defmodule BitArena.Leaderboard do
  @moduledoc """
  Cumulative results across every match, kept in a public ETS table so any
  process can read the board without going through this GenServer. Writes go
  through `record/2` as a cast, so a finishing match never blocks on the board.

  One row per display name: `{name, wins, best_single_match_score, matches_played}`.
  """

  use GenServer

  @table :bit_arena_leaderboard

  def start_link(_opts), do: GenServer.start_link(__MODULE__, :ok, name: __MODULE__)

  @doc """
  Record a finished match: `scores` is `%{name => score}`, `winner` is the name
  of the winning player (or `nil` for a draw / abandoned round).
  """
  def record(scores, winner) when is_map(scores) do
    GenServer.cast(__MODULE__, {:record, scores, winner})
  end

  @doc "Top `limit` entries, ranked by wins, then best score, then matches played."
  def top(limit \\ 10) do
    @table
    |> :ets.tab2list()
    |> Enum.map(fn {name, wins, best, played} ->
      %{name: name, wins: wins, best: best, played: played}
    end)
    |> Enum.sort_by(&{-&1.wins, -&1.best, -&1.played})
    |> Enum.take(limit)
  rescue
    ArgumentError -> []
  end

  @impl true
  def init(:ok) do
    :ets.new(@table, [:set, :named_table, :public, read_concurrency: true])
    {:ok, %{}}
  end

  @impl true
  def handle_cast({:record, scores, winner}, state) do
    Enum.each(scores, fn {name, score} ->
      won = if name == winner, do: 1, else: 0

      case :ets.lookup(@table, name) do
        [{^name, wins, best, played}] ->
          :ets.insert(@table, {name, wins + won, max(best, score), played + 1})

        [] ->
          :ets.insert(@table, {name, won, score, 1})
      end
    end)

    {:noreply, state}
  end
end
