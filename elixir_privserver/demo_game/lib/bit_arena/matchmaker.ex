defmodule BitArena.Matchmaker do
  @moduledoc """
  Places a joining player into a match: reuse the first one with room, otherwise
  start a fresh `BitArena.Match` under the dynamic supervisor.

  Serialising this through one process is what makes "is there room?" and "take
  the slot" a single atomic decision — with a few hundred sockets connecting at
  once, checking capacity and then joining as two separate steps would happily
  overfill a match.
  """

  use GenServer
  require Logger

  alias BitArena.Match

  def start_link(_opts), do: GenServer.start_link(__MODULE__, :ok, name: __MODULE__)

  @doc """
  Join a match. `player` is `%{id:, name:, socket:, perks:}`.
  Returns `{:ok, match_pid}`.
  """
  def join(player) when is_map(player), do: GenServer.call(__MODULE__, {:join, player})

  @doc "Names and pids of every live match."
  def matches do
    Registry.select(BitArena.MatchRegistry, [
      {{:"$1", :"$2", :_}, [], [{{:"$1", :"$2"}}]}
    ])
  end

  @impl true
  def init(:ok), do: {:ok, %{seq: 0}}

  @impl true
  def handle_call({:join, player}, _from, state) do
    case place(player, matches()) do
      {:ok, pid} ->
        {:reply, {:ok, pid}, state}

      :no_room ->
        {pid, state} = open_match(state)
        :ok = Match.add_player(pid, player)
        {:reply, {:ok, pid}, state}
    end
  end

  # Walk the live matches in creation order and take the first free slot.
  defp place(_player, []), do: :no_room

  defp place(player, [{_name, pid} | rest]) do
    case add(pid, player) do
      :ok -> {:ok, pid}
      _full_or_dead -> place(player, rest)
    end
  end

  # A match can finish between listing the registry and calling into it.
  defp add(pid, player) do
    Match.add_player(pid, player)
  catch
    :exit, _reason -> :full
  end

  defp open_match(%{seq: seq} = state) do
    name = "arena-#{seq + 1}"

    {:ok, pid} =
      DynamicSupervisor.start_child(BitArena.MatchSupervisor, {Match, %{name: name}})

    Logger.info("matchmaker: opened #{name}")
    {pid, %{state | seq: seq + 1}}
  end
end
