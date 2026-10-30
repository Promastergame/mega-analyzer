defmodule MockServer.Stats do
  @moduledoc """
  Request counters and a small rolling log of recent traffic, kept in ETS so the
  dashboard can read them without going through this process.
  """

  use GenServer

  @counters :mock_server_counters
  @recent :mock_server_recent
  @max_recent 50

  def start_link(_), do: GenServer.start_link(__MODULE__, [], name: __MODULE__)

  @doc "Record one served request."
  def record(entry) when is_map(entry), do: GenServer.cast(__MODULE__, {:record, entry})

  @doc "Totals plus a per-rule breakdown."
  def summary do
    %{
      total: counter(:total),
      by_rule: by_rule(),
      started_at: counter(:started_at)
    }
  end

  @doc "The last #{@max_recent} requests, newest first."
  def recent do
    case :ets.lookup(@recent, :log) do
      [{:log, entries}] -> entries
      _ -> []
    end
  end

  @impl true
  def init(_) do
    :ets.new(@counters, [:set, :named_table, :public, write_concurrency: true])
    :ets.new(@recent, [:set, :named_table, :public, read_concurrency: true])
    :ets.insert(@counters, {:total, 0})
    :ets.insert(@counters, {:started_at, System.system_time(:second)})
    :ets.insert(@recent, {:log, []})
    {:ok, %{}}
  end

  @impl true
  def handle_cast({:record, entry}, state) do
    rule = Map.get(entry, :rule, "unknown")

    :ets.update_counter(@counters, :total, {2, 1}, {:total, 0})
    :ets.update_counter(@counters, {:rule, rule}, {2, 1}, {{:rule, rule}, 0})
    :ets.insert(@recent, {:log, Enum.take([entry | recent()], @max_recent)})

    {:noreply, state}
  end

  defp counter(key) do
    case :ets.lookup(@counters, key) do
      [{^key, value}] -> value
      _ -> 0
    end
  end

  defp by_rule do
    @counters
    |> :ets.match_object({{:rule, :_}, :_})
    |> Map.new(fn {{:rule, name}, count} -> {name, count} end)
  end
end
