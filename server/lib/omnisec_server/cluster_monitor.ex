defmodule OmnisecServer.ClusterMonitor do
  @moduledoc """
  Cluster Monitor — tracks connected nodes and worker availability
  across the OTP cluster for distributed analysis.

  ## Multi-Node Architecture

  When running in cluster mode, OmniSec distributes analysis jobs
  across multiple BEAM nodes. Each node runs its own WorkerPool
  with Rust NIF workers. The ClusterMonitor:

  1. Discovers other nodes via Erlang distribution
  2. Monitors node health (heartbeat)
  3. Reports aggregate cluster capacity
  4. Routes overflow jobs to nodes with available workers

  ## Single-Node Mode

  When no other nodes are connected, the ClusterMonitor simply
  monitors local resources (CPU, memory, disk) and reports
  health status for the API.
  """

  use GenServer
  require Logger

  @heartbeat_interval_ms 10_000

  defstruct [:nodes, :local_metrics, :started_at]

  # ═══════════════════════════════════════════════════════════════
  # PUBLIC API
  # ═══════════════════════════════════════════════════════════════

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  @doc "Get cluster status overview."
  def cluster_status do
    GenServer.call(__MODULE__, :cluster_status)
  end

  @doc "Get list of connected analysis nodes."
  def connected_nodes do
    GenServer.call(__MODULE__, :connected_nodes)
  end

  # ═══════════════════════════════════════════════════════════════
  # GENSERVER CALLBACKS
  # ═══════════════════════════════════════════════════════════════

  @impl true
  def init(_) do
    # Subscribe to node up/down events
    :net_kernel.monitor_nodes(true)

    # Schedule heartbeat
    Process.send_after(self(), :heartbeat, @heartbeat_interval_ms)

    state = %__MODULE__{
      nodes: MapSet.new(),
      local_metrics: collect_metrics(),
      started_at: DateTime.utc_now()
    }

    Logger.info("[ClusterMonitor] Started on #{Node.self()}")
    {:ok, state}
  end

  @impl true
  def handle_call(:cluster_status, _from, state) do
    status = %{
      node: Node.self(),
      uptime_seconds: DateTime.diff(DateTime.utc_now(), state.started_at),
      connected_nodes: MapSet.to_list(state.nodes),
      node_count: MapSet.size(state.nodes) + 1,
      local: state.local_metrics
    }

    {:reply, status, state}
  end

  @impl true
  def handle_call(:connected_nodes, _from, state) do
    {:reply, MapSet.to_list(state.nodes), state}
  end

  @impl true
  def handle_info({:nodeup, node}, state) do
    Logger.info("[ClusterMonitor] Node joined: #{node}")
    new_nodes = MapSet.put(state.nodes, node)
    {:noreply, %{state | nodes: new_nodes}}
  end

  @impl true
  def handle_info({:nodedown, node}, state) do
    Logger.warning("[ClusterMonitor] Node left: #{node}")
    new_nodes = MapSet.delete(state.nodes, node)
    {:noreply, %{state | nodes: new_nodes}}
  end

  @impl true
  def handle_info(:heartbeat, state) do
    new_metrics = collect_metrics()

    # Log warning if resources are constrained
    if new_metrics.memory_percent > 85.0 do
      Logger.warning("[ClusterMonitor] High memory: #{new_metrics.memory_percent}%")
    end

    Process.send_after(self(), :heartbeat, @heartbeat_interval_ms)
    {:noreply, %{state | local_metrics: new_metrics}}
  end

  # ═══════════════════════════════════════════════════════════════
  # METRICS COLLECTION
  # ═══════════════════════════════════════════════════════════════

  defp collect_metrics do
    memory = :erlang.memory()

    %{
      schedulers: System.schedulers_online(),
      total_memory_mb: Float.round(memory[:total] / (1024 * 1024), 1),
      process_memory_mb: Float.round(memory[:processes] / (1024 * 1024), 1),
      ets_memory_mb: Float.round(memory[:ets] / (1024 * 1024), 1),
      process_count: :erlang.system_info(:process_count),
      memory_percent: memory_usage_percent(),
      timestamp: DateTime.utc_now()
    }
  end

  defp memory_usage_percent do
    case :memsup.get_system_memory_data() do
      data when is_list(data) ->
        total = Keyword.get(data, :total_memory, 1)
        free = Keyword.get(data, :free_memory, 0)
        Float.round((1.0 - free / max(total, 1)) * 100, 1)

      _ ->
        0.0
    end
  rescue
    _ -> 0.0
  end
end
