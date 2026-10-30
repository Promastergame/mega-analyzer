defmodule OmnisecServer.ResultCache do
  @moduledoc """
  ETS-based result cache for analysis results.

  Deduplicates analysis requests by SHA-256 hash of the input.
  Results are cached for a configurable TTL (default: 1 hour).

  ## Why ETS?

  - In-memory: microsecond lookups (vs ms for Redis/Postgres)
  - Process-independent: survives worker crashes
  - No external dependencies for the base setup
  - Can be swapped for Mnesia for multi-node clustering
  """

  use GenServer
  require Logger

  @table_name :omnisec_result_cache
  @default_ttl_seconds 3600
  @cleanup_interval_ms 60_000

  # ═══════════════════════════════════════════════════════════════
  # PUBLIC API
  # ═══════════════════════════════════════════════════════════════

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  @doc """
  Look up a cached result by content hash.
  Returns `{:ok, result}` or `:miss`.
  """
  def get(hash) when is_binary(hash) do
    case :ets.lookup(@table_name, hash) do
      [{^hash, result, expires_at}] ->
        if System.monotonic_time(:second) < expires_at do
          {:ok, result}
        else
          :ets.delete(@table_name, hash)
          :miss
        end

      [] ->
        :miss
    end
  end

  @doc """
  Store a result in the cache.
  """
  def put(hash, result, ttl_seconds \\ @default_ttl_seconds) when is_binary(hash) do
    expires_at = System.monotonic_time(:second) + ttl_seconds
    :ets.insert(@table_name, {hash, result, expires_at})
    :ok
  end

  @doc """
  Get cache statistics.
  """
  def stats do
    size = :ets.info(@table_name, :size)
    memory = :ets.info(@table_name, :memory) * :erlang.system_info(:wordsize)

    %{
      entries: size,
      memory_bytes: memory,
      memory_mb: Float.round(memory / (1024 * 1024), 2)
    }
  end

  @doc """
  Clear all cached results.
  """
  def clear do
    :ets.delete_all_objects(@table_name)
    :ok
  end

  # ═══════════════════════════════════════════════════════════════
  # GENSERVER CALLBACKS
  # ═══════════════════════════════════════════════════════════════

  @impl true
  def init(_) do
    table = :ets.new(@table_name, [
      :named_table,
      :set,
      :public,
      read_concurrency: true,
      write_concurrency: true
    ])

    Logger.info("[ResultCache] ETS table #{inspect(table)} created")

    # Schedule periodic cleanup
    Process.send_after(self(), :cleanup, @cleanup_interval_ms)

    {:ok, %{}}
  end

  @impl true
  def handle_info(:cleanup, state) do
    now = System.monotonic_time(:second)
    expired = :ets.select(@table_name, [{{:"$1", :_, :"$3"}, [{:<, :"$3", now}], [:"$1"]}])

    for hash <- expired do
      :ets.delete(@table_name, hash)
    end

    if length(expired) > 0 do
      Logger.debug("[ResultCache] Evicted #{length(expired)} expired entries")
    end

    Process.send_after(self(), :cleanup, @cleanup_interval_ms)
    {:noreply, state}
  end
end
