defmodule OmnisecServer.WorkerPool do
  @moduledoc """
  Worker Pool — manages a pool of Rust NIF analysis workers.

  Each worker is a GenServer that holds a reference to the Rust NIF
  analysis engine. Workers are checked out from the pool, perform
  analysis, and are returned when done.

  ## Architecture

  The pool uses a simple FIFO queue:
  - Available workers sit in a queue
  - When a job arrives, a worker is popped from the queue
  - When analysis completes, the worker is pushed back
  - If no workers are available, the job waits with a per-call timeout

  ## Fault Tolerance

  - Each worker is `Process.monitor`ed when the pool boots and again
    whenever a replacement is started, so the pool reliably observes
    crashes via `{:DOWN, ...}` even though the workers run under
    `start_link/1` (no `start_monitor` available in stock GenServer).
  - When a worker crashes the pool spawns a replacement and rotates it
    back into the available queue.
  - Waiting callers carry a deadline. When the deadline elapses we
    GenServer.reply with `{:error, :timeout}` and prune them from
    `state.waiting` so a dead client never receives a stale worker.
  """

  use GenServer
  require Logger

  defstruct [
    :pool_size,
    :available,
    :busy,
    :waiting,
    :monitors
  ]

  # ═══════════════════════════════════════════════════════════════
  # PUBLIC API
  # ═══════════════════════════════════════════════════════════════

  def start_link(opts) do
    pool_size = Keyword.get(opts, :pool_size, System.schedulers_online())
    GenServer.start_link(__MODULE__, pool_size, name: __MODULE__)
  end

  @doc """
  Check out a worker from the pool.

  Returns `{:ok, worker_pid}` once a worker is available, or
  `{:error, :timeout}` if `timeout` ms elapse without one being freed
  (or the pool itself is unreachable, e.g. mid-restart).
  """
  def checkout(timeout \\ 5_000) do
    GenServer.call(__MODULE__, {:checkout, timeout}, timeout + 100)
  catch
    :exit, _ -> {:error, :timeout}
  end

  @doc """
  Return a worker to the pool after use.
  """
  def checkin(worker_pid) do
    GenServer.cast(__MODULE__, {:checkin, worker_pid})
  end

  @doc """
  Execute a function with an auto-checked-out worker.
  Worker is automatically returned to the pool after the function completes,
  even when the function raises.
  """
  def with_worker(fun, timeout \\ 30_000) do
    case checkout(timeout) do
      {:ok, worker} ->
        try do
          result = fun.(worker)
          {:ok, result}
        after
          checkin(worker)
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Get current pool status.
  """
  def status do
    GenServer.call(__MODULE__, :status)
  end

  # ═══════════════════════════════════════════════════════════════
  # GENSERVER CALLBACKS
  # ═══════════════════════════════════════════════════════════════

  @impl true
  def init(pool_size) do
    Logger.info("[WorkerPool] Starting #{pool_size} analysis workers")

    # Workers are started with `start_link/1` (below), which links them to
    # this pool process. Trap exits so a crashing worker does NOT tear the
    # pool down through that link — instead the crash is surfaced as a
    # `{:DOWN, ...}` monitor message and handled by replacing the worker.
    # (The parent-shutdown `{:EXIT, parent, reason}` is still handled by
    # gen_server itself, so trapping here does not leak supervisor signals.)
    Process.flag(:trap_exit, true)

    {workers, monitors} =
      Enum.reduce(1..pool_size, {[], %{}}, fn i, {acc_workers, acc_monitors} ->
        {:ok, pid} = OmnisecServer.Worker.start_link(id: i)
        ref = Process.monitor(pid)
        {[pid | acc_workers], Map.put(acc_monitors, pid, ref)}
      end)

    state = %__MODULE__{
      pool_size: pool_size,
      available: :queue.from_list(Enum.reverse(workers)),
      busy: MapSet.new(),
      waiting: :queue.new(),
      monitors: monitors
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:checkout, timeout}, from, state) do
    case :queue.out(state.available) do
      {{:value, worker}, rest} ->
        new_state = %{state | available: rest, busy: MapSet.put(state.busy, worker)}
        {:reply, {:ok, worker}, new_state}

      {:empty, _} ->
        # Queue the caller with a deadline. The pool sends itself a tick;
        # a dead waiter receives `{:error, :timeout}` and is pruned.
        deadline = System.monotonic_time(:millisecond) + timeout
        Process.send_after(self(), {:waiter_timeout, from, deadline}, timeout)
        new_waiting = :queue.in({from, deadline}, state.waiting)
        {:noreply, %{state | waiting: new_waiting}}
    end
  end

  @impl true
  def handle_call(:status, _from, state) do
    status = %{
      pool_size: state.pool_size,
      available: :queue.len(state.available),
      busy: MapSet.size(state.busy),
      waiting: :queue.len(state.waiting),
      monitors: map_size(state.monitors)
    }

    {:reply, status, state}
  end

  @impl true
  def handle_cast({:checkin, worker}, state) do
    new_busy = MapSet.delete(state.busy, worker)

    # A worker that crashed while checked out is removed from `monitors` and
    # replaced by the `{:DOWN, ...}` handler. If its (now dead) pid is checked
    # back in afterwards — e.g. from `with_worker/2`'s `after` clause once the
    # analysis call exits — we must NOT return it to `available`, or a later
    # checkout would hand a client a dead pid. `monitors` is the source of
    # truth for live workers, so ignore check-ins for unknown pids.
    cond do
      not Map.has_key?(state.monitors, worker) ->
        {:noreply, %{state | busy: new_busy}}

      true ->
        # If someone is waiting for a worker, give it to them immediately
        case dequeue_live_waiter(state.waiting) do
          {:ok, {waiter, _deadline}, rest} ->
            GenServer.reply(waiter, {:ok, worker})
            {:noreply, %{state | busy: MapSet.put(new_busy, worker), waiting: rest}}

          :empty ->
            new_available = :queue.in(worker, state.available)
            {:noreply, %{state | available: new_available, busy: new_busy}}
        end
    end
  end

  @impl true
  def handle_info({:waiter_timeout, from, deadline}, state) do
    now = System.monotonic_time(:millisecond)

    if now < deadline do
      {:noreply, state}
    else
      # Drop the waiter if still queued and reply :timeout. If the waiter
      # already received a worker the prune is a no-op.
      {still_waiting, removed?} =
        prune_waiter(state.waiting, from)

      if removed? do
        GenServer.reply(from, {:error, :timeout})
      end

      {:noreply, %{state | waiting: still_waiting}}
    end
  end

  @impl true
  def handle_info({:DOWN, _ref, :process, pid, reason}, state) do
    Logger.warning("[WorkerPool] Worker #{inspect(pid)} crashed: #{inspect(reason)}")

    new_busy = MapSet.delete(state.busy, pid)
    new_available = drop_pid_from_queue(state.available, pid)
    new_monitors = Map.delete(state.monitors, pid)

    # Start a replacement worker
    {:ok, new_pid} = OmnisecServer.Worker.start_link(id: :replacement)
    new_ref = Process.monitor(new_pid)

    state = %{
      state
      | busy: new_busy,
        monitors: Map.put(new_monitors, new_pid, new_ref)
    }

    new_state =
      case dequeue_live_waiter(state.waiting) do
        {:ok, {waiter, _deadline}, rest} ->
          GenServer.reply(waiter, {:ok, new_pid})
          %{state | available: new_available, busy: MapSet.put(state.busy, new_pid), waiting: rest}

        :empty ->
          %{state | available: :queue.in(new_pid, new_available)}
      end

    {:noreply, new_state}
  end

  # Linked worker exits arrive here because we trap exits. Crash recovery is
  # driven entirely by the `{:DOWN, ...}` monitor message above, so this clause
  # simply absorbs the redundant `{:EXIT, ...}` signal instead of letting it
  # fall through and crash the pool with a FunctionClauseError.
  @impl true
  def handle_info({:EXIT, _pid, _reason}, state) do
    {:noreply, state}
  end

  # ═══════════════════════════════════════════════════════════════
  # INTERNAL HELPERS
  # ═══════════════════════════════════════════════════════════════

  defp dequeue_live_waiter(queue) do
    case :queue.out(queue) do
      {:empty, _} ->
        :empty

      {{:value, {from, deadline}}, rest} ->
        now = System.monotonic_time(:millisecond)

        if now >= deadline do
          # Stale waiter — skip and recurse.
          dequeue_live_waiter(rest)
        else
          {:ok, {from, deadline}, rest}
        end
    end
  end

  defp prune_waiter(queue, target_from) do
    list = :queue.to_list(queue)
    {kept, removed} = Enum.split_with(list, fn {from, _} -> from != target_from end)
    {:queue.from_list(kept), removed != []}
  end

  defp drop_pid_from_queue(queue, pid) do
    queue
    |> :queue.to_list()
    |> Enum.reject(&(&1 == pid))
    |> :queue.from_list()
  end
end
