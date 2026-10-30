defmodule OmnisecServer.WorkerPoolTest do
  @moduledoc """
  Fault-tolerance regression tests for the analysis worker pool.

  Workers are started with `start_link/1`, so they are linked to the pool.
  These tests pin down the guarantees that keep a single worker crash from
  taking the whole pool down (or, worse, resurrecting a dead worker into the
  available queue).

  They intentionally use only `WorkerPool` + `Worker`, which depend on nothing
  beyond stdlib + Logger, so they run without the Rust NIFs or Phoenix.
  """
  use ExUnit.Case, async: false

  alias OmnisecServer.WorkerPool

  setup do
    if Process.whereis(WorkerPool) do
      Supervisor.terminate_child(OmnisecServer.Supervisor, WorkerPool)
    end

    # Give the application pool back afterwards — other suites (health,
    # analyze) call the app-owned pool by name.
    on_exit(fn ->
      case Supervisor.restart_child(OmnisecServer.Supervisor, WorkerPool) do
        {:ok, _} -> :ok
        {:error, :running} -> :ok
        {:error, _} -> :ok
      end
    end)

    {:ok, pool} = start_supervised({WorkerPool, pool_size: 2})
    %{pool: pool}
  end

  test "pool survives a worker crash and replaces it", %{pool: pool} do
    {:ok, worker} = WorkerPool.checkout(1_000)

    ref = Process.monitor(worker)
    Process.exit(worker, :kill)
    assert_receive {:DOWN, ^ref, :process, ^worker, _reason}, 1_000

    # Let the pool process the {:DOWN, ...} and spin up a replacement.
    wait_until(fn -> WorkerPool.status().monitors == 2 end)

    assert Process.alive?(pool)
    status = WorkerPool.status()
    assert status.pool_size == 2
    assert status.monitors == 2
    assert status.available == 2
  end

  test "a late check-in of a crashed worker is not resurrected", %{pool: _pool} do
    {:ok, worker} = WorkerPool.checkout(1_000)

    ref = Process.monitor(worker)
    Process.exit(worker, :kill)
    assert_receive {:DOWN, ^ref, :process, ^worker, _reason}, 1_000
    wait_until(fn -> WorkerPool.status().monitors == 2 end)

    # Mimic `with_worker/2`'s `after` clause returning the now-dead pid.
    WorkerPool.checkin(worker)
    wait_until(fn -> WorkerPool.status().available == 2 end)

    # Every worker we can check out must be alive — the dead pid must never
    # have been queued back into `available`.
    status = WorkerPool.status()

    handed =
      Enum.map(1..status.available, fn _ ->
        {:ok, pid} = WorkerPool.checkout(500)
        pid
      end)

    assert Enum.all?(handed, &Process.alive?/1)
    refute worker in handed
    Enum.each(handed, &WorkerPool.checkin/1)
  end

  test "with_worker still works after a crash", %{pool: _pool} do
    {:ok, worker} = WorkerPool.checkout(1_000)
    ref = Process.monitor(worker)
    Process.exit(worker, :kill)
    assert_receive {:DOWN, ^ref, :process, ^worker, _reason}, 1_000
    wait_until(fn -> WorkerPool.status().monitors == 2 end)

    assert {:ok, true} =
             WorkerPool.with_worker(fn w -> is_pid(w) and Process.alive?(w) end)
  end

  test "a blocked caller is handed a worker on check-in", %{pool: _pool} do
    {:ok, w1} = WorkerPool.checkout(1_000)
    {:ok, w2} = WorkerPool.checkout(1_000)

    task = Task.async(fn -> WorkerPool.checkout(2_000) end)
    # Give the task time to enqueue itself as a waiter.
    Process.sleep(100)

    WorkerPool.checkin(w1)
    assert {:ok, handed} = Task.await(task, 3_000)
    assert Process.alive?(handed)

    WorkerPool.checkin(w2)
    WorkerPool.checkin(handed)
  end

  test "checkout returns {:error, :timeout} when the pool is exhausted", %{pool: _pool} do
    {:ok, w1} = WorkerPool.checkout(1_000)
    {:ok, w2} = WorkerPool.checkout(1_000)

    assert {:error, :timeout} = WorkerPool.checkout(200)

    WorkerPool.checkin(w1)
    WorkerPool.checkin(w2)
  end

  defp wait_until(fun, attempts \\ 50)
  defp wait_until(_fun, 0), do: flunk("condition not met in time")

  defp wait_until(fun, attempts) do
    if fun.() do
      :ok
    else
      Process.sleep(20)
      wait_until(fun, attempts - 1)
    end
  end
end
