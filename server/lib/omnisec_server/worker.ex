defmodule OmnisecServer.Worker do
  @moduledoc """
  Analysis Worker — wraps the Rust NIF engine in a GenServer.

  Each worker holds a reference to the native Rust analysis engine
  and processes one job at a time. The worker is isolated in its own
  process, so a crash in Rust analysis (panic, OOM, etc.) only kills
  this worker — the pool replaces it automatically.

  ## Supported Operations

  - `:analyze_apk` — Full APK analysis (DEX + native + manifest)
  - `:analyze_binary` — Native binary (.so/.dll/.dylib) analysis
  - `:scan_patterns` — Pattern matching against code
  - `:rank_hotspots` — ML-based hotspot ranking
  - `:hash_features` — HDC feature vector computation
  """

  use GenServer
  require Logger

  defstruct [:id, :jobs_completed, :last_job_at, :status]

  # ═══════════════════════════════════════════════════════════════
  # PUBLIC API
  # ═══════════════════════════════════════════════════════════════

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts)
  end

  @doc """
  Submit an analysis job to this worker.
  """
  def analyze(worker, job_type, payload, timeout \\ 60_000) do
    GenServer.call(worker, {:analyze, job_type, payload}, timeout)
  end

  @doc """
  Get worker stats.
  """
  def stats(worker) do
    GenServer.call(worker, :stats)
  end

  # ═══════════════════════════════════════════════════════════════
  # GENSERVER CALLBACKS
  # ═══════════════════════════════════════════════════════════════

  @impl true
  def init(opts) do
    id = Keyword.get(opts, :id, :erlang.unique_integer([:positive]))
    Logger.debug("[Worker-#{id}] Initialized")

    state = %__MODULE__{
      id: id,
      jobs_completed: 0,
      last_job_at: nil,
      status: :idle
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:analyze, job_type, payload}, _from, state) do
    started_at = System.monotonic_time(:millisecond)

    state = %{state | status: :busy}

    result =
      try do
        run_analysis(job_type, payload)
      rescue
        e ->
          Logger.error("[Worker-#{state.id}] Analysis failed: #{inspect(e)}")
          {:error, Exception.message(e)}
      end

    elapsed = System.monotonic_time(:millisecond) - started_at

    Logger.info(
      "[Worker-#{state.id}] #{job_type} completed in #{elapsed}ms"
    )

    new_state = %{state |
      jobs_completed: state.jobs_completed + 1,
      last_job_at: DateTime.utc_now(),
      status: :idle
    }

    {:reply, result, new_state}
  end

  @impl true
  def handle_call(:stats, _from, state) do
    stats = %{
      id: state.id,
      jobs_completed: state.jobs_completed,
      last_job_at: state.last_job_at,
      status: state.status
    }

    {:reply, stats, state}
  end

  # ═══════════════════════════════════════════════════════════════
  # ANALYSIS DISPATCH
  # ═══════════════════════════════════════════════════════════════

  defp run_analysis(:analyze_apk, %{data: data}) when is_binary(data) do
    # Calls into Rust NIF via OmnisecServer.Native
    OmnisecServer.Native.analyze_apk(data)
  end

  defp run_analysis(:analyze_binzap, %{data: data}) when is_binary(data) do
    # 1. Write the raw APK bytes to a temporary file
    temp_dir = System.tmp_dir!() |> Path.join("binzap_#{:erlang.unique_integer([:positive])}")
    File.mkdir_p!(temp_dir)
    
    apk_path = Path.join(temp_dir, "target.apk")
    report_dir = Path.join(temp_dir, "reports")
    File.write!(apk_path, data)

    # 2. Execute the Go BinZAP CLI
    # In production, this would be a precompiled binary for speed.
    args = ["run", "./cmd/binzap/main.go", "--apk", apk_path, "--output", report_dir]
    project_root = Application.get_env(:omnisec_server, :project_root) || Path.expand("../")
    
    try do
      {_output, exit_status} = System.cmd("go", args, cd: project_root)
      
      if exit_status != 0 do
        {:error, "BinZAP CLI execution failed with status #{exit_status}"}
      else
        # 3. Read the generated JSON report containing the vulnerabilities
        json_path = Path.join(report_dir, "target.apk_binzap_report.json")
        
        case File.read(json_path) do
          {:ok, json_data} -> 
            case OmnisecServer.JSON.decode(json_data) do
              {:ok, decoded} -> {:ok, %{vulnerabilities: decoded}}
              {:error, _} -> {:error, "Failed to decode BinZAP JSON report"}
            end
          {:error, _} -> 
            {:error, "BinZAP JSON report not found"}
        end
      end
    after
      # 4. Clean up temporary directories
      File.rm_rf!(temp_dir)
    end
  end

  defp run_analysis(:analyze_binary, %{data: data}) when is_binary(data) do
    OmnisecServer.Native.analyze_binary(data)
  end

  defp run_analysis(:scan_patterns, %{data: data, patterns: patterns}) do
    OmnisecServer.Native.scan_patterns(data, patterns)
  end

  defp run_analysis(:scan_yara, %{data: data, rules: rules}) do
    # Call into Rust NIF
    OmnisecServer.Native.scan_yara(rules, data)
  end

  defp run_analysis(:rank_hotspots, %{request: request_json}) do
    OmnisecServer.Native.rank_hotspots(request_json)
  end

  defp run_analysis(:hash_features, %{features: features, seed: seed}) do
    OmnisecServer.Native.hash_features(features, seed)
  end

  defp run_analysis(unknown_type, _payload) do
    {:error, "unknown job type: #{inspect(unknown_type)}"}
  end
end
