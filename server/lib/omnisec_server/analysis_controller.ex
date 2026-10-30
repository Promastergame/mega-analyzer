defmodule OmnisecServer.AnalysisController do
  @moduledoc """
  REST controller for analysis operations.

  All POST endpoints accept binary payloads either as raw `application/octet-stream`
  (preferred, zero-copy) or as a JSON object with a base64-encoded `data` field.
  """

  alias OmnisecServer.{Conn, ResultCache, WorkerPool, Worker, ClusterMonitor}

  @max_payload_bytes 50 * 1024 * 1024

  # ─── Health ─────────────────────────────────────────────────────

  def health(conn, _params) do
    Conn.json(conn, sanitize(%{
      status: "ok",
      node: to_string(Node.self()),
      cluster: safe_status(&ClusterMonitor.cluster_status/0),
      pool: safe_status(&WorkerPool.status/0),
      cache: safe_status(&ResultCache.stats/0)
    }))
  end

  # ─── Standalone read-only endpoints ─────────────────────────────

  def cluster(conn, _params) do
    Conn.json(conn, sanitize(%{
      ok: true,
      cluster: safe_status(&ClusterMonitor.cluster_status/0),
      nodes: safe_status(&ClusterMonitor.connected_nodes/0)
    }))
  end

  def pool(conn, _params) do
    Conn.json(conn, sanitize(%{ok: true, pool: safe_status(&WorkerPool.status/0)}))
  end

  # A dead dependency (e.g. pool restarting) degrades the probe instead
  # of leaking a 500 with an exit.
  defp safe_status(fun) do
    try do
      fun.()
    catch
      :exit, _ -> %{error: "unavailable"}
    end
  end

  # ─── Analysis dispatch ──────────────────────────────────────────

  def analyze_apk(conn, params), do: dispatch(conn, :analyze_apk, params)
  def analyze_binzap(conn, params), do: dispatch(conn, :analyze_binzap, params)
  def analyze_binary(conn, params), do: dispatch(conn, :analyze_binary, params)

  def scan_yara(conn, %{"rules" => rules} = params) do
    with {:ok, data} <- payload(conn, params) do
      run_job(:scan_yara, %{data: data, rules: rules}, conn)
    else
      {:error, reason} -> error(conn, 400, reason)
    end
  end

  def scan_patterns(conn, %{"patterns" => patterns} = params) do
    with {:ok, data} <- payload(conn, params),
         {:ok, json_str} <- OmnisecServer.JSON.encode(patterns) do
      run_job(:scan_patterns, %{data: data, patterns: json_str}, conn)
    else
      {:error, reason} -> error(conn, 400, reason)
    end
  end

  def rank_hotspots(conn, params) do
    with {:ok, json_str} <- OmnisecServer.JSON.encode(params) do
      run_job(:rank_hotspots, %{request: json_str}, conn)
    end
  end

  def symexec_solve(conn, %{"expr" => expr}) do
    case OmniSec.Native.SymExec.solve_opaque_predicate(expr) do
      :sat -> Conn.json(conn, %{ok: true, result: "sat"})
      :unsat -> Conn.json(conn, %{ok: true, result: "unsat"})
      {:unknown, reason} -> Conn.json(conn, %{ok: true, result: "unknown", reason: to_string(reason)})
      {:error, reason} -> error(conn, 400, "z3 error: #{reason}")
      other -> error(conn, 500, "unexpected result: #{inspect(other)}")
    end
  end
  def symexec_solve(conn, _), do: error(conn, 400, "missing 'expr' in json payload")

  def micro_emu_emulate(conn, %{"shellcode_hex" => hex_code}) do
    case Base.decode16(hex_code, case: :mixed) do
      {:ok, bytes} ->
        case OmniSec.Native.MicroEmu.emulate_shellcode(bytes) do
          :ok -> Conn.json(conn, %{ok: true, result: "emulated_successfully"})
          {:error, reason} -> error(conn, 400, "emulation error: #{inspect(reason)}")
          {:error, reason, details} -> error(conn, 400, "emulation error: #{inspect(reason)} - #{details}")
          other -> error(conn, 500, "unexpected result: #{inspect(other)}")
        end
      :error ->
        error(conn, 400, "invalid hex string in 'shellcode_hex'")
    end
  end
  def micro_emu_emulate(conn, _), do: error(conn, 400, "missing 'shellcode_hex' in json payload")

  def hash_features(conn, %{"features" => features} = params) do
    seed = Map.get(params, "seed", 42)

    with {:ok, json_str} <- OmnisecServer.JSON.encode(features) do
      run_job(:hash_features, %{features: json_str, seed: seed}, conn)
    end
  end

  # ─── Internal helpers ───────────────────────────────────────────

  # NIF results and monitor snapshots may carry Elixir-only terms
  # (DateTime structs, atoms, tuples) that have no JSON form. Walk the
  # envelope and coerce them, so responses never leak a 500 from the
  # codec. JSON-native values pass through untouched.
  defp sanitize(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  defp sanitize(%NaiveDateTime{} = dt), do: NaiveDateTime.to_iso8601(dt)
  defp sanitize(%Date{} = d), do: Date.to_iso8601(d)
  defp sanitize(%Time{} = t), do: Time.to_iso8601(t)
  defp sanitize(%_{} = struct), do: inspect(struct)
  defp sanitize(map) when is_map(map), do: Map.new(map, fn {k, v} -> {k, sanitize(v)} end)
  defp sanitize(list) when is_list(list), do: Enum.map(list, &sanitize/1)
  defp sanitize(tuple) when is_tuple(tuple), do: tuple |> Tuple.to_list() |> sanitize()
  defp sanitize(true), do: true
  defp sanitize(false), do: false
  defp sanitize(nil), do: nil
  defp sanitize(atom) when is_atom(atom), do: Atom.to_string(atom)
  defp sanitize(other), do: other

  defp dispatch(conn, job_type, params) do
    case payload(conn, params) do
      {:ok, data} ->
        # Result cache lookup keyed by SHA-256 of the binary payload —
        # repeated submissions of the same APK / binary are answered
        # in microseconds without booking a worker.
        hash = :crypto.hash(:sha256, data) |> Base.encode16(case: :lower)

        case ResultCache.get(hash) do
          {:ok, cached} ->
            Conn.json(conn, sanitize(%{ok: true, result: cached, cached: true}))

          :miss ->
            run_job_and_cache(job_type, %{data: data}, hash, conn)
        end

      {:error, reason} ->
        error(conn, 400, reason)
    end
  end

  defp run_job_and_cache(job_type, payload_map, cache_key, conn) do
    case WorkerPool.with_worker(fn worker ->
           Worker.analyze(worker, job_type, payload_map)
         end) do
      {:ok, result} ->
        # Only cache successful results to avoid pinning errors.
        case result do
          {:error, _} -> :ok
          _ -> ResultCache.put(cache_key, result)
        end

        Conn.json(conn, sanitize(%{ok: true, result: result, cached: false}))

      {:error, reason} ->
        error(conn, 503, "pool unavailable: #{inspect(reason)}")
    end
  end

  defp run_job(job_type, payload_map, conn) do
    case WorkerPool.with_worker(fn worker ->
           Worker.analyze(worker, job_type, payload_map)
         end) do
      {:ok, result} -> Conn.json(conn, sanitize(%{ok: true, result: result}))
      {:error, reason} -> error(conn, 503, "pool unavailable: #{inspect(reason)}")
    end
  end

  defp payload(conn, params) do
    cond do
      is_map(params) and Map.has_key?(params, "data_b64") ->
        Base.decode64(params["data_b64"]) |> case do
          {:ok, bin} when byte_size(bin) <= @max_payload_bytes -> {:ok, bin}
          {:ok, _} -> {:error, "payload exceeds #{@max_payload_bytes} bytes"}
          :error -> {:error, "invalid base64 in data_b64"}
        end

      byte_size(conn.body || "") > @max_payload_bytes ->
        {:error, "payload exceeds #{@max_payload_bytes} bytes"}

      byte_size(conn.body || "") > 0 ->
        {:ok, conn.body}

      true ->
        {:error, "empty body"}
    end
  end

  defp error(conn, status, reason) do
    conn
    |> Conn.put_status(status)
    |> Conn.json(%{ok: false, error: to_string(reason)})
  end
end
