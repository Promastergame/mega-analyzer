defmodule OmnisecServer.Native do
  @moduledoc """
  Native NIF bridge — calls into the omnisec-ml-inference and
  omnisec-scan-native Rust libraries via raw Erlang NIFs.

  Loading is handled by `OmnisecServer.NifLoader` (a small
  dependency-free replacement for `Rustler`'s `use Rustler, ...`
  runtime loader). The NIF ABI itself (the `ErlNifEntry` table, arg
  decoding/encoding, dirty-scheduler flags) is implemented by the
  `nifshim` Rust crate — see `native/nifshim` and
  `native/omnisec_worker_nif/src/entry.c`.

  ## Dirty Schedulers

  All analysis functions run on dirty CPU schedulers to avoid
  blocking the normal BEAM schedulers. Rust analysis can take
  10-500ms, which would wreck latency for other processes.
  """

  @on_load :__load_nif__
  # `NifLoader.load/2` is a macro: the `:erlang.load_nif/2` call must
  # expand inside THIS module for the BEAM name check to pass.
  require OmnisecServer.NifLoader
  def __load_nif__, do: OmnisecServer.NifLoader.load(:omnisec_server, :omnisec_worker_nif)

  # ═══════════════════════════════════════════════════════════════
  # NIF STUBS — replaced at load time by the compiled NIF
  # ═══════════════════════════════════════════════════════════════

  @doc "Full APK analysis (DEX parsing + threat detection + ML scoring)"
  def analyze_apk(_data), do: :erlang.nif_error(:nif_not_loaded)

  @doc "Native binary (.so/.dll) security analysis"
  def analyze_binary(_data), do: :erlang.nif_error(:nif_not_loaded)

  @doc "Multi-pattern vulnerability scan"
  def scan_patterns(_data, _patterns_json), do: :erlang.nif_error(:nif_not_loaded)

  @doc "ML-based hotspot ranking via HDC similarity"
  def rank_hotspots(_request_json), do: :erlang.nif_error(:nif_not_loaded)

  @doc "Feature vector computation via HDC hashing"
  def hash_features(_features_json, _seed), do: :erlang.nif_error(:nif_not_loaded)

  @doc "Health check — returns :ok if NIF is loaded"
  def health_check, do: :erlang.nif_error(:nif_not_loaded)

  @doc "Scan binary data against YARA rules using Boreal (Rust NIF)"
  def scan_yara(_rules_str, _data), do: :erlang.nif_error(:nif_not_loaded)

  @doc "Predict the name of a variable based on its HDC context"
  def predict_variable_name(_context_json, _database_json, _threshold), do: :erlang.nif_error(:nif_not_loaded)

  @doc "Predict the name of a function based on its structural HDC context"
  def predict_function_name(_context_json, _database_json, _threshold), do: :erlang.nif_error(:nif_not_loaded)

  @doc "Train a variable name by associating its HDC context with a clean name"
  def train_variable_name(_context_json, _database_json, _clean_name), do: :erlang.nif_error(:nif_not_loaded)

  @doc "Train a function name by associating its HDC context with a clean name"
  def train_function_name(_context_json, _database_json, _clean_name), do: :erlang.nif_error(:nif_not_loaded)

  @doc "Initialize an eBPF tracing session for a target process"
  def ebpf_start_trace(_pid), do: :erlang.nif_error(:nif_not_loaded)

  @doc "Poll new events from an active eBPF tracing session"
  def ebpf_poll_events(_session_id), do: :erlang.nif_error(:nif_not_loaded)

  @doc "Stop an eBPF tracing session and return its captured events"
  def ebpf_stop_trace(_session_id), do: :erlang.nif_error(:nif_not_loaded)
end
