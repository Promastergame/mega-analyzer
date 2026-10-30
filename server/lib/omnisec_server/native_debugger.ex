defmodule OmnisecServer.NativeDebugger do
  @moduledoc """
  Native NIF bridge for the OmniSec interactive debugger.

  See `OmnisecServer.Native` for the loading/ABI architecture notes;
  this module follows the exact same pattern for the
  `omnisec_debugger_nif` crate.

  All functions run on dirty CPU schedulers because emulation
  can take milliseconds per step.
  """

  @on_load :__load_nif__
  # `NifLoader.load/2` is a macro: the `:erlang.load_nif/2` call must
  # expand inside THIS module for the BEAM name check to pass.
  require OmnisecServer.NifLoader
  def __load_nif__, do: OmnisecServer.NifLoader.load(:omnisec_server, :omnisec_debugger_nif)

  # ═══════════════════════════════════════════════════════════════
  # Session lifecycle
  # ═══════════════════════════════════════════════════════════════

  @doc "Start a debugger session. Returns JSON with session_id, entry_point, arch."
  def debug_session_start(_json), do: :erlang.nif_error(:nif_not_loaded)

  @doc "Stop and destroy a session."
  def debug_session_stop(_session_id), do: :erlang.nif_error(:nif_not_loaded)

  # ═══════════════════════════════════════════════════════════════
  # Execution control
  # ═══════════════════════════════════════════════════════════════

  @doc "Step one instruction. Returns JSON with rip, instruction, stop_reason."
  def debug_step(_session_id), do: :erlang.nif_error(:nif_not_loaded)

  @doc "Continue until stop. Same JSON shape as debug_step."
  def debug_continue(_session_id), do: :erlang.nif_error(:nif_not_loaded)

  # ═══════════════════════════════════════════════════════════════
  # Breakpoints
  # ═══════════════════════════════════════════════════════════════

  @doc "Set a breakpoint. target = '0x401000' or 'main'. Returns JSON ok/id/address."
  def debug_breakpoint(_session_id, _target), do: :erlang.nif_error(:nif_not_loaded)

  @doc "Remove a breakpoint by id."
  def debug_remove_bp(_session_id, _bp_id), do: :erlang.nif_error(:nif_not_loaded)

  @doc "List all breakpoints. Returns JSON array."
  def debug_list_bp(_session_id), do: :erlang.nif_error(:nif_not_loaded)

  # ═══════════════════════════════════════════════════════════════
  # Watchpoints
  # ═══════════════════════════════════════════════════════════════

  @doc "Add a watchpoint. kind = 'read' | 'write' | 'access'. Returns JSON ok/id."
  def debug_add_watch(_session_id, _address, _size, _kind), do: :erlang.nif_error(:nif_not_loaded)

  @doc "Remove a watchpoint by id."
  def debug_remove_watch(_session_id, _watch_id), do: :erlang.nif_error(:nif_not_loaded)

  @doc "List all watchpoints. Returns JSON array."
  def debug_list_watch(_session_id), do: :erlang.nif_error(:nif_not_loaded)

  # ═══════════════════════════════════════════════════════════════
  # Introspection
  # ═══════════════════════════════════════════════════════════════

  @doc "Read all general-purpose registers + flags. Returns JSON."
  def debug_registers(_session_id), do: :erlang.nif_error(:nif_not_loaded)

  @doc "Disassemble at address. Returns JSON array of lines."
  def debug_disassemble(_session_id, _address, _count), do: :erlang.nif_error(:nif_not_loaded)

  @doc "Read raw memory bytes. Returns JSON with hex string."
  def debug_read_memory(_session_id, _address, _size), do: :erlang.nif_error(:nif_not_loaded)

  @doc "Set disassembly flavor ('intel' or 'att'). Returns :ok atom."
  def debug_set_flavor(_session_id, _flavor), do: :erlang.nif_error(:nif_not_loaded)

  @doc "Write raw hex bytes to memory. Returns JSON ok/written."
  def debug_write_memory(_session_id, _address, _hex_str), do: :erlang.nif_error(:nif_not_loaded)

  @doc "Set a register value. Returns JSON ok."
  def debug_set_register(_session_id, _reg, _value), do: :erlang.nif_error(:nif_not_loaded)

  @doc "Scan memory for byte pattern (hex with ?? wildcards). Returns JSON hits array."
  def debug_scan_memory(_session_id, _pattern), do: :erlang.nif_error(:nif_not_loaded)

  @doc "Enable/disable time-travel tracing. Returns JSON ok."
  def debug_trace_enable(_session_id, _enabled), do: :erlang.nif_error(:nif_not_loaded)

  @doc "Reverse-step one instruction. Returns JSON like debug_step."
  def debug_reverse_step(_session_id), do: :erlang.nif_error(:nif_not_loaded)

  @doc "Reverse-continue until previous breakpoint. Returns JSON like debug_continue."
  def debug_reverse_continue(_session_id), do: :erlang.nif_error(:nif_not_loaded)

  @doc "Get trace execution log. Returns JSON array of steps."
  def debug_trace_log(_session_id, _start, _count), do: :erlang.nif_error(:nif_not_loaded)

  @doc "Get trace statistics. Returns JSON with stats."
  def debug_trace_stats(_session_id), do: :erlang.nif_error(:nif_not_loaded)

  @doc "Generate a Control Flow Graph starting at address. Returns JSON graph."
  def debug_cfg(_session_id, _address, _count), do: :erlang.nif_error(:nif_not_loaded)

  @doc "Set CPU flags (ZF, SF, CF, OF) for branch forcing. Returns JSON ok."
  def debug_set_flag(_session_id, _flag, _value), do: :erlang.nif_error(:nif_not_loaded)
end
