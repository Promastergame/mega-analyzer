defmodule OmniSec.Native.MicroEmu do
  @moduledoc """
  Native NIF bridge for the OmniSec Micro-Emulator engine
  (`rust/crates/omnisec-micro-emu`, crate `omnisec_micro_emu_nif`).

  Returns `:ok`, `{:error, :timeout}`, or `{:error, "emu_failed: ..."}`
  (the old 3-tuple `{:error, :emu_failed, details}` was flattened because
  `nifshim` only builds atoms and 2-tuples).
  """

  @on_load :__load_nif__
  # `NifLoader.load/2` is a macro: the `:erlang.load_nif/2` call must
  # expand inside THIS module for the BEAM name check to pass.
  require OmnisecServer.NifLoader
  def __load_nif__, do: OmnisecServer.NifLoader.load(:omnisec_server, :omnisec_micro_emu_nif)

  @doc """
  Runs shellcode in OmniSec Micro-Emulator engine.
  """
  def emulate_shellcode(_code), do: :erlang.nif_error(:nif_not_loaded)
end
