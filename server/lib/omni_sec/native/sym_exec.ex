defmodule OmniSec.Native.SymExec do
  @moduledoc """
  Native NIF bridge for the OmniSec Z3-backed symbolic execution worker
  (`native/omnisec-z3-worker`, crate `omnisec_symexec_nif`).
  """

  @on_load :__load_nif__
  # `NifLoader.load/2` is a macro: the `:erlang.load_nif/2` call must
  # expand inside THIS module for the BEAM name check to pass.
  require OmnisecServer.NifLoader
  def __load_nif__, do: OmnisecServer.NifLoader.load(:omnisec_server, :omnisec_symexec_nif)

  @doc """
  Solves an SMT-LIB2 expression to evaluate an opaque predicate.
  Returns `:sat`, `:unsat`, `{:unknown, reason}`, or `{:error, reason}`.
  """
  def solve_opaque_predicate(_smtlib2_expr), do: :erlang.nif_error(:nif_not_loaded)
end
