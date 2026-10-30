defmodule OmnisecServer.NifLoader do
  @moduledoc """
  Minimal, dependency-free replacement for `Rustler`'s runtime NIF
  loading step.

  Rustler's `use Rustler, otp_app: ..., crate: ...` macro does two
  things at runtime: it defines an `@on_load` callback, and inside that
  callback it resolves `priv/native/<crate>` (platform extension added
  automatically by `:erlang.load_nif/2`) and loads it. This module does
  exactly that and nothing else — no macros, no external dependencies.
  """

  # NOTE: logging here uses `:logger`, not `Logger` — this module is
  # expanded as a macro into NIF facades, so it must not depend on the
  # caller's `require`s.

  @doc """
  Loads the compiled NIF library named `crate` (an atom, matching the
  cdylib's `[lib] name` in its `Cargo.toml`) from `priv/native/` of
  `otp_app`.

  This MUST be a macro (not a function): the BEAM attributes the
  `:erlang.load_nif/2` call to the module whose code textually contains
  it, and the NIF's `ERL_NIF_INIT` name must equal that caller module.
  A shared helper function would make every library appear to load from
  `OmnisecServer.NifLoader` itself and the VM would refuse them all.

  Intended usage in each NIF facade module (which must also match the
  crate's `ERL_NIF_INIT` name):

      require OmnisecServer.NifLoader

      @on_load :__load_nif__
      def __load_nif__, do: OmnisecServer.NifLoader.load(:omnisec_server, :omnisec_worker_nif)
  """
  defmacro load(otp_app, crate) do
    quote do
      case :code.priv_dir(unquote(otp_app)) do
        {:error, reason} ->
          # App not loaded (e.g. module compiled standalone): nothing to
          # load from, the NIF stubs stay in place. Must not crash here —
          # `@on_load` failures are noisy and mask the real state.
          :logger.warning(
            "NIF #{unquote(crate)}: priv dir unavailable (#{inspect(reason)}), skipping load"
          )

          :ok

        priv_dir ->
          # NOTE: this `:erlang.load_nif/2` call MUST stay textually here,
          # inside the macro expansion — the BEAM attributes it to the
          # module being compiled (the NIF facade), never to NifLoader.
          path =
            Path.join([to_string(priv_dir), "native", Atom.to_string(unquote(crate))])

          case :erlang.load_nif(String.to_charlist(path), 0) do
            :ok ->
              :ok

            {:error, {:reload, _}} ->
              # Already loaded (can happen under hot code reloading) — fine.
              :ok

            {:error, {:load_failed, reason}} ->
              :logger.error(
                "Failed to load NIF #{unquote(crate)} from #{path}: #{inspect(reason)}. " <>
                  "Build it first, e.g.: `mix compile` (with the rust_nifs compiler enabled)."
              )

              :ok

            {:error, reason} ->
              :logger.warning("Failed to load NIF #{unquote(crate)}: #{inspect(reason)}")
              :ok
          end
      end
    end
  end
end
