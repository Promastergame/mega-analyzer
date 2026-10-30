defmodule Mix.Tasks.Compile.RustNifs do
  @moduledoc """
  Dependency-free replacement for Rustler's build-time Mix compiler.

  Builds each configured native crate with `cargo build` and copies
  the resulting shared library into `priv/native/<name>.<ext>`, where
  `:erlang.load_nif/2` (via `OmnisecServer.NifLoader`) expects to find
  it.

  Configure crates to build in `mix.exs`:

      def project do
        [
          ...,
          rust_nifs: rust_nifs()
        ]
      end

      defp rust_nifs do
        [
          %{name: :omnisec_worker_nif, path: "native/omnisec_worker_nif"},
          %{name: :omnisec_debugger_nif, path: "native/omnisec_debugger_nif"},
          %{name: :omnisec_symexec_nif, path: "../rust/crates/omnisec-z3-worker"},
          %{name: :omnisec_micro_emu_nif, path: "../rust/crates/omnisec-micro-emu"}
        ]
      end

  Each crate directory must have its own `Cargo.toml` producing a
  `cdylib` and its own `build.rs` (compiling `src/entry.c` against the
  real `erl_nif.h` — see `native/nifshim`).
  """

  use Mix.Task.Compiler

  @impl Mix.Task.Compiler
  def run(_args) do
    crates = Mix.Project.config()[:rust_nifs] || []
    mode = if Mix.env() == :prod, do: "release", else: "debug"
    priv_native = Path.join(Mix.Project.app_path(), "priv/native")
    File.mkdir_p!(priv_native)

    results =
      Enum.map(crates, fn %{name: name, path: path} ->
        build_one(name, path, mode, priv_native)
      end)

    if Enum.any?(results, &(&1 != :ok)) do
      {:error, ["one or more Rust NIF crates failed to build"]}
    else
      {:ok, []}
    end
  end

  defp build_one(name, path, mode, priv_native) do
    Mix.shell().info("[rust_nifs] building #{name} (#{mode}) in #{path}")

    args = ["build"] ++ if(mode == "release", do: ["--release"], else: [])

    case System.cmd("cargo", args, cd: path, stderr_to_stdout: true) do
      {output, 0} ->
        Mix.shell().info(output)
        copy_artifact(name, path, mode, priv_native)

      {output, code} ->
        Mix.shell().error(output)
        Mix.shell().error("[rust_nifs] cargo build failed for #{name} (exit #{code})")
        :error
    end
  end

  defp copy_artifact(name, path, mode, priv_native) do
    target_dir = resolve_target_dir(path, mode)
    # cargo emits `lib<name>.so/.dylib` on Unix but bare `<name>.dll`
    # on Windows — accept both spellings on every platform.
    candidates =
      for base <- ["lib#{name}", "#{name}"], ext <- [".so", ".dylib", ".dll"] do
        Path.join(target_dir, base <> ext)
      end

    case Enum.find(candidates, &File.exists?/1) do
      nil ->
        Mix.shell().error("[rust_nifs] no built artifact found for #{name} in #{target_dir}")
        :error

      src ->
        ext = Path.extname(src)
        dest = Path.join(priv_native, Atom.to_string(name) <> ext)
        File.cp!(src, dest)
        Mix.shell().info("[rust_nifs] #{src} -> #{dest}")

        # Also copy to root priv/native in case :code.priv_dir resolves
        # directly to the source directory rather than the app build directory.
        root_priv = Path.join([File.cwd!(), "priv", "native"])
        File.mkdir_p!(root_priv)
        root_dest = Path.join(root_priv, Atom.to_string(name) <> ext)
        if root_dest != dest do
          _ = File.cp(src, root_dest)
        end

        :ok
    end
  end

  # Workspace members share the workspace-level `target/` dir, standalone
  # crates use their own. Ask cargo where this crate really links.
  defp resolve_target_dir(path, mode) do
    fallback = Path.join([path, "target", mode])

    case System.cmd("cargo", ["metadata", "--format-version=1", "--no-deps"],
           cd: path,
           stderr_to_stdout: true
         ) do
      {out, 0} ->
        case Regex.run(~r/"target_directory"\s*:\s*"((?:[^"\\]|\\.)*)"/, out) do
          [_, dir] -> Path.join(String.replace(dir, "\\\\", "\\"), mode)
          _ -> fallback
        end

      _ ->
        fallback
    end
  end
end
