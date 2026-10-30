defmodule OmnisecServer.MixProject do
  use Mix.Project

  def project do
    [
      app: :omnisec_server,
      version: "0.2.0",
      elixir: "~> 1.17",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      aliases: aliases(),
      compilers: Mix.compilers() ++ [:rust_nifs],
      rust_nifs: rust_nifs(),
      description: "OmniSec Distributed Binary Analysis Server"
    ]
  end

  # Native crates built via `Mix.Tasks.Compile.RustNifs`
  # (`lib/mix/tasks/compile.rust_nifs.ex`) — a dependency-free
  # replacement for Rustler's `rustler_crates` + Mix compiler.
  defp rust_nifs do
    [
      %{name: :omnisec_symexec_nif, path: "../rust/crates/omnisec-z3-worker"},
      %{name: :omnisec_micro_emu_nif, path: "../rust/crates/omnisec-micro-emu"},
      %{name: :omnisec_debugger_nif, path: "native/omnisec_debugger_nif"},
      %{name: :omnisec_worker_nif, path: "native/omnisec_worker_nif"}
    ]
  end

  def application do
    [
      extra_applications: [:logger, :runtime_tools, :crypto, :os_mon, :inets, :ssl],
      mod: {OmnisecServer.Application, []}
    ]
  end

  # Zero hex dependencies: the HTTP layer runs on OTP `:inets`, the
  # WebSocket debugger on `:gen_tcp`, JSON on the in-house
  # `OmnisecServer.JSON` codec, and NIFs on the local `:rust_nifs`
  # Mix compiler. `mix.lock` is intentionally empty.
  defp deps do
    []
  end

  defp aliases do
    [
      setup: ["deps.get", "compile"]
    ]
  end
end
