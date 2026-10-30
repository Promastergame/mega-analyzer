defmodule BitArena.MixProject do
  use Mix.Project

  def project do
    [
      app: :bit_arena,
      version: "0.1.0",
      elixir: "~> 1.17",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto, :ssl, :inets],
      mod: {BitArena.Application, []}
    ]
  end

  # Zero hex dependencies: HTTP runs on OTP `:inets`, the game socket
  # on `:gen_tcp`, JSON on the in-house `BitArena.JSON` codec.
  # `mix.lock` is intentionally empty.
  defp deps do
    []
  end
end
