defmodule MockServer.MixProject do
  use Mix.Project

  def project do
    [
      app: :mock_server,
      version: "0.1.0",
      elixir: "~> 1.19",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto, :ssl, :inets],
      mod: {MockServer.Application, []}
    ]
  end

  # Zero hex dependencies: HTTP runs on OTP `:inets`, JSON on the
  # in-house `MockServer.JSON` codec. `mix.lock` is intentionally empty.
  defp deps do
    []
  end
end
