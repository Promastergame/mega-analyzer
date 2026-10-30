defmodule OmnisecServer.Crypto do
  @moduledoc """
  Dependency-free constant-time comparison (replaces
  `Plug.Crypto.secure_compare/2`).

  Inputs are SHA-256 pre-hashed so the comparison itself never leaks
  the length of the original secrets, then compared with
  `:crypto.hash_equals/2` (OTP 26+).
  """

  @doc "Constant-time equality for secret strings."
  @spec secure_compare(binary(), binary()) :: boolean()
  def secure_compare(a, b) when is_binary(a) and is_binary(b) do
    :crypto.hash_equals(:crypto.hash(:sha256, a), :crypto.hash(:sha256, b))
  end

  def secure_compare(_, _), do: false
end
