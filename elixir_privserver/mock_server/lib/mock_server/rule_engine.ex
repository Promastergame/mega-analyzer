defmodule MockServer.RuleEngine do
  @moduledoc """
  Decides what this private server answers, in three stages:

    1. `MockServer.Scenario.gate/1` — may short-circuit (offline, flaky, expired).
    2. `MockServer.RuleStore.match/2` — first matching rule from `priv/rules.json`.
    3. `builtin/1` — heuristic fallback that recognises auth / license / feature
       endpoints by name, so an unknown app usually "just works" with no rules.

  Response bodies support a few interpolation directives so rules can stay
  static JSON while still minting fresh values:

    * `"$premium_token"` / `"$free_token"` — a Bit-Arena-compatible token
    * `"$now"`      — current unix timestamp
    * `"$rand_hex"` — 16 random hex characters
  """

  alias MockServer.{Entitlements, RuleStore, Scenario}

  @auth ~r/(login|register|signin|signup|auth|session|token|account|device)/i
  @license ~r/(subscription|plan|license|premium|pro|entitlement|billing|purchase)/i
  @features ~r/(feature|flag|config|settings|experiment|remote)/i

  @doc "Resolve a request into `{rule_name, status, body_map}`."
  def resolve(method, path, _body \\ %{}) do
    case Scenario.gate(path) do
      {:short, status, body} ->
        {"scenario:#{Scenario.current()}", status, body}

      :continue ->
        case RuleStore.match(method, path) do
          %{"response" => response} = rule when is_map(response) ->
            {
              Map.get(rule, "name", "unnamed"),
              Map.get(response, "status", 200),
              interpolate(Map.get(response, "json", %{}))
            }

          _no_rule ->
            {"builtin", 200, builtin(path)}
        end
    end
  end

  # ── Interpolation ──────────────────────────────────────────────────

  defp interpolate(map) when is_map(map) do
    Map.new(map, fn {key, value} -> {key, interpolate(value)} end)
  end

  defp interpolate(list) when is_list(list), do: Enum.map(list, &interpolate/1)
  defp interpolate("$premium_token"), do: Entitlements.issue("lab", "premium")
  defp interpolate("$free_token"), do: Entitlements.issue("lab", "free")
  defp interpolate("$now"), do: System.system_time(:second)
  defp interpolate("$rand_hex"), do: Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)
  defp interpolate(other), do: other

  # ── Heuristic fallback ──────────────────────────────────────────────

  defp builtin(path) do
    cond do
      Regex.match?(@auth, path) ->
        %{
          "status" => 200,
          "error" => false,
          "message" => "OK",
          "user_id" => "mock-user-0001",
          "account" => "lab",
          "email" => "admin@localhost",
          "name" => "Mock User",
          "tier" => "premium",
          "token" => Entitlements.issue("lab", "premium"),
          "expires_in" => 86_400
        }

      Regex.match?(@license, path) ->
        %{
          "status" => 200,
          "error" => false,
          "plan" => "professional",
          "tier" => "premium",
          "active" => true,
          "seats" => 999,
          "expires" => "2099-12-31T23:59:59Z"
        }

      Regex.match?(@features, path) ->
        %{"status" => 200, "error" => false, "features" => %{"*" => true}}

      true ->
        %{"status" => 200, "error" => false, "message" => "OK", "data" => %{}}
    end
  end
end
