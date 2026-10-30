defmodule MockServer.Scenario do
  @moduledoc """
  Live-switchable behaviour profiles, so you can see how a client copes when its
  backend stops being polite. Flip them from the dashboard while traffic runs.

    * `:normal`  — always healthy, no added delay
    * `:flaky`   — 20–250 ms of latency and roughly 20% `503`s
    * `:offline` — every request fails with `503`
    * `:expired` — anything license-shaped reports an inactive, expired plan
  """

  use Agent

  @scenarios [:normal, :flaky, :offline, :expired]
  @license_paths ~r/(license|subscription|premium|entitlement|session|plan|billing)/i

  def start_link(_), do: Agent.start_link(fn -> :normal end, name: __MODULE__)

  @doc "The active scenario."
  def current, do: Agent.get(__MODULE__, & &1)

  @doc "Every scenario this server knows about."
  def all, do: @scenarios

  @doc "Switch scenario. Accepts an atom or its string name."
  def set(name) when name in @scenarios do
    Agent.update(__MODULE__, fn _ -> name end)
    {:ok, name}
  end

  def set(name) when is_binary(name) do
    case Enum.find(@scenarios, &(Atom.to_string(&1) == name)) do
      nil -> {:error, :unknown}
      scenario -> set(scenario)
    end
  end

  def set(_other), do: {:error, :unknown}

  @doc """
  Applied before any rule runs. Returns `:continue` to fall through to normal
  rule handling, or `{:short, status, body}` to answer immediately. Latency is
  injected as a side effect.
  """
  def gate(path) do
    case current() do
      :normal ->
        :continue

      :flaky ->
        Process.sleep(Enum.random(20..250))

        if :rand.uniform() < 0.2 do
          {:short, 503, %{"error" => true, "message" => "upstream timeout (flaky scenario)"}}
        else
          :continue
        end

      :offline ->
        {:short, 503, %{"error" => true, "message" => "server offline (scenario)"}}

      :expired ->
        if Regex.match?(@license_paths, path) do
          {:short, 200,
           %{
             "status" => 200,
             "error" => false,
             "tier" => "free",
             "plan" => "none",
             "active" => false,
             "expired" => true
           }}
        else
          :continue
        end
    end
  end
end
