defmodule MockServer.RuleStore do
  @moduledoc """
  Holds the declarative request → response rules loaded from `priv/rules.json`,
  and can reload them at runtime while clients stay connected.

  A rule looks like this:

      {
        "name": "bit-arena-premium-session",
        "match":    { "method": "GET", "path": "^/api/v1/session" },
        "response": { "status": 200, "json": { "tier": "premium" } }
      }

  `match` supports `method`, `path` (regex) and `path_prefix`; anything omitted
  matches everything. The first matching rule wins.
  """

  use GenServer
  require Logger

  def start_link(_), do: GenServer.start_link(__MODULE__, [], name: __MODULE__)

  @doc "All loaded rules, in file order."
  def rules, do: GenServer.call(__MODULE__, :rules)

  @doc "How many rules are loaded."
  def count, do: length(rules())

  @doc "Re-read priv/rules.json. Returns `{:ok, rule_count}`."
  def reload, do: GenServer.call(__MODULE__, :reload)

  @doc "First rule matching this request, or `nil`."
  def match(method, path) do
    Enum.find(rules(), &matches?(&1, method, path))
  end

  @impl true
  def init(_), do: {:ok, load()}

  @impl true
  def handle_call(:rules, _from, rules), do: {:reply, rules, rules}

  def handle_call(:reload, _from, _rules) do
    rules = load()
    {:reply, {:ok, length(rules)}, rules}
  end

  defp load do
    path =
      Path.join(
        :code.priv_dir(:mock_server),
        Application.get_env(:mock_server, :rules_path, "rules.json")
      )

    with {:ok, body} <- File.read(path),
         {:ok, %{"rules" => rules}} when is_list(rules) <- MockServer.JSON.decode(body) do
      Logger.info("rule store: loaded #{length(rules)} rule(s)")
      rules
    else
      other ->
        Logger.warning(
          "rule store: could not load #{path} (#{inspect(other)}); built-in fallbacks only"
        )

        []
    end
  end

  defp matches?(%{"match" => matcher}, method, path) when is_map(matcher) do
    method_matches?(matcher, method) and path_matches?(matcher, path)
  end

  defp matches?(_rule, _method, _path), do: false

  defp method_matches?(%{"method" => want}, method) when is_binary(want) do
    String.upcase(want) == String.upcase(method)
  end

  defp method_matches?(_matcher, _method), do: true

  defp path_matches?(%{"path" => pattern}, path) when is_binary(pattern) do
    case Regex.compile(pattern) do
      {:ok, regex} -> Regex.match?(regex, path)
      {:error, _reason} -> false
    end
  end

  defp path_matches?(%{"path_prefix" => prefix}, path) when is_binary(prefix) do
    String.starts_with?(path, prefix)
  end

  defp path_matches?(_matcher, _path), do: true
end
