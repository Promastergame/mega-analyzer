defmodule BitArena.HttpServer do
  @moduledoc """
  Dependency-free HTTP listener on OTP `:inets httpd` (replaces
  `Plug.Cowboy`). Serves the browser client, the session/status/
  leaderboard JSON API, and answers `426` on `/ws` pointing clients at
  the real WebSocket listener (`BitArena.WsServer`, which `:inets`
  cannot upgrade to).
  """

  use GenServer
  require Logger

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts)
  end

  @impl true
  def init(opts) do
    port = Keyword.get(opts, :port, BitArena.config(:http_port, 4000))
    ip = Keyword.get(opts, :ip, {127, 0, 0, 1})

    server_root = Path.join(System.tmp_dir!(), "bitarena_httpd_#{port}") |> String.to_charlist()
    File.mkdir_p!(to_string(server_root))

    httpd_opts = [
      port: port,
      bind_address: ip,
      server_name: ~c"bitarena",
      server_root: server_root,
      document_root: server_root,
      modules: [__MODULE__.Mod]
    ]

    case :inets.start(:httpd, httpd_opts) do
      {:ok, pid} ->
        Logger.info("[HttpServer] BitArena.Router on #{:inet.ntoa(ip)}:#{port}")
        {:ok, %{httpd: pid}}

      {:error, {:already_started, pid}} ->
        {:ok, %{httpd: pid}}

      {:error, reason} ->
        {:stop, reason}
    end
  end

  @impl true
  def terminate(_reason, %{httpd: pid}) do
    :inets.stop(:httpd, pid)
    :ok
  end

  @doc false
  def conn_from_mod(mod_data) do
    {:mod, init_data, _data, _st, _sock, _db, method, _abs, uri, _ver, _line, headers, entity_body, _conn} =
      mod_data

    {path, query_string, query_params} =
      uri |> to_string() |> BitArena.Conn.split_path()

    BitArena.Conn.new(
      method: to_string(method) |> String.upcase(),
      path: path,
      query_string: query_string,
      query_params: query_params,
      params: query_params,
      headers: Enum.map(headers, fn {k, v} -> {to_string(k), to_string(v)} end),
      body: entity_to_binary(entity_body),
      remote_ip: peer_ip(init_data)
    )
    |> BitArena.Conn.parse_body()
  end

  defp entity_to_binary(bin) when is_binary(bin), do: bin
  defp entity_to_binary(list) when is_list(list), do: IO.iodata_to_binary(list)
  defp entity_to_binary(_), do: ""

  defp peer_ip({:init_data, {_port, ip}, _sockname, _resolve}) when is_list(ip), do: to_string(ip)
  defp peer_ip(_), do: "127.0.0.1"

  @doc false
  def to_httpd_response(%BitArena.Conn{} = conn) do
    {status, headers, wire_body} = BitArena.Conn.response(conn)

    headers =
      for {k, v} <- headers do
        {String.to_charlist(k), String.to_charlist(v)}
      end

    [{:response, {:response, [{:code, status} | headers], wire_body}}]
  end

  defmodule Mod do
    @moduledoc false

    def unquote(:do)(mod_data) do
      try do
        conn =
          mod_data
          |> BitArena.HttpServer.conn_from_mod()
          |> BitArena.Router.dispatch()

        {:break, BitArena.HttpServer.to_httpd_response(conn)}
      rescue
        e ->
          require Logger
          Logger.error("[HttpServer] request failed: #{Exception.message(e)}")
          {:break, [{:response, {:response, [code: 500, content_type: ~c"text/plain", content_length: ~c"5"], "crash"}}]}
      end
    end
  end
end
