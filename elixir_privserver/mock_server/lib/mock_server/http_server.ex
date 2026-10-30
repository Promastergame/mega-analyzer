defmodule MockServer.HttpServer do
  @moduledoc """
  Dependency-free HTTP listener on OTP `:inets httpd` (replaces
  `Plug.Cowboy`).

  One child per port; the router module is chosen by the local port
  (`persistent_term` mapping set at boot), so the fake backend and the
  admin dashboard can share this module on different listeners.
  """

  use GenServer
  require Logger

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts)
  end

  @impl true
  def init(opts) do
    port = Keyword.fetch!(opts, :port)
    router = Keyword.fetch!(opts, :router)
    ip = Keyword.get(opts, :ip, {127, 0, 0, 1})

    server_root = Path.join(System.tmp_dir!(), "mock_httpd_#{port}") |> String.to_charlist()
    File.mkdir_p!(to_string(server_root))

    httpd_opts = [
      port: port,
      bind_address: ip,
      server_name: ~c"mock",
      server_root: server_root,
      document_root: server_root,
      modules: [__MODULE__.Mod]
    ]

    case :inets.start(:httpd, httpd_opts) do
      {:ok, pid} ->
        :persistent_term.put({__MODULE__, port}, router)
        Logger.info("[HttpServer] #{inspect(router)} on #{:inet.ntoa(ip)}:#{port}")
        {:ok, %{httpd: pid, port: port}}

      {:error, {:already_started, pid}} ->
        :persistent_term.put({__MODULE__, port}, router)
        {:ok, %{httpd: pid, port: port}}

      {:error, reason} ->
        {:stop, reason}
    end
  end

  @impl true
  def terminate(_reason, %{httpd: pid, port: port}) do
    :persistent_term.erase({__MODULE__, port})
    :inets.stop(:httpd, pid)
    :ok
  end

  @doc false
  def router_for(port), do: :persistent_term.get({__MODULE__, port}, MockServer.Router)

  @doc false
  def conn_from_mod(mod_data) do
    {:mod, init_data, _data, _st, _sock, _db, method, _abs, uri, _ver, _line, headers, entity_body, _conn} =
      mod_data

    {path, query_string, query_params} =
      uri |> to_string() |> MockServer.Conn.split_path()

    MockServer.Conn.new(
      method: to_string(method) |> String.upcase(),
      path: path,
      query_string: query_string,
      query_params: query_params,
      params: query_params,
      headers: Enum.map(headers, fn {k, v} -> {to_string(k), to_string(v)} end),
      body: entity_to_binary(entity_body),
      remote_ip: peer_ip(init_data)
    )
    |> MockServer.Conn.parse_body()
  end

  defp entity_to_binary(bin) when is_binary(bin), do: bin
  defp entity_to_binary(list) when is_list(list), do: IO.iodata_to_binary(list)
  defp entity_to_binary(_), do: ""

  defp peer_ip({:init_data, {_port, ip}, _sockname, _resolve}) when is_list(ip), do: to_string(ip)
  defp peer_ip(_), do: "127.0.0.1"

  @doc false
  def to_httpd_response(%MockServer.Conn{} = conn) do
    {status, headers, wire_body} = MockServer.Conn.response(conn)

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
        {:mod, _init, _data, _st, sock, _db, _m, _abs, _uri, _ver, _line, _h, _body, _conn} = mod_data
        {:ok, {_ip, port}} = :inet.sockname(sock)
        router = MockServer.HttpServer.router_for(port)

        conn =
          mod_data
          |> MockServer.HttpServer.conn_from_mod()
          |> router.dispatch()

        {:break, MockServer.HttpServer.to_httpd_response(conn)}
      rescue
        e ->
          require Logger
          Logger.error("[HttpServer] request failed: #{Exception.message(e)}")
          {:break, [{:response, {:response, [code: 500, content_type: ~c"text/plain", content_length: ~c"5"], "crash"}}]}
      end
    end
  end
end
