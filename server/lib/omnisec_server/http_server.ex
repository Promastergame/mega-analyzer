defmodule OmnisecServer.HttpServer do
  @moduledoc """
  Dependency-free HTTP server on OTP `:inets httpd` (replaces
  `Phoenix.Endpoint` + `Plug.Cowboy`).

  A single custom httpd module (`do/1`) converts every request into an
  `OmnisecServer.Conn`, serves `priv/static` files for the old
  `Plug.Static` paths, and dispatches the rest through
  `OmnisecServer.Router`. Responses use the `{response, {response,
  headers, body}}` httpd convention with charlist header values.

  Started only when `:enable_endpoint` is true (see `Application`).
  """

  use GenServer
  require Logger

  @max_body_bytes 50 * 1024 * 1024
  @static_files ~w(css js images favicon.ico robots.txt index.html)

  # ── Supervision ──

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(opts) do
    port = Keyword.get(opts, :port, 4000)
    ip = Keyword.get(opts, :ip, {127, 0, 0, 1})

    server_root = Path.join(System.tmp_dir!(), "omnisec_httpd") |> String.to_charlist()
    File.mkdir_p!(to_string(server_root))

    httpd_opts = [
      port: port,
      bind_address: ip,
      server_name: ~c"omnisec",
      server_root: server_root,
      document_root: server_root,
      max_body_size: @max_body_bytes,
      modules: [__MODULE__.Mod]
    ]

    case :inets.start(:httpd, httpd_opts) do
      {:ok, pid} ->
        Logger.info("[HttpServer] listening on #{:inet.ntoa(ip)}:#{port}")
        {:ok, %{httpd: pid, port: port}}

      {:error, {:already_started, pid}} ->
        {:ok, %{httpd: pid, port: port}}

      {:error, reason} ->
        {:stop, reason}
    end
  end

  @impl true
  def terminate(_reason, %{httpd: pid}) do
    :inets.stop(:httpd, pid)
    :ok
  end

  @doc "Builds a `%Conn{}` from an httpd `#mod{}` record (also useful in tests)."
  @spec conn_from_mod(tuple()) :: OmnisecServer.Conn.t()
  def conn_from_mod(mod_data) do
    {:mod, init_data, _data, _socket_type, _socket, _config_db, method, _abs_uri, uri, _version,
     _line, headers, entity_body, _connection} = mod_data

    {path, query_string, query_params} =
      uri |> to_string() |> OmnisecServer.Conn.split_path()

    %OmnisecServer.Conn{
      method: to_string(method) |> String.upcase(),
      path: path,
      query_string: query_string,
      query_params: query_params,
      headers: Enum.map(headers, fn {k, v} -> {to_string(k) |> String.downcase(), to_string(v)} end),
      body: entity_to_binary(entity_body),
      remote_ip: peer_ip(init_data),
      request_id: Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)
    }
    |> OmnisecServer.Conn.parse_body()
  end

  defp entity_to_binary(bin) when is_binary(bin), do: bin
  defp entity_to_binary(list) when is_list(list), do: IO.iodata_to_binary(list)
  defp entity_to_binary(_), do: ""

  defp peer_ip({:init_data, {_port, ip}, _sockname, _resolve}) when is_list(ip), do: to_string(ip)
  defp peer_ip({:init_data, {{a, b, c, d}, _port}, _sockname, _resolve}), do: "#{a}.#{b}.#{c}.#{d}"
  defp peer_ip(_), do: "127.0.0.1"

  # ── httpd custom module ──

  defmodule Mod do
    @moduledoc false

    # `do` is a keyword — define via unquote so `:inets` can
    # `apply(__MODULE__, :do, [mod_data])`.
    def unquote(:do)(mod_data) do
      try do
        conn =
          mod_data
          |> OmnisecServer.HttpServer.conn_from_mod()
          |> OmnisecServer.HttpServer.maybe_serve_static()
          |> OmnisecServer.HttpServer.dispatch_unless_sent()

        {:break, OmnisecServer.HttpServer.to_httpd_response(conn)}
      rescue
        e ->
          require Logger

          Logger.error("[HttpServer] request failed: #{Exception.message(e)}")

          conn = %OmnisecServer.Conn{status: 500, resp_body: ~s({"ok":false,"error":"internal error"})}
          {:break, OmnisecServer.HttpServer.to_httpd_response(conn)}
      end
    end
  end

  @doc false
  def maybe_serve_static(%OmnisecServer.Conn{method: "GET", path: "/" <> rest} = conn) do
    first = rest |> String.split("/", parts: 2) |> hd()

    if first in @static_files do
      priv = :code.priv_dir(:omnisec_server) |> to_string()
      file = Path.join([priv, "static", rest])

      if safe_static_path?(priv, file) and File.regular?(file) do
        %{conn | status: 200, resp_body: File.read!(file)}
        |> OmnisecServer.Conn.put_resp_content_type(mime_type(file))
        |> OmnisecServer.Conn.halt()
      else
        conn
      end
    else
      conn
    end
  end

  def maybe_serve_static(%OmnisecServer.Conn{} = conn), do: conn

  defp safe_static_path?(priv, file) do
    static = Path.join(priv, "static")
    expanded = Path.expand(file)
    expanded == static or String.starts_with?(expanded, static <> "/")
  end

  defp mime_type(path) do
    case Path.extname(path) |> String.downcase() do
      ".html" -> "text/html"
      ".css" -> "text/css"
      ".js" -> "application/javascript"
      ".json" -> "application/json"
      ".ico" -> "image/x-icon"
      ".png" -> "image/png"
      ".txt" -> "text/plain"
      _ -> "application/octet-stream"
    end
  end

  @doc false
  def dispatch_unless_sent(%OmnisecServer.Conn{halted: true} = conn), do: conn

  # HEAD routes like GET but sends no body (was `Plug.Head`).
  def dispatch_unless_sent(%OmnisecServer.Conn{method: "HEAD"} = conn) do
    %{OmnisecServer.Router.dispatch(%{conn | method: "GET"}) | method: "HEAD"}
  end

  def dispatch_unless_sent(%OmnisecServer.Conn{} = conn), do: OmnisecServer.Router.dispatch(conn)

  @doc false
  def to_httpd_response(%OmnisecServer.Conn{} = conn) do
    body = IO.iodata_to_binary(conn.resp_body)
    # HEAD behaves like GET without a body (was `Plug.Head`).
    wire_body = if conn.method == "HEAD", do: "", else: body

    headers =
      for {k, v} <- conn.resp_headers do
        {String.to_charlist(k), String.to_charlist(v)}
      end

    headers = [
      {:code, conn.status},
      {:content_length, to_charlist(byte_size(body))} | headers
    ]

    [{:response, {:response, headers, wire_body}}]
  end
end
