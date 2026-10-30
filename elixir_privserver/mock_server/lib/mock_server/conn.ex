defmodule MockServer.Conn do
  @moduledoc """
  Minimal dependency-free HTTP connection struct (replaces the
  `Plug.Conn` surface this application used).
  """

  @type t :: %__MODULE__{
          method: String.t(),
          path: String.t(),
          query_string: String.t(),
          query_params: map(),
          headers: [{String.t(), String.t()}],
          body: binary(),
          body_params: map(),
          params: map(),
          remote_ip: String.t(),
          status: pos_integer(),
          resp_headers: [{String.t(), String.t()}],
          resp_body: iodata()
        }

  defstruct method: "GET",
            path: "/",
            query_string: "",
            query_params: %{},
            headers: [],
            body: "",
            body_params: %{},
            params: %{},
            remote_ip: "127.0.0.1",
            status: 200,
            resp_headers: [{"content-type", "application/json"}],
            resp_body: ""

  @spec new(keyword()) :: t()
  def new(opts \\ []) do
    conn = struct!(__MODULE__, opts)
    %{conn | headers: Enum.map(conn.headers, fn {k, v} -> {String.downcase(k), v} end)}
  end

  @spec get_req_header(t(), String.t()) :: [String.t()]
  def get_req_header(%__MODULE__{headers: headers}, name) do
    down = String.downcase(name)
    for {k, v} <- headers, k == down, do: v
  end

  @spec put_resp_header(t(), String.t(), String.t()) :: t()
  def put_resp_header(%__MODULE__{resp_headers: headers} = conn, name, value) do
    down = String.downcase(name)
    %{conn | resp_headers: Enum.reject(headers, fn {k, _} -> k == down end) ++ [{down, value}]}
  end

  @spec put_resp_content_type(t(), String.t()) :: t()
  def put_resp_content_type(conn, content_type), do: put_resp_header(conn, "content-type", content_type)

  @spec send_resp(t(), pos_integer(), iodata()) :: t()
  def send_resp(%__MODULE__{} = conn, status, body), do: %{conn | status: status, resp_body: body}

  @spec json(t(), pos_integer(), term()) :: t()
  def json(%__MODULE__{} = conn, status, term) do
    %{conn | status: status, resp_body: MockServer.JSON.encode!(term)}
    |> put_resp_content_type("application/json")
  end

  @doc """
  Renders the conn into `{status, headers, wire_body}` shared by the
  `:inets` and `:gen_tcp` servers. HEAD sends headers only.
  """
  @spec response(t()) :: {pos_integer(), [{String.t(), String.t()}], binary()}
  def response(%__MODULE__{} = conn) do
    body = IO.iodata_to_binary(conn.resp_body)
    wire = if conn.method == "HEAD", do: "", else: body
    {conn.status, conn.resp_headers ++ [{"content-length", Integer.to_string(byte_size(body))}], wire}
  end

  @doc "Parses JSON/urlencoded bodies into `body_params` (mirrors `Plug.Parsers` for our cases)."
  @spec parse_body(t()) :: t()
  def parse_body(%__MODULE__{body: body} = conn) do
    content_type =
      case get_req_header(conn, "content-type") do
        [ct | _] -> ct |> String.split(";") |> hd() |> String.trim() |> String.downcase()
        [] -> ""
      end

    body_params =
      cond do
        body == "" or body == nil ->
          %{}

        content_type == "application/json" ->
          case MockServer.JSON.decode(body) do
            {:ok, map} when is_map(map) -> map
            _ -> %{}
          end

        content_type == "application/x-www-form-urlencoded" ->
          URI.decode_query(body)

        true ->
          %{}
      end

    %{conn | body_params: body_params, params: Map.merge(conn.query_params, body_params)}
  end

  @spec split_path(String.t()) :: {String.t(), String.t(), map()}
  def split_path(request_target) do
    case String.split(request_target, "?", parts: 2) do
      [path] -> {path, "", %{}}
      [path, qs] -> {path, qs, URI.decode_query(qs)}
    end
  end
end
