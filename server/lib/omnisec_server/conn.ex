defmodule OmnisecServer.Conn do
  @moduledoc """
  Minimal dependency-free replacement for the `Plug.Conn` surface used
  by this codebase (plus the `json/2` helper from `Phoenix.Controller`).

  A `%Conn{}` is built by `OmnisecServer.HttpServer` from the `:inets`
  `#mod{}` record and threaded through `AllowlistPlug`, `AuthPlug`,
  `Router` and the controllers. Unit tests can build one directly with
  `new/1` — no HTTP server required.
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
          request_id: String.t() | nil,
          status: pos_integer(),
          resp_headers: [{String.t(), String.t()}],
          resp_body: iodata(),
          halted: boolean(),
          assigns: map()
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
            request_id: nil,
            status: 200,
            resp_headers: [{"content-type", "application/json"}],
            resp_body: "",
            halted: false,
            assigns: %{}

  @doc "Builds a `%Conn{}` from keyword opts (used by the HTTP adapter and tests)."
  @spec new(keyword()) :: t()
  def new(opts \\ []) do
    conn = struct!(__MODULE__, opts)
    %{conn | headers: Enum.map(conn.headers, fn {k, v} -> {String.downcase(k), v} end)}
  end

  @doc "Returns all values of request header `name` (case-insensitive), like `Plug.Conn.get_req_header/2`."
  @spec get_req_header(t(), String.t()) :: [String.t()]
  def get_req_header(%__MODULE__{headers: headers}, name) do
    down = String.downcase(name)

    for {k, v} <- headers, k == down, do: v
  end

  @doc "Reads a single request header value (first match) or `default`."
  @spec get_header(t(), String.t(), String.t() | nil) :: String.t() | nil
  def get_header(conn, name, default \\ nil) do
    case get_req_header(conn, name) do
      [v | _] -> v
      [] -> default
    end
  end

  @doc "Assigns a value (e.g. `:is_admin`), like `Phoenix.Socket.assign/3`."
  @spec assign(t(), atom(), term()) :: t()
  def assign(%__MODULE__{assigns: assigns} = conn, key, value) do
    %{conn | assigns: Map.put(assigns, key, value)}
  end

  @doc "Sets the response status."
  @spec put_status(t(), pos_integer()) :: t()
  def put_status(%__MODULE__{} = conn, status) when is_integer(status) do
    %{conn | status: status}
  end

  @doc "Sets a response header (replaces existing entries with the same name)."
  @spec put_resp_header(t(), String.t(), String.t()) :: t()
  def put_resp_header(%__MODULE__{resp_headers: headers} = conn, name, value) do
    down = String.downcase(name)
    rest = Enum.reject(headers, fn {k, _} -> k == down end)
    %{conn | resp_headers: rest ++ [{down, value}]}
  end

  @doc "Sets the response content type."
  @spec put_resp_content_type(t(), String.t()) :: t()
  def put_resp_content_type(conn, content_type) do
    put_resp_header(conn, "content-type", content_type)
  end

  @doc "Sends a response with `status` and `body` (marks the conn as sent)."
  @spec send_resp(t(), pos_integer(), iodata()) :: t()
  def send_resp(%__MODULE__{} = conn, status, body) do
    %{conn | status: status, resp_body: body}
  end

  @doc "Halts the pipeline — no further plugs / routes run."
  @spec halt(t()) :: t()
  def halt(%__MODULE__{} = conn), do: %{conn | halted: true}

  @doc "True when the conn was halted."
  @spec halted?(t()) :: boolean()
  def halted?(%__MODULE__{halted: halted}), do: halted

  @doc """
  Sends `term` as a JSON response using `OmnisecServer.JSON`
  (replaces `Phoenix.Controller.json/2`). Uses `conn.status`.
  """
  @spec json(t(), term()) :: t()
  def json(%__MODULE__{} = conn, term) do
    body = OmnisecServer.JSON.encode!(term)

    %{conn | resp_body: body}
    |> put_resp_content_type("application/json")
  end

  @doc "Sends a `%{ok: false, error: ...}` JSON error with `status` and halts."
  @spec send_error(t(), pos_integer(), String.t()) :: t()
  def send_error(%__MODULE__{} = conn, status, reason) do
    conn
    |> put_status(status)
    |> json(%{ok: false, error: to_string(reason)})
    |> halt()
  end

  @doc """
  Parses the request body according to its content type into
  `body_params` and merges them over `query_params` into `params`
  (mirrors `Plug.Conn` + `Plug.Parsers` for the cases we serve:
  JSON, urlencoded, everything else stays raw in `body`).
  """
  @spec parse_body(t()) :: t()
  def parse_body(%__MODULE__{body: body} = conn) do
    content_type = conn |> get_header("content-type", "") |> strip_params()

    body_params =
      cond do
        body == "" or body == nil ->
          %{}

        content_type == "application/json" ->
          case OmnisecServer.JSON.decode(body) do
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

  @doc "Splits `path?query` into `{path, query_string, query_params}`."
  @spec split_path(String.t()) :: {String.t(), String.t(), map()}
  def split_path(request_target) do
    case String.split(request_target, "?", parts: 2) do
      [path] -> {path, "", %{}}
      [path, qs] -> {path, qs, URI.decode_query(qs)}
    end
  end

  defp strip_params(header_value) do
    header_value |> String.split(";") |> List.first("") |> String.trim() |> String.downcase()
  end
end
