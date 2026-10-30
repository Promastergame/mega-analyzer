defmodule MockServer.TcpServer do
  @moduledoc """
  Minimal dependency-free HTTP/1.1 server on `:gen_tcp` for the fake
  backend (replaces `Plug.Cowboy` on the mock port).

  Why not `:inets` here: `httpd_request:validate/3` in OTP only knows
  `HEAD | GET | POST | PATCH | TRACE | PUT | DELETE` and answers
  `501 Not Implemented` to anything else — including the `OPTIONS`
  CORS preflight this backend contractually short-circuits (`Router`
  answers every method on every path). This server parses any method
  token itself.

  One request per connection (`Connection: close`), bodies by
  `Content-Length` or `Transfer-Encoding: chunked`, capped at
  `@max_body_bytes`.
  """

  use GenServer
  require Logger

  @max_header_bytes 64 * 1024
  @max_body_bytes 10 * 1024 * 1024

  @phrases %{
    200 => "OK",
    204 => "No Content",
    400 => "Bad Request",
    404 => "Not Found",
    413 => "Request Entity Too Large",
    500 => "Internal Server Error"
  }

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts)
  end

  @impl true
  def init(opts) do
    port = Keyword.fetch!(opts, :port)
    router = Keyword.get(opts, :router, MockServer.Router)
    ip = Keyword.get(opts, :ip, {127, 0, 0, 1})

    case :gen_tcp.listen(port, [:binary, packet: :raw, active: false, reuseaddr: true, ip: ip]) do
      {:ok, listen} ->
        Logger.info("[TcpServer] #{inspect(router)} on #{:inet.ntoa(ip)}:#{port}")
        send(self(), :accept)
        {:ok, %{listen: listen, router: router}}

      {:error, reason} ->
        {:stop, reason}
    end
  end

  @impl true
  def handle_info(:accept, %{listen: listen, router: router} = state) do
    case :gen_tcp.accept(listen, 500) do
      {:ok, sock} ->
        pid = spawn_link(fn -> serve(sock, router) end)
        :gen_tcp.controlling_process(sock, pid)

      {:error, :timeout} ->
        :ok

      {:error, reason} ->
        Logger.warning("[TcpServer] accept failed: #{inspect(reason)}")
    end

    send(self(), :accept)
    {:noreply, state}
  end

  # ── Connection (one request, then close) ──

  defp serve(sock, router) do
    case read_request(sock) do
      {:ok, conn} ->
        conn =
          try do
            router.dispatch(conn)
          rescue
            e ->
              Logger.error("[TcpServer] dispatch failed: #{Exception.message(e)}")
              MockServer.Conn.new(status: 500, resp_body: ~s({"error":"internal error"}))
          end

        :gen_tcp.send(sock, render(conn))

      {:error, :too_large} ->
        :gen_tcp.send(sock, render(MockServer.Conn.new(status: 413, resp_body: ~s({"error":"body too large"}))))

      {:error, _} ->
        :ok
    end

    :gen_tcp.close(sock)
  end

  defp render(conn) do
    {status, headers, body} = MockServer.Conn.response(conn)
    phrase = Map.get(@phrases, status, "OK")

    head =
      ["HTTP/1.1 ", Integer.to_string(status), " ", phrase, "\r\n"] ++
        Enum.map(headers, fn {k, v} -> [k, ": ", v, "\r\n"] end) ++
        ["Connection: close\r\n\r\n"]

    [head, body]
  end

  # ── Request parsing ──

  defp read_request(sock) do
    with {:ok, head, rest} <- read_head(sock, ""),
         {:ok, method, target, headers} <- parse_head(head),
         {:ok, body} <- read_body(sock, rest, headers),
         {:ok, ip} <- peer_ip(sock) do
      {path, qs, query} = MockServer.Conn.split_path(target)

      {:ok,
       MockServer.Conn.new(
         method: method,
         path: path,
         query_string: qs,
         query_params: query,
         params: query,
         headers: headers,
         body: body,
         remote_ip: ip
       )
       |> MockServer.Conn.parse_body()}
    end
  end

  defp read_head(sock, acc) do
    if byte_size(acc) > @max_header_bytes do
      {:error, :too_large}
    else
      case :gen_tcp.recv(sock, 0, 5_000) do
        {:ok, data} ->
          acc = acc <> data

          case :binary.split(acc, "\r\n\r\n") do
            [head, rest] -> {:ok, head, rest}
            [_] -> read_head(sock, acc)
          end

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  defp parse_head(head) do
    case String.split(head, "\r\n") do
      [request_line | header_lines] ->
        with [method, target, _version] <- String.split(request_line, " ", parts: 3),
             true <- method != "" and target != "" do
          headers =
            Enum.flat_map(header_lines, fn line ->
              case String.split(line, ":", parts: 2) do
                [k, v] -> [{String.downcase(String.trim(k)), String.trim(v)}]
                _ -> []
              end
            end)

          {:ok, String.upcase(method), target, headers}
        else
          _ -> {:error, :bad_request}
        end

      _ ->
        {:error, :bad_request}
    end
  end

  defp read_body(sock, rest, headers) do
    header_map = Map.new(headers)

    cond do
      Map.get(header_map, "transfer-encoding", "") |> String.downcase() |> String.contains?("chunked") ->
        read_chunked(sock, rest, "")

      true ->
        length =
          case Integer.parse(Map.get(header_map, "content-length", "0")) do
            {n, ""} when n >= 0 -> n
            _ -> 0
          end

        if length > @max_body_bytes do
          {:error, :too_large}
        else
          read_exact(sock, rest, length)
        end
    end
  end

  defp read_exact(_sock, rest, 0), do: {:ok, ""}
  defp read_exact(_sock, rest, n) when byte_size(rest) >= n, do: :erlang.split_binary(rest, n) |> then(fn {b, _} -> {:ok, b} end)

  defp read_exact(sock, rest, n) do
    case :gen_tcp.recv(sock, 0, 5_000) do
      {:ok, data} -> read_exact(sock, rest <> data, n)
      {:error, reason} -> {:error, reason}
    end
  end

  defp read_chunked(sock, buf, acc) do
    if byte_size(acc) > @max_body_bytes do
      {:error, :too_large}
    else
      with {:ok, line, rest} <- chunk_line(sock, buf),
           {size, _} <- Integer.parse(String.trim(line), 16) do
        if size == 0 do
          {:ok, acc}
        else
          case read_exact(sock, rest, size + 2) do
            {:ok, chunk_with_crlf} ->
              chunk = binary_part(chunk_with_crlf, 0, size)
              read_chunked(sock, "", acc <> chunk)

            {:error, reason} ->
              {:error, reason}
          end
        end
      else
        _ -> {:error, :bad_request}
      end
    end
  end

  defp chunk_line(sock, buf) do
    case :binary.split(buf, "\r\n") do
      [line, rest] ->
        {:ok, line, rest}

      [_] ->
        case :gen_tcp.recv(sock, 0, 5_000) do
          {:ok, data} -> chunk_line(sock, buf <> data)
          {:error, reason} -> {:error, reason}
        end
    end
  end

  defp peer_ip(sock) do
    case :inet.peername(sock) do
      {:ok, {{a, b, c, d}, _port}} -> {:ok, "#{a}.#{b}.#{c}.#{d}"}
      {:ok, {ip, _port}} -> {:ok, to_string(:inet.ntoa(ip))}
      {:error, reason} -> {:error, reason}
    end
  end
end
