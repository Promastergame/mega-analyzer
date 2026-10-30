defmodule OmnisecServer.WsServer do
  @moduledoc """
  Plain-JSON WebSocket server on `:gen_tcp` (replaces `Phoenix.Socket`
  `UserSocket` + `Phoenix.Channel` `DebugChannel`).

  ## Protocol

  Each text frame is one JSON object:

      {"op": "step", "authorization": "Bearer SECRET",
       "params": {"session_id": 5}}

  The reply is the controller JSON envelope:

      {"ok": true, "result": {...}}

  `authorization` carries the same value as the HTTP `Authorization`
  header, so private-token auth, admin checks and `DebugSessions`
  ownership behave exactly like the REST API — every op is dispatched
  through `DebugController`, which stays the single source of truth.
  Available ops mirror the controller actions: `start`, `stop`,
  `step`, `continue`, `breakpoint`, `remove_bp`, `breakpoints`,
  `add_watch`, `remove_watch`, `watchpoints`, `registers`,
  `disassemble`, `memory`, `patch`, `set_register`, `set_flag`,
  `flavor`, `scan`, `trace_enable`, `reverse_step`,
  `reverse_continue`, `trace_log`, `trace_stats`, `cfg`.

  Started only when `:enable_endpoint` is true (see `Application`).
  Listens on `:ws_port` (default: HTTP port + 1).
  """

  use GenServer
  require Logger

  @ws_guid "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
  @max_frame_bytes 10 * 1024 * 1024

  # ── Supervision ──

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(opts) do
    port = Keyword.fetch!(opts, :port)
    ip = Keyword.get(opts, :ip, {127, 0, 0, 1})

    case :gen_tcp.listen(port, [:binary, packet: :raw, active: false, reuseaddr: true, ip: ip]) do
      {:ok, listen} ->
        {:ok, actual} = :inet.port(listen)
        Logger.info("[WsServer] listening on #{:inet.ntoa(ip)}:#{actual}")
        send(self(), :accept)
        {:ok, %{listen: listen, port: actual}}

      {:error, reason} ->
        {:stop, reason}
    end
  end

  @impl true
  def handle_info(:accept, %{listen: listen} = state) do
    case :gen_tcp.accept(listen, 500) do
      {:ok, sock} ->
        pid = spawn_link(fn -> serve(sock) end)
        :gen_tcp.controlling_process(sock, pid)
        send(pid, :handshake)

      {:error, :timeout} ->
        :ok

      {:error, reason} ->
        Logger.warning("[WsServer] accept failed: #{inspect(reason)}")
    end

    send(self(), :accept)
    {:noreply, state}
  end

  @doc "Actual bound port (useful when started with port 0 in tests)."
  def port, do: GenServer.call(__MODULE__, :port)

  @impl true
  def handle_call(:port, _from, %{port: port} = state), do: {:reply, port, state}

  # ── Connection ──

  defp serve(sock) do
    receive do
      :handshake -> :ok
    after
      5_000 -> :ok
    end

    case handshake(sock, "") do
      :ok -> frame_loop(sock, "", nil)
      {:error, _} -> :gen_tcp.close(sock)
    end
  end

  defp handshake(sock, acc) do
    case :gen_tcp.recv(sock, 0, 5_000) do
      {:ok, data} ->
        acc = acc <> data

        case :binary.split(acc, "\r\n\r\n") do
          [head, _rest] -> reply_handshake(sock, head)
          [_] -> handshake(sock, acc)
        end

      {:error, _} ->
        {:error, :closed}
    end
  end

  defp reply_handshake(sock, head) do
    headers =
      head
      |> String.split("\r\n")
      |> Enum.drop(1)
      |> Enum.map(fn line ->
        case String.split(line, ":", parts: 2) do
          [k, v] -> {String.downcase(String.trim(k)), String.trim(v)}
          _ -> {"", ""}
        end
      end)
      |> Map.new()

    with "websocket" <- String.downcase(Map.get(headers, "upgrade", "")),
         key when is_binary(key) and key != "" <- Map.get(headers, "sec-websocket-key") do
      accept = :crypto.hash(:sha, key <> @ws_guid) |> Base.encode64()

      resp =
        "HTTP/1.1 101 Switching Protocols\r\n" <>
          "Upgrade: websocket\r\n" <>
          "Connection: Upgrade\r\n" <>
          "Sec-WebSocket-Accept: #{accept}\r\n\r\n"

      :gen_tcp.send(sock, resp)
    else
      _ -> {:error, :bad_handshake}
    end
  end

  defp frame_loop(sock, buf, frag) do
    :inet.setopts(sock, active: :once)

    receive do
      {:tcp, ^sock, data} ->
        case consume_frames(sock, buf <> data, frag) do
          {:ok, rest, frag2} -> frame_loop(sock, rest, frag2)
          {:closed, _} -> :gen_tcp.close(sock)
        end

      {:tcp_closed, ^sock} ->
        :ok

      {:tcp_error, ^sock, _} ->
        :gen_tcp.close(sock)
    after
      120_000 -> :gen_tcp.close(sock)
    end
  end

  defp consume_frames(sock, buf, frag) do
    case parse_frame(buf) do
      {:ok, frame, rest} ->
        case handle_frame(sock, frame, frag) do
          {:ok, frag2} -> consume_frames(sock, rest, frag2)
          {:closed, _} = closed -> closed
        end

      :need_more ->
        {:ok, buf, frag}
    end
  end

  defp parse_frame(<<fin::1, _rsv::3, opcode::4, masked::1, len7::7, rest::binary>>) do
    with {:ok, len, rest} <- frame_length(len7, rest),
         {:ok, mask, rest} <- frame_mask(masked, rest),
         true <- byte_size(rest) >= len do
      {payload, rest2} = :erlang.split_binary(rest, len)
      {:ok, %{fin: fin == 1, opcode: opcode, payload: unmask(mask, payload)}, rest2}
    else
      _ -> :need_more
    end
  end

  defp parse_frame(_), do: :need_more

  defp frame_length(126, <<len::16, rest::binary>>), do: {:ok, len, rest}
  defp frame_length(127, <<len::64, rest::binary>>), do: {:ok, len, rest}
  defp frame_length(len, rest) when len < 126, do: {:ok, len, rest}
  defp frame_length(_, _), do: :error

  defp frame_mask(1, <<mask::binary-size(4), rest::binary>>), do: {:ok, mask, rest}
  defp frame_mask(0, rest), do: {:ok, nil, rest}
  defp frame_mask(_, _), do: :error

  defp unmask(nil, payload), do: payload

  defp unmask(<<m1, m2, m3, m4>>, payload) do
    payload
    |> :binary.bin_to_list()
    |> Enum.with_index()
    |> Enum.map(fn {b, i} ->
      m =
        case rem(i, 4) do
          0 -> m1
          1 -> m2
          2 -> m3
          3 -> m4
        end

      Bitwise.bxor(b, m)
    end)
    |> :binary.list_to_bin()
  end

  # ── Frame dispatch ──

  defp handle_frame(sock, %{opcode: 0x8}, _frag) do
    send_frame(sock, 0x8, "")
    {:closed, :client_close}
  end

  defp handle_frame(sock, %{opcode: 0x9, payload: payload}, frag) do
    send_frame(sock, 0xA, payload)
    {:ok, frag}
  end

  defp handle_frame(_sock, %{opcode: 0xA}, frag), do: {:ok, frag}

  defp handle_frame(sock, %{opcode: opcode, fin: fin, payload: payload}, frag)
       when opcode in [0x0, 0x1, 0x2] do
    cond do
      byte_size(payload) > @max_frame_bytes ->
        send_text(sock, %{"ok" => false, "error" => "frame too large"})
        {:ok, nil}

      opcode in [0x1, 0x2] and not is_nil(frag) ->
        # New message while a fragmented one is in flight — drop the old.
        handle_frame(sock, %{opcode: opcode, fin: fin, payload: payload}, nil)

      opcode in [0x1, 0x2] and fin ->
        dispatch_text(sock, payload)
        {:ok, nil}

      opcode in [0x1, 0x2] ->
        {:ok, payload}

      opcode == 0x0 and is_nil(frag) ->
        {:ok, nil}

      opcode == 0x0 and fin ->
        dispatch_text(sock, frag <> payload)
        {:ok, nil}

      opcode == 0x0 ->
        {:ok, frag <> payload}
    end
  end

  defp handle_frame(_sock, _frame, frag), do: {:ok, frag}

  defp dispatch_text(sock, payload) do
    case OmnisecServer.JSON.decode(payload) do
      {:ok, %{"op" => op} = msg} when is_binary(op) ->
        reply =
          try do
            handle_op(op, msg)
          rescue
            e -> %{"ok" => false, "error" => "op failed: #{Exception.message(e)}"}
          end

        send_text(sock, reply)

      {:ok, _} ->
        send_text(sock, %{"ok" => false, "error" => "missing 'op'"})

      {:error, _} ->
        send_text(sock, %{"ok" => false, "error" => "invalid JSON"})
    end

    {:ok, nil}
  end

  # ── Op dispatch (auth + ownership mirror the REST API) ──

  @ops %{
    "start" => :start,
    "stop" => :stop,
    "step" => :step,
    "continue" => :continue,
    "breakpoint" => :breakpoint,
    "remove_bp" => :remove_bp,
    "breakpoints" => :breakpoints,
    "add_watch" => :add_watch,
    "remove_watch" => :remove_watch,
    "watchpoints" => :watchpoints,
    "registers" => :registers,
    "disassemble" => :disassemble,
    "memory" => :memory,
    "patch" => :patch_memory,
    "set_register" => :set_register,
    "set_flag" => :set_flag,
    "flavor" => :set_flavor,
    "scan" => :scan,
    "trace_enable" => :trace_enable,
    "reverse_step" => :reverse_step,
    "reverse_continue" => :reverse_continue,
    "trace_log" => :trace_log,
    "trace_stats" => :trace_stats,
    "cfg" => :cfg
  }

  defp handle_op(op, %{"authorization" => auth} = msg) when is_binary(auth) do
    case Map.fetch(@ops, op) do
      {:ok, action} ->
        params = Map.get(msg, "params", %{})
        params = if is_map(params), do: params, else: %{}

        conn = %OmnisecServer.Conn{
          method: "WS",
          path: "/ws",
          headers: [{"authorization", auth}],
          params: params,
          body_params: params
        }

        conn = private_check(conn, auth)

        conn =
          if OmnisecServer.Conn.halted?(conn) do
            conn
          else
            apply(OmnisecServer.DebugController, action, [conn, params])
          end

        case OmnisecServer.JSON.decode(conn.resp_body) do
          {:ok, decoded} -> stringify(decoded)
          _ -> %{"ok" => false, "error" => "invalid controller response"}
        end

      :error ->
        %{"ok" => false, "error" => "unknown op: #{op}"}
    end
  end

  defp handle_op(_op, _msg), do: %{"ok" => false, "error" => "missing 'authorization'"}

  # Mirrors `AuthPlug` (private mode) for sockets. In open mode everything
  # passes; otherwise the authorization value must carry the private token.
  defp private_check(conn, auth) do
    token = Application.get_env(:omnisec_server, :private_token)

    cond do
      is_nil(token) or token == "" ->
        conn

      auth == token or auth == "Bearer " <> token ->
        conn

      true ->
        OmnisecServer.Conn.send_error(conn, 401, "invalid token")
    end
  end

  # Controller envelopes use atom keys; WS clients get string keys.
  defp stringify(map) when is_map(map) do
    Map.new(map, fn {k, v} -> {to_string(k), stringify(v)} end)
  end

  defp stringify(list) when is_list(list), do: Enum.map(list, &stringify/1)
  defp stringify(other), do: other

  # ── Wire out ──

  defp send_text(sock, term) do
    send_frame(sock, 0x1, OmnisecServer.JSON.encode!(term))
  end

  defp send_frame(sock, opcode, payload) do
    len = byte_size(payload)

    header =
      cond do
        len < 126 -> <<1::1, 0::3, opcode::4, 0::1, len::7>>
        len < 65_536 -> <<1::1, 0::3, opcode::4, 0::1, 126::7, len::16>>
        true -> <<1::1, 0::3, opcode::4, 0::1, 127::7, len::64>>
      end

    :gen_tcp.send(sock, [header, payload])
  end
end
