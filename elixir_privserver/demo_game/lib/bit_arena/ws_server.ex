defmodule BitArena.WsServer do
  @moduledoc """
  Dependency-free game WebSocket listener on `:gen_tcp` (replaces
  `WebSockAdapter` + `Plug.Cowboy` upgrade).

  Wire protocol is unchanged (`PROTOCOL.md`): one JSON object per text
  frame (`{"t": "input", "dir": [...]}` in, `%{type: "state" | ...}`
  snapshots out, `{"t": "ping"}` → pong). The entitlement token arrives
  as the `?token=` query param of the handshake target; game logic
  lives in `BitArena.PlayerConn`.
  """

  use GenServer
  require Logger

  @ws_guid "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
  @max_frame_bytes 1 * 1024 * 1024

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts)
  end

  @impl true
  def init(opts) do
    port = Keyword.get(opts, :port, BitArena.config(:ws_port, 4001))
    ip = Keyword.get(opts, :ip, {127, 0, 0, 1})

    case :gen_tcp.listen(port, [:binary, packet: :raw, active: false, reuseaddr: true, ip: ip]) do
      {:ok, listen} ->
        Logger.info("[WsServer] game socket on #{:inet.ntoa(ip)}:#{port}")
        send(self(), :accept)
        {:ok, %{listen: listen}}

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

      {:error, :timeout} ->
        :ok

      {:error, reason} ->
        Logger.warning("[WsServer] accept failed: #{inspect(reason)}")
    end

    send(self(), :accept)
    {:noreply, state}
  end

  # ── Connection ──

  defp serve(sock) do
    case handshake(sock, "") do
      {:ok, token} ->
        try do
          player = BitArena.PlayerConn.init(token)
          frame_loop(sock, "", nil, player)
        rescue
          e ->
            Logger.warning("[WsServer] join failed: #{Exception.message(e)}")
            :gen_tcp.close(sock)
        end

      {:error, _} ->
        :gen_tcp.close(sock)
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
    [request_line | header_lines] = String.split(head, "\r\n")

    headers =
      header_lines
      |> Enum.map(fn line ->
        case String.split(line, ":", parts: 2) do
          [k, v] -> {String.downcase(String.trim(k)), String.trim(v)}
          _ -> {"", ""}
        end
      end)
      |> Map.new()

    with [_method, target, _version] <- String.split(request_line, " ", parts: 3),
         {_path, _qs, query} <- BitArena.Conn.split_path(target),
         "websocket" <- String.downcase(Map.get(headers, "upgrade", "")),
         key when is_binary(key) and key != "" <- Map.get(headers, "sec-websocket-key") do
      accept = :crypto.hash(:sha, key <> @ws_guid) |> Base.encode64()

      resp =
        "HTTP/1.1 101 Switching Protocols\r\n" <>
          "Upgrade: websocket\r\n" <>
          "Connection: Upgrade\r\n" <>
          "Sec-WebSocket-Accept: #{accept}\r\n\r\n"

      :ok = :gen_tcp.send(sock, resp)
      {:ok, Map.get(query, "token")}
    else
      _ -> {:error, :bad_handshake}
    end
  end

  defp frame_loop(sock, buf, frag, player) do
    :inet.setopts(sock, active: :once)

    receive do
      {:tcp, ^sock, data} ->
        case consume_frames(sock, buf <> data, frag, player) do
          {:ok, rest, frag2, player2} -> frame_loop(sock, rest, frag2, player2)
          {:closed, _} -> :gen_tcp.close(sock)
        end

      {:push, payload} ->
        send_frame(sock, 0x1, BitArena.PlayerConn.render_push(payload))
        frame_loop(sock, buf, frag, player)

      {:tcp_closed, ^sock} ->
        :ok

      {:tcp_error, ^sock, _} ->
        :gen_tcp.close(sock)
    after
      120_000 -> :gen_tcp.close(sock)
    end
  end

  defp consume_frames(sock, buf, frag, player) do
    case parse_frame(buf) do
      {:ok, frame, rest} ->
        case handle_frame(sock, frame, frag, player) do
          {:ok, frag2, player2} -> consume_frames(sock, rest, frag2, player2)
          {:closed, _} = closed -> closed
        end

      :need_more ->
        {:ok, buf, frag, player}
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

  defp handle_frame(sock, %{opcode: 0x8}, _frag, player) do
    send_frame(sock, 0x8, "")
    {:closed, player}
  end

  defp handle_frame(sock, %{opcode: 0x9, payload: payload}, frag, player) do
    send_frame(sock, 0xA, payload)
    {:ok, frag, player}
  end

  defp handle_frame(_sock, %{opcode: 0xA}, frag, player), do: {:ok, frag, player}

  defp handle_frame(sock, %{opcode: opcode, fin: fin, payload: payload}, frag, player)
       when opcode in [0x0, 0x1, 0x2] do
    cond do
      byte_size(payload) > @max_frame_bytes ->
        {:closed, player}

      opcode in [0x1, 0x2] and fin ->
        player2 = dispatch_text(sock, payload, player)
        {:ok, nil, player2}

      opcode in [0x1, 0x2] ->
        {:ok, payload, player}

      opcode == 0x0 and is_nil(frag) ->
        {:ok, nil, player}

      opcode == 0x0 and fin ->
        player2 = dispatch_text(sock, frag <> payload, player)
        {:ok, nil, player2}

      opcode == 0x0 ->
        {:ok, frag <> payload, player}
    end
  end

  defp handle_frame(_sock, _frame, frag, player), do: {:ok, frag, player}

  defp dispatch_text(sock, payload, player) do
    case BitArena.PlayerConn.handle_text(payload, player) do
      {:push, reply, player2} ->
        send_frame(sock, 0x1, reply)
        player2

      {:ok, player2} ->
        player2
    end
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
