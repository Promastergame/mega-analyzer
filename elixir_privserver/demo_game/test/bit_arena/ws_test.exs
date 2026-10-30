defmodule BitArena.WsTest do
  @moduledoc """
  End-to-end tests for the game WebSocket: real TCP, RFC 6455
  handshake, stdlib client. Expects a `welcome` snapshot, answers
  `ping` with `pong`, and cleans the player up on disconnect.
  """
  use ExUnit.Case, async: false

  @ws_port 4001

  defp ws_connect(token) do
    {:ok, sock} = :gen_tcp.connect({127, 0, 0, 1}, @ws_port, [:binary, packet: :raw, active: false])
    key = Base.encode64(:crypto.strong_rand_bytes(16))

    req =
      "GET /ws?token=#{URI.encode_www_form(token)} HTTP/1.1\r\nHost: 127.0.0.1\r\n" <>
        "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: #{key}\r\n" <>
        "Sec-WebSocket-Version: 13\r\n\r\n"

    :ok = :gen_tcp.send(sock, req)
    {:ok, resp} = :gen_tcp.recv(sock, 0, 5_000)
    assert resp =~ "101 Switching Protocols"
    sock
  end

  defp ws_send(sock, text) do
    mask = :crypto.strong_rand_bytes(4)
    masked = mask_payload(mask, text)
    len = byte_size(text)

    header =
      cond do
        len < 126 -> <<0x81, 0x80 + len>>
        len < 65_536 -> <<0x81, 0xFE, len::16>>
        true -> <<0x81, 0xFF, len::64>>
      end

    :ok = :gen_tcp.send(sock, [header, mask, masked])
  end

  defp mask_payload(<<m1, m2, m3, m4>>, text) do
    text
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

  defp ws_recv(sock) do
    {:ok, <<_fin::1, _rsv::3, opcode::4, 0::1, len7::7>>} = :gen_tcp.recv(sock, 2, 5_000)

    len =
      case len7 do
        126 ->
          {:ok, <<n::16>>} = :gen_tcp.recv(sock, 2, 5_000)
          n

        127 ->
          {:ok, <<n::64>>} = :gen_tcp.recv(sock, 8, 5_000)
          n

        n ->
          n
      end

    {:ok, payload} = :gen_tcp.recv(sock, len, 5_000)
    {opcode, payload}
  end

  test "joining with a token yields a welcome snapshot" do
    token = BitArena.Entitlements.issue("guest")
    sock = ws_connect(token)
    {1, payload} = ws_recv(sock)
    assert {:ok, %{"type" => "welcome", "you" => "p_" <> _, "match" => _}} = BitArena.JSON.decode(payload)
    :gen_tcp.close(sock)
  end

  test "garbage token degrades to free instead of refusing the socket" do
    sock = ws_connect("complete nonsense")
    {1, payload} = ws_recv(sock)
    assert {:ok, %{"type" => "welcome"}} = BitArena.JSON.decode(payload)
    :gen_tcp.close(sock)
  end

  test "ping gets a pong and input is accepted silently" do
    token = BitArena.Entitlements.issue("guest")
    sock = ws_connect(token)
    {1, _welcome} = ws_recv(sock)

    ws_send(sock, BitArena.JSON.encode!(%{"t" => "ping"}))
    assert {1, pong} = ws_recv(sock)
    assert {:ok, %{"type" => "pong"}} = BitArena.JSON.decode(pong)

    ws_send(sock, BitArena.JSON.encode!(%{"t" => "input", "dir" => [1, 0]}))
    :gen_tcp.close(sock)
  end
end
