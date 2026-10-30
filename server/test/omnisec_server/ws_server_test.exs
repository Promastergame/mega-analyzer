defmodule OmnisecServer.WsServerTest do
  @moduledoc """
  End-to-end tests for the plain-JSON WebSocket debugger transport:
  real TCP, real RFC 6455 handshake and framing, stdlib client.
  """
  use ExUnit.Case, async: false

  alias OmnisecServer.WsServer

  setup do
    old_private = Application.get_env(:omnisec_server, :private_token)
    old_admin = Application.get_env(:omnisec_server, :admin_token)

    on_exit(fn ->
      Application.put_env(:omnisec_server, :private_token, old_private)
      Application.put_env(:omnisec_server, :admin_token, old_admin)
    end)

    Application.put_env(:omnisec_server, :private_token, nil)
    Application.put_env(:omnisec_server, :admin_token, nil)

    {:ok, _} = start_supervised({WsServer, port: 0, ip: {127, 0, 0, 1}})
    %{port: WsServer.port()}
  end

  # ── client helpers (stdlib only) ──

  defp ws_connect(port, key \\ Base.encode64(:crypto.strong_rand_bytes(16))) do
    {:ok, sock} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, packet: :raw, active: false])

    req =
      "GET /ws HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\n" <>
        "Connection: Upgrade\r\nSec-WebSocket-Key: #{key}\r\nSec-WebSocket-Version: 13\r\n\r\n"

    :ok = :gen_tcp.send(sock, req)
    {:ok, resp} = :gen_tcp.recv(sock, 0, 5_000)
    {sock, key, resp}
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

  defp ws_call(sock, op, params \\ %{}, auth \\ "open") do
    ws_send(sock, OmnisecServer.JSON.encode!(%{"op" => op, "authorization" => auth, "params" => params}))
    {1, payload} = ws_recv(sock)
    {:ok, decoded} = OmnisecServer.JSON.decode(payload)
    decoded
  end

  # ── tests ──

  test "handshake emits the RFC 6455 accept key", %{port: port} do
    {_sock, _key, resp} = ws_connect(port, "dGhlIHNhbXBsZSBub25jZQ==")
    assert resp =~ "101 Switching Protocols"
    assert resp =~ "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
  end

  test "non-websocket request is rejected", %{port: port} do
    {:ok, sock} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, packet: :raw, active: false])
    :ok = :gen_tcp.send(sock, "GET /ws HTTP/1.1\r\nHost: x\r\n\r\n")
    assert {:error, :closed} = :gen_tcp.recv(sock, 0, 5_000)
  end

  test "unknown op returns an error envelope", %{port: port} do
    {sock, _, _} = ws_connect(port)
    assert %{"ok" => false, "error" => "unknown op: frobnicate"} = ws_call(sock, "frobnicate")
  end

  test "step on unknown session returns 404 via the ownership guard", %{port: port} do
    {sock, _, _} = ws_connect(port)

    assert %{"ok" => false, "error" => "unknown session"} =
             ws_call(sock, "step", %{"session_id" => 424_242})
  end

  test "private mode rejects bad token over WS", %{port: port} do
    Application.put_env(:omnisec_server, :private_token, "secret")
    {sock, _, _} = ws_connect(port)

    assert %{"ok" => false, "error" => "invalid token"} =
             ws_call(sock, "step", %{"session_id" => 1}, "Bearer wrong")
  end

  test "admin-only op rejects non-admin credentials", %{port: port} do
    Application.put_env(:omnisec_server, :private_token, "secret")
    Application.put_env(:omnisec_server, :admin_token, "admin-secret")
    {sock, _, _} = ws_connect(port)

    assert %{"ok" => false, "error" => "invalid admin token"} =
             ws_call(sock, "patch", %{"session_id" => 1, "address" => 0, "hex" => "90"}, "Bearer secret")
  end

  test "ping gets a pong", %{port: port} do
    {sock, _, _} = ws_connect(port)
    :ok = :gen_tcp.send(sock, <<0x89, 0x81, 1, 2, 3, 4, Bitwise.bxor(?P, 1)>>)
    assert {0xA, <<"P">>} = ws_recv(sock)
  end
end
