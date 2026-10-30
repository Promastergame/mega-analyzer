defmodule OmnisecServer.ConnTest do
  use ExUnit.Case, async: true

  alias OmnisecServer.Conn

  test "get_req_header is case-insensitive" do
    conn = Conn.new(headers: [{"Authorization", "Bearer x"}, {"content-type", "application/json"}])
    assert Conn.get_req_header(conn, "authorization") == ["Bearer x"]
    assert Conn.get_req_header(conn, "AUTHORIZATION") == ["Bearer x"]
    assert Conn.get_req_header(conn, "missing") == []
  end

  test "split_path separates path and query" do
    assert Conn.split_path("/health") == {"/health", "", %{}}
    assert Conn.split_path("/api/v1/debug/registers?session_id=3&count=10") ==
             {"/api/v1/debug/registers", "session_id=3&count=10", %{"session_id" => "3", "count" => "10"}}
  end

  test "parse_body decodes JSON into body_params and merges params" do
    conn =
      Conn.new(
        headers: [{"content-type", "application/json"}],
        body: ~s({"a":1}),
        query_params: %{"q" => "x"},
        params: %{"q" => "x"}
      )
      |> Conn.parse_body()

    assert conn.body_params == %{"a" => 1}
    assert conn.params == %{"q" => "x", "a" => 1}
  end

  test "parse_body decodes urlencoded" do
    conn =
      Conn.new(headers: [{"content-type", "application/x-www-form-urlencoded"}], body: "a=1&b=two")
      |> Conn.parse_body()

    assert conn.body_params == %{"a" => "1", "b" => "two"}
  end

  test "parse_body keeps raw bodies raw" do
    conn =
      Conn.new(headers: [{"content-type", "application/octet-stream"}], body: <<1, 2, 3>>)
      |> Conn.parse_body()

    assert conn.body_params == %{}
    assert conn.body == <<1, 2, 3>>
  end

  test "json/2 sets envelope body and content type" do
    conn = Conn.new() |> Conn.json(%{ok: true})
    assert conn.status == 200
    assert IO.iodata_to_binary(conn.resp_body) == ~s({"ok":true})
    assert Conn.get_req_header(%{conn | headers: conn.resp_headers}, "content-type") == ["application/json"]
  end

  test "send_error sets status, envelope and halts" do
    conn = Conn.new() |> Conn.send_error(401, "nope")
    assert conn.status == 401
    assert conn.halted
    assert IO.iodata_to_binary(conn.resp_body) == ~s({"error":"nope","ok":false})
  end
end
