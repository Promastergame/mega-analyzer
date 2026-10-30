defmodule OmnisecServer.HdcNamerTest do
  use ExUnit.Case, async: true

  alias OmnisecServer.Native

  @database_init ~s({"variables":[],"functions":[]})

  test "predicts and trains variable name using HDC VSA" do
    # 1. Define variable context
    context = %{
      var_type: "char*",
      usages: [
        %{
          opcode: "call",
          role: %{
            "CallArg" => %{
              arg_index: 0,
              callee: "recv"
            }
          }
        },
        %{
          opcode: "call",
          role: %{
            "CallArg" => %{
              arg_index: 1,
              callee: "memcpy"
            }
          }
        }
      ]
    }

    context_json = OmnisecServer.JSON.encode!(context)

    # 2. Train the database
    updated_db_json = Native.train_variable_name(context_json, @database_init, "network_buffer")
    assert String.contains?(updated_db_json, "network_buffer")

    # 3. Predict the name on exact match
    predictions_json = Native.predict_variable_name(context_json, updated_db_json, 0.1)
    predictions = OmnisecServer.JSON.decode!(predictions_json)

    assert length(predictions) == 1
    [["network_buffer", score]] = predictions
    assert score > 0.99
  end

  test "predicts and trains function name using HDC VSA" do
    # 1. Define function context (structural blocks/edges + called APIs)
    context = %{
      node_vectors: [
        [1, 2, 3],
        [4, 5, 6]
      ],
      edges: [
        # block 0 -> block 1, data edge
        [0, 1, 0]
      ],
      called_apis: ["recv", "memcpy", "decrypt"]
    }

    context_json = OmnisecServer.JSON.encode!(context)

    # 2. Train the database
    updated_db_json =
      Native.train_function_name(context_json, @database_init, "decrypt_network_packet")

    assert String.contains?(updated_db_json, "decrypt_network_packet")

    # 3. Predict the function name
    predictions_json = Native.predict_function_name(context_json, updated_db_json, 0.1)
    predictions = OmnisecServer.JSON.decode!(predictions_json)

    assert length(predictions) == 1
    [["decrypt_network_packet", score]] = predictions
    assert score > 0.99
  end

  test "starts, drains, and stops eBPF tracing session" do
    session_id = Native.ebpf_start_trace(9999)
    assert is_integer(session_id)
    assert session_id > 0

    events =
      session_id
      |> Native.ebpf_poll_events()
      |> OmnisecServer.JSON.decode!()

    assert Enum.all?(events, &(&1["simulated"] == false))

    stopped_json = Native.ebpf_stop_trace(session_id)
    remaining_events = OmnisecServer.JSON.decode!(stopped_json)
    assert remaining_events == []
  end

  test "eBPF production sessions never inject simulated events" do
    session_id = Native.ebpf_start_trace(9999)
    assert is_integer(session_id)
    assert session_id > 0

    polled_json = Native.ebpf_poll_events(session_id)
    events = OmnisecServer.JSON.decode!(polled_json)

    assert Enum.all?(events, &(&1["simulated"] == false))
    assert Native.ebpf_stop_trace(session_id) == "[]"
  end
end
