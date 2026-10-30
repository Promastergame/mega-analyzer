defmodule OmnisecServer.DebugController do
  @moduledoc """
  REST controller for the interactive debugger.

  All endpoints wrap `OmnisecServer.NativeDebugger` NIF calls and
  return JSON. Session state is kept in the Rust NIF process-local
  store (a `Mutex<HashMap<u64, DebuggerSession>>`).
  """

  alias OmnisecServer.{AdminAuthPlug, Conn}
  alias OmnisecServer.NativeDebugger
  alias OmnisecServer.DebugSessions

  @doc """
  Derives the session owner key from the request: a SHA-256 of the
  Authorization header when present (token holders are distinguished by
  what they present), or the literal "open" in tokenless mode.
  """
  def session_owner(conn) do
    case Conn.get_req_header(conn, "authorization") do
      [value | _] when is_binary(value) and value != "" ->
        Base.encode16(:crypto.hash(:sha256, value))

      _ ->
        "open"
    end
  end

  # Every action below consumes another client's session when left
  # unchecked: session IDs are sequential integers, so the second API
  # client could stop/step/read the first client's session. The guard
  # verifies the session's registered owner (derived from the request)
  # before the action runs. `start` creates sessions, so it is exempt;
  # missing/invalid session_id is still rejected by the action clauses.
  # `admin?` mirrors the old `plug AdminAuthPlug when action in [...]`.
  defp guard(conn, admin?, fun) do
    conn =
      if admin? do
        AdminAuthPlug.call(conn, AdminAuthPlug.init([]))
      else
        conn
      end

    if Conn.halted?(conn) do
      conn
    else
      case authorize_debug_session(conn) do
        {:cont, conn} -> fun.(conn)
        {:halt, conn} -> conn
      end
    end
  end

  defp authorize_debug_session(conn) do
    case to_int(conn.params["session_id"], nil) do
      nil ->
        {:cont, conn}

      id ->
        owner = session_owner(conn)

        case DebugSessions.owner_of(id) do
          {:ok, ^owner} ->
            {:cont, conn}

          {:ok, _foreign} ->
            {:halt, Conn.send_error(conn, 403, "session belongs to another client")}

          :error ->
            {:halt, Conn.send_error(conn, 404, "unknown session")}
        end
    end
  end

  # ── Session lifecycle ──────────────────────────────────────────

  @doc """
  POST /api/debug/start

  Body: JSON %{"file_path" => string, "entry" => optional integer,
               "flavor" => optional "intel" | "att"}
  Returns: %{ok: true, session_id: int, entry_point: int, arch: string}
  """
  def start(conn, params) do
    file_path = Map.get(params, "file_path", "")

    uploads_abs = Path.expand(Application.get_env(:omnisec_server, :uploads_dir) || "uploads")
    File.mkdir_p!(uploads_abs)

    uploads_prefix = if String.ends_with?(uploads_abs, "/"), do: uploads_abs, else: uploads_abs <> "/"
    expanded_path = Path.expand(file_path, uploads_abs)

    if String.starts_with?(expanded_path, uploads_prefix) or expanded_path == uploads_abs do
      payload = %{
        file_path: expanded_path,
        entry: case Map.get(params, "entry") do
          nil -> nil
          val -> to_int(val, nil)
        end,
        flavor: Map.get(params, "flavor", "intel")
      }

      case OmnisecServer.JSON.encode(payload) do
        {:ok, json} ->
          case NativeDebugger.debug_session_start(json) do
            json_result when is_binary(json_result) ->
              case OmnisecServer.JSON.decode(json_result) do
                {:ok, decoded} ->
                  # Bind the fresh session to this client before the ID
                  # ever reaches the response body.
                  DebugSessions.claim(session_owner(conn), decoded["session_id"])
                  Conn.json(conn, %{ok: true, result: decoded})

                {:error, _} ->
                  error(conn, 500, "invalid NIF response")
              end

            {:error, reason} ->
              error(conn, 500, "NIF error: #{inspect(reason)}")
          end

        {:error, _} ->
          error(conn, 400, "invalid params")
      end
    else
      error(conn, 403, "Access denied: file must be located inside the uploads directory")
    end
  end

  @doc """
  POST /api/debug/stop

  Body: JSON %{"session_id" => integer}
  """
  def stop(conn, %{"session_id" => sid}) do
    guard(conn, false, fn c ->
      id = to_int(sid)
      NativeDebugger.debug_session_stop(id)
      DebugSessions.release(id)
      Conn.json(c, %{ok: true})
    end)
  end

  def stop(conn, _), do: error(conn, 400, "missing session_id")

  # ── Execution control ──────────────────────────────────────────

  def step(conn, %{"session_id" => sid}) do
    guard(conn, false, fn c ->
      with {:ok, decoded} <- OmnisecServer.JSON.decode(NativeDebugger.debug_step(to_int(sid))) do
        Conn.json(c, %{ok: true, result: decoded})
      else
        _ -> error(c, 500, "step failed")
      end
    end)
  end

  def step(conn, _), do: error(conn, 400, "missing session_id")

  def continue(conn, %{"session_id" => sid}) do
    guard(conn, false, fn c ->
      with {:ok, decoded} <- OmnisecServer.JSON.decode(NativeDebugger.debug_continue(to_int(sid))) do
        Conn.json(c, %{ok: true, result: decoded})
      else
        _ -> error(c, 500, "continue failed")
      end
    end)
  end

  def continue(conn, _), do: error(conn, 400, "missing session_id")

  # ── Breakpoints ────────────────────────────────────────────────

  def breakpoint(conn, %{"session_id" => sid, "target" => target}) do
    guard(conn, false, fn c ->
      with {:ok, decoded} <- OmnisecServer.JSON.decode(NativeDebugger.debug_breakpoint(to_int(sid), to_string(target))) do
        Conn.json(c, %{ok: true, result: decoded})
      else
        _ -> error(c, 500, "breakpoint failed")
      end
    end)
  end

  def breakpoint(conn, _), do: error(conn, 400, "missing session_id or target")

  def remove_bp(conn, %{"session_id" => sid, "id" => id}) do
    guard(conn, false, fn c ->
      with {:ok, decoded} <- OmnisecServer.JSON.decode(NativeDebugger.debug_remove_bp(to_int(sid), to_int(id))) do
        Conn.json(c, %{ok: true, result: decoded})
      else
        _ -> error(c, 500, "remove_bp failed")
      end
    end)
  end

  def remove_bp(conn, _), do: error(conn, 400, "missing session_id or id")

  def breakpoints(conn, %{"session_id" => sid}) do
    guard(conn, false, fn c ->
      with {:ok, decoded} <- OmnisecServer.JSON.decode(NativeDebugger.debug_list_bp(to_int(sid))) do
        Conn.json(c, %{ok: true, result: decoded})
      else
        _ -> error(c, 500, "list_bp failed")
      end
    end)
  end

  def breakpoints(conn, _), do: error(conn, 400, "missing session_id")

  # ── Watchpoints ────────────────────────────────────────────────

  def add_watch(conn, %{"session_id" => sid, "address" => addr, "size" => sz, "kind" => kind}) do
    guard(conn, false, fn c ->
      with {:ok, decoded} <- OmnisecServer.JSON.decode(NativeDebugger.debug_add_watch(to_int(sid), to_int(addr), to_int(sz), to_string(kind))) do
        Conn.json(c, %{ok: true, result: decoded})
      else
        _ -> error(c, 500, "add_watch failed")
      end
    end)
  end

  def add_watch(conn, _), do: error(conn, 400, "missing params")

  def remove_watch(conn, %{"session_id" => sid, "id" => id}) do
    guard(conn, false, fn c ->
      with {:ok, decoded} <- OmnisecServer.JSON.decode(NativeDebugger.debug_remove_watch(to_int(sid), to_int(id))) do
        Conn.json(c, %{ok: true, result: decoded})
      else
        _ -> error(c, 500, "remove_watch failed")
      end
    end)
  end

  def remove_watch(conn, _), do: error(conn, 400, "missing session_id or id")

  def watchpoints(conn, %{"session_id" => sid}) do
    guard(conn, false, fn c ->
      with {:ok, decoded} <- OmnisecServer.JSON.decode(NativeDebugger.debug_list_watch(to_int(sid))) do
        Conn.json(c, %{ok: true, result: decoded})
      else
        _ -> error(c, 500, "list_watch failed")
      end
    end)
  end

  def watchpoints(conn, _), do: error(conn, 400, "missing session_id")

  # ── Introspection ──────────────────────────────────────────────

  def registers(conn, %{"session_id" => sid}) do
    guard(conn, false, fn c ->
      with {:ok, decoded} <- OmnisecServer.JSON.decode(NativeDebugger.debug_registers(to_int(sid))) do
        Conn.json(c, %{ok: true, result: decoded})
      else
        _ -> error(c, 500, "registers failed")
      end
    end)
  end

  def registers(conn, _), do: error(conn, 400, "missing session_id")

  def disassemble(conn, %{"session_id" => sid} = params) do
    guard(conn, false, fn c ->
      address = Map.get(params, "address", 0)
      count = Map.get(params, "count", 10)

      with {:ok, decoded} <- OmnisecServer.JSON.decode(NativeDebugger.debug_disassemble(to_int(sid), to_int(address), to_int(count, 10))) do
        Conn.json(c, %{ok: true, result: decoded})
      else
        _ -> error(c, 500, "disassemble failed")
      end
    end)
  end

  def disassemble(conn, _), do: error(conn, 400, "missing session_id")

  def memory(conn, %{"session_id" => sid} = params) do
    guard(conn, false, fn c ->
      address = Map.get(params, "address", 0)
      size = Map.get(params, "size", 16)

      with {:ok, decoded} <- OmnisecServer.JSON.decode(NativeDebugger.debug_read_memory(to_int(sid), to_int(address), to_int(size, 16))) do
        Conn.json(c, %{ok: true, result: decoded})
      else
        _ -> error(c, 500, "read_memory failed")
      end
    end)
  end

  def memory(conn, _), do: error(conn, 400, "missing session_id")

  def set_flavor(conn, %{"session_id" => sid, "flavor" => flavor}) do
    guard(conn, false, fn c ->
      NativeDebugger.debug_set_flavor(to_int(sid), to_string(flavor))
      Conn.json(c, %{ok: true, flavor: flavor})
    end)
  end

  def set_flavor(conn, _), do: error(conn, 400, "missing session_id or flavor")

  # ── Patch & Continue ─────────────────────────────────────────

  def patch_memory(conn, %{"session_id" => sid, "address" => addr, "hex" => hex}) do
    guard(conn, true, fn c ->
      with {:ok, decoded} <- OmnisecServer.JSON.decode(NativeDebugger.debug_write_memory(to_int(sid), to_int(addr), to_string(hex))) do
        Conn.json(c, %{ok: true, result: decoded})
      else
        _ -> error(c, 500, "write_memory failed")
      end
    end)
  end

  def patch_memory(conn, _), do: error(conn, 400, "missing session_id, address or hex")

  def set_register(conn, %{"session_id" => sid, "register" => reg, "value" => val}) do
    guard(conn, true, fn c ->
      with {:ok, decoded} <- OmnisecServer.JSON.decode(NativeDebugger.debug_set_register(to_int(sid), to_string(reg), to_int(val))) do
        Conn.json(c, %{ok: true, result: decoded})
      else
        _ -> error(c, 500, "set_register failed")
      end
    end)
  end

  def set_register(conn, _), do: error(conn, 400, "missing session_id, register or value")

  def set_flag(conn, %{"session_id" => sid, "flag" => flag, "value" => val}) do
    guard(conn, true, fn c ->
      with {:ok, decoded} <- OmnisecServer.JSON.decode(NativeDebugger.debug_set_flag(to_int(sid), to_string(flag), to_bool(val))) do
        Conn.json(c, %{ok: true, result: decoded})
      else
        _ -> error(c, 500, "set_flag failed")
      end
    end)
  end

  def set_flag(conn, _), do: error(conn, 400, "missing session_id, flag or value")

  # ── Memory scan ────────────────────────────────────────────────

  def scan(conn, %{"session_id" => sid, "pattern" => pattern}) do
    guard(conn, false, fn c ->
      with {:ok, decoded} <- OmnisecServer.JSON.decode(NativeDebugger.debug_scan_memory(to_int(sid), to_string(pattern))) do
        Conn.json(c, %{ok: true, result: decoded})
      else
        _ -> error(c, 500, "scan failed")
      end
    end)
  end

  def scan(conn, _), do: error(conn, 400, "missing session_id or pattern")

  # ── Time Travel Debugging ─────────────────────────────────────

  def trace_enable(conn, %{"session_id" => sid, "enabled" => enabled}) do
    guard(conn, false, fn c ->
      with {:ok, decoded} <- OmnisecServer.JSON.decode(NativeDebugger.debug_trace_enable(to_int(sid), to_bool(enabled))) do
        Conn.json(c, %{ok: true, result: decoded})
      else
        _ -> error(c, 500, "trace_enable failed")
      end
    end)
  end

  def trace_enable(conn, _), do: error(conn, 400, "missing session_id or enabled")

  def reverse_step(conn, %{"session_id" => sid}) do
    guard(conn, false, fn c ->
      with {:ok, decoded} <- OmnisecServer.JSON.decode(NativeDebugger.debug_reverse_step(to_int(sid))) do
        Conn.json(c, %{ok: true, result: decoded})
      else
        _ -> error(c, 500, "reverse_step failed")
      end
    end)
  end

  def reverse_step(conn, _), do: error(conn, 400, "missing session_id")

  def reverse_continue(conn, %{"session_id" => sid}) do
    guard(conn, false, fn c ->
      with {:ok, decoded} <- OmnisecServer.JSON.decode(NativeDebugger.debug_reverse_continue(to_int(sid))) do
        Conn.json(c, %{ok: true, result: decoded})
      else
        _ -> error(c, 500, "reverse_continue failed")
      end
    end)
  end

  def reverse_continue(conn, _), do: error(conn, 400, "missing session_id")

  # ── Premium features ───────────────────────────────────────────

  def trace_log(conn, %{"session_id" => sid} = params) do
    guard(conn, false, fn c ->
      start = Map.get(params, "start", 0)
      count = Map.get(params, "count", 100)

      with {:ok, decoded} <- OmnisecServer.JSON.decode(NativeDebugger.debug_trace_log(to_int(sid), to_int(start), to_int(count))) do
        Conn.json(c, %{ok: true, result: decoded})
      else
        _ -> error(c, 500, "trace_log failed")
      end
    end)
  end

  def trace_log(conn, _), do: error(conn, 400, "missing session_id")

  def trace_stats(conn, %{"session_id" => sid}) do
    guard(conn, false, fn c ->
      with {:ok, decoded} <- OmnisecServer.JSON.decode(NativeDebugger.debug_trace_stats(to_int(sid))) do
        Conn.json(c, %{ok: true, result: decoded})
      else
        _ -> error(c, 500, "trace_stats failed")
      end
    end)
  end

  def trace_stats(conn, _), do: error(conn, 400, "missing session_id")

  def cfg(conn, %{"session_id" => sid} = params) do
    guard(conn, false, fn c ->
      address = Map.get(params, "address", 0)
      count = Map.get(params, "count", 50)

      with {:ok, decoded} <- OmnisecServer.JSON.decode(NativeDebugger.debug_cfg(to_int(sid), to_int(address), to_int(count))) do
        Conn.json(c, %{ok: true, result: decoded})
      else
        _ -> error(c, 500, "cfg failed")
      end
    end)
  end

  def cfg(conn, _), do: error(conn, 400, "missing session_id")

  # ── Internal helpers ───────────────────────────────────────────

  defp error(conn, status, reason) do
    conn
    |> Conn.put_status(status)
    |> Conn.json(%{ok: false, error: to_string(reason)})
  end

  defp to_int(nil, default), do: default
  defp to_int(val, _default) when is_integer(val), do: val
  defp to_int(val, default) when is_binary(val) do
    val = String.trim(val)
    cond do
      String.starts_with?(val, "0x") or String.starts_with?(val, "0X") ->
        case Integer.parse(String.slice(val, 2..-1//-1), 16) do
          {num, ""} -> num
          _ -> default
        end
      true ->
        case Integer.parse(val) do
          {num, ""} -> num
          _ -> default
        end
    end
  rescue
    _ -> default
  end

  # JSON payloads may carry any shape (a list, a map, a nested object) for
  # numeric fields; those are not numbers and must fall back to the default
  # instead of raising FunctionClauseError and leaking a 500.
  defp to_int(_val, default), do: default

  defp to_int(val), do: to_int(val, 0)

  defp to_bool(nil), do: false
  defp to_bool(val) when is_boolean(val), do: val
  defp to_bool("true"), do: true
  defp to_bool("false"), do: false
  defp to_bool("1"), do: true
  defp to_bool("0"), do: false
  defp to_bool(1), do: true
  defp to_bool(0), do: false
  defp to_bool(_), do: false
end
