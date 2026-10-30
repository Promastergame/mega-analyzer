defmodule OmnisecServer.Router do
  @moduledoc """
  HTTP routes for the OmniSec analysis API (dependency-free dispatch,
  replaces `Phoenix.Router`).

  ## Endpoints

  | Method | Path                     | Action                                |
  | ------ | ------------------------ | ------------------------------------- |
  | GET    | /health                  | liveness probe + cluster + cache stats|
  | POST   | /api/v1/analyze/apk      | submit raw APK bytes for analysis     |
  | POST   | /api/v1/analyze/binary   | submit raw ELF/PE for analysis        |
  | POST   | /api/v1/scan/patterns    | run pattern scan against payload      |
  | POST   | /api/v1/ml/rank          | rank candidates against HDC anchors   |
  | POST   | /api/v1/ml/hash          | compute HDC feature vector            |
  | POST   | /api/v1/debug/start      | start debugger session                |
  | POST   | /api/v1/debug/stop       | stop debugger session                 |
  | POST   | /api/v1/debug/step       | step one instruction                  |
  | POST   | /api/v1/debug/continue   | continue until stop                   |
  | POST   | /api/v1/debug/breakpoint | set breakpoint (addr or symbol)       |
  | POST   | /api/v1/debug/remove_bp  | remove breakpoint by id               |
  | GET    | /api/v1/debug/breakpoints| list breakpoints                      |
  | POST   | /api/v1/debug/watch      | add watchpoint                        |
  | POST   | /api/v1/debug/remove_watch | remove watchpoint by id             |
  | GET    | /api/v1/debug/watchpoints| list watchpoints                      |
  | GET    | /api/v1/debug/registers  | read CPU registers                    |
  | GET    | /api/v1/debug/disassemble| disassemble at address                |
  | GET    | /api/v1/debug/memory     | read raw memory                       |
  | POST   | /api/v1/debug/flavor     | set disassembly flavor (intel/att)    |
  """

  alias OmnisecServer.{AllowlistPlug, AnalysisController, AuthPlug, Conn, DebugController}

  @doc "Routes a parsed `%Conn{}` to a controller action. Always returns a `%Conn{}` with the response set."
  @spec dispatch(Conn.t()) :: Conn.t()
  def dispatch(%Conn{} = conn) do
    conn
    |> pipeline_api()
    |> route()
  end

  # ── `:api` pipeline — JSON only (was `plug :accepts, ["json"]`) ──

  defp pipeline_api(%Conn{halted: true} = conn), do: conn

  defp pipeline_api(%Conn{} = conn) do
    case Conn.get_req_header(conn, "accept") do
      [] ->
        conn

      values ->
        if Enum.any?(values, &accepts_json?/1) do
          conn
        else
          Conn.send_error(conn, 406, "only application/json is supported")
        end
    end
  end

  defp accepts_json?(value) do
    value
    |> String.split(",")
    |> Enum.any?(fn part ->
      part = part |> String.split(";") |> hd() |> String.trim() |> String.downcase()
      part in ["application/json", "application/*", "*/*", "json"]
    end)
  end

  # ── `:private` pipeline — allowlist + bearer auth ──

  defp pipeline_private(%Conn{halted: true} = conn), do: conn

  defp pipeline_private(%Conn{} = conn) do
    conn
    |> AllowlistPlug.call(AllowlistPlug.init([]))
    |> run_if_continuing(fn c -> AuthPlug.call(c, AuthPlug.init([])) end)
  end

  defp run_if_continuing(%Conn{halted: true} = conn, _fun), do: conn
  defp run_if_continuing(%Conn{} = conn, fun), do: fun.(conn)

  # ── Routes ──

  defp route(%Conn{halted: true} = conn), do: conn
  defp route(%Conn{method: "GET", path: "/health"} = conn), do: AnalysisController.health(conn, conn.params)

  defp route(%Conn{method: "POST", path: "/api/v1/analyze/apk"} = conn),
    do: private(conn, &AnalysisController.analyze_apk/2)

  defp route(%Conn{method: "POST", path: "/api/v1/analyze/binzap"} = conn),
    do: private(conn, &AnalysisController.analyze_binzap/2)

  defp route(%Conn{method: "POST", path: "/api/v1/analyze/binary"} = conn),
    do: private(conn, &AnalysisController.analyze_binary/2)

  defp route(%Conn{method: "POST", path: "/api/v1/scan/patterns"} = conn),
    do: private(conn, &AnalysisController.scan_patterns/2)

  defp route(%Conn{method: "POST", path: "/api/v1/scan/yara"} = conn),
    do: private(conn, &AnalysisController.scan_yara/2)

  defp route(%Conn{method: "POST", path: "/api/v1/ml/rank"} = conn),
    do: private(conn, &AnalysisController.rank_hotspots/2)

  defp route(%Conn{method: "POST", path: "/api/v1/ml/hash"} = conn),
    do: private(conn, &AnalysisController.hash_features/2)

  defp route(%Conn{method: "GET", path: "/api/v1/cluster"} = conn),
    do: private(conn, &AnalysisController.cluster/2)

  defp route(%Conn{method: "GET", path: "/api/v1/pool"} = conn),
    do: private(conn, &AnalysisController.pool/2)

  defp route(%Conn{method: "POST", path: "/api/v1/symexec/solve"} = conn),
    do: private(conn, &AnalysisController.symexec_solve/2)

  defp route(%Conn{method: "POST", path: "/api/v1/microemu/emulate"} = conn),
    do: private(conn, &AnalysisController.micro_emu_emulate/2)

  # ── Interactive debugger ──

  defp route(%Conn{method: "POST", path: "/api/v1/debug/start"} = conn),
    do: private(conn, &DebugController.start/2)

  defp route(%Conn{method: "POST", path: "/api/v1/debug/stop"} = conn),
    do: private(conn, &DebugController.stop/2)

  defp route(%Conn{method: "POST", path: "/api/v1/debug/step"} = conn),
    do: private(conn, &DebugController.step/2)

  defp route(%Conn{method: "POST", path: "/api/v1/debug/continue"} = conn),
    do: private(conn, &DebugController.continue/2)

  defp route(%Conn{method: "POST", path: "/api/v1/debug/breakpoint"} = conn),
    do: private(conn, &DebugController.breakpoint/2)

  defp route(%Conn{method: "POST", path: "/api/v1/debug/remove_bp"} = conn),
    do: private(conn, &DebugController.remove_bp/2)

  defp route(%Conn{method: "GET", path: "/api/v1/debug/breakpoints"} = conn),
    do: private(conn, &DebugController.breakpoints/2)

  defp route(%Conn{method: "POST", path: "/api/v1/debug/watch"} = conn),
    do: private(conn, &DebugController.add_watch/2)

  defp route(%Conn{method: "POST", path: "/api/v1/debug/remove_watch"} = conn),
    do: private(conn, &DebugController.remove_watch/2)

  defp route(%Conn{method: "GET", path: "/api/v1/debug/watchpoints"} = conn),
    do: private(conn, &DebugController.watchpoints/2)

  defp route(%Conn{method: "GET", path: "/api/v1/debug/registers"} = conn),
    do: private(conn, &DebugController.registers/2)

  defp route(%Conn{method: "GET", path: "/api/v1/debug/disassemble"} = conn),
    do: private(conn, &DebugController.disassemble/2)

  defp route(%Conn{method: "GET", path: "/api/v1/debug/memory"} = conn),
    do: private(conn, &DebugController.memory/2)

  defp route(%Conn{method: "POST", path: "/api/v1/debug/flavor"} = conn),
    do: private(conn, &DebugController.set_flavor/2)

  defp route(%Conn{method: "POST", path: "/api/v1/debug/patch"} = conn),
    do: private(conn, &DebugController.patch_memory/2)

  defp route(%Conn{method: "POST", path: "/api/v1/debug/register"} = conn),
    do: private(conn, &DebugController.set_register/2)

  defp route(%Conn{method: "POST", path: "/api/v1/debug/flag"} = conn),
    do: private(conn, &DebugController.set_flag/2)

  defp route(%Conn{method: "GET", path: "/api/v1/debug/scan"} = conn),
    do: private(conn, &DebugController.scan/2)

  defp route(%Conn{method: "POST", path: "/api/v1/debug/trace"} = conn),
    do: private(conn, &DebugController.trace_enable/2)

  defp route(%Conn{method: "POST", path: "/api/v1/debug/reverse_step"} = conn),
    do: private(conn, &DebugController.reverse_step/2)

  defp route(%Conn{method: "POST", path: "/api/v1/debug/reverse_continue"} = conn),
    do: private(conn, &DebugController.reverse_continue/2)

  defp route(%Conn{method: "GET", path: "/api/v1/debug/trace_log"} = conn),
    do: private(conn, &DebugController.trace_log/2)

  defp route(%Conn{method: "GET", path: "/api/v1/debug/trace_stats"} = conn),
    do: private(conn, &DebugController.trace_stats/2)

  defp route(%Conn{method: "GET", path: "/api/v1/debug/cfg"} = conn),
    do: private(conn, &DebugController.cfg/2)

  defp route(%Conn{} = conn) do
    Conn.send_error(conn, 404, "not found")
  end

  defp private(%Conn{} = conn, action) do
    conn
    |> pipeline_private()
    |> run_if_continuing(fn c -> action.(c, c.params) end)
  end
end
