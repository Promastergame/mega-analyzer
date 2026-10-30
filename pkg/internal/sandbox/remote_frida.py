"""Trusted host bridge. Never opens or executes the guest sample on this host."""
import datetime
import json
import queue
import sys
import threading
import time


def run(cfg, frida):
    stop = threading.Event()
    ready = threading.Event()
    ack = queue.Queue(maxsize=2)
    events = queue.Queue(maxsize=256)
    children = queue.Queue(maxsize=64)
    failed = threading.Event()
    detached = threading.Event()
    detach_reason = []
    device = None
    session = None
    pid = None
    child_count = 0
    seq = 0

    def control():
        try:
            for line in sys.stdin:
                value = json.loads(line)
                if value.get("stop"):
                    break
                ack.put_nowait(value["ack"])
        except Exception:
            pass
        stop.set()

    def enqueue(event, durable=None):
        try:
            events.put_nowait((event, durable))
        except queue.Full:
            failed.set()
            stop.set()

    def write_events():
        nonlocal seq
        while True:
            event, durable = events.get()
            if event is None:
                return
            try:
                seq += 1
                event["seq"] = seq
                data = json.dumps(event, ensure_ascii=True, separators=(",", ":"))
                if len(data) > 64000:
                    raise ValueError("event limit")
                sys.stdout.write(data + "\n")
                sys.stdout.flush()
                if ack.get(timeout=15) != seq:
                    raise ValueError("ack sequence")
                if durable is not None:
                    durable.set()
            except Exception:
                failed.set()
                stop.set()
                return

    threading.Thread(target=control, daemon=True).start()
    threading.Thread(target=write_events, daemon=True).start()

    def message(msg, data):
        try:
            if msg.get("type") == "error":
                raise ValueError("instrumentation error")
            if msg.get("type") != "log":
                return
            text = msg.get("payload", "")
            if not isinstance(text, str) or len(text) > 64000:
                raise ValueError("log limit")
            if text.startswith("FRIDA_SESSION "):
                value = json.loads(text[len("FRIDA_SESSION "):])
                if value.get("type") != "ready" or value.get("pid") != pid or not value.get("hooked"):
                    raise ValueError("invalid handshake")
                enqueue({"kind": "ready", "pid": pid, "hooked": value["hooked"]}, ready)
                if value.get("gaps"):
                    enqueue({"kind": "gap", "detail": "Some API hooks unavailable: " + json.dumps(value["gaps"])[:1500]})
            elif text.startswith("FRIDA_API "):
                value = json.loads(text[len("FRIDA_API "):])
                if value.get("pid") != pid:
                    raise ValueError("process attribution")
                stamp = datetime.datetime.fromtimestamp(value["ts"] / 1000, datetime.timezone.utc).isoformat().replace("+00:00", "Z")
                enqueue({"kind": "api", "call": {
                    "timestamp": stamp, "process_id": pid, "thread_id": value["tid"],
                    "module": value["mod"], "function": value["fn"],
                    "parameters": value["params"], "return_value": value["ret"],
                    "last_error": value.get("err", 0), "stack_trace": value.get("stack", [])}})
        except Exception:
            failed.set()
            stop.set()

    def on_child(child):
        try:
            children.put_nowait(child.pid)
        except queue.Full:
            failed.set()
            stop.set()

    def on_detached(reason, crash=None):
        detach_reason.append(reason)
        detached.set()

    terminal = "error"
    detail = "Collector stopped before execution"
    try:
        # Certificate is the pinned PEM filename, as in frida-tools --certificate.
        device = frida.get_device_manager().add_remote_device(
            cfg["endpoint"], certificate=cfg["certificate"], token=cfg["token"], keepalive_interval=2)
        params = device.query_system_parameters()
        if params.get("platform") != "windows" and params.get("os", {}).get("id") != "windows":
            raise ValueError("remote device is not Windows")
        device.on("child-added", on_child)
        device.on("lost", stop.set)
        pid = device.spawn(cfg["target"], argv=[cfg["target"]] + cfg["args"], stdio="pipe")
        session = device.attach(pid)
        session.on("detached", on_detached)
        # This collector deliberately stops descendants. No uninstrumented
        # child is resumed as a fallback when hooks or limits fail.
        session.enable_child_gating()
        script = session.create_script(cfg["script"], name="mega-windows-capture")
        script.on("message", message)
        script.load()
        deadline = time.monotonic() + 12
        while not ready.wait(0.05):
            if stop.is_set() or detached.is_set() or time.monotonic() >= deadline:
                raise RuntimeError("hook handshake failed")
        if stop.is_set():
            raise RuntimeError("collector stopped before resume")
        resumed = threading.Event()
        # Persist launch intent before the only remote resume operation.
        enqueue({"kind": "launch", "pid": pid}, resumed)
        if not resumed.wait(12) or stop.is_set():
            raise RuntimeError("host did not persist launch intent")
        device.resume(pid)
        enqueue({"kind": "resumed", "pid": pid})
        started = time.monotonic()
        heartbeat = started
        while not stop.wait(0.05) and not detached.is_set():
            while not children.empty():
                child_pid = children.get_nowait()
                device.kill(child_pid)
                child_count += 1
                enqueue({"kind": "gap", "pid": child_pid, "detail": "Gated child stopped; descendant API coverage unavailable"})
                if child_count >= 64:
                    raise RuntimeError("child limit reached")
            now = time.monotonic()
            if cfg["duration_seconds"] and now - started >= cfg["duration_seconds"]:
                terminal, detail = "end", "Observation duration reached; remote process cleanup requested"
                break
            if now - heartbeat >= 1:
                device.query_system_parameters()  # Real remote round trip, no synthetic liveness.
                enqueue({"kind": "heartbeat"})
                heartbeat = now
        if detached.is_set():
            if detach_reason == ["process-terminated"]:
                terminal, detail = "end", "Root process terminated; exit code unavailable"
            else:
                detail = "Guest session lost; captured host data retained"
        elif stop.is_set():
            detail = "Collector canceled or transport lost; guest may still be running"
    except Exception as exc:
        detail = "Remote capture failed (" + type(exc).__name__ + "); check VM agent, TLS profile and matching Frida versions"
    finally:
        if device is not None:
            # Keep child gating active until all known processes are stopped.
            pending = []
            if pid is not None:
                pending.append(pid)
            while not children.empty():
                pending.append(children.get_nowait())
            for process_id in pending:
                try:
                    device.kill(process_id)
                except frida.ProcessNotFoundError:
                    pass
                except Exception:
                    terminal, detail = "error", "Remote cleanup unconfirmed; stop or revert the VM manually"
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass
        if failed.is_set():
            terminal, detail = "error", "Capture incomplete: event overflow, invalid instrumentation data or host acknowledgment failure"
        done = threading.Event()
        enqueue({"kind": terminal, "detail": detail}, done)
        done.wait(3)
    return 0 if terminal == "end" else 1


if __name__ == "__main__":
    try:
        config = json.loads(sys.stdin.readline())
        import frida
        sys.exit(run(config, frida))
    except Exception:
        # Never print configuration, credentials or arbitrary guest exceptions.
        sys.exit(1)
