"""Offline bridge regressions. All devices and samples below are fake."""
import importlib.util
import json
from pathlib import Path
import queue
import threading
import types
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "pkg/internal/sandbox/remote_frida.py"
spec = importlib.util.spec_from_file_location("remote_frida", SOURCE)
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)


class Input:
    def __init__(self):
        self.queue = queue.Queue()

    def __iter__(self):
        return self

    def __next__(self):
        value = self.queue.get(timeout=20)
        if value is None:
            raise StopIteration
        return value


class Output:
    def __init__(self, control):
        self.control = control
        self.records = []
        self.acknowledged = []

    def write(self, data):
        record = json.loads(data)
        self.records.append(record)
        self.acknowledged.append(record["kind"])
        self.control.queue.put(json.dumps({"ack": record["seq"]}) + "\n")

    def flush(self):
        pass


class FakeDevice:
    def __init__(self, output, mode):
        self.output, self.mode = output, mode
        self.handlers = {}
        self.killed = []
        self.resumed = []
        self.session = FakeSession(self)

    def on(self, signal, callback):
        self.handlers[signal] = callback

    def query_system_parameters(self):
        return {"platform": "linux" if self.mode == "wrong-os" else "windows"}

    def spawn(self, target, argv, stdio):
        assert target == r"C:\Lab\fixture.exe"
        assert argv == [target, "--fixture"]
        assert stdio == "pipe"
        return 42

    def attach(self, pid):
        assert pid == 42
        return self.session

    def resume(self, pid):
        assert "ready" in self.output.acknowledged
        assert "launch" in self.output.acknowledged
        assert self.session.gated
        self.resumed.append(pid)
        value = {"ts": 1700000000000, "pid": 42, "tid": 7, "cat": "Crypto", "mod": "bcrypt.dll",
                 "fn": "BCryptGenerateSymmetricKey", "ret": "0x0", "err": 0,
                 "params": [{"name": "KeyHex", "type": "hex", "value": "00" * 16}]}
        self.session.message({"type": "log", "payload": "FRIDA_API " + json.dumps(value)}, None)
        reason = "process-terminated" if self.mode == "normal" else "connection-terminated"
        self.session.handlers["detached"](reason, None)

    def kill(self, pid):
        self.killed.append(pid)


class FakeSession:
    def __init__(self, device):
        self.device = device
        self.handlers = {}
        self.gated = False

    def on(self, signal, callback):
        if signal == "message":
            self.message = callback
        else:
            self.handlers[signal] = callback

    def enable_child_gating(self):
        if self.device.mode == "gating-failure":
            raise RuntimeError("gating unavailable")
        self.gated = True

    def create_script(self, source, name):
        assert source == "trusted-hook-source"
        return self

    def load(self):
        pid = 99 if self.device.mode == "wrong-pid" else 42
        value = {"type": "ready", "pid": pid, "hooked": ["bcrypt.dll!BCryptGenerateSymmetricKey"], "gaps": []}
        self.message({"type": "log", "payload": "FRIDA_SESSION " + json.dumps(value)}, None)

    def detach(self):
        pass


class RemoteBridgeTests(unittest.TestCase):
    def exercise(self, mode):
        control = Input()
        output = Output(control)
        device = FakeDevice(output, mode)
        connections = []

        def remote(address, **kwargs):
            connections.append((address, kwargs))
            return device

        sdk = types.SimpleNamespace(
            get_device_manager=lambda: types.SimpleNamespace(add_remote_device=remote),
            ProcessNotFoundError=ProcessLookupError)
        cfg = {"endpoint": "192.168.222.222:27042", "certificate": "host-pin.pem", "token": "test-secret",
               "target": r"C:\Lab\fixture.exe", "args": ["--fixture"], "script": "trusted-hook-source", "duration_seconds": 5}
        try:
            with patch.object(bridge.sys, "stdin", control), patch.object(bridge.sys, "stdout", output):
                status = bridge.run(cfg, sdk)
        finally:
            control.queue.put(None)
        self.assertEqual(connections, [(cfg["endpoint"], {"certificate": "host-pin.pem", "token": "test-secret", "keepalive_interval": 2})])
        self.assertNotIn("test-secret", json.dumps(output.records))
        self.assertEqual([r["seq"] for r in output.records], list(range(1, len(output.records) + 1)))
        return status, device, output.records

    def test_guest_disconnect_preserves_key_event_and_marks_incomplete(self):
        status, device, records = self.exercise("disconnect")
        self.assertEqual(status, 1)
        self.assertEqual(device.resumed, [42])
        self.assertIn(42, device.killed)
        self.assertEqual([r["kind"] for r in records], ["ready", "launch", "api", "resumed", "error"])
        self.assertEqual(records[2]["call"]["parameters"][0]["value"], "00" * 16)

    def test_normal_termination_has_terminal_record(self):
        status, _, records = self.exercise("normal")
        self.assertEqual(status, 0)
        self.assertEqual(records[-1]["kind"], "end")

    def test_fail_closed_before_resume(self):
        for mode in ("wrong-pid", "wrong-os", "gating-failure"):
            with self.subTest(mode=mode):
                status, device, records = self.exercise(mode)
                self.assertEqual(status, 1)
                self.assertEqual(device.resumed, [])
                self.assertEqual(records[-1]["kind"], "error")


if __name__ == "__main__":
    unittest.main()
