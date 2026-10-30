package debugger

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"mega-analyzer/pkg/debugger/native"
)

func captureStdout(f func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	f()

	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	io.Copy(&buf, r)
	return buf.String()
}

func TestPrintHelp(t *testing.T) {
	out := captureStdout(printHelp)
	if !strings.Contains(out, "step, s") {
		t.Error("missing help text")
	}
}

func TestPrintStep(t *testing.T) {
	res := map[string]interface{}{
		"result": map[string]interface{}{
			"rip":         "0x100",
			"instruction": "nop",
			"stop_reason": "breakpoint",
		},
	}
	out := captureStdout(func() { printStep(res) })
	if !strings.Contains(out, "RIP=0x100") || !strings.Contains(out, "reason=breakpoint") {
		t.Errorf("bad step output: %s", out)
	}
}

func TestPrintRegs(t *testing.T) {
	res := map[string]interface{}{
		"result": map[string]interface{}{
			"rax": "1",
			"rbx": "2",
			"flags": map[string]interface{}{
				"zf": true,
			},
		},
	}
	out := captureStdout(func() { printRegs(res) })
	if !strings.Contains(out, "RAX=1") || !strings.Contains(out, "ZF=true") {
		t.Errorf("bad regs output: %s", out)
	}
}

func TestPrintDisas(t *testing.T) {
	res := map[string]interface{}{
		"result": map[string]interface{}{
			"lines": []interface{}{
				map[string]interface{}{
					"is_pc":   true,
					"address": "0x100",
					"raw":     "90",
					"text":    "nop",
				},
			},
		},
	}
	out := captureStdout(func() { printDisas(res) })
	if !strings.Contains(out, "> 0x100") || !strings.Contains(out, "nop") {
		t.Errorf("bad disas output: %s", out)
	}
}

func TestPrintMem(t *testing.T) {
	res := map[string]interface{}{
		"result": map[string]interface{}{
			"address": "0x100",
			"hex":     "90 90",
		},
	}
	out := captureStdout(func() { printMem(res) })
	if !strings.Contains(out, "0x100: 90 90") {
		t.Errorf("bad mem output: %s", out)
	}
}

func TestPrintScan(t *testing.T) {
	res := map[string]interface{}{
		"result": map[string]interface{}{
			"count": float64(1),
			"hits": []interface{}{
				map[string]interface{}{
					"address": "0x200",
				},
			},
		},
	}
	out := captureStdout(func() { printScan(res) })
	if !strings.Contains(out, "hit at 0x200") {
		t.Errorf("bad scan output: %s", out)
	}
}

func TestUnwrapResult(t *testing.T) {
	res := map[string]interface{}{
		"ok": true,
	}
	unwrapped := unwrapResult(res)
	if unwrapped["ok"] != true {
		t.Error("unwrap failed")
	}
}

func TestUnwrapResult_Direct(t *testing.T) {
	res := map[string]interface{}{
		"rip": "0x100",
	}
	r := unwrapResult(res)
	if r["rip"] != "0x100" {
		t.Errorf("expected direct value, got %v", r)
	}
}

func TestRunREPL_StartFailure(t *testing.T) {
	err := RunREPL("nonexistent_file_path_12345.exe", "0x1000")
	if err == nil {
		t.Error("expected error starting debugger for nonexistent file")
	} else if !strings.Contains(err.Error(), "failed to start debugger session") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestRunREPL_BadEntry(t *testing.T) {
	err := RunREPL("some_file", "invalid_hex_val")
	if err == nil {
		t.Error("expected error parsing bad entry point")
	} else if !strings.Contains(err.Error(), "bad entry point") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPrintRegs_MissingFlags(t *testing.T) {
	res := map[string]interface{}{
		"rax": "123",
	}
	out := captureStdout(func() { printRegs(res) })
	if !strings.Contains(out, "RAX=123") {
		t.Errorf("expected RAX=123, got %q", out)
	}
}

func TestPrintDisas_InvalidLinesType(t *testing.T) {
	res := map[string]interface{}{
		"lines": "not a slice",
	}
	out := captureStdout(func() { printDisas(res) })
	_ = out // should not panic
}

func TestAutoContext_InvalidSession(t *testing.T) {
	defer func() {
		recover()
	}()
	eng := native.NewNative()
	autoContext(eng, 99999) // should not panic
}

func TestPrintScan_NonMapHits(t *testing.T) {
	res := map[string]interface{}{
		"count": float64(1),
		"hits": []interface{}{
			"0x1000",
		},
	}
	out := captureStdout(func() { printScan(res) })
	if !strings.Contains(out, "0x1000") {
		t.Errorf("expected hit 0x1000, got %q", out)
	}
}
