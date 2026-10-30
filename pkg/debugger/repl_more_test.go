package debugger

import (
	"io"
	"os"
	"testing"
)

type mockDebugger struct {
	lastSessionID uint64
}

func (m *mockDebugger) Start(filePath string, entry uint64) uint64 {
	m.lastSessionID = 42
	return 42
}

func (m *mockDebugger) Stop(sessionID uint64) {}

func (m *mockDebugger) Step(sessionID uint64) (map[string]interface{}, error) {
	return map[string]interface{}{
		"rip":         "0x1000",
		"instruction": "nop",
		"stop_reason": "step",
	}, nil
}

func (m *mockDebugger) Next(sessionID uint64) (map[string]interface{}, error) {
	return map[string]interface{}{
		"rip":         "0x1004",
		"instruction": "mov rax, 1",
		"stop_reason": "next",
	}, nil
}

func (m *mockDebugger) Continue(sessionID uint64) (map[string]interface{}, error) {
	return map[string]interface{}{
		"rip":         "0x2000",
		"instruction": "ret",
		"stop_reason": "breakpoint",
	}, nil
}

func (m *mockDebugger) Registers(sessionID uint64) (map[string]interface{}, error) {
	return map[string]interface{}{
		"rax": "0x123",
		"rip": "0x1000",
	}, nil
}

func (m *mockDebugger) Disassemble(sessionID uint64, address uint64, count int) (map[string]interface{}, error) {
	return map[string]interface{}{
		"lines": []interface{}{
			map[string]interface{}{
				"is_pc":   true,
				"address": "0x1000",
				"raw":     "90",
				"text":    "nop",
			},
		},
	}, nil
}

func (m *mockDebugger) ReadMemory(sessionID uint64, address uint64, size uint64) (map[string]interface{}, error) {
	return map[string]interface{}{
		"address": "0x1000",
		"hex":     "90 90",
	}, nil
}

func (m *mockDebugger) WriteMemory(sessionID uint64, address uint64, hex string) (map[string]interface{}, error) {
	return map[string]interface{}{
		"ok": true,
	}, nil
}

func (m *mockDebugger) SetRegister(sessionID uint64, reg string, value uint64) (map[string]interface{}, error) {
	return map[string]interface{}{
		"ok": true,
	}, nil
}

func (m *mockDebugger) Breakpoint(sessionID uint64, target string) (map[string]interface{}, error) {
	return map[string]interface{}{
		"id":      float64(1),
		"address": "0x1000",
	}, nil
}

func (m *mockDebugger) RemoveBreakpoint(sessionID uint64, id uint32) (map[string]interface{}, error) {
	return map[string]interface{}{
		"ok": true,
	}, nil
}

func (m *mockDebugger) TraceEnable(sessionID uint64, enabled bool) {}

func (m *mockDebugger) SetFlavor(sessionID uint64, flavor string) {}

func (m *mockDebugger) ReverseStep(sessionID uint64) (map[string]interface{}, error) {
	return map[string]interface{}{
		"rip":         "0x0ffc",
		"instruction": "xor rax, rax",
		"stop_reason": "reverse_step",
	}, nil
}

func (m *mockDebugger) ReverseContinue(sessionID uint64) (map[string]interface{}, error) {
	return map[string]interface{}{
		"rip":         "0x0500",
		"instruction": "int3",
		"stop_reason": "reverse_continue",
	}, nil
}

func (m *mockDebugger) ScanMemory(sessionID uint64, pattern string) (map[string]interface{}, error) {
	return map[string]interface{}{
		"count": float64(1),
		"hits": []interface{}{
			map[string]interface{}{
				"address": "0x1000",
			},
		},
	}, nil
}

func TestRunREPL_MockedInteractiveLoop(t *testing.T) {
	// Temporarily override the newDebuggerEngine function
	oldEngine := newDebuggerEngine
	newDebuggerEngine = func() DebuggerEngine {
		return &mockDebugger{}
	}
	defer func() {
		newDebuggerEngine = oldEngine
	}()

	// Capture and redirect Stdin
	oldStdin := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = r
	defer func() {
		os.Stdin = oldStdin
	}()

	// Write mock input commands sequentially
	commands := []string{
		"help",
		"step",
		"next",
		"continue",
		"regs",
		"disas 0x1000 5",
		"mem 0x1000 16",
		"bp main",
		"remove-bp 1",
		"patch 0x1000 9090",
		"set-reg rip 0x2000",
		"reverse-step",
		"reverse-continue",
		"trace on",
		"scan 90 90",
		"flavor att",
		"unknown-cmd-xyz",
		"",
		"quit",
	}

	go func() {
		defer w.Close()
		for _, cmd := range commands {
			_, _ = io.WriteString(w, cmd+"\n")
		}
	}()

	// Capture output to prevent console spam
	oldStdout := os.Stdout
	_, wOut, _ := os.Pipe()
	os.Stdout = wOut
	defer func() {
		wOut.Close()
		os.Stdout = oldStdout
	}()

	err = RunREPL("test_file_path.exe", "0x1000")
	if err != nil {
		t.Fatalf("unexpected REPL error: %v", err)
	}
}

func TestRunREPL_EntryParsing(t *testing.T) {
	// Temporarily override the newDebuggerEngine function
	oldEngine := newDebuggerEngine
	newDebuggerEngine = func() DebuggerEngine {
		return &mockDebugger{}
	}
	defer func() {
		newDebuggerEngine = oldEngine
	}()

	// Mock stdin immediately quitting
	oldStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r
	defer func() {
		os.Stdin = oldStdin
	}()
	_, _ = io.WriteString(w, "quit\n")
	w.Close()

	// Capture output
	oldStdout := os.Stdout
	_, wOut, _ := os.Pipe()
	os.Stdout = wOut
	defer func() {
		wOut.Close()
		os.Stdout = oldStdout
	}()

	err := RunREPL("test.exe", "0X1000")
	if err != nil {
		t.Fatalf("unexpected entry error: %v", err)
	}
}
