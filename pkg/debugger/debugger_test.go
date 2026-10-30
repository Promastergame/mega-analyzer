package debugger

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestNewClient(t *testing.T) {
	c := NewClient("http://localhost:8080")
	if c.BaseURL != "http://localhost:8080" {
		t.Errorf("Expected base URL, got %s", c.BaseURL)
	}
}

func TestDebuggerClientAllEndpoints(t *testing.T) {
	// Start local mock HTTP server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		path := r.URL.Path
		switch path {
		case "/api/v1/debug/start":
			w.Write([]byte(`{"ok":true,"result":{"ok":true,"session_id":123,"entry_point":4096,"arch":"x86_64"}}`))
		case "/api/v1/debug/stop":
			w.Write([]byte(`{"ok":true}`))
		case "/api/v1/debug/step", "/api/v1/debug/continue", "/api/v1/debug/reverse_step", "/api/v1/debug/reverse_continue":
			w.Write([]byte(`{"ok":true,"result":{"rip":4100,"instruction":"nop","stop_reason":"breakpoint"}}`))
		case "/api/v1/debug/registers":
			w.Write([]byte(`{"ok":true,"result":{"rip":4100,"rax":1,"rbx":2}}`))
		case "/api/v1/debug/disassemble":
			w.Write([]byte(`{"ok":true,"result":{"lines":[{"address":"0x1000","raw":"90","text":"nop","is_pc":true}]}}`))
		case "/api/v1/debug/memory":
			w.Write([]byte(`{"ok":true,"result":{"ok":true,"address":4096,"hex":"9090","size":2}}`))
		case "/api/v1/debug/breakpoint":
			w.Write([]byte(`{"ok":true,"result":{"ok":true,"id":1,"address":4100}}`))
		case "/api/v1/debug/remove_bp", "/api/v1/debug/flavor", "/api/v1/debug/patch", "/api/v1/debug/register", "/api/v1/debug/trace":
			w.Write([]byte(`{"ok":true}`))
		case "/api/v1/debug/breakpoints":
			w.Write([]byte(`{"ok":true,"result":{"breakpoints":[{"ok":true,"id":1,"address":4100}]}}`))
		case "/api/v1/debug/scan":
			w.Write([]byte(`{"ok":true,"result":{"hits":[{"address":4096}],"count":1}}`))
		default:
			w.Write([]byte(`{"ok":false,"error":"unknown path"}`))
		}
	}))
	defer ts.Close()

	c := NewClient(ts.URL)

	// 1. Start
	entry := uint64(4096)
	startRes, err := c.Start(StartRequest{FilePath: "test.exe", Entry: &entry})
	if err != nil {
		t.Fatal(err)
	}
	if startRes.SessionID != 123 {
		t.Errorf("Expected SessionID 123, got %d", startRes.SessionID)
	}

	// Start error case
	tsErr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":false,"error":"start_error_msg"}`))
	}))
	defer tsErr.Close()
	cErr := NewClient(tsErr.URL)
	_, err = cErr.Start(StartRequest{FilePath: "test.exe"})
	if err == nil || !strings.Contains(err.Error(), "start_error_msg") {
		t.Errorf("Expected start error, got %v", err)
	}

	// 2. Stop
	err = c.Stop(123)
	if err != nil {
		t.Error(err)
	}

	// 3. Step
	stepRes, err := c.Step(123)
	if err != nil {
		t.Fatal(err)
	}
	if stepRes.RIP != 4100 {
		t.Errorf("Expected step RIP 4100, got %d", stepRes.RIP)
	}

	// 4. Continue
	contRes, err := c.Continue(123)
	if err != nil {
		t.Fatal(err)
	}
	if contRes.RIP != 4100 {
		t.Errorf("Expected continue RIP 4100, got %d", contRes.RIP)
	}

	// 5. Registers
	regsRes, err := c.Registers(123)
	if err != nil {
		t.Fatal(err)
	}
	if regsRes.RAX != 1 {
		t.Errorf("Expected RAX 1, got %d", regsRes.RAX)
	}

	// 6. Disassemble
	disasRes, err := c.Disassemble(123, 4096, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(disasRes.Lines) != 1 || disasRes.Lines[0].Text != "nop" {
		t.Errorf("Expected nop instruction: %v", disasRes)
	}

	// 7. ReadMemory
	memRes, err := c.ReadMemory(123, 4096, 2)
	if err != nil {
		t.Fatal(err)
	}
	if memRes.Hex != "9090" {
		t.Errorf("Expected Hex 9090, got %s", memRes.Hex)
	}

	// 8. SetBreakpoint
	bpRes, err := c.SetBreakpoint(123, "main")
	if err != nil {
		t.Fatal(err)
	}
	if bpRes.ID != 1 {
		t.Errorf("Expected bp ID 1, got %d", bpRes.ID)
	}

	// 9. RemoveBreakpoint
	err = c.RemoveBreakpoint(123, 1)
	if err != nil {
		t.Error(err)
	}

	// 10. ListBreakpoints
	bps, err := c.ListBreakpoints(123)
	if err != nil {
		t.Fatal(err)
	}
	if len(bps) != 1 || bps[0].ID != 1 {
		t.Errorf("Expected 1 breakpoint with ID 1, got %v", bps)
	}

	// 11. SetFlavor
	err = c.SetFlavor(123, "intel")
	if err != nil {
		t.Error(err)
	}

	// 12. PatchMemory
	err = c.PatchMemory(123, 4096, "9090")
	if err != nil {
		t.Error(err)
	}

	// 13. SetRegister
	err = c.SetRegister(123, "rax", 5)
	if err != nil {
		t.Error(err)
	}

	// 14. ScanMemory
	hits, err := c.ScanMemory(123, "9090")
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0] != 4096 {
		t.Errorf("Expected scan hit at 4096, got %v", hits)
	}

	// 15. TraceEnable
	err = c.TraceEnable(123, true)
	if err != nil {
		t.Error(err)
	}

	// 16. ReverseStep
	revStep, err := c.ReverseStep(123)
	if err != nil {
		t.Fatal(err)
	}
	if revStep.RIP != 4100 {
		t.Errorf("Expected reverse step RIP 4100, got %d", revStep.RIP)
	}

	// 17. ReverseContinue
	revCont, err := c.ReverseContinue(123)
	if err != nil {
		t.Fatal(err)
	}
	if revCont.RIP != 4100 {
		t.Errorf("Expected reverse continue RIP 4100, got %d", revCont.RIP)
	}
}

func TestRunREPLInteractive(t *testing.T) {
	// Setup Stdin simulation with all commands to feed RunREPL loop
	r, w, _ := os.Pipe()
	oldStdin := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = oldStdin }()

	// Commands list
	cmds := []string{
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
		"unknown-command",
		"quit",
	}

	w.Write([]byte(strings.Join(cmds, "\n") + "\n"))

	// We recover from any missing DLL DLL-load panics inside native.NewNative()
	defer func() {
		recover()
	}()

	_ = RunREPL("dummy.exe", "0x1000")
}

func TestParseUint64(t *testing.T) {
	v, err := parseUint64("12345")
	if err != nil || v != 12345 {
		t.Errorf("Expected 12345, got %d (err: %v)", v, err)
	}

	v, err = parseUint64("0x10")
	if err != nil || v != 16 {
		t.Errorf("Expected 16, got %d (err: %v)", v, err)
	}
}

func TestREPLHelpers(t *testing.T) {
	// Test unwrapResult
	m := map[string]interface{}{
		"result": map[string]interface{}{"foo": "bar"},
	}
	unwrapped := unwrapResult(m)
	if unwrapped["foo"] != "bar" {
		t.Errorf("Expected foo = bar, got %v", unwrapped)
	}

	// Print functions should not panic
	printStep(map[string]interface{}{"rip": float64(100), "instruction": "nop", "stop_reason": "bp"})
	printRegs(map[string]interface{}{"rax": float64(1), "flags": map[string]interface{}{"zf": true}})
	printMem(map[string]interface{}{"address": float64(100), "hex": "9090"})
	printScan(map[string]interface{}{"count": float64(1), "hits": []interface{}{map[string]interface{}{"address": float64(100)}}})

	line := map[string]interface{}{"address": "0x1000", "raw": "90", "text": "nop", "is_pc": true}
	printDisas(map[string]interface{}{"lines": []interface{}{line}})
}
