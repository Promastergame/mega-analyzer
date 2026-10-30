package debugger

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ─── error branch coverage for Start ─────────────────────────────────────────

func TestClient_Start_ErrorEnvelope(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":false,"error":"session_limit_reached"}`))
	}))
	defer ts.Close()
	c := NewClient(ts.URL)
	_, err := c.Start(StartRequest{FilePath: "a.exe"})
	if err == nil || !strings.Contains(err.Error(), "session_limit_reached") {
		t.Errorf("expected session_limit_reached, got %v", err)
	}
}

func TestClient_Start_BadJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`not-json`))
	}))
	defer ts.Close()
	c := NewClient(ts.URL)
	_, err := c.Start(StartRequest{FilePath: "a.exe"})
	if err == nil {
		t.Error("expected JSON parse error")
	}
}

// ─── error branches for Step / Continue / ReverseStep / ReverseContinue ──────

func TestClient_Step_ErrorEnvelope(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":false,"error":"step_failed"}`))
	}))
	defer ts.Close()
	c := NewClient(ts.URL)
	_, err := c.Step(1)
	if err == nil || !strings.Contains(err.Error(), "step_failed") {
		t.Errorf("expected step_failed, got %v", err)
	}
}

func TestClient_Continue_ErrorEnvelope(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":false,"error":"continue_failed"}`))
	}))
	defer ts.Close()
	c := NewClient(ts.URL)
	_, err := c.Continue(1)
	if err == nil || !strings.Contains(err.Error(), "continue_failed") {
		t.Errorf("expected continue_failed, got %v", err)
	}
}

func TestClient_ReverseStep_ErrorEnvelope(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":false,"error":"reverse_step_failed"}`))
	}))
	defer ts.Close()
	c := NewClient(ts.URL)
	_, err := c.ReverseStep(1)
	if err == nil || !strings.Contains(err.Error(), "reverse_step_failed") {
		t.Errorf("expected reverse_step_failed, got %v", err)
	}
}

func TestClient_ReverseContinue_ErrorEnvelope(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":false,"error":"rc_failed"}`))
	}))
	defer ts.Close()
	c := NewClient(ts.URL)
	_, err := c.ReverseContinue(1)
	if err == nil || !strings.Contains(err.Error(), "rc_failed") {
		t.Errorf("expected rc_failed, got %v", err)
	}
}

// ─── error branches for Registers / Disassemble / ReadMemory / SetBreakpoint ─

func TestClient_Registers_ErrorEnvelope(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":false,"error":"regs_failed"}`))
	}))
	defer ts.Close()
	c := NewClient(ts.URL)
	_, err := c.Registers(1)
	if err == nil || !strings.Contains(err.Error(), "regs_failed") {
		t.Errorf("expected regs_failed, got %v", err)
	}
}

func TestClient_Disassemble_ErrorEnvelope(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":false,"error":"disas_failed"}`))
	}))
	defer ts.Close()
	c := NewClient(ts.URL)
	_, err := c.Disassemble(1, 0x1000, 5)
	if err == nil || !strings.Contains(err.Error(), "disas_failed") {
		t.Errorf("expected disas_failed, got %v", err)
	}
}

func TestClient_ReadMemory_ErrorEnvelope(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":false,"error":"read_memory_failed"}`))
	}))
	defer ts.Close()
	c := NewClient(ts.URL)
	_, err := c.ReadMemory(1, 0x1000, 16)
	if err == nil || !strings.Contains(err.Error(), "read_memory_failed") {
		t.Errorf("expected read_memory_failed, got %v", err)
	}
}

func TestClient_SetBreakpoint_ErrorEnvelope(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":false,"error":"bp_failed"}`))
	}))
	defer ts.Close()
	c := NewClient(ts.URL)
	_, err := c.SetBreakpoint(1, "main")
	if err == nil || !strings.Contains(err.Error(), "bp_failed") {
		t.Errorf("expected bp_failed, got %v", err)
	}
}

func TestClient_ListBreakpoints_ErrorEnvelope(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":false,"error":"list_bp_failed"}`))
	}))
	defer ts.Close()
	c := NewClient(ts.URL)
	_, err := c.ListBreakpoints(1)
	if err == nil || !strings.Contains(err.Error(), "list_bp_failed") {
		t.Errorf("expected list_bp_failed, got %v", err)
	}
}

func TestClient_ScanMemory_ErrorEnvelope(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":false,"error":"scan_failed"}`))
	}))
	defer ts.Close()
	c := NewClient(ts.URL)
	_, err := c.ScanMemory(1, "90??90")
	if err == nil || !strings.Contains(err.Error(), "scan_failed") {
		t.Errorf("expected scan_failed, got %v", err)
	}
}

// ─── network-error branches (unreachable server) ──────────────────────────────

func TestClient_NetworkError_GetMethods(t *testing.T) {
	c := NewClient("http://127.0.0.1:1") // nothing listens on port 1
	if _, err := c.Registers(1); err == nil {
		t.Error("expected network error for Registers")
	}
	if _, err := c.Disassemble(1, 0, 1); err == nil {
		t.Error("expected network error for Disassemble")
	}
	if _, err := c.ReadMemory(1, 0, 4); err == nil {
		t.Error("expected network error for ReadMemory")
	}
	if _, err := c.ListBreakpoints(1); err == nil {
		t.Error("expected network error for ListBreakpoints")
	}
	if _, err := c.ScanMemory(1, "90"); err == nil {
		t.Error("expected network error for ScanMemory")
	}
}

func TestClient_NetworkError_PostMethods(t *testing.T) {
	c := NewClient("http://127.0.0.1:1")
	if _, err := c.Start(StartRequest{FilePath: "x"}); err == nil {
		t.Error("expected network error for Start")
	}
	if err := c.Stop(1); err == nil {
		t.Error("expected network error for Stop")
	}
	if _, err := c.Step(1); err == nil {
		t.Error("expected network error for Step")
	}
	if _, err := c.Continue(1); err == nil {
		t.Error("expected network error for Continue")
	}
	if err := c.RemoveBreakpoint(1, 1); err == nil {
		t.Error("expected network error for RemoveBreakpoint")
	}
	if err := c.SetFlavor(1, "intel"); err == nil {
		t.Error("expected network error for SetFlavor")
	}
	if err := c.PatchMemory(1, 0, "9090"); err == nil {
		t.Error("expected network error for PatchMemory")
	}
	if err := c.SetRegister(1, "rax", 0); err == nil {
		t.Error("expected network error for SetRegister")
	}
	if err := c.TraceEnable(1, true); err == nil {
		t.Error("expected network error for TraceEnable")
	}
	if _, err := c.ReverseStep(1); err == nil {
		t.Error("expected network error for ReverseStep")
	}
	if _, err := c.ReverseContinue(1); err == nil {
		t.Error("expected network error for ReverseContinue")
	}
}

// ─── parseUint64 extra cases ──────────────────────────────────────────────────

func TestParseUint64_UpperCaseHex(t *testing.T) {
	v, err := parseUint64("0XFF")
	if err != nil || v != 255 {
		t.Errorf("0XFF should be 255, got %d err=%v", v, err)
	}
}

func TestParseUint64_Invalid(t *testing.T) {
	if _, err := parseUint64("not-a-number"); err == nil {
		t.Error("expected error for non-numeric input")
	}
	if _, err := parseUint64("0x"); err == nil {
		t.Error("expected error for bare 0x")
	}
}

// ─── print helpers: edge cases ────────────────────────────────────────────────

func TestPrintRegs_WithFlags(t *testing.T) {
	// Ensure printRegs doesn't panic when flags map is present
	m := map[string]interface{}{
		"result": map[string]interface{}{
			"rax": float64(42),
			"flags": map[string]interface{}{
				"zf": true, "sf": false, "cf": true, "of": false,
			},
		},
	}
	printRegs(m) // must not panic
}

func TestPrintRegs_WithoutFlags(t *testing.T) {
	m := map[string]interface{}{
		"rax": float64(1),
		// no flags key
	}
	printRegs(m) // must not panic
}

func TestPrintDisas_EmptyLines(t *testing.T) {
	m := map[string]interface{}{"lines": []interface{}{}}
	printDisas(m) // must not panic
}

func TestPrintDisas_NonPC(t *testing.T) {
	line := map[string]interface{}{
		"address": "0x2000", "raw": "cc", "text": "int3", "is_pc": false,
	}
	m := map[string]interface{}{"lines": []interface{}{line}}
	printDisas(m) // must not panic
}

func TestPrintScan_NoHits(t *testing.T) {
	m := map[string]interface{}{
		"count": float64(0),
		"hits":  []interface{}{},
	}
	printScan(m) // must not panic
}

func TestPrintScan_HitNotAMap(t *testing.T) {
	m := map[string]interface{}{
		"count": float64(1),
		"hits":  []interface{}{"0x1000"}, // not a map
	}
	printScan(m) // must not panic
}

func TestUnwrapResult_NoResultKey(t *testing.T) {
	m := map[string]interface{}{"foo": "bar"}
	out := unwrapResult(m)
	if out["foo"] != "bar" {
		t.Error("without 'result' key, unwrapResult should return original map")
	}
}

// ─── URL builder ──────────────────────────────────────────────────────────────

func TestClientURL(t *testing.T) {
	c := NewClient("http://localhost:8080")
	if got := c.url("/api/v1/debug/start"); got != "http://localhost:8080/api/v1/debug/start" {
		t.Errorf("url() = %q", got)
	}
}

// ─── JSON marshaling / request body correctness ───────────────────────────────

func TestClient_StartRequest_EntryOmitted(t *testing.T) {
	var captured []byte
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, r.ContentLength)
		r.Body.Read(buf)
		captured = buf
		w.Write([]byte(`{"ok":true,"result":{"ok":true,"session_id":1,"entry_point":0,"arch":"x86_64"}}`))
	}))
	defer ts.Close()

	c := NewClient(ts.URL)
	_, _ = c.Start(StartRequest{FilePath: "test.bin"})

	var body map[string]interface{}
	if err := json.Unmarshal(captured, &body); err != nil {
		t.Fatalf("request body not valid JSON: %v", err)
	}
	if _, hasEntry := body["entry"]; hasEntry {
		t.Error("entry field should be omitted when not set (omitempty)")
	}
}
