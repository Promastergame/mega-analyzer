package debugger

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClient_AdditionalMethods(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/debug/breakpoints":
			res := struct {
				Ok     bool `json:"ok"`
				Result struct {
					Breakpoints []BreakpointResponse `json:"breakpoints"`
				} `json:"result"`
			}{
				Ok: true,
			}
			res.Result.Breakpoints = []BreakpointResponse{
				{Ok: true, ID: 1, Address: 0x1000},
			}
			json.NewEncoder(w).Encode(res)
		case "/api/v1/debug/breakpoint":
			res := struct {
				Ok     bool               `json:"ok"`
				Result BreakpointResponse `json:"result"`
			}{
				Ok: true,
				Result: BreakpointResponse{
					Ok:      true,
					ID:      1,
					Address: 0x1000,
				},
			}
			json.NewEncoder(w).Encode(res)
		case "/api/v1/debug/remove_bp":
			w.Write([]byte(`{"ok": true}`))
		case "/api/v1/debug/flavor":
			w.Write([]byte(`{"ok": true}`))
		case "/api/v1/debug/patch":
			w.Write([]byte(`{"ok": true}`))
		case "/api/v1/debug/register":
			w.Write([]byte(`{"ok": true}`))
		case "/api/v1/debug/scan":
			res := struct {
				Ok     bool `json:"ok"`
				Result struct {
					Hits []struct {
						Address uint64 `json:"address"`
					} `json:"hits"`
					Count int `json:"count"`
				} `json:"result"`
			}{
				Ok: true,
			}
			res.Result.Count = 1
			res.Result.Hits = []struct {
				Address uint64 `json:"address"`
			}{{Address: 0x2000}}
			json.NewEncoder(w).Encode(res)
		case "/api/v1/debug/trace":
			w.Write([]byte(`{"ok": true}`))
		case "/api/v1/debug/reverse_step":
			res := struct {
				Ok     bool         `json:"ok"`
				Result StepResponse `json:"result"`
			}{
				Ok: true,
				Result: StepResponse{
					RIP:        0x1000,
					StopReason: "step",
				},
			}
			json.NewEncoder(w).Encode(res)
		case "/api/v1/debug/reverse_continue":
			res := struct {
				Ok     bool         `json:"ok"`
				Result StepResponse `json:"result"`
			}{
				Ok: true,
				Result: StepResponse{
					RIP:        0x1000,
					StopReason: "breakpoint",
				},
			}
			json.NewEncoder(w).Encode(res)
		case "/api/v1/debug/memory":
			res := struct {
				Ok     bool           `json:"ok"`
				Result MemoryResponse `json:"result"`
			}{
				Ok: true,
				Result: MemoryResponse{
					Ok:      true,
					Address: 0x1000,
					Size:    8,
					Hex:     "9090",
				},
			}
			json.NewEncoder(w).Encode(res)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	c := NewClient(ts.URL)

	// Test ListBreakpoints
	bps, err := c.ListBreakpoints(123)
	if err != nil {
		t.Fatalf("ListBreakpoints failed: %v", err)
	}
	if len(bps) != 1 || bps[0].ID != 1 {
		t.Errorf("Unexpected breakpoints: %v", bps)
	}

	// Test SetBreakpoint
	bp, err := c.SetBreakpoint(123, "main")
	if err != nil {
		t.Fatalf("SetBreakpoint failed: %v", err)
	}
	if bp.ID != 1 {
		t.Errorf("Unexpected breakpoint: %v", bp)
	}

	// Test RemoveBreakpoint
	err = c.RemoveBreakpoint(123, 1)
	if err != nil {
		t.Fatalf("RemoveBreakpoint failed: %v", err)
	}

	// Test SetFlavor
	err = c.SetFlavor(123, "intel")
	if err != nil {
		t.Fatalf("SetFlavor failed: %v", err)
	}

	// Test PatchMemory
	err = c.PatchMemory(123, 0x1000, "9090")
	if err != nil {
		t.Fatalf("PatchMemory failed: %v", err)
	}

	// Test SetRegister
	err = c.SetRegister(123, "rax", 1)
	if err != nil {
		t.Fatalf("SetRegister failed: %v", err)
	}

	// Test ScanMemory
	hits, err := c.ScanMemory(123, "9090")
	if err != nil {
		t.Fatalf("ScanMemory failed: %v", err)
	}
	if len(hits) != 1 || hits[0] != 0x2000 {
		t.Errorf("Unexpected scan hits: %v", hits)
	}

	// Test TraceEnable
	err = c.TraceEnable(123, true)
	if err != nil {
		t.Fatalf("TraceEnable failed: %v", err)
	}

	// Test ReverseStep
	rs, err := c.ReverseStep(123)
	if err != nil {
		t.Fatalf("ReverseStep failed: %v", err)
	}
	if rs.RIP != 0x1000 {
		t.Errorf("Unexpected ReverseStep RIP: 0x%x", rs.RIP)
	}

	// Test ReverseContinue
	rc, err := c.ReverseContinue(123)
	if err != nil {
		t.Fatalf("ReverseContinue failed: %v", err)
	}
	if rc.RIP != 0x1000 {
		t.Errorf("Unexpected ReverseContinue RIP: 0x%x", rc.RIP)
	}

	// Test ReadMemory
	mem, err := c.ReadMemory(123, 0x1000, 8)
	if err != nil {
		t.Fatalf("ReadMemory failed: %v", err)
	}
	if mem.Hex != "9090" {
		t.Errorf("Unexpected ReadMemory Hex: %s", mem.Hex)
	}
}

func TestClient_ErrorResponses(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok": false, "error": "mock error message"}`))
	}))
	defer ts.Close()

	c := NewClient(ts.URL)

	_, err := c.Start(StartRequest{})
	if err == nil || err.Error() != "start failed: mock error message" {
		t.Errorf("expected error, got: %v", err)
	}

	_, err = c.Step(123)
	if err == nil || err.Error() != "step failed: mock error message" {
		t.Errorf("expected error, got: %v", err)
	}

	_, err = c.Continue(123)
	if err == nil || err.Error() != "continue failed: mock error message" {
		t.Errorf("expected error, got: %v", err)
	}

	_, err = c.Registers(123)
	if err == nil || err.Error() != "registers failed: mock error message" {
		t.Errorf("expected error, got: %v", err)
	}

	_, err = c.Disassemble(123, 0x1000, 5)
	if err == nil || err.Error() != "disassemble failed: mock error message" {
		t.Errorf("expected error, got: %v", err)
	}

	_, err = c.ReadMemory(123, 0x1000, 8)
	if err == nil || err.Error() != "read_memory failed: mock error message" {
		t.Errorf("expected error, got: %v", err)
	}

	_, err = c.SetBreakpoint(123, "main")
	if err == nil || err.Error() != "breakpoint failed: mock error message" {
		t.Errorf("expected error, got: %v", err)
	}

	_, err = c.ListBreakpoints(123)
	if err == nil || err.Error() != "list breakpoints failed: mock error message" {
		t.Errorf("expected error, got: %v", err)
	}

	_, err = c.ScanMemory(123, "9090")
	if err == nil || err.Error() != "scan failed: mock error message" {
		t.Errorf("expected error, got: %v", err)
	}

	_, err = c.ReverseStep(123)
	if err == nil || err.Error() != "reverse_step failed: mock error message" {
		t.Errorf("expected error, got: %v", err)
	}

	_, err = c.ReverseContinue(123)
	if err == nil || err.Error() != "reverse_continue failed: mock error message" {
		t.Errorf("expected error, got: %v", err)
	}
}
