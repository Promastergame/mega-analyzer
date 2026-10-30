package debugger

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClient_StartStop(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/debug/start" {
			res := struct {
				Ok     bool          `json:"ok"`
				Result StartResponse `json:"result"`
				Error  string        `json:"error"`
			}{
				Ok: true,
				Result: StartResponse{
					SessionID: 1234,
				},
			}
			json.NewEncoder(w).Encode(res)
			return
		}
		if r.URL.Path == "/api/v1/debug/stop" {
			w.Write([]byte(`{"ok": true}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	c := NewClient(ts.URL)
	res, err := c.Start(StartRequest{})
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	if res.SessionID != 1234 {
		t.Errorf("expected session 1234, got %d", res.SessionID)
	}

	err = c.Stop(1234)
	if err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
}

func TestClient_StepContinue(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		res := struct {
			Ok     bool         `json:"ok"`
			Result StepResponse `json:"result"`
		}{
			Ok: true,
			Result: StepResponse{
				StopReason: "breakpoint",
			},
		}
		json.NewEncoder(w).Encode(res)
	}))
	defer ts.Close()

	c := NewClient(ts.URL)
	res, err := c.Step(1234)
	if err != nil {
		t.Fatalf("Step failed: %v", err)
	}
	if res.StopReason != "breakpoint" {
		t.Errorf("expected breakpoint, got %v", res.StopReason)
	}

	res, err = c.Continue(1234)
	if err != nil {
		t.Fatalf("Continue failed: %v", err)
	}
	if res.StopReason != "breakpoint" {
		t.Errorf("expected breakpoint, got %v", res.StopReason)
	}
}

func TestClient_RegistersDisassemble(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/debug/registers" {
			res := struct {
				Ok     bool              `json:"ok"`
				Result RegistersResponse `json:"result"`
			}{
				Ok: true,
				Result: RegistersResponse{
					RAX: 1,
				},
			}
			json.NewEncoder(w).Encode(res)
			return
		}
		if r.URL.Path == "/api/v1/debug/disassemble" {
			res := struct {
				Ok     bool                `json:"ok"`
				Result DisassembleResponse `json:"result"`
			}{
				Ok: true,
				Result: DisassembleResponse{
					Lines: []DisassemblyLine{{Text: "nop"}},
				},
			}
			json.NewEncoder(w).Encode(res)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	c := NewClient(ts.URL)
	res, err := c.Registers(1234)
	if err != nil {
		t.Fatalf("Registers failed: %v", err)
	}
	if res.RAX != 1 {
		t.Errorf("expected rax=1, got %v", res.RAX)
	}

	dis, err := c.Disassemble(1234, 0x1000, 1)
	if err != nil {
		t.Fatalf("Disassemble failed: %v", err)
	}
	if len(dis.Lines) != 1 || dis.Lines[0].Text != "nop" {
		t.Errorf("unexpected instructions: %v", dis.Lines)
	}
}
