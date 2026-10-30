package debugger

import (
	"testing"
)

// ─── parseUint64 extended tests ────────────────────────────────────────────────

func TestParseUint64_Decimal_More(t *testing.T) {
	val, err := parseUint64("12345")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != 12345 {
		t.Errorf("expected 12345, got %d", val)
	}
}

func TestParseUint64_HexUpper_More(t *testing.T) {
	val, err := parseUint64("0XABCD")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != 0xabcd {
		t.Errorf("expected 0xabcd, got %d", val)
	}
}

func TestParseUint64_Zero_More(t *testing.T) {
	val, err := parseUint64("0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != 0 {
		t.Errorf("expected 0, got %d", val)
	}
}

// ─── NewClient ─────────────────────────────────────────────────────────────────

func TestNewClient_Initialization(t *testing.T) {
	c := NewClient("http://localhost:8080")
	if c == nil {
		t.Fatal("expected non-nil client")
	}
	if c.BaseURL != "http://localhost:8080" {
		t.Errorf("expected BaseURL set, got %q", c.BaseURL)
	}
}

// ─── Client.url ────────────────────────────────────────────────────────────────

func TestClient_url_Simple(t *testing.T) {
	c := NewClient("http://localhost:8080")
	result := c.url("/api/step")
	if result != "http://localhost:8080/api/step" {
		t.Errorf("expected 'http://localhost:8080/api/step', got %q", result)
	}
}

func TestClient_url_Complex(t *testing.T) {
	c := NewClient("https://debugger.internal:9339")
	result := c.url("/session/12345/register")
	expected := "https://debugger.internal:9339/session/12345/register"
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

// ─── StartRequest / StartResponse ──────────────────────────────────────────────

func TestStartRequest_FilePath(t *testing.T) {
	req := StartRequest{
		FilePath: "/path/to/binary",
	}
	if req.FilePath != "/path/to/binary" {
		t.Errorf("expected file path, got %q", req.FilePath)
	}
}

func TestStartRequest_WithEntry(t *testing.T) {
	entry := uint64(0x400000)
	req := StartRequest{
		FilePath: "/bin/app",
		Entry:    &entry,
	}
	if req.Entry == nil {
		t.Error("expected entry to be set")
	}
	if *req.Entry != 0x400000 {
		t.Errorf("expected entry 0x400000, got 0x%x", *req.Entry)
	}
}

func TestStartResponse_Ok(t *testing.T) {
	resp := StartResponse{
		Ok:        true,
		SessionID: 12345,
	}
	if !resp.Ok {
		t.Error("expected Ok=true")
	}
	if resp.SessionID != 12345 {
		t.Errorf("expected session ID 12345, got %d", resp.SessionID)
	}
}

func TestStartResponse_WithArch(t *testing.T) {
	resp := StartResponse{
		Ok:         true,
		EntryPoint: 0x400000,
		Arch:       "x86_64",
	}
	if resp.Arch != "x86_64" {
		t.Errorf("expected arch x86_64, got %q", resp.Arch)
	}
}

func TestStepResponse_WithInstruction(t *testing.T) {
	insn := "mov rax, [rbx]"
	resp := StepResponse{
		RIP:         0x400010,
		Instruction: &insn,
		StopReason:  "breakpoint",
	}
	if resp.RIP != 0x400010 {
		t.Errorf("expected RIP 0x400010, got 0x%x", resp.RIP)
	}
	if resp.Instruction == nil || *resp.Instruction != "mov rax, [rbx]" {
		t.Error("expected instruction set")
	}
}

func TestRegistersResponse_AllRegisters(t *testing.T) {
	resp := RegistersResponse{
		RAX: 0x1111111111111111,
		RBX: 0x2222222222222222,
		RSI: 0x5555555555555555,
		RSP: 0x8888888888888888,
	}
	if resp.RAX != 0x1111111111111111 {
		t.Errorf("expected RAX, got 0x%x", resp.RAX)
	}
	if resp.RSP != 0x8888888888888888 {
		t.Errorf("expected RSP, got 0x%x", resp.RSP)
	}
}

func TestDisassemblyLine_WithString(t *testing.T) {
	line := DisassemblyLine{
		Address: "0x400000",
		Raw:     "488b45f8",
		Text:    "mov rax, [rbp-8]",
		IsPC:    false,
	}
	if line.Address != "0x400000" {
		t.Errorf("expected address, got %s", line.Address)
	}
	if line.Text != "mov rax, [rbp-8]" {
		t.Errorf("expected text, got %q", line.Text)
	}
	if line.IsPC {
		t.Error("expected IsPC=false")
	}
}

func TestBreakpointResponse_Created(t *testing.T) {
	resp := BreakpointResponse{
		Ok:      true,
		ID:      1,
		Address: 0x400010,
	}
	if !resp.Ok {
		t.Error("expected Ok=true")
	}
	if resp.ID != 1 {
		t.Errorf("expected ID 1, got %d", resp.ID)
	}
}

func TestMemoryResponse_Read(t *testing.T) {
	resp := MemoryResponse{
		Ok:      true,
		Address: 0x7fff0000,
		Size:    64,
		Hex:     "48656c6c6f",
	}
	if !resp.Ok {
		t.Error("expected Ok=true")
	}
	if resp.Address != 0x7fff0000 {
		t.Errorf("expected address, got 0x%x", resp.Address)
	}
	if resp.Size != 64 {
		t.Errorf("expected size 64, got %d", resp.Size)
	}
}
