package correlation

import (
	"testing"
	"time"
)

func TestSignal_HasTag(t *testing.T) {
	s := &Signal{Tags: []string{"jit", "controllable"}}
	if !s.HasTag("jit") {
		t.Fatal("should have tag 'jit'")
	}
	if !s.HasTag("controllable") {
		t.Fatal("should have tag 'controllable'")
	}
	if s.HasTag("nonexistent") {
		t.Fatal("should not have tag 'nonexistent'")
	}
}

func TestSignal_HasTag_Nil(t *testing.T) {
	var s *Signal
	if s.HasTag("anything") {
		t.Fatal("nil signal should not have any tag")
	}
}

func TestSignal_HasTag_Empty(t *testing.T) {
	s := &Signal{}
	if s.HasTag("x") {
		t.Fatal("signal with no tags should not have any tag")
	}
}

func TestSignal_AddTag(t *testing.T) {
	s := &Signal{}
	s.AddTag("new_tag")
	if !s.HasTag("new_tag") {
		t.Fatal("should have added tag")
	}
	if len(s.Tags) != 1 {
		t.Fatalf("expected 1 tag, got %d", len(s.Tags))
	}
}

func TestSignal_AddTag_NoDuplicate(t *testing.T) {
	s := &Signal{Tags: []string{"existing"}}
	s.AddTag("existing")
	if len(s.Tags) != 1 {
		t.Fatalf("should not duplicate, got %d tags", len(s.Tags))
	}
}

func TestSignal_AddTag_EmptyString(t *testing.T) {
	s := &Signal{}
	s.AddTag("")
	if len(s.Tags) != 0 {
		t.Fatal("should not add empty tag")
	}
}

func TestSignal_AddTag_Nil(t *testing.T) {
	var s *Signal
	s.AddTag("x") // should not panic
}

func TestSignal_IsRuntime(t *testing.T) {
	runtimeKinds := []SignalKind{
		KindMemory, KindNetwork, KindBehavior, KindExploit,
		KindFile, KindRegistry, KindAPI,
	}
	for _, k := range runtimeKinds {
		s := &Signal{Kind: k}
		if !s.IsRuntime() {
			t.Fatalf("Kind %s should be runtime", k)
		}
	}
}

func TestSignal_IsRuntime_Static(t *testing.T) {
	s := &Signal{Kind: KindAudit}
	if s.IsRuntime() {
		t.Fatal("KindAudit should not be runtime")
	}
}

func TestSignal_IsRuntime_Nil(t *testing.T) {
	var s *Signal
	if s.IsRuntime() {
		t.Fatal("nil signal should not be runtime")
	}
}

func TestSignal_IsStatic(t *testing.T) {
	s := &Signal{Kind: KindAudit}
	if !s.IsStatic() {
		t.Fatal("KindAudit should be static")
	}
}

func TestSignal_IsStatic_Runtime(t *testing.T) {
	s := &Signal{Kind: KindMemory}
	if s.IsStatic() {
		t.Fatal("KindMemory should not be static")
	}
}

func TestSignal_IsStatic_Nil(t *testing.T) {
	var s *Signal
	if s.IsStatic() {
		t.Fatal("nil signal should not be static")
	}
}

func TestSignal_ProcessKey_Static(t *testing.T) {
	s := &Signal{Kind: KindAudit, PID: 0}
	if s.ProcessKey() != "static" {
		t.Fatalf("static signal ProcessKey = %q, want 'static'", s.ProcessKey())
	}
}

func TestSignal_ProcessKey_Runtime(t *testing.T) {
	s := &Signal{Kind: KindMemory, PID: 1234, ProcessName: "evil.exe"}
	key := s.ProcessKey()
	if key == "" || key == "static" {
		t.Fatalf("runtime signal should have non-static key, got %q", key)
	}
}

func TestSignal_ProcessKey_RuntimeNoPID(t *testing.T) {
	s := &Signal{Kind: KindAudit, PID: 0}
	if s.ProcessKey() != "static" {
		t.Fatalf("PID=0 should be 'static', got %q", s.ProcessKey())
	}
}

func TestSignal_ProcessKey_Nil(t *testing.T) {
	var s *Signal
	if s.ProcessKey() != "" {
		t.Fatalf("nil signal ProcessKey should be empty, got %q", s.ProcessKey())
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Context tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestGroup_Nil(t *testing.T) {
	ctx := Group(nil)
	if ctx == nil {
		t.Fatal("Group(nil) should return non-nil context")
	}
	if len(ctx.Processes) != 0 {
		t.Fatalf("expected 0 processes, got %d", len(ctx.Processes))
	}
	if len(ctx.Static.Signals) != 0 {
		t.Fatalf("expected 0 static signals, got %d", len(ctx.Static.Signals))
	}
}

func TestGroup_StaticSignals(t *testing.T) {
	signals := []*Signal{
		{ID: "1", Kind: KindAudit, Type: TypeHardcodedSecret},
		{ID: "2", Kind: KindAudit, Type: TypeWeakCrypto},
	}
	ctx := Group(signals)
	if len(ctx.Static.Signals) != 2 {
		t.Fatalf("expected 2 static signals, got %d", len(ctx.Static.Signals))
	}
	if len(ctx.Processes) != 0 {
		t.Fatalf("expected 0 processes for static-only signals, got %d", len(ctx.Processes))
	}
}

func TestGroup_RuntimeSignals(t *testing.T) {
	t0 := time.Now()
	signals := []*Signal{
		{ID: "1", Kind: KindMemory, Type: TypeRWXMemory, PID: 100, ProcessName: "proc", Timestamp: t0},
		{ID: "2", Kind: KindMemory, Type: TypeMemoryWrite, PID: 100, ProcessName: "proc", Timestamp: t0.Add(time.Second)},
		{ID: "3", Kind: KindNetwork, Type: TypePublicEgress, PID: 200, ProcessName: "net", Timestamp: t0},
	}
	ctx := Group(signals)
	if len(ctx.Processes) != 2 {
		t.Fatalf("expected 2 processes, got %d", len(ctx.Processes))
	}
}

func TestGroup_MixedSignals(t *testing.T) {
	t0 := time.Now()
	signals := []*Signal{
		{ID: "1", Kind: KindAudit, Type: TypeHardcodedSecret},
		{ID: "2", Kind: KindMemory, Type: TypeRWXMemory, PID: 100, ProcessName: "proc", Timestamp: t0},
	}
	ctx := Group(signals)
	if len(ctx.Static.Signals) != 1 {
		t.Fatalf("expected 1 static signal, got %d", len(ctx.Static.Signals))
	}
	if len(ctx.Processes) != 1 {
		t.Fatalf("expected 1 process, got %d", len(ctx.Processes))
	}
}

func TestGroup_NilSignalsSkipped(t *testing.T) {
	signals := []*Signal{nil, {ID: "1", Kind: KindAudit, Type: "x"}, nil}
	ctx := Group(signals)
	if len(ctx.Static.Signals) != 1 {
		t.Fatalf("expected 1 static signal (nil skipped), got %d", len(ctx.Static.Signals))
	}
}

func TestExecutionContext_SignalsOfType_New(t *testing.T) {
	signals := []*Signal{
		{ID: "1", Kind: KindAudit, Type: TypeHardcodedSecret},
		{ID: "2", Kind: KindAudit, Type: TypeWeakCrypto},
		{ID: "3", Kind: KindAudit, Type: TypeHardcodedSecret},
	}
	ctx := Group(signals)
	secrets := ctx.SignalsOfType(TypeHardcodedSecret)
	if len(secrets) != 2 {
		t.Fatalf("expected 2 hardcoded_secret signals, got %d", len(secrets))
	}
}

func TestExecutionContext_SignalsOfType_Nil(t *testing.T) {
	var ctx *ExecutionContext
	result := ctx.SignalsOfType("any")
	if result != nil {
		t.Fatalf("nil context should return nil, got %v", result)
	}
}

func TestExecutionContext_SignalsOfKind(t *testing.T) {
	t0 := time.Now()
	signals := []*Signal{
		{ID: "1", Kind: KindMemory, PID: 1, Timestamp: t0},
		{ID: "2", Kind: KindNetwork, PID: 1, Timestamp: t0},
		{ID: "3", Kind: KindMemory, PID: 1, Timestamp: t0},
	}
	ctx := Group(signals)
	mem := ctx.SignalsOfKind(KindMemory)
	if len(mem) != 2 {
		t.Fatalf("expected 2 memory signals, got %d", len(mem))
	}
}

func TestExecutionContext_SignalsOfKind_Nil(t *testing.T) {
	var ctx *ExecutionContext
	result := ctx.SignalsOfKind(KindMemory)
	if result != nil {
		t.Fatalf("nil context should return nil, got %v", result)
	}
}

func TestExecutionContext_HasType_Signal(t *testing.T) {
	signals := []*Signal{
		{ID: "1", Kind: KindAudit, Type: TypeHardcodedSecret},
	}
	ctx := Group(signals)
	if !ctx.HasType(TypeHardcodedSecret) {
		t.Fatal("should have type hardcoded_secret")
	}
	if ctx.HasType(TypeWeakCrypto) {
		t.Fatal("should not have type weak_crypto")
	}
}

func TestExecutionContext_HasKind(t *testing.T) {
	signals := []*Signal{
		{ID: "1", Kind: KindAudit, Type: "x"},
	}
	ctx := Group(signals)
	if !ctx.HasKind(KindAudit) {
		t.Fatal("should have kind audit")
	}
	if ctx.HasKind(KindMemory) {
		t.Fatal("should not have kind memory")
	}
}

func TestExecutionContext_Process(t *testing.T) {
	t0 := time.Now()
	signals := []*Signal{
		{ID: "1", Kind: KindMemory, PID: 100, ProcessName: "proc", Timestamp: t0},
	}
	ctx := Group(signals)
	// Get the key from the signal
	key := signals[0].ProcessKey()
	pc := ctx.Process(key)
	if pc == nil {
		t.Fatal("expected non-nil ProcessContext")
	}
	if pc.PID != 100 {
		t.Fatalf("PID = %d, want 100", pc.PID)
	}
}

func TestExecutionContext_Process_Nil(t *testing.T) {
	var ctx *ExecutionContext
	if ctx.Process("any") != nil {
		t.Fatal("nil context should return nil")
	}
}

func TestExecutionContext_Process_NotFound(t *testing.T) {
	ctx := Group(nil)
	if ctx.Process("nonexistent") != nil {
		t.Fatal("should return nil for unknown key")
	}
}

func TestFilter(t *testing.T) {
	signals := []*Signal{
		{ID: "1", Severity: 3},
		{ID: "2", Severity: 7},
		{ID: "3", Severity: 5},
		{ID: "4", Severity: 9},
	}
	high := Filter(signals, func(s *Signal) bool { return s.Severity >= 7 })
	if len(high) != 2 {
		t.Fatalf("expected 2 high-severity signals, got %d", len(high))
	}
}

func TestFilter_Empty(t *testing.T) {
	result := Filter(nil, func(s *Signal) bool { return true })
	if len(result) != 0 {
		t.Fatalf("expected empty, got %d", len(result))
	}
}

func TestFilter_NoneMatch(t *testing.T) {
	signals := []*Signal{{ID: "1", Severity: 1}}
	result := Filter(signals, func(s *Signal) bool { return s.Severity > 10 })
	if len(result) != 0 {
		t.Fatalf("expected 0, got %d", len(result))
	}
}
