package ml

import (
	"testing"
)

// ─── MethodFlags HasFlag / SetFlag / ClearFlag / ToggleFlag ──────────────────

func TestMethodFlags_HasFlag_Set(t *testing.T) {
	var f MethodFlags
	f.SetFlag(FlagIsPublic)
	if !f.HasFlag(FlagIsPublic) {
		t.Error("HasFlag should return true after SetFlag")
	}
}

func TestMethodFlags_HasFlag_NotSet(t *testing.T) {
	var f MethodFlags
	if f.HasFlag(FlagIsPublic) {
		t.Error("HasFlag should return false on zero value")
	}
}

func TestMethodFlags_ClearFlag(t *testing.T) {
	var f MethodFlags
	f.SetFlag(FlagIsPublic)
	f.ClearFlag(FlagIsPublic)
	if f.HasFlag(FlagIsPublic) {
		t.Error("HasFlag should return false after ClearFlag")
	}
}

func TestMethodFlags_ToggleFlag_OnOff(t *testing.T) {
	var f MethodFlags
	f.ToggleFlag(FlagIsStatic)
	if !f.HasFlag(FlagIsStatic) {
		t.Error("should be set after first toggle")
	}
	f.ToggleFlag(FlagIsStatic)
	if f.HasFlag(FlagIsStatic) {
		t.Error("should be cleared after second toggle")
	}
}

func TestMethodFlags_MultipleFlags(t *testing.T) {
	var f MethodFlags
	f.SetFlag(FlagIsPublic)
	f.SetFlag(FlagIsStatic)
	f.SetFlag(FlagReturnsBoolean)
	if !f.HasFlag(FlagIsPublic) || !f.HasFlag(FlagIsStatic) || !f.HasFlag(FlagReturnsBoolean) {
		t.Error("all three flags should be set")
	}
	f.ClearFlag(FlagIsStatic)
	if f.HasFlag(FlagIsStatic) {
		t.Error("static flag should be cleared")
	}
	if !f.HasFlag(FlagIsPublic) {
		t.Error("public flag should still be set")
	}
}

// ─── MethodInfo.ToCompact / CompactMethodInfo.FromCompact ────────────────────

func TestMethodInfo_ToCompact_NoPanic(t *testing.T) {
	mi := &MethodInfo{
		Name:             "testMethod",
		ClassName:        "Lcom/example/Test;",
		FilePath:         "smali/com/example/Test.smali",
		FullSignature:    "testMethod()V",
		ReturnType:       "V",
		ReturnsVoid:      true,
		IsPublic:         true,
		IsStatic:         false,
		IsConstructor:    false,
		HasSecurityAPI:   true,
		InstructionCount: 20,
	}
	cmi := mi.ToCompact()
	if cmi == nil {
		t.Fatal("ToCompact should return non-nil")
	}
	if cmi.Name != mi.Name {
		t.Errorf("Name mismatch: %q vs %q", cmi.Name, mi.Name)
	}
	if !cmi.Flags.HasFlag(FlagIsPublic) {
		t.Error("IsPublic flag should be set in compact")
	}
	if !cmi.Flags.HasFlag(FlagReturnsVoid) {
		t.Error("ReturnsVoid flag should be set in compact")
	}
	if cmi.Flags.HasFlag(FlagIsStatic) {
		t.Error("IsStatic flag should not be set")
	}
}

func TestCompactMethodInfo_FromCompact_NoPanic(t *testing.T) {
	mi := &MethodInfo{
		Name:           "someMethod",
		ClassName:      "Lcom/example/X;",
		ReturnType:     "Z",
		ReturnsBoolean: true,
		IsPrivate:      true,
		IsFinal:        true,
	}
	cmi := mi.ToCompact()
	restored := cmi.FromCompact()
	if restored == nil {
		t.Fatal("FromCompact should return non-nil")
	}
	if restored.Name != mi.Name {
		t.Errorf("Name: %q vs %q", restored.Name, mi.Name)
	}
	if !restored.ReturnsBoolean {
		t.Error("ReturnsBoolean should be true after roundtrip")
	}
	if !restored.IsPrivate {
		t.Error("IsPrivate should be true after roundtrip")
	}
}

// ─── BatchOptimizer.ResetBuffers / GetStats ───────────────────────────────────

func TestBatchOptimizer_ResetBuffers(t *testing.T) {
	bo := NewBatchOptimizer(4)
	bo.resultBuffer = append(bo.resultBuffer, &EnhancedScore{})
	bo.methodBuffer = append(bo.methodBuffer, &MethodInfo{})
	bo.ResetBuffers()
	if len(bo.resultBuffer) != 0 {
		t.Error("resultBuffer should be empty after ResetBuffers")
	}
	if len(bo.methodBuffer) != 0 {
		t.Error("methodBuffer should be empty after ResetBuffers")
	}
}

func TestBatchOptimizer_GetStats(t *testing.T) {
	bo := NewBatchOptimizer(8)
	stats := bo.GetStats()
	if stats.BatchSize != 8 {
		t.Errorf("expected BatchSize=8, got %d", stats.BatchSize)
	}
}

func TestBatchOptimizer_GetStats_AfterReset(t *testing.T) {
	bo := NewBatchOptimizer(4)
	bo.resultBuffer = append(bo.resultBuffer, &EnhancedScore{})
	bo.ResetBuffers()
	stats := bo.GetStats()
	if stats.ResultBufferLen != 0 {
		t.Errorf("expected 0 after reset, got %d", stats.ResultBufferLen)
	}
}

// ─── countHighConfidence ──────────────────────────────────────────────────────

func TestCountHighConfidence_Empty(t *testing.T) {
	if got := countHighConfidence(nil); got != 0 {
		t.Errorf("expected 0, got %d", got)
	}
}

func TestCountHighConfidence_Mixed(t *testing.T) {
	results := []*EnhancedScore{
		{IsHighConfidence: true},
		{IsHighConfidence: false},
		{IsHighConfidence: true},
		{IsHighConfidence: true},
	}
	if got := countHighConfidence(results); got != 3 {
		t.Errorf("expected 3, got %d", got)
	}
}

// ─── getCurrentTime ───────────────────────────────────────────────────────────

func TestGetCurrentTime_Positive(t *testing.T) {
	ts := getCurrentTime()
	if ts <= 0 {
		t.Errorf("expected positive timestamp, got %d", ts)
	}
}

// ─── errLR / errGBT / fmtErr ─────────────────────────────────────────────────

func TestErrLR_Message(t *testing.T) {
	err := errLR("missing weights")
	if err == nil {
		t.Fatal("expected non-nil error")
	}
	if err.Error() == "" {
		t.Error("error message should not be empty")
	}
	if err.Error() != "logistic_regression: missing weights" {
		t.Errorf("unexpected error message: %q", err.Error())
	}
}

func TestErrGBT_Message(t *testing.T) {
	err := errGBT("invalid trees")
	if err == nil {
		t.Fatal("expected non-nil error")
	}
	if err.Error() != "gradient_boosting: invalid trees" {
		t.Errorf("unexpected error message: %q", err.Error())
	}
}

func TestFmtErr_Empty(t *testing.T) {
	err := fmtErr("")
	if err == nil {
		t.Fatal("expected non-nil error")
	}
	if err.Error() != "" {
		t.Errorf("expected empty message, got %q", err.Error())
	}
}
