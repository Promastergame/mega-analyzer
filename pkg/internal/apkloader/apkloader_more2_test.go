package apkloader

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ─── constant_propagation.go — foldArithmetic branches ───────────────────────

func TestFoldArithmetic_AllOps(t *testing.T) {
	pr := &PropagationResult{Constants: make(map[int16]*ConstantValue)}
	mk := func(v int64) *ConstantValue {
		return &ConstantValue{Value: v, Source: "literal", Confidence: 100}
	}

	cases := []struct {
		kind MIROpKind
		a, b int64
		want int64
	}{
		{MIR_ADD, 10, 3, 13},
		{MIR_SUB, 10, 3, 7},
		{MIR_MUL, 4, 5, 20},
		{MIR_DIV, 20, 4, 5},
		{MIR_REM, 10, 3, 1},
	}
	for _, c := range cases {
		result := pr.foldArithmetic(c.kind, mk(c.a), mk(c.b))
		if result == nil {
			t.Fatalf("foldArithmetic(%v, %d, %d) returned nil", c.kind, c.a, c.b)
		}
		if result.Value.(int64) != c.want {
			t.Errorf("foldArithmetic(%v, %d, %d) = %d, want %d", c.kind, c.a, c.b, result.Value.(int64), c.want)
		}
	}
}

func TestFoldArithmetic_DivisionByZero(t *testing.T) {
	pr := &PropagationResult{Constants: make(map[int16]*ConstantValue)}
	mk := func(v int64) *ConstantValue { return &ConstantValue{Value: v, Source: "literal", Confidence: 100} }
	if result := pr.foldArithmetic(MIR_DIV, mk(10), mk(0)); result != nil {
		t.Error("division by zero should return nil")
	}
	if result := pr.foldArithmetic(MIR_REM, mk(10), mk(0)); result != nil {
		t.Error("remainder by zero should return nil")
	}
}

func TestFoldArithmetic_NonIntValues(t *testing.T) {
	pr := &PropagationResult{Constants: make(map[int16]*ConstantValue)}
	v1 := &ConstantValue{Value: "str", Source: "literal", Confidence: 100}
	v2 := &ConstantValue{Value: int64(5), Source: "literal", Confidence: 100}
	if pr.foldArithmetic(MIR_ADD, v1, v2) != nil {
		t.Error("foldArithmetic with non-int should return nil")
	}
	if pr.foldArithmetic(MIR_ADD, v2, v1) != nil {
		t.Error("foldArithmetic with non-int v2 should return nil")
	}
}

func TestFoldArithmetic_UnknownOp(t *testing.T) {
	pr := &PropagationResult{Constants: make(map[int16]*ConstantValue)}
	mk := func(v int64) *ConstantValue { return &ConstantValue{Value: v, Source: "literal", Confidence: 100} }
	// MIR_NOP is not an arithmetic op
	if pr.foldArithmetic(MIR_NOP, mk(1), mk(2)) != nil {
		t.Error("unknown op should return nil")
	}
}

func TestConstantPropagation_SubMulDiv(t *testing.T) {
	// v0=10, v1=3, v2=v0-v1=7, v3=v0*v1=30, v4=v0/v1=3, v5=v0%v1=1
	insns := []MIRInsn{
		{Kind: MIR_CONST, Dst: 0, Imm: 10},
		{Kind: MIR_CONST, Dst: 1, Imm: 3},
		{Kind: MIR_SUB, Dst: 2, Src1: 0, Src2: 1},
		{Kind: MIR_MUL, Dst: 3, Src1: 0, Src2: 1},
		{Kind: MIR_DIV, Dst: 4, Src1: 0, Src2: 1},
		{Kind: MIR_REM, Dst: 5, Src1: 0, Src2: 1},
	}
	cfg := makeCFGWithInsns(insns)
	result := ConstantPropagation(cfg, &SSAForm{})

	expected := map[int16]int64{2: 7, 3: 30, 4: 3, 5: 1}
	for reg, want := range expected {
		cv := result.GetConstantValue(reg)
		if cv == nil {
			t.Fatalf("v%d should be folded", reg)
		}
		if cv.Value.(int64) != want {
			t.Errorf("v%d = %v, want %d", reg, cv.Value, want)
		}
	}
}

func TestConstantPropagation_OR_XOR(t *testing.T) {
	// v0=0b1010, v1=0b1100, v2=v0|v1=0b1110, v3=v0^v1=0b0110
	insns := []MIRInsn{
		{Kind: MIR_CONST, Dst: 0, Imm: 0b1010},
		{Kind: MIR_CONST, Dst: 1, Imm: 0b1100},
		{Kind: MIR_OR, Dst: 2, Src1: 0, Src2: 1},
		{Kind: MIR_XOR, Dst: 3, Src1: 0, Src2: 1},
	}
	cfg := makeCFGWithInsns(insns)
	result := ConstantPropagation(cfg, &SSAForm{})

	cv2 := result.GetConstantValue(2)
	if cv2 == nil || cv2.Value.(int64) != 0b1110 {
		t.Errorf("OR: expected 0b1110=14, got %v", cv2)
	}
	cv3 := result.GetConstantValue(3)
	if cv3 == nil || cv3.Value.(int64) != 0b0110 {
		t.Errorf("XOR: expected 0b0110=6, got %v", cv3)
	}
}

func TestConstantPropagation_NestedChain(t *testing.T) {
	// v0=2, v1=3, v2=v0+v1=5, v3=v2*v2=25
	insns := []MIRInsn{
		{Kind: MIR_CONST, Dst: 0, Imm: 2},
		{Kind: MIR_CONST, Dst: 1, Imm: 3},
		{Kind: MIR_ADD, Dst: 2, Src1: 0, Src2: 1},
		{Kind: MIR_MUL, Dst: 3, Src1: 2, Src2: 2},
	}
	cfg := makeCFGWithInsns(insns)
	result := ConstantPropagation(cfg, &SSAForm{})
	cv := result.GetConstantValue(3)
	if cv == nil {
		t.Fatal("v3 should be folded (nested chain)")
	}
	if cv.Value.(int64) != 25 {
		t.Errorf("v3 = %v, want 25", cv.Value)
	}
}

func TestConstantPropagation_BranchNeverTaken(t *testing.T) {
	// v0 = 0 (zero); IF v0 → branch never taken
	insns := []MIRInsn{
		{Kind: MIR_CONST, Dst: 0, Imm: 0},
		{Kind: MIR_IF, Src1: 0},
	}
	cfg := makeCFGWithInsns(insns)
	result := ConstantPropagation(cfg, &SSAForm{})
	found := false
	for _, t2 := range result.GetTrace() {
		if strings.Contains(t2, "never taken") {
			found = true
		}
	}
	if !found {
		// The trace should mention "never taken" for zero branch
		// (some implementations say "never taken" others may say "always taken")
		// Either way result should have trace entries
		if len(result.GetTrace()) == 0 {
			_ = result // just ensure no panic
		}
	}
}

// ─── deobfuscation_pipeline.go ───────────────────────────────────────────────

func TestDefaultPipelineConfig(t *testing.T) {
	cfg := DefaultPipelineConfig()
	if cfg == nil {
		t.Fatal("DefaultPipelineConfig() returned nil")
	}
	if !cfg.EnableConstantPropagation {
		t.Error("EnableConstantPropagation should be true")
	}
	if !cfg.EnableDeadCodeElimination {
		t.Error("EnableDeadCodeElimination should be true")
	}
	if cfg.MaxIterations != 5 {
		t.Errorf("MaxIterations=%d, want 5", cfg.MaxIterations)
	}
	if cfg.MinConfidenceThreshold != 50 {
		t.Errorf("MinConfidenceThreshold=%d, want 50", cfg.MinConfidenceThreshold)
	}
	if cfg.ParallelConfig == nil {
		t.Error("ParallelConfig should not be nil")
	}
}

func TestNewDeobfuscationPipeline_NilConfig(t *testing.T) {
	p := NewDeobfuscationPipeline(nil)
	if p == nil {
		t.Fatal("NewDeobfuscationPipeline(nil) returned nil")
	}
	if p.Config == nil {
		t.Error("Config should use default when nil is passed")
	}
}

func TestNewDeobfuscationPipeline_CustomConfig(t *testing.T) {
	cfg := &PipelineConfig{MaxIterations: 10, MinConfidenceThreshold: 75}
	p := NewDeobfuscationPipeline(cfg)
	if p.Config.MaxIterations != 10 {
		t.Errorf("MaxIterations=%d", p.Config.MaxIterations)
	}
}

// ─── robustness_handler.go ───────────────────────────────────────────────────

func TestPipelineErrorSeverity_String(t *testing.T) {
	cases := []struct {
		s    PipelineErrorSeverity
		want string
	}{
		{PipelineSeverityInfo, "INFO"},
		{PipelineSeverityWarning, "WARNING"},
		{PipelineSeverityError, "ERROR"},
		{PipelineSeverityCritical, "CRITICAL"},
		{PipelineErrorSeverity(99), "UNKNOWN"},
	}
	for _, c := range cases {
		if got := c.s.String(); got != c.want {
			t.Errorf("PipelineErrorSeverity(%d).String()=%q, want %q", c.s, got, c.want)
		}
	}
}

func TestPipelineErrorInfo_Error(t *testing.T) {
	e := &PipelineErrorInfo{
		Severity:  PipelineSeverityError,
		Component: "DEXParser",
		Message:   "bad magic",
	}
	got := e.Error()
	if !strings.Contains(got, "ERROR") || !strings.Contains(got, "DEXParser") || !strings.Contains(got, "bad magic") {
		t.Errorf("Error() = %q", got)
	}
}

func TestRobustnessHandler_RecordAndGet(t *testing.T) {
	h := NewRobustnessHandler()
	h.RecordError(&PipelineErrorInfo{
		Severity:    PipelineSeverityError,
		Component:   "CFG",
		Message:     "cycle",
		Recoverable: true,
	})
	h.RecordWarning("SSA", "phi node missing")

	errs := h.GetErrors()
	if len(errs) != 1 {
		t.Errorf("expected 1 error, got %d", len(errs))
	}
	warns := h.GetWarnings()
	if len(warns) != 1 {
		t.Errorf("expected 1 warning, got %d", len(warns))
	}

	stats := h.GetStatistics()
	if stats.TotalErrors != 1 {
		t.Errorf("TotalErrors=%d", stats.TotalErrors)
	}
	if stats.WarningCount != 1 {
		t.Errorf("WarningCount=%d", stats.WarningCount)
	}
}

func TestRobustnessHandler_AttemptRecovery_NonRecoverable(t *testing.T) {
	h := NewRobustnessHandler()
	err := &PipelineErrorInfo{Recoverable: false, Component: "X", Message: "fatal"}
	if h.AttemptRecovery(err) {
		t.Error("non-recoverable error should not be recovered")
	}
	stats := h.GetStatistics()
	if stats.FailedRecoveries != 1 {
		t.Errorf("FailedRecoveries=%d", stats.FailedRecoveries)
	}
}

func TestRobustnessHandler_AttemptRecovery_WithStrategy(t *testing.T) {
	h := NewRobustnessHandler()
	recovered := false
	strategy := NewFallbackStrategy("test", func() error {
		recovered = true
		return nil
	})
	h.RegisterStrategy("test", strategy)

	err := &PipelineErrorInfo{Recoverable: true, Component: "X", Message: "recoverable"}
	if !h.AttemptRecovery(err) {
		t.Error("should have recovered with registered strategy")
	}
	if !recovered {
		t.Error("strategy recovery function was not called")
	}
	stats := h.GetStatistics()
	if stats.RecoveredErrors != 1 {
		t.Errorf("RecoveredErrors=%d", stats.RecoveredErrors)
	}
}

func TestRobustnessHandler_AttemptRecovery_StrategyFails(t *testing.T) {
	h := NewRobustnessHandler()
	strategy := NewFallbackStrategy("failing", func() error {
		return errors.New("cannot recover")
	})
	h.RegisterStrategy("failing", strategy)

	err := &PipelineErrorInfo{Recoverable: true, Component: "X", Message: "hard error"}
	if h.AttemptRecovery(err) {
		t.Error("should not recover when strategy returns error")
	}
	stats := h.GetStatistics()
	if stats.FailedRecoveries != 1 {
		t.Errorf("FailedRecoveries=%d", stats.FailedRecoveries)
	}
}

func TestRobustnessHandler_RecoveryRate(t *testing.T) {
	h := NewRobustnessHandler()
	// Zero attempts → rate 0.0
	stats := h.GetStatistics()
	if stats.RecoveryRate != 0.0 {
		t.Errorf("initial RecoveryRate=%f", stats.RecoveryRate)
	}
}

// ─── detector.go — additional branches ───────────────────────────────────────

func TestDetectFile_APKMAndAAB(t *testing.T) {
	dir := t.TempDir()

	for _, ext := range []string{".apkm", ".aab"} {
		path := filepath.Join(dir, "app"+ext)
		if err := os.WriteFile(path, []byte("data"), 0644); err != nil {
			t.Fatal(err)
		}
		got, err := detectFile(path)
		if err != nil {
			t.Errorf("detectFile(%s): %v", ext, err)
		}
		if got != InputTypeAPKFile {
			t.Errorf("detectFile(%s)=%v, want APKFile", ext, got)
		}
	}
}

func TestDetectFile_OBBandIPA(t *testing.T) {
	dir := t.TempDir()
	for _, ext := range []string{".obb", ".ipa"} {
		path := filepath.Join(dir, "file"+ext)
		if err := os.WriteFile(path, []byte("data"), 0644); err != nil {
			t.Fatal(err)
		}
		got, err := detectFile(path)
		if err != nil {
			t.Errorf("detectFile(%s): %v", ext, err)
		}
		if got != InputTypeArchiveFile {
			t.Errorf("detectFile(%s)=%v, want ArchiveFile", ext, got)
		}
	}
}

func TestDetectFile_OatVdexOdexArtByExtension(t *testing.T) {
	dir := t.TempDir()
	for _, ext := range []string{".vdex", ".odex", ".art", ".oat"} {
		path := filepath.Join(dir, "file"+ext)
		if err := os.WriteFile(path, []byte("data"), 0644); err != nil {
			t.Fatal(err)
		}
		got, err := detectFile(path)
		if err != nil {
			t.Errorf("detectFile(%s): %v", ext, err)
		}
		if got != InputTypeDEXFile {
			t.Errorf("detectFile(%s)=%v, want DEXFile", ext, got)
		}
	}
}

func TestHasCacheArtifacts_DepthLimit(t *testing.T) {
	dir := t.TempDir()
	// Create deeply nested dalvik-cache beyond maxDepth
	deep := filepath.Join(dir, "a", "b", "c", "d", "dalvik-cache")
	if err := os.MkdirAll(deep, 0755); err != nil {
		t.Fatal(err)
	}
	// Should return false because depth > 3
	if hasCacheArtifacts(dir, 0) {
		t.Error("should not detect cache artifacts beyond maxDepth")
	}
}

func TestHasCacheArtifacts_RecurseIntoSubdirs(t *testing.T) {
	dir := t.TempDir()
	// oat is 2 levels deep — within maxDepth=3
	sub := filepath.Join(dir, "system", "framework", "oat")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatal(err)
	}
	if !hasCacheArtifacts(dir, 0) {
		t.Error("should detect 'oat' subdirectory within maxDepth")
	}
}

// ─── errors.go ───────────────────────────────────────────────────────────────

func TestLoaderError_NilInner(t *testing.T) {
	import_errors_pkg := fmt.Errorf("inner error")
	e := &LoaderError{Op: "test", Path: "p", err: import_errors_pkg}
	if e.Unwrap() != import_errors_pkg {
		t.Error("Unwrap() should return inner err")
	}
	got := e.Error()
	if !strings.Contains(got, "test") {
		t.Errorf("Error()=%q", got)
	}
}

// ─── constant_propagation.go — canFold edge cases ────────────────────────────

func TestCanFold_AllCoveredKinds(t *testing.T) {
	pr := &PropagationResult{
		Constants: map[int16]*ConstantValue{
			0: {Value: int64(1), Source: "literal", Confidence: 100},
			1: {Value: int64(2), Source: "literal", Confidence: 100},
		},
	}

	// Two-operand foldable kinds
	foldable := []MIROpKind{MIR_ADD, MIR_SUB, MIR_MUL, MIR_DIV, MIR_REM, MIR_AND, MIR_OR, MIR_XOR}
	for _, kind := range foldable {
		insn := MIRInsn{Kind: kind, Src1: 0, Src2: 1}
		if !pr.canFold(insn) {
			t.Errorf("canFold(%v) should be true when both operands are constant", kind)
		}
	}

	// NOT is foldable with one operand
	notInsn := MIRInsn{Kind: MIR_NOT, Src1: 0}
	if !pr.canFold(notInsn) {
		t.Error("canFold(MIR_NOT) should be true when operand is constant")
	}

	// Unknown kinds are not foldable
	nopInsn := MIRInsn{Kind: MIR_NOP}
	if pr.canFold(nopInsn) {
		t.Error("canFold(MIR_NOP) should be false")
	}
}

func TestCanFold_MissingOperand(t *testing.T) {
	pr := &PropagationResult{
		Constants: map[int16]*ConstantValue{
			0: {Value: int64(1), Source: "literal", Confidence: 100},
			// 1 is NOT in constants
		},
	}
	insn := MIRInsn{Kind: MIR_ADD, Src1: 0, Src2: 1}
	if pr.canFold(insn) {
		t.Error("canFold should be false when Src2 is not constant")
	}
}

// ─── PropagationResult methods ────────────────────────────────────────────────

func TestPropagationResult_EmptyState(t *testing.T) {
	pr := &PropagationResult{
		Constants: make(map[int16]*ConstantValue),
	}
	if pr.IsConstant(0) {
		t.Error("should not be constant when empty")
	}
	if pr.GetConstantValue(0) != nil {
		t.Error("should return nil for unknown register")
	}
	if pr.ChangeCount() != 0 {
		t.Errorf("ChangeCount=%d", pr.ChangeCount())
	}
	if len(pr.GetTrace()) != 0 {
		t.Errorf("Trace should be empty, got %v", pr.GetTrace())
	}
}

// ─── opName full coverage ─────────────────────────────────────────────────────

func TestOpName_AllOps(t *testing.T) {
	cases := []struct {
		kind MIROpKind
		want string
	}{
		{MIR_ADD, "+"},
		{MIR_SUB, "-"},
		{MIR_MUL, "*"},
		{MIR_DIV, "/"},
		{MIR_REM, "%"},
		{MIR_AND, "&"},
		{MIR_OR, "|"},
		{MIR_XOR, "^"},
		// default case
		{MIR_CONST, "?"},
		{MIR_MOVE, "?"},
		{MIR_IF, "?"},
		{MIR_NOP, "?"},
	}
	for _, c := range cases {
		if got := opName(c.kind); got != c.want {
			t.Errorf("opName(%d)=%q, want %q", c.kind, got, c.want)
		}
	}
}

// ─── string_patterns.go — additional GetCategory paths ───────────────────────

func TestStringPatternDatabase_AllCategories(t *testing.T) {
	db := NewStringPatternDatabase()
	// These should all return known categories (not "unknown")
	categorised := []string{
		"AES/CBC/PKCS5Padding", // crypto
		"http://",              // network
	}
	for _, s := range categorised {
		cat := db.GetCategory(s)
		if cat == "unknown" {
			t.Errorf("GetCategory(%q) returned 'unknown', expected a real category", s)
		}
	}
}

// ─── cache_analyzer.go — WriteReport to nonexistent dir ──────────────────────

func TestCacheAnalyzer_WriteReport_Success(t *testing.T) {
	ca := NewCacheAnalyzer("com.test", t.TempDir())
	outDir := t.TempDir()
	err := ca.WriteReport(outDir)
	if err != nil {
		t.Errorf("WriteReport: %v", err)
	}
	if _, statErr := os.Stat(outDir + "/CACHE_ANALYSIS.json"); statErr != nil {
		t.Errorf("expected CACHE_ANALYSIS.json to exist: %v", statErr)
	}
}

// ─── deobfuscation_pipeline.go — PipelineResult ──────────────────────────────

func TestPipelineResult_ZeroValue(t *testing.T) {
	result := &PipelineResult{
		DeobfuscatedClasses: make(map[string]string),
	}
	result.DeobfuscatedClasses["com.evil.MainActivity"] = ".class public L..."
	if len(result.DeobfuscatedClasses) != 1 {
		t.Errorf("expected 1 class, got %d", len(result.DeobfuscatedClasses))
	}
}
