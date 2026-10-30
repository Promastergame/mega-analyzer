package ml

import (
	"testing"
)

// ─── AttributionReport.TopK ───────────────────────────────────────────────────

func TestTopK_LessThanK(t *testing.T) {
	r := &AttributionReport{
		Contributions: []Attribution{
			{FeatureName: "f1", AbsContribution: 0.8},
			{FeatureName: "f2", AbsContribution: 0.5},
		},
	}
	got := r.TopK(10)
	if len(got) != 2 {
		t.Errorf("TopK(10) with 2 contribs: got %d", len(got))
	}
}

func TestTopK_MoreThanK(t *testing.T) {
	r := &AttributionReport{
		Contributions: []Attribution{
			{FeatureName: "f1", AbsContribution: 0.9},
			{FeatureName: "f2", AbsContribution: 0.7},
			{FeatureName: "f3", AbsContribution: 0.5},
		},
	}
	got := r.TopK(2)
	if len(got) != 2 {
		t.Errorf("TopK(2) with 3 contribs: got %d", len(got))
	}
	if got[0].FeatureName != "f1" {
		t.Errorf("first should be f1, got %q", got[0].FeatureName)
	}
}

func TestTopK_Zero(t *testing.T) {
	r := &AttributionReport{
		Contributions: []Attribution{{FeatureName: "f1"}},
	}
	got := r.TopK(0)
	if len(got) != 0 {
		t.Errorf("TopK(0): expected empty, got %d", len(got))
	}
}

// ─── OptimizedBatchResult getters ─────────────────────────────────────────────

func TestGetPerFileOverhead_ZeroFiles(t *testing.T) {
	r := &OptimizedBatchResult{TotalFiles: 0, Duration: 1000}
	if got := r.GetPerFileOverhead(); got != 0 {
		t.Errorf("expected 0 for zero files, got %v", got)
	}
}

func TestGetPerFileOverhead_Normal(t *testing.T) {
	r := &OptimizedBatchResult{TotalFiles: 10, Duration: 100}
	got := r.GetPerFileOverhead()
	if got != 10.0 {
		t.Errorf("expected 10.0, got %v", got)
	}
}

func TestGetThroughput_ZeroDuration(t *testing.T) {
	r := &OptimizedBatchResult{AnalyzedMethods: 100, Duration: 0}
	if got := r.GetThroughput(); got != 0 {
		t.Errorf("expected 0 for zero duration, got %v", got)
	}
}

func TestGetThroughput_Normal(t *testing.T) {
	r := &OptimizedBatchResult{AnalyzedMethods: 100, Duration: 1000}
	got := r.GetThroughput()
	if got <= 0 {
		t.Errorf("throughput should be positive, got %v", got)
	}
}

// ─── AppContext IsLegitimateAdminUser / IsLegitimateOverlayUser ───────────────

func TestIsLegitimateAdminUser_Security(t *testing.T) {
	ctx := &AppContext{DetectedType: AppTypeSecurity}
	if !ctx.IsLegitimateAdminUser() {
		t.Error("security app should be legitimate admin user")
	}
}

func TestIsLegitimateAdminUser_System(t *testing.T) {
	ctx := &AppContext{DetectedType: AppTypeSystem}
	if !ctx.IsLegitimateAdminUser() {
		t.Error("system app should be legitimate admin user")
	}
}

func TestIsLegitimateAdminUser_Gaming(t *testing.T) {
	ctx := &AppContext{DetectedType: AppTypeGaming}
	if ctx.IsLegitimateAdminUser() {
		t.Error("gaming app should NOT be legitimate admin user")
	}
}

// ─── AdvancedPatcherEngine ────────────────────────────────────────────────────

func TestNewAdvancedPatcherEngine_NotNil(t *testing.T) {
	eng := NewAdvancedPatcherEngine(nil, nil, nil)
	if eng == nil {
		t.Fatal("expected non-nil engine")
	}
}

func TestRegisterPattern_NilPattern(t *testing.T) {
	eng := NewAdvancedPatcherEngine(nil, nil, nil)
	err := eng.RegisterPattern(nil)
	if err == nil {
		t.Error("expected error for nil pattern")
	}
}

func TestRegisterPattern_EmptyID(t *testing.T) {
	eng := NewAdvancedPatcherEngine(nil, nil, nil)
	err := eng.RegisterPattern(&AdvancedPatcherPattern{ID: ""})
	if err == nil {
		t.Error("expected error for empty ID")
	}
}

func TestRegisterPattern_InvalidRegex(t *testing.T) {
	eng := NewAdvancedPatcherEngine(nil, nil, nil)
	err := eng.RegisterPattern(&AdvancedPatcherPattern{
		ID:       "test",
		Patterns: []string{"[invalid regex"},
	})
	if err == nil {
		t.Error("expected error for invalid regex")
	}
}

func TestRegisterPattern_Valid(t *testing.T) {
	eng := NewAdvancedPatcherEngine(nil, nil, nil)
	err := eng.RegisterPattern(&AdvancedPatcherPattern{
		ID:       "test-pattern",
		Patterns: []string{"dispatch_table"},
	})
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestGetAllPatternsAdvanced_Empty(t *testing.T) {
	eng := NewAdvancedPatcherEngine(nil, nil, nil)
	patterns := eng.GetAllPatterns()
	if patterns == nil {
		t.Error("GetAllPatterns should not return nil")
	}
	if len(patterns) != 0 {
		t.Errorf("fresh engine should have 0 patterns, got %d", len(patterns))
	}
}

func TestGetAllPatternsAdvanced_AfterRegister(t *testing.T) {
	eng := NewAdvancedPatcherEngine(nil, nil, nil)
	_ = eng.RegisterPattern(&AdvancedPatcherPattern{ID: "p1", Patterns: []string{"foo"}})
	patterns := eng.GetAllPatterns()
	if len(patterns) != 1 {
		t.Errorf("expected 1 pattern, got %d", len(patterns))
	}
}

func TestInitializeDefaultPatterns_NoPanic(t *testing.T) {
	eng := NewAdvancedPatcherEngine(nil, nil, nil)
	_ = eng.InitializeDefaultPatterns()
	patterns := eng.GetAllPatterns()
	if len(patterns) == 0 {
		t.Error("InitializeDefaultPatterns should add at least one pattern")
	}
}

// ─── PermissionFlags.String ───────────────────────────────────────────────────

func TestPermissionFlagsString_Empty(t *testing.T) {
	var pf PermissionFlags
	s := pf.String()
	_ = s // just ensure no panic
}

func TestPermissionFlagsString_Overlay(t *testing.T) {
	pf := PermOverlay
	s := pf.String()
	if s == "" {
		t.Error("OVERLAY flag should produce non-empty string")
	}
}

// ─── NewBatchOptimizer ────────────────────────────────────────────────────────

func TestNewBatchOptimizer_NotNil(t *testing.T) {
	b := NewBatchOptimizer(4)
	if b == nil {
		t.Fatal("expected non-nil BatchOptimizer")
	}
}

func TestNewBatchOptimizer_ZeroSize(t *testing.T) {
	b := NewBatchOptimizer(0)
	if b == nil {
		t.Fatal("expected non-nil BatchOptimizer")
	}
}
