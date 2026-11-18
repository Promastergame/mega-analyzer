package pipeline

import (
	"context"
	"testing"

	"mega-analyzer/pkg/internal/piracy"
	"mega-analyzer/pkg/internal/types"
)

// ─── makeCtx helpers ──────────────────────────────────────────────────────────

func makeCtxFull(content []byte, fileType types.FileType, isAppCode bool, path string) *FileDetectContext {
	lower := make([]byte, len(content))
	for i, b := range content {
		if b >= 'A' && b <= 'Z' {
			lower[i] = b + 32
		} else {
			lower[i] = b
		}
	}
	return &FileDetectContext{
		Ctx:          context.Background(),
		Path:         path,
		Content:      content,
		ContentLower: lower,
		FileType:     fileType,
		IsAppCode:    isAppCode,
	}
}

func makeAnalysisFull(path string) *types.FileAnalysis {
	return &types.FileAnalysis{
		Path: path,
	}
}

// ─── OverlayDetector.Reset / Signals / Finalize ───────────────────────────────

func TestOverlayDetector_Reset(t *testing.T) {
	d := NewOverlayDetector()
	d.hasSystemAlertWindow = true
	d.hasMediaProjection = true
	d.signals = []Signal{{ID: "test"}}
	d.Reset()
	if d.hasSystemAlertWindow || d.hasMediaProjection {
		t.Error("Reset should clear flags")
	}
	if len(d.signals) != 0 {
		t.Error("Reset should clear signals")
	}
}

func TestOverlayDetector_Signals_Empty(t *testing.T) {
	d := NewOverlayDetector()
	sigs := d.Signals()
	if sigs == nil {
		t.Error("Signals should return non-nil")
	}
}

func TestOverlayDetector_Finalize_NoSignals(t *testing.T) {
	d := NewOverlayDetector()
	matches := d.Finalize()
	_ = matches // no panic
}

// ─── CorrelationDetector.Detect / Reset ───────────────────────────────────────

func TestCorrelationDetector_Detect_NoPanic(t *testing.T) {
	d := NewCorrelationDetector()
	ctx := makeCtxFull([]byte("some content"), types.FileTypeSmali, true, "test.smali")
	analysis := makeAnalysisFull("test.smali")
	d.Detect(ctx, analysis) // pass-through, no panic
}

func TestCorrelationDetector_Reset(t *testing.T) {
	d := NewCorrelationDetector()
	d.hasRun = true
	d.Reset()
	if d.hasRun {
		t.Error("Reset should clear hasRun")
	}
}

func TestCorrelationDetector_CollectSignals_Empty(t *testing.T) {
	d := NewCorrelationDetector()
	d.CollectSignals(nil)             // no panic
	d.CollectSignals([]types.Match{}) // no panic
}

func TestCorrelationDetector_CollectSignals_WithMatches(t *testing.T) {
	d := NewCorrelationDetector()
	matches := []types.Match{
		{
			Categorized: types.Categorized{Category: types.CategoryPermissionRule},
			Pattern:     "READ_SMS",
			Text:        "READ_SMS permission detected",
		},
		{
			Categorized: types.Categorized{Category: types.CategoryNetwork},
			Pattern:     "INTERNET",
		},
	}
	d.CollectSignals(matches) // no panic
}

// ─── SubscriptionDetector.Name ────────────────────────────────────────────────

func TestSubscriptionDetector_Name(t *testing.T) {
	d := NewSubscriptionDetector()
	if d.Name() != "subscription" {
		t.Errorf("expected 'subscription', got %q", d.Name())
	}
}

// ─── PiracyDetectorAdapter.Name ──────────────────────────────────────────────

func TestPiracyDetectorAdapter_Name(t *testing.T) {
	inner := piracy.NewDetector()
	d := NewPiracyDetectorAdapter(inner)
	if d.Name() != "piracy" {
		t.Errorf("expected 'piracy', got %q", d.Name())
	}
}

func TestBuildPiracyAnalysis_PreservesDetectorEvidence(t *testing.T) {
	p := &Pipeline{result: &types.AnalysisResult{Files: map[string]*types.FileAnalysis{
		"Main.smali": {
			Path: "Main.smali",
			Matches: []types.Match{newPiracyMatch(
				types.CategoryPiracySite,
				"Main.smali",
				piracy.Finding{
					Type: "site", Source: "HappyMod", Pattern: "happymod.com",
					Confidence: 0.93, SiteName: "HappyMod", SiteDomain: "happymod.com",
					RiskTags: []string{"mod_apk"},
				},
				false,
			)},
		},
	}}}

	p.buildPiracyAnalysis()
	if p.result.Piracy == nil || len(p.result.Piracy.Findings) != 1 {
		t.Fatalf("expected one typed piracy finding, got %#v", p.result.Piracy)
	}
	finding := p.result.Piracy.Findings[0]
	if finding.Confidence != 0.93 || finding.Source != "HappyMod" || finding.SiteDomain != "happymod.com" {
		t.Fatalf("piracy evidence was lost: %#v", finding)
	}
	if len(p.result.Piracy.Sites) != 1 || p.result.Piracy.Sites[0] != "HappyMod" {
		t.Fatalf("sites = %#v, want HappyMod", p.result.Piracy.Sites)
	}
}

// ─── LibraryCallDetector.Name / Detect ───────────────────────────────────────

func TestLibraryCallDetector_Name(t *testing.T) {
	d := NewLibraryCallDetector()
	if d.Name() != "library_calls" {
		t.Errorf("expected 'library_calls', got %q", d.Name())
	}
}

func TestLibraryCallDetector_Detect_NotAppCode(t *testing.T) {
	d := NewLibraryCallDetector()
	ctx := makeCtxFull([]byte("invoke-virtual {v0}, Ljava/lang/String;->length()I"), types.FileTypeSmali, false, "test.smali")
	analysis := makeAnalysisFull("test.smali")
	d.Detect(ctx, analysis) // non-app code should be skipped
	if len(analysis.Matches) != 0 {
		t.Error("non-app code should not produce matches")
	}
}

func TestLibraryCallDetector_Detect_NonSmali(t *testing.T) {
	d := NewLibraryCallDetector()
	ctx := makeCtxFull([]byte("invoke-virtual something"), types.FileTypeXML, true, "res/layout/main.xml")
	analysis := makeAnalysisFull("res/layout/main.xml")
	d.Detect(ctx, analysis) // non-smali should be skipped
	if len(analysis.Matches) != 0 {
		t.Error("non-smali should not produce matches")
	}
}

func TestLibraryCallDetector_Detect_NoInvoke(t *testing.T) {
	d := NewLibraryCallDetector()
	ctx := makeCtxFull([]byte("const/4 v0, 0x1"), types.FileTypeSmali, true, "Main.smali")
	analysis := makeAnalysisFull("Main.smali")
	d.Detect(ctx, analysis) // no invoke- prefix, should be skipped
}

func TestLibraryCallDetector_DetectLibraryCalls_Empty(t *testing.T) {
	d := NewLibraryCallDetector()
	ctx := makeCtxFull([]byte("invoke-virtual {v0}, Lsome/unknown/Class;->method()V"), types.FileTypeSmali, true, "Main.smali")
	analysis := makeAnalysisFull("Main.smali")
	d.detectLibraryCalls(ctx, analysis) // no panic, may or may not match
}

func TestLibraryCallDetector_ExtractMethodName_NoArrow(t *testing.T) {
	d := NewLibraryCallDetector()
	result := d.extractMethodName([]byte("invoke-virtual {v0}, Lsome/Class;"))
	_ = result // no arrow → empty or default
}

func TestLibraryCallDetector_ExtractMethodName_WithArrow(t *testing.T) {
	d := NewLibraryCallDetector()
	result := d.extractMethodName([]byte("invoke-virtual {v0}, Ljava/lang/String;->length()I"))
	if string(result) == "" {
		t.Error("expected non-empty method name")
	}
}

// ─── detectBytesPattern helpers ──────────────────────────────────────────────

func TestDetectBytesPattern_NoMatch(t *testing.T) {
	ctx := makeCtxFull([]byte("some random content"), types.FileTypeSmali, true, "test.smali")
	analysis := makeAnalysisFull("test.smali")
	found := detectBytesPattern(ctx, analysis, [][]byte{[]byte("luckypatcher")}, types.CategoryPiracy, "Lucky Patcher", true)
	if found {
		t.Error("should not find luckypatcher in unrelated content")
	}
}

func TestDetectBytesPattern_Match(t *testing.T) {
	ctx := makeCtxFull([]byte("invoke luckypatcher.install()"), types.FileTypeSmali, true, "test.smali")
	analysis := makeAnalysisFull("test.smali")
	found := detectBytesPattern(ctx, analysis, [][]byte{[]byte("luckypatcher")}, types.CategoryPiracy, "Lucky Patcher", true)
	if !found {
		t.Error("should find luckypatcher in content")
	}
	if len(analysis.Matches) != 1 {
		t.Errorf("expected 1 match, got %d", len(analysis.Matches))
	}
}

func TestDetectBytesPatternLower_Match(t *testing.T) {
	ctx := makeCtxFull([]byte("invoke LuckyPatcher.install()"), types.FileTypeSmali, true, "test.smali")
	analysis := makeAnalysisFull("test.smali")
	found := detectBytesPatternLower(ctx, analysis, [][]byte{[]byte("luckypatcher")}, types.CategoryPiracy, "desc", true)
	if !found {
		t.Error("case-insensitive match should work")
	}
}

// ─── shouldSkipPiracyFinding / isCriticalPiracyFinding ───────────────────────

func TestShouldSkipPiracyFinding_PathType(t *testing.T) {
	f := piracy.Finding{Type: "path"}
	if !shouldSkipPiracyFinding("some/file.smali", f) {
		t.Error("path type should be skipped")
	}
}

func TestShouldSkipPiracyFinding_ApktoolYml(t *testing.T) {
	f := piracy.Finding{Type: "mod"}
	if !shouldSkipPiracyFinding("apktool.yml", f) {
		t.Error("apktool.yml should be skipped")
	}
}

func TestShouldSkipPiracyFinding_NormalFile(t *testing.T) {
	f := piracy.Finding{Type: "crack"}
	if shouldSkipPiracyFinding("smali/com/example/Main.smali", f) {
		t.Error("normal smali file should not be skipped")
	}
}

func TestShouldSkipPiracyFinding_Watermark(t *testing.T) {
	f := piracy.Finding{Type: "watermark"}
	if !shouldSkipPiracyFinding("any/file.smali", f) {
		t.Error("watermark type should be skipped")
	}
}

func TestIsCriticalPiracyFinding_BareKeygen(t *testing.T) {
	f := piracy.Finding{Type: "crack", Pattern: "keygen"}
	if isCriticalPiracyFinding(f) {
		t.Error("bare keygen is ambiguous and must not be critical")
	}
}

func TestIsCriticalPiracyFinding_LuckyPatcher(t *testing.T) {
	f := piracy.Finding{Type: "crack", Description: "Lucky Patcher patch detected"}
	if !isCriticalPiracyFinding(f) {
		t.Error("lucky patcher should be critical")
	}
}

func TestIsCriticalPiracyFinding_StrongMod(t *testing.T) {
	f := piracy.Finding{Type: "mod", Strength: piracy.StrengthStrong}
	if !isCriticalPiracyFinding(f) {
		t.Error("strong mod should be critical")
	}
}

func TestIsCriticalPiracyFinding_WeakMod(t *testing.T) {
	f := piracy.Finding{Type: "mod", Strength: "weak"}
	if isCriticalPiracyFinding(f) {
		t.Error("weak mod should not be critical")
	}
}

// ─── newMatchWithScore ────────────────────────────────────────────────────────

func TestNewMatchWithScore_Fields(t *testing.T) {
	m := newMatchWithScore(types.CategoryPiracy, "test.smali", 42, "ctx", "pattern", 85.0, true)
	if m.Category != types.CategoryPiracy {
		t.Errorf("expected piracy category, got %v", m.Category)
	}
	if m.File != "test.smali" {
		t.Errorf("expected test.smali, got %q", m.File)
	}
	if m.Line != 42 {
		t.Errorf("expected line 42, got %d", m.Line)
	}
	if m.Score != 85.0 {
		t.Errorf("expected score 85.0, got %f", m.Score)
	}
	if !m.IsCritical {
		t.Error("expected IsCritical=true")
	}
}
