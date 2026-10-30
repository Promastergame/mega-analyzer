package report

import (
	"os"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

// ─── options.go — preset functions not covered elsewhere ─────────────────────

func TestFullReportOptions(t *testing.T) {
	opts := FullReportOptions()
	if opts.MaxHotspots != 100 {
		t.Errorf("MaxHotspots = %d, want 100", opts.MaxHotspots)
	}
	if !opts.ShowEmptyGroups {
		t.Error("ShowEmptyGroups should be true in full report")
	}
	if opts.MaxPathLen != 0 {
		t.Errorf("MaxPathLen should be 0 (unlimited) in full report, got %d", opts.MaxPathLen)
	}
}

func TestAllReportOptions(t *testing.T) {
	opts := AllReportOptions()
	if opts.MaxHotspots != 0 {
		t.Errorf("MaxHotspots should be 0 (unlimited), got %d", opts.MaxHotspots)
	}
	if opts.MaxDetections != 0 {
		t.Errorf("MaxDetections should be 0, got %d", opts.MaxDetections)
	}
	if !opts.ShowEmptyGroups {
		t.Error("ShowEmptyGroups should be true in all-options report")
	}
}

func TestCIReportOptions(t *testing.T) {
	opts := CIReportOptions()
	if opts.MaxHotspots != 30 {
		t.Errorf("MaxHotspots = %d, want 30", opts.MaxHotspots)
	}
	if opts.CollapsibleDetails {
		t.Error("CollapsibleDetails should be false in CI report")
	}
	if opts.ShowScoreBar {
		t.Error("ShowScoreBar should be false in CI report")
	}
}

// ─── utils.go — TruncateString (coverage uses TestTruncateString_Report) ────

func TestTruncateString(t *testing.T) {
	if got := TruncateString("hello", 10); got != "hello" {
		t.Errorf("short string should pass through, got %q", got)
	}
	if got := TruncateString("hello", 5); got != "hello" {
		t.Errorf("exact-length string should pass through, got %q", got)
	}
	got := TruncateString("hello world this is a long string", 10)
	if len(got) > 10 {
		t.Errorf("truncated string should be at most 10 chars, got %d: %q", len(got), got)
	}
	if !strings.HasPrefix(got, "...") {
		t.Errorf("truncated string should start with '...', got %q", got)
	}
	// maxLen <= 3 — returns raw truncation without ellipsis prefix
	got2 := TruncateString("hello", 3)
	if len(got2) > 3 {
		t.Errorf("maxLen=3 should be at most 3 chars, got %q", got2)
	}
}

// ─── builder.go — ViewBuilder construction ───────────────────────────────────

func TestNewViewBuilder_Build_EmptyResult(t *testing.T) {
	result := types.NewAnalysisResult("/tmp")
	builder := NewViewBuilder(result, DefaultOptions())
	if builder == nil {
		t.Fatal("expected non-nil builder")
	}
	view := builder.Build()
	_ = view // ensure no panic
}

func TestViewBuilder_BuildHTMLView(t *testing.T) {
	result := types.NewAnalysisResult("/tmp")
	builder := NewViewBuilder(result, DefaultOptions())
	htmlView := builder.BuildHTMLView(DefaultHTMLOptions())
	_ = htmlView
}

// ─── html.go — HTMLReporter construction ─────────────────────────────────────

func TestNewHTMLReporter(t *testing.T) {
	result := types.NewAnalysisResult("/tmp")
	reporter := NewHTMLReporter(result)
	if reporter == nil {
		t.Fatal("expected non-nil reporter")
	}
}

func TestHTMLReporter_WithOptions(t *testing.T) {
	result := types.NewAnalysisResult("/tmp")
	reporter := NewHTMLReporter(result).WithOptions(HTMLOptions{
		ContextLinesBefore: 5,
		ContextLinesAfter:  5,
	})
	if reporter == nil {
		t.Fatal("expected non-nil reporter")
	}
	if reporter.htmlOpts.ContextLinesBefore != 5 {
		t.Errorf("expected ContextLinesBefore=5, got %d", reporter.htmlOpts.ContextLinesBefore)
	}
}

func TestHTMLReporter_WithMarkdownOptions(t *testing.T) {
	result := types.NewAnalysisResult("/tmp")
	customOpts := DefaultOptions()
	customOpts.MaxHotspots = 42
	reporter := NewHTMLReporter(result).WithMarkdownOptions(customOpts)
	if reporter == nil {
		t.Fatal("expected non-nil reporter")
	}
}

func TestHTMLReporter_WithArtifacts_Nil(t *testing.T) {
	result := types.NewAnalysisResult("/tmp")
	reporter := NewHTMLReporter(result).WithArtifacts(nil)
	if reporter == nil {
		t.Fatal("expected non-nil reporter")
	}
	if reporter.artifacts != nil {
		t.Error("expected nil artifacts after passing nil")
	}
}

func TestHTMLReporter_BuildHTML_NilResult(t *testing.T) {
	reporter := NewHTMLReporter(nil)
	htmlOut := reporter.BuildHTML()
	if htmlOut == "" {
		t.Error("expected non-empty HTML even for nil result")
	}
	if !strings.Contains(htmlOut, "<!DOCTYPE html>") {
		t.Error("expected valid HTML document structure")
	}
}

// ─── html.go — Generate to tempdir ───────────────────────────────────────────

func TestHTMLReporter_Generate_TempDir(t *testing.T) {
	result := types.NewAnalysisResult("/tmp")
	result.Files["com/example/Test.smali"] = &types.FileAnalysis{
		Path: "com/example/Test.smali",
		Type: types.FileTypeSmali,
		Matches: []types.Match{
			{
				SourceLocation: types.SourceLocation{File: "com/example/Test.smali", Line: 5},
				Categorized:    types.Categorized{Category: types.CategoryGoogleLVL},
				Severity:       types.SeverityHigh,
				Text:           "LICENSE_CHECK_BYPASS",
			},
		},
	}

	outDir := t.TempDir()
	reporter := NewHTMLReporter(result)
	if err := reporter.Generate(outDir); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if _, err := os.Stat(outDir + "/REPORT.html"); err != nil {
		t.Errorf("expected REPORT.html to be created, got: %v", err)
	}
}

// ─── sarif.go — SARIFReporter ────────────────────────────────────────────────

func TestSARIFReporter_Build_EmptyResult(t *testing.T) {
	result := types.NewAnalysisResult("/tmp")
	reporter := NewSARIFReporter(result)
	if reporter == nil {
		t.Fatal("expected non-nil SARIF reporter")
	}
	log := reporter.Build()
	if log.Version != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %q", log.Version)
	}
	if len(log.Runs) == 0 {
		t.Error("expected at least one run in SARIF log")
	}
}

func TestSARIFReporter_Build_WithRuleMatches(t *testing.T) {
	result := types.NewAnalysisResult("/tmp")
	result.RuleMatches = append(result.RuleMatches, types.Match{
		SourceLocation: types.SourceLocation{File: "com/example/Test.smali", Line: 10},
		Categorized:    types.Categorized{Category: types.CategorySecurity},
		Severity:       types.SeverityHigh,
		Pattern:        "dangerous_call",
		Text:           "exec(command)",
	})
	reporter := NewSARIFReporter(result)
	log := reporter.Build()
	if len(log.Runs) == 0 {
		t.Fatal("expected at least one run")
	}
	if len(log.Runs[0].Results) == 0 {
		t.Error("expected at least one result in SARIF output")
	}
}

func TestSARIFReporter_Generate_TempDir(t *testing.T) {
	result := types.NewAnalysisResult("/tmp")
	outDir := t.TempDir()
	reporter := NewSARIFReporter(result)
	if err := reporter.Generate(outDir); err != nil {
		t.Fatalf("SARIF Generate failed: %v", err)
	}
	if _, err := os.Stat(outDir + "/analysis.sarif"); err != nil {
		t.Errorf("expected analysis.sarif to be created: %v", err)
	}
}

// ─── sarif.go helper functions ────────────────────────────────────────────────

func TestSeverityToSARIFLevel_UppercaseCases(t *testing.T) {
	if got := severityToSARIFLevel("CRITICAL"); got != "error" {
		t.Errorf("CRITICAL uppercase → %q, want 'error'", got)
	}
	if got := severityToSARIFLevel("HIGH"); got != "error" {
		t.Errorf("HIGH uppercase → %q, want 'error'", got)
	}
	if got := severityToSARIFLevel("MEDIUM"); got != "warning" {
		t.Errorf("MEDIUM uppercase → %q, want 'warning'", got)
	}
}

func TestSanitizeRuleID_LongInput(t *testing.T) {
	long := strings.Repeat("a", 100)
	got := sanitizeRuleID(long)
	if len(got) != 100 {
		t.Errorf("valid long ID should pass through, got len=%d", len(got))
	}
}

func TestSanitizeRuleID_AllSpecialChars(t *testing.T) {
	got := sanitizeRuleID("@#$%^&*()")
	for _, ch := range got {
		if ch != '_' {
			t.Errorf("expected all special chars to become _, got %q", got)
			break
		}
	}
}

// ─── renderer.go — MarkdownRenderer ──────────────────────────────────────────

func TestMarkdownRenderer_RenderEmptyView(t *testing.T) {
	r := NewMarkdownRenderer(DefaultOptions())
	if r == nil {
		t.Fatal("expected non-nil renderer")
	}
	view := ReportView{}
	output := r.Render(view)
	if output == "" {
		t.Error("expected non-empty markdown output even for empty view")
	}
}

func TestMarkdownRenderer_RenderWithMeta(t *testing.T) {
	r := NewMarkdownRenderer(DefaultOptions())
	view := ReportView{
		Meta: MetaView{
			TargetName:    "com.example.app",
			EngineVersion: "1.0.0",
		},
	}
	output := r.Render(view)
	if !strings.Contains(output, "com.example.app") {
		t.Errorf("expected target name in markdown output, got length %d", len(output))
	}
}

// ─── builder.go — categoryToRisk more combinations ───────────────────────────

func TestCategoryToRisk_FrequencyBumpHighPrio(t *testing.T) {
	info := types.CategoryInfo{IsCritical: false, Priority: 9}
	bumped := categoryToRisk(info, 50)
	if bumped <= types.RiskMedium {
		t.Errorf("count=50 high-prio should bump above Medium, got %v", bumped)
	}
}

func TestCategoryToRisk_ZeroCount(t *testing.T) {
	info := types.CategoryInfo{IsCritical: false, Priority: 7}
	got := categoryToRisk(info, 0)
	if got != types.RiskMedium {
		t.Errorf("prio7+count0 = %v, want Medium", got)
	}
}

// ─── builder.go — estimateConfidence ─────────────────────────────────────────

func TestEstimateConfidence_DecisionPointsAverage(t *testing.T) {
	hs := types.Hotspot{
		DecisionPoints: []types.DecisionPoint{
			{Scored: types.Scored{Confidence: 1.0}},
			{Scored: types.Scored{Confidence: 0.0}},
		},
	}
	got := estimateConfidence(hs)
	if got < 0.0 || got > 1.0 {
		t.Errorf("confidence should be in [0,1], got %f", got)
	}
}

func TestEstimateConfidence_HighMatchCounts(t *testing.T) {
	hs := types.Hotspot{
		MatchCount:    100,
		CriticalCount: 50,
		Score:         90,
	}
	got := estimateConfidence(hs)
	if got < 0.5 {
		t.Errorf("high match count should give confidence >= 0.5, got %f", got)
	}
	if got > 1.0 {
		t.Errorf("confidence should be capped at 1.0, got %f", got)
	}
}

// ─── builder.go — normalizeHTMLOptions all-zero ───────────────────────────────

func TestNormalizeHTMLOptions_AllZero(t *testing.T) {
	got := normalizeHTMLOptions(HTMLOptions{})
	def := DefaultHTMLOptions()
	if got.ContextLinesBefore != def.ContextLinesBefore {
		t.Errorf("ContextLinesBefore: %d vs %d", got.ContextLinesBefore, def.ContextLinesBefore)
	}
	if got.ContextLinesAfter != def.ContextLinesAfter {
		t.Errorf("ContextLinesAfter: %d vs %d", got.ContextLinesAfter, def.ContextLinesAfter)
	}
	if got.DefaultSnippetLines != def.DefaultSnippetLines {
		t.Errorf("DefaultSnippetLines: %d vs %d", got.DefaultSnippetLines, def.DefaultSnippetLines)
	}
	if got.MaxSnippetsPerCategory != def.MaxSnippetsPerCategory {
		t.Errorf("MaxSnippetsPerCategory: %d vs %d", got.MaxSnippetsPerCategory, def.MaxSnippetsPerCategory)
	}
}

// ─── html_fpfilter.go — isBinarySnippetData mixed content ────────────────────

func TestIsBinarySnippetData_MostlyPrintable(t *testing.T) {
	// 12 printable + 3 control = 15 total. printable ratio = 0.80 > 0.65 → NOT binary
	data := []byte("Hello World\n")
	for i := 0; i < 3; i++ {
		data = append(data, 0x02)
	}
	if isBinarySnippetData(data) {
		t.Error("mostly printable data should not be classified as binary")
	}
}

// ─── renderer.go — verdictKey additional cases ───────────────────────────────

func TestVerdictKey_UpperCaseInput(t *testing.T) {
	cases := map[string]string{
		"CLEAN":      "clean",
		"SUSPICIOUS": "suspicious",
		"MALICIOUS":  "malicious",
	}
	for input, want := range cases {
		if got := verdictKey(input); got != want {
			t.Errorf("verdictKey(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestVerdictKey_SpacesAndSpecialChars(t *testing.T) {
	got := verdictKey("High Risk")
	if strings.Contains(got, " ") {
		t.Errorf("expected spaces to become dashes, got %q", got)
	}
}

// ─── renderer.go — shortBaseName edge cases ──────────────────────────────────

func TestShortBaseName_VeryLongName(t *testing.T) {
	long := strings.Repeat("x", 200) + ".smali"
	got := shortBaseName(long)
	if got == "" {
		t.Error("expected non-empty result for long basename")
	}
}

func TestShortBaseName_EmptyString(t *testing.T) {
	// Should not panic
	got := shortBaseName("")
	_ = got
}

// ─── html.go — truncate edge cases ───────────────────────────────────────────

func TestTruncateHTML_ExactLength(t *testing.T) {
	if got := truncate("hello", 5); got != "hello" {
		t.Errorf("exact-length should not be truncated, got %q", got)
	}
}

func TestTruncateHTML_Unicode(t *testing.T) {
	got := truncate("hello", 4)
	if !strings.HasSuffix(got, "...") {
		t.Errorf("expected truncation with '...', got %q", got)
	}
}

// ─── html.go — generateMatchID collision resistance ──────────────────────────

func TestGenerateMatchID_DifferentLines(t *testing.T) {
	id1 := generateMatchID("File.smali", 10, "security")
	id2 := generateMatchID("File.smali", 20, "security")
	if id1 == id2 {
		t.Error("different lines should produce different IDs")
	}
}

func TestGenerateMatchID_DifferentCategories(t *testing.T) {
	id1 := generateMatchID("File.smali", 10, "security")
	id2 := generateMatchID("File.smali", 10, "license")
	if id1 == id2 {
		t.Error("different categories should produce different IDs")
	}
}
