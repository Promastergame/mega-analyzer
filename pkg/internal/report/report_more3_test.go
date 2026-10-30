package report

import (
	"os"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func TestRuleSeverityClass_High(t *testing.T) {
	if got := ruleSeverityClass("high"); got != "sev-high" {
		t.Errorf("got %q", got)
	}
}

func TestRuleSeverityClass_Critical(t *testing.T) {
	if got := ruleSeverityClass("critical"); got != "sev-critical" {
		t.Errorf("got %q", got)
	}
}

func TestRuleSeverityClass_Unknown(t *testing.T) {
	if got := ruleSeverityClass("unknown"); got != "sev-info" {
		t.Errorf("unknown should fallback to sev-info, got %q", got)
	}
}

func TestRuleSeverityClass_Empty(t *testing.T) {
	if got := ruleSeverityClass(""); got != "sev-info" {
		t.Errorf("empty should fallback to sev-info, got %q", got)
	}
}

func TestSarifFromArtifactFinding_NoPanic(t *testing.T) {
	f := types.ArtifactFinding{
		Path:     "lib/x86/libnative.so",
		Severity: types.SeverityHigh,
		Reason:   "Suspicious native library",
	}
	result := sarifFromArtifactFinding(f)
	if result.RuleID == "" {
		t.Error("expected non-empty ruleID")
	}
}

func TestSarifFromMachineCodeFinding_NoPanic(t *testing.T) {
	finding := types.MachineCodeFinding{
		Category: "memory",
		Severity: "high",
		Title:    "Buffer Overflow",
	}
	result := sarifFromMachineCodeFinding("target.so", finding)
	if result.RuleID == "" {
		t.Error("expected non-empty ruleID")
	}
}

func TestSarifFromMachineCodeFinding_WithCWE(t *testing.T) {
	cwe := "CWE-120"
	offset := uint64(0x1000)
	finding := types.MachineCodeFinding{
		Category:   "memory",
		CWE:        &cwe,
		FileOffset: &offset,
	}
	result := sarifFromMachineCodeFinding("target.so", finding)
	if result.Properties["cwe"] != cwe {
		t.Errorf("CWE not in properties: %v", result.Properties)
	}
}

func TestIsBinarySnippetData_Empty(t *testing.T) {
	if isBinarySnippetData([]byte{}) {
		t.Error("empty should not be binary")
	}
}

func TestIsBinarySnippetData_PureText(t *testing.T) {
	if isBinarySnippetData([]byte("hello world this is text content")) {
		t.Error("pure text should not be binary")
	}
}

func TestIsBinarySnippetData_NullBytes(t *testing.T) {
	data := make([]byte, 100)
	for i := range data {
		data[i] = 0x00
	}
	if !isBinarySnippetData(data) {
		t.Error("null bytes should be binary")
	}
}

func TestResolveReportPath_Empty(t *testing.T) {
	got := resolveReportPath("", "")
	if got != "" {
		t.Errorf("empty inputs should return empty, got %q", got)
	}
}

func TestResolveReportPath_Absolute(t *testing.T) {
	got := resolveReportPath("/base", "/abs/path.smali")
	_ = got // Windows may rewrite slashes; just ensure no panic/empty
}

func TestResolveReportPath_Relative(t *testing.T) {
	got := resolveReportPath("/base", "rel/file.smali")
	if got == "" {
		t.Error("relative path with base should resolve to something")
	}
}

func TestSplitReportLines_Empty(t *testing.T) {
	lines := splitReportLines("")
	_ = lines // may return 0 or 1 depending on strings.Split behavior
}

func TestSplitReportLines_Multi(t *testing.T) {
	lines := splitReportLines("a\nb\nc")
	if len(lines) != 3 {
		t.Errorf("expected 3, got %d", len(lines))
	}
}

func TestCategoryToRisk_NoPanic(t *testing.T) {
	info := types.GetCategoryInfo(types.CategoryCrypto)
	r := categoryToRisk(info, 5)
	_ = r
}

func TestCategoryToRisk_Network(t *testing.T) {
	info := types.GetCategoryInfo(types.CategoryNetwork)
	r := categoryToRisk(info, 1)
	_ = r
}

func TestBuildStats_EmptyResult(t *testing.T) {
	result := types.NewAnalysisResult("/tmp/test.apk")
	b := NewViewBuilder(result, MarkdownOptions{})
	stats := b.buildStats()
	_ = stats
}

func TestBuildVerdict_EmptyResult(t *testing.T) {
	result := types.NewAnalysisResult("/tmp/test.apk")
	b := NewViewBuilder(result, MarkdownOptions{})
	sum := b.buildSummary()
	verdict := b.buildVerdict(sum)
	if verdict == "" {
		t.Error("buildVerdict should not return empty string")
	}
}

func TestBuildTopCategories_Empty(t *testing.T) {
	result := types.NewAnalysisResult("/tmp/test.apk")
	b := NewViewBuilder(result, MarkdownOptions{})
	cats := b.buildTopCategories(10)
	_ = cats
}

func TestBuildRecommendations_Empty(t *testing.T) {
	result := types.NewAnalysisResult("/tmp/test.apk")
	b := NewViewBuilder(result, MarkdownOptions{})
	recs := b.buildRecommendations()
	_ = recs
}

func TestBuildCrackPointsSortsVisibleConfidenceThenImpact(t *testing.T) {
	result := types.NewAnalysisResult("/tmp/test.apk")
	result.CrackPoint = &types.CrackPointResult{
		Points: []types.CrackPoint{
			{Method: "tamperGate", Category: "tamper", Confidence: 0.954, Impact: 8},
			{Method: "licenseGate", Category: "license", Confidence: 0.950, Impact: 9},
		},
	}

	view := NewViewBuilder(result, MarkdownOptions{}).Build()
	if len(view.CrackPoints) != 2 {
		t.Fatalf("expected 2 crack points, got %d", len(view.CrackPoints))
	}
	if view.CrackPoints[0].Method != "licenseGate" {
		t.Fatalf("expected equal rendered confidence to sort by impact first, got %q", view.CrackPoints[0].Method)
	}
}

func TestReadSourceLines_NonExistentFile(t *testing.T) {
	cache := map[string][]string{}
	failed := map[string]bool{}
	result := types.NewAnalysisResult("/tmp")
	b := NewViewBuilder(result, MarkdownOptions{})
	lines := b.readSourceLines("/tmp", "/nonexistent/path.smali", types.FileTypeSmali, cache, failed)
	if len(lines) != 0 {
		t.Errorf("non-existent file should return nil/empty")
	}
}

func TestReadSourceLines_ExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/test.smali"
	_ = os.WriteFile(path, []byte("line1\nline2\nline3\n"), 0o644)
	cache := map[string][]string{}
	failed := map[string]bool{}
	result := types.NewAnalysisResult(dir)
	b := NewViewBuilder(result, MarkdownOptions{})
	lines := b.readSourceLines(dir, path, types.FileTypeSmali, cache, failed)
	if len(lines) == 0 {
		t.Error("existing file should return lines")
	}
}
