package report

import (
	"testing"
)

// ─── verdictKey ────────────────────────────────────────────────────────────────

func TestVerdictKey_Empty(t *testing.T) {
	result := verdictKey("")
	if result == "" {
		t.Error("expected non-empty result for empty input")
	}
}

func TestVerdictKey_Safe(t *testing.T) {
	result := verdictKey("safe")
	if result != "safe" {
		t.Errorf("expected 'safe', got %q", result)
	}
}

func TestVerdictKey_Risky(t *testing.T) {
	result := verdictKey("risky")
	if result != "risky" {
		t.Errorf("expected 'risky', got %q", result)
	}
}

// ─── shortBaseName ────────────────────────────────────────────────────────────

func TestShortBaseName_Simple(t *testing.T) {
	result := shortBaseName("file.apk")
	if result != "file.apk" {
		t.Errorf("expected 'file.apk', got %q", result)
	}
}

func TestShortBaseName_WithPath(t *testing.T) {
	result := shortBaseName("/path/to/file.apk")
	if result != "file.apk" {
		t.Errorf("expected 'file.apk', got %q", result)
	}
}

func TestShortBaseName_Empty(t *testing.T) {
	result := shortBaseName("")
	if result != "" {
		t.Errorf("expected empty, got %q", result)
	}
}

// ─── fontExt ───────────────────────────────────────────────────────────────────

func TestFontExt_TTF(t *testing.T) {
	result := fontExt("font.ttf")
	if result != "ttf" {
		t.Errorf("expected 'ttf', got %q", result)
	}
}

func TestFontExt_OTF(t *testing.T) {
	result := fontExt("font.otf")
	if result != "otf" {
		t.Errorf("expected 'otf', got %q", result)
	}
}

// ─── humanSize ────────────────────────────────────────────────────────────────

func TestHumanSize_Zero(t *testing.T) {
	result := humanSize(0)
	if result != "0B" {
		t.Errorf("expected '0B', got %q", result)
	}
}

func TestHumanSize_Bytes(t *testing.T) {
	result := humanSize(512)
	if result != "512B" {
		t.Errorf("expected '512B', got %q", result)
	}
}

func TestHumanSize_KB(t *testing.T) {
	result := humanSize(1024)
	if result != "1.0KB" {
		t.Errorf("expected '1.0KB', got %q", result)
	}
}

func TestHumanSize_MB(t *testing.T) {
	result := humanSize(1024 * 1024)
	if result != "1.0MB" {
		t.Errorf("expected '1.0MB', got %q", result)
	}
}

func TestHumanSize_GB(t *testing.T) {
	result := humanSize(1024 * 1024 * 1024)
	if result != "1.00GB" {
		t.Errorf("expected '1.00GB', got %q", result)
	}
}

// ─── isBinarySnippetData ──────────────────────────────────────────────────────

func TestIsBinarySnippetData_Text(t *testing.T) {
	if isBinarySnippetData([]byte("hello world")) {
		t.Error("expected text to not be binary")
	}
}

func TestIsBinarySnippetData_UTF8(t *testing.T) {
	if isBinarySnippetData([]byte("Test data")) {
		t.Error("expected normal text to not be binary")
	}
}

func TestIsBinarySnippetData_WithNull(t *testing.T) {
	if !isBinarySnippetData([]byte("hello\x00world")) {
		t.Error("expected null byte to indicate binary")
	}
}

// ─── splitReportLines extended ────────────────────────────────────────────────

func TestSplitReportLines_Single_More(t *testing.T) {
	result := splitReportLines("line1")
	if len(result) != 1 || result[0] != "line1" {
		t.Errorf("expected 1 line, got %v", result)
	}
}

func TestSplitReportLines_Multiple_More(t *testing.T) {
	result := splitReportLines("line1\nline2\nline3")
	if len(result) != 3 {
		t.Errorf("expected 3 lines, got %d", len(result))
	}
}

// ─── scoreToRisk ──────────────────────────────────────────────────────────────

func TestScoreToRisk_ValidRange(t *testing.T) {
	result := scoreToRisk(50.0)
	if !result.IsValid() {
		t.Error("expected valid risk level")
	}
}

// ─── severityRank ────────────────────────────────────────────────────────────

func TestSeverityRank_Critical(t *testing.T) {
	result := severityRank("critical")
	if result == 0 {
		t.Error("expected non-zero rank for critical")
	}
}

func TestSeverityRank_High(t *testing.T) {
	result := severityRank("high")
	if result == 0 {
		t.Error("expected non-zero rank for high")
	}
}

func TestSeverityRank_Low(t *testing.T) {
	result := severityRank("low")
	if result == 0 {
		t.Error("expected non-zero rank for low")
	}
}

// ─── estimateComplexity ───────────────────────────────────────────────────────

func TestEstimateComplexity_Small(t *testing.T) {
	result := estimateComplexity(5)
	if result == "" {
		t.Error("expected non-empty complexity")
	}
}

func TestEstimateComplexity_Medium(t *testing.T) {
	result := estimateComplexity(100)
	if result == "" {
		t.Error("expected non-empty complexity")
	}
}

func TestEstimateComplexity_Large(t *testing.T) {
	result := estimateComplexity(1000)
	if result == "" {
		t.Error("expected non-empty complexity")
	}
}

// ─── firstNonEmpty ────────────────────────────────────────────────────────────

func TestFirstNonEmpty_BothEmpty(t *testing.T) {
	result := firstNonEmpty("", "")
	if result != "" {
		t.Errorf("expected empty, got %q", result)
	}
}

func TestFirstNonEmpty_First(t *testing.T) {
	result := firstNonEmpty("first", "second")
	if result != "first" {
		t.Errorf("expected 'first', got %q", result)
	}
}

func TestFirstNonEmpty_Second(t *testing.T) {
	result := firstNonEmpty("", "second")
	if result != "second" {
		t.Errorf("expected 'second', got %q", result)
	}
}

// ─── buildScoreBar ────────────────────────────────────────────────────────────

func TestBuildScoreBar_Zero(t *testing.T) {
	result := buildScoreBar(0.0)
	if result == "" {
		t.Error("expected non-empty bar")
	}
}

func TestBuildScoreBar_Half(t *testing.T) {
	result := buildScoreBar(50.0)
	if result == "" {
		t.Error("expected non-empty bar for 50%")
	}
}

func TestBuildScoreBar_Full(t *testing.T) {
	result := buildScoreBar(100.0)
	if result == "" {
		t.Error("expected non-empty bar for 100%")
	}
}

// ─── ruleSetLabel ────────────────────────────────────────────────────────────

func TestRuleSetLabel_Common(t *testing.T) {
	result := ruleSetLabel("OWASP")
	if result == "" {
		t.Error("expected non-empty label")
	}
}

func TestRuleSetLabel_Unknown(t *testing.T) {
	result := ruleSetLabel("UNKNOWN_RULESET")
	if result == "" {
		t.Error("expected label even for unknown ruleset")
	}
}

// ─── isLegitimateGroup (implementation varies, basic structure test)

func TestIsLegitimateGroup_Empty(t *testing.T) {
	result := isLegitimateGroup("")
	if result {
		t.Error("expected empty group to not be legitimate")
	}
}
