package types

import (
	"encoding/json"
	"testing"
	"time"
)

// ─── RiskLevel.String() ────────────────────────────────────────────────────────

func TestRiskLevel_String_None(t *testing.T) {
	result := RiskNone.String()
	if result == "" {
		t.Error("RiskNone.String() should not be empty")
	}
}

func TestRiskLevel_String_Low(t *testing.T) {
	result := RiskLow.String()
	if result == "" {
		t.Error("RiskLow.String() should not be empty")
	}
}

func TestRiskLevel_String_Medium(t *testing.T) {
	result := RiskMedium.String()
	if result == "" {
		t.Error("RiskMedium.String() should not be empty")
	}
}

func TestRiskLevel_String_High(t *testing.T) {
	result := RiskHigh.String()
	if result == "" {
		t.Error("RiskHigh.String() should not be empty")
	}
}

func TestRiskLevel_String_Critical(t *testing.T) {
	result := RiskCritical.String()
	if result == "" {
		t.Error("RiskCritical.String() should not be empty")
	}
}

// ─── RiskLevel.Emoji() ─────────────────────────────────────────────────────────

func TestRiskLevel_Emoji_Low(t *testing.T) {
	result := RiskLow.Emoji()
	if result == "" {
		t.Error("RiskLow.Emoji() should not be empty")
	}
}

func TestRiskLevel_Emoji_High(t *testing.T) {
	result := RiskHigh.Emoji()
	if result == "" {
		t.Error("RiskHigh.Emoji() should not be empty")
	}
}

// ─── RiskLevel.Color() ─────────────────────────────────────────────────────────

func TestRiskLevel_Color_Critical(t *testing.T) {
	result := RiskCritical.Color()
	if result == "" {
		t.Error("RiskCritical.Color() should not be empty")
	}
}

// ─── Severity.String() ─────────────────────────────────────────────────────────

func TestSeverity_String(t *testing.T) {
	severities := []Severity{
		SeverityInfo,
		SeverityLow,
		SeverityMedium,
		SeverityHigh,
		SeverityCritical,
	}
	for _, sev := range severities {
		result := sev.String()
		if result == "" {
			t.Errorf("Severity(%v).String() should not be empty", sev)
		}
	}
}

// ─── Severity.Emoji() ──────────────────────────────────────────────────────────

func TestSeverity_Emoji_High(t *testing.T) {
	result := SeverityHigh.Emoji()
	if result == "" {
		t.Error("SeverityHigh.Emoji() should not be empty")
	}
}

// ─── Severity.MarshalJSON / UnmarshalJSON ──────────────────────────────────────

func TestSeverity_MarshalJSON(t *testing.T) {
	sev := SeverityCritical
	data, err := json.Marshal(sev)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty JSON")
	}
}

func TestSeverity_UnmarshalJSON(t *testing.T) {
	var sev Severity
	err := json.Unmarshal([]byte(`"high"`), &sev)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sev != SeverityHigh {
		t.Errorf("expected SeverityHigh, got %v", sev)
	}
}

// ─── Category.String() ─────────────────────────────────────────────────────────

func TestCategory_String_Common(t *testing.T) {
	result := CategoryMalware.String()
	if result == "" {
		t.Error("CategoryMalware.String() should not be empty")
	}
}

// ─── Category.Icon() ──────────────────────────────────────────────────────────

func TestCategory_Icon_Malware(t *testing.T) {
	result := CategoryMalware.Icon()
	if result == "" {
		t.Error("CategoryMalware.Icon() should not be empty")
	}
}

func TestCategory_Icon_MalwareCombo(t *testing.T) {
	result := CategoryMalwareCombo.Icon()
	if result == "" {
		t.Error("CategoryMalwareCombo.Icon() should not be empty")
	}
}

// ─── Match.TotalImportance() ──────────────────────────────────────────────────

func TestMatch_TotalImportance(t *testing.T) {
	m := Match{
		Severity: SeverityHigh,
		Scored: Scored{
			Score: 10.0,
		},
	}
	// 10 * 5 + 3 * 2 = 56
	val := m.TotalImportance()
	if val != 56 {
		t.Errorf("expected TotalImportance to be 56, got %d", val)
	}
}

// ─── LineOffsets ───────────────────────────────────────────────────────────────

func TestLineOffsets_LineAt(t *testing.T) {
	content := []byte("hello\nworld\ntest")
	lo := NewLineOffsets(content)
	if lo.LineCount() != 3 {
		t.Errorf("expected 3 lines, got %d", lo.LineCount())
	}

	// 'h' is at index 0, should be line 1
	if line := lo.LineAt(0); line != 1 {
		t.Errorf("index 0: expected line 1, got %d", line)
	}

	// 'w' is at index 6 (after "hello\n"), should be line 2
	if line := lo.LineAt(6); line != 2 {
		t.Errorf("index 6: expected line 2, got %d", line)
	}

	// Out of bounds negative
	if line := lo.LineAt(-5); line != 1 {
		t.Errorf("index -5: expected line 1, got %d", line)
	}

	// Out of bounds large
	if line := lo.LineAt(999); line != 3 {
		t.Errorf("index 999: expected line 3, got %d", line)
	}

	// Nil receiver guard
	var loNil *LineOffsets
	if line := loNil.LineAt(10); line != 1 {
		t.Errorf("nil: expected line 1, got %d", line)
	}
	if count := loNil.LineCount(); count != 0 {
		t.Errorf("nil: expected line count 0, got %d", count)
	}
}

// ─── FileAnalysis.DeepCopy ────────────────────────────────────────────────────

func TestFileAnalysis_DeepCopy_Empty(t *testing.T) {
	f := &FileAnalysis{}
	copy := f.DeepCopy()
	if copy == nil {
		t.Fatal("expected non-nil copy")
	}
	if copy == f {
		t.Error("expected different pointer")
	}
}

func TestFileAnalysis_DeepCopy_WithMatches(t *testing.T) {
	f := &FileAnalysis{
		Path: "test.apk",
		Matches: []Match{
			{Pattern: "malware"},
			{Pattern: "trojan"},
		},
	}
	copy := f.DeepCopy()
	if copy == nil {
		t.Fatal("expected non-nil copy")
	}
	if len(copy.Matches) != 2 {
		t.Errorf("expected 2 matches in copy, got %d", len(copy.Matches))
	}
}

// ─── AnalysisResult.Merge ──────────────────────────────────────────────────────

func TestAnalysisResult_Merge_Empty(t *testing.T) {
	r1 := &AnalysisResult{}
	r2 := &AnalysisResult{}
	r1.Merge(r2)
	// should handle gracefully
}

func TestAnalysisResult_Merge_WithFiles(t *testing.T) {
	r1 := &AnalysisResult{
		Files: map[string]*FileAnalysis{
			"a.txt": {Path: "a.txt"},
		},
	}
	r2 := &AnalysisResult{
		Files: map[string]*FileAnalysis{
			"b.txt": {Path: "b.txt"},
		},
	}
	r1.Merge(r2)
	if len(r1.Files) < 2 {
		t.Errorf("expected at least 2 files after merge, got %d", len(r1.Files))
	}
}

// ─── AnalysisResult.Finalize ──────────────────────────────────────────────────

func TestAnalysisResult_Finalize_Empty(t *testing.T) {
	r := &AnalysisResult{}
	r.Finalize(time.Now())
	// should handle gracefully
}

func TestAnalysisResult_Finalize_WithMatches(t *testing.T) {
	r := &AnalysisResult{
		Files: map[string]*FileAnalysis{
			"test.smali": {
				Path: "test.smali",
				Matches: []Match{
					{Pattern: "malware", Scored: Scored{Score: 85.0}},
					{Pattern: "trojan", Scored: Scored{Score: 75.0}},
				},
			},
		},
	}
	r.Finalize(time.Now())
	// should finalize without panic
}

// ─── Risk Levels comparisons ───────────────────────────────────────────────────

func TestRiskLevel_IsValid(t *testing.T) {
	if !RiskHigh.IsValid() {
		t.Error("RiskHigh should be valid")
	}
}

func TestRiskLevel_IsCritical(t *testing.T) {
	if !RiskCritical.IsCritical() {
		t.Error("RiskCritical.IsCritical() should return true")
	}
	if RiskHigh.IsCritical() {
		t.Error("RiskHigh.IsCritical() should return false")
	}
}

func TestRiskLevel_IsHigh(t *testing.T) {
	if !RiskHigh.IsHigh() {
		t.Error("RiskHigh.IsHigh() should return true")
	}
	if !RiskCritical.IsHigh() {
		t.Error("RiskCritical.IsHigh() should return true")
	}
	if RiskMedium.IsHigh() {
		t.Error("RiskMedium.IsHigh() should return false")
	}
}

func TestRiskLevel_RequiresAction(t *testing.T) {
	if !RiskMedium.RequiresAction() {
		t.Error("RiskMedium.RequiresAction() should return true")
	}
	if RiskLow.RequiresAction() {
		t.Error("RiskLow.RequiresAction() should return false")
	}
}
