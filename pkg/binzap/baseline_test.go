package binzap

import (
	"path/filepath"
	"testing"
)

func sampleFindings() []Finding {
	return []Finding{
		Finding{RuleID: "BZ-PASS-001", Severity: SeverityHigh, Message: "weak crypto", File: "a.smali", Line: 10, Evidence: "MD5"}.WithFingerprint(),
		Finding{RuleID: "BZ-PASS-007", Severity: SeverityMedium, Message: "path", File: "b.smali", Line: 5, Evidence: "../etc"}.WithFingerprint(),
	}
}

func TestBaselineSuppressesKnown(t *testing.T) {
	f := sampleFindings()
	b := NewBaselineFromFindings(f)
	if got := b.Apply(f); len(got) != 0 {
		t.Errorf("expected all known findings suppressed, got %d", len(got))
	}
}

func TestBaselineSurfacesNew(t *testing.T) {
	f := sampleFindings()
	b := NewBaselineFromFindings(f[:1])
	got := b.Apply(f)
	if len(got) != 1 || got[0].RuleID != "BZ-PASS-007" {
		t.Errorf("expected only the new finding, got %+v", got)
	}
}

func TestBaselineSuppressRule(t *testing.T) {
	f := sampleFindings()
	b := NewBaseline()
	b.SuppressRule("BZ-PASS-001")
	got := b.Apply(f)
	if len(got) != 1 || got[0].RuleID != "BZ-PASS-007" {
		t.Errorf("expected rule suppression, got %+v", got)
	}
}

func TestBaselineRoundTrip(t *testing.T) {
	f := sampleFindings()
	b := NewBaselineFromFindings(f)
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := b.Save(path); err != nil {
		t.Fatalf("save: %v", err)
	}
	loaded, err := LoadBaseline(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := loaded.Apply(f); len(got) != 0 {
		t.Errorf("expected round-tripped baseline to suppress all, got %d", len(got))
	}
}

func TestLoadBaselineMissingFile(t *testing.T) {
	b, err := LoadBaseline(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatalf("missing baseline should not error: %v", err)
	}
	if len(b.Apply(sampleFindings())) != 2 {
		t.Error("empty baseline should suppress nothing")
	}
}
