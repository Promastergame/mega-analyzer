package vulnscan

import (
	"testing"
)

func TestVulnscanFusionIntegration(t *testing.T) {
	v := Vulnerability{
		ID:          "injection-sqli",
		Name:        "SQL Injection",
		Description: "Unsanitized user input in query",
		Severity:    SeverityCritical,
		URL:         "https://example.com/item?id=1",
		Parameter:   "id",
	}

	f := FindingFromVuln(v)
	if f.FusionIntelligence == nil {
		t.Fatal("expected non-nil FusionIntelligence attached to vulnscan Finding")
	}

	fi := f.FusionIntelligence
	if fi.SampleID == "" {
		t.Error("expected sample ID in fusion report")
	}
	if fi.Decision.Explanation == "" {
		t.Error("expected explanation in fusion report")
	}

	// Test EnrichAndCorrelate
	engine := NewEngine(&Scanner{})
	findings := engine.EnrichAndCorrelate([]Vulnerability{v})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].FusionIntelligence == nil {
		t.Error("expected non-nil FusionIntelligence from EnrichAndCorrelate")
	}
}
