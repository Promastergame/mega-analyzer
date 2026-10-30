package featurestore

import (
	"math"
	"testing"
)

func TestEnrichWithHDCFindings_PopulatesAggregates(t *testing.T) {
	fs := New()
	findings := []HDCFinding{
		{AnchorName: "use_after_free", Jaccard: 0.9, HammingSim: 0.7, Severity: 0.92},
		{AnchorName: "use_after_free", Jaccard: 0.85, HammingSim: 0.65, Severity: 0.92},
		{AnchorName: "command_injection", Jaccard: 0.5, HammingSim: 0.4, Severity: 0.95},
	}
	if err := EnrichWithHDCFindings(fs, findings); err != nil {
		t.Fatal(err)
	}

	// Per-anchor best-of-run.
	if got := fs.Value("hdc.use_after_free.jaccard", -1); math.Abs(got-0.9) > 1e-9 {
		t.Errorf("UAF best jaccard = %f, want 0.9", got)
	}
	if got := fs.Value("hdc.use_after_free.hits", -1); got != 2 {
		t.Errorf("UAF hits = %f, want 2", got)
	}

	// Aggregates.
	if got := fs.Value("hdc.aggregate.n_findings", -1); got != 3 {
		t.Errorf("n_findings = %f, want 3", got)
	}
	if got := fs.Value("hdc.aggregate.n_anchors", -1); got != 2 {
		t.Errorf("n_anchors = %f, want 2", got)
	}
	if got := fs.Value("hdc.any.matched", -1); got != 1 {
		t.Errorf("any.matched = %f, want 1", got)
	}
	if got := fs.Value("hdc.aggregate.max_jaccard", -1); math.Abs(got-0.9) > 1e-9 {
		t.Errorf("max_jaccard = %f, want 0.9", got)
	}

	// Severity score: 0.92*0.9 + 0.92*0.85 + 0.95*0.5 = 2.085.
	want := 0.92*0.9 + 0.92*0.85 + 0.95*0.5
	if got := fs.Value("hdc.aggregate.severity_score", -999); math.Abs(got-want) > 1e-9 {
		t.Errorf("severity_score = %f, want %f", got, want)
	}

	// Origin tagging.
	hdcKeys := fs.FilterByOrigin(OriginHDC)
	if len(hdcKeys) < 5 {
		t.Errorf("expected ≥5 HDC features, got %d: %v", len(hdcKeys), hdcKeys)
	}
}

func TestEnrichWithEmptyFindings(t *testing.T) {
	fs := New()
	if err := EnrichWithHDCFindings(fs, nil); err != nil {
		t.Fatal(err)
	}
	// When nothing matched we still emit stable schema-defining features.
	if fs.Value("hdc.any.matched", -1) != 0 {
		t.Errorf("any.matched should be 0 with no findings")
	}
	if fs.Value("hdc.aggregate.severity_score", -1) != 0 {
		t.Errorf("severity_score should be 0 with no findings")
	}
}
