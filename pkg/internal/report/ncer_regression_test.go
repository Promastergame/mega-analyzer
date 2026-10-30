package report

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"mega-analyzer/pkg/internal/types"
)

// TestRegression_StableJSONOutput verifies that for identical input analysis
// results, the generated JSON output is byte-for-byte stable and reproducible.
func TestRegression_StableJSONOutput(t *testing.T) {
	fixedTime := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	res := &types.AnalysisResult{
		Timestamp: fixedTime,
		Stats: types.AnalysisStats{
			TotalFiles:    10,
			AnalyzedFiles: 8,
		},
		NcerResult: &types.NcerCausalResult{
			BoundCount:       400,
			UnboundCount:     50,
			OrphanCount:      20,
			TotalEvents:      470,
			DCausal:          0.1489,
			CoverageQuality:  0.8511,
			EvidenceRefs:     []string{"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
			EvidenceVerified: true,
			EvidenceCount:    1,
		},
	}

	dir1 := filepath.Join(t.TempDir(), "run1")
	dir2 := filepath.Join(t.TempDir(), "run2")

	if err := NewJSONReporter(res).Generate(dir1); err != nil {
		t.Fatalf("run1 Generate failed: %v", err)
	}
	if err := NewJSONReporter(res).Generate(dir2); err != nil {
		t.Fatalf("run2 Generate failed: %v", err)
	}

	data1, err := os.ReadFile(filepath.Join(dir1, "analysis.json"))
	if err != nil {
		t.Fatalf("read run1: %v", err)
	}
	data2, err := os.ReadFile(filepath.Join(dir2, "analysis.json"))
	if err != nil {
		t.Fatalf("read run2: %v", err)
	}

	if !bytes.Equal(data1, data2) {
		t.Errorf("JSON output is not byte-for-byte stable across runs:\nRun 1:\n%s\nRun 2:\n%s", string(data1), string(data2))
	}
}

// TestRegression_StableSARIFOutput verifies that for identical input analysis
// results, the SARIF log structure and NCER properties are deterministic.
func TestRegression_StableSARIFOutput(t *testing.T) {
	fixedTime := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	res := &types.AnalysisResult{
		Timestamp: fixedTime,
		NcerResult: &types.NcerCausalResult{
			BoundCount:       100,
			UnboundCount:     10,
			OrphanCount:      5,
			TotalEvents:      115,
			DCausal:          0.0909,
			CoverageQuality:  0.9091,
			EvidenceRefs:     []string{"hash_abc_123"},
			EvidenceVerified: true,
			EvidenceCount:    1,
		},
	}

	rep1 := NewSARIFReporter(res).Build()
	rep2 := NewSARIFReporter(res).Build()

	if len(rep1.Runs) != 1 || len(rep2.Runs) != 1 {
		t.Fatalf("unexpected runs length")
	}
	run1 := rep1.Runs[0]
	run2 := rep2.Runs[0]

	if len(run1.Results) != len(run2.Results) {
		t.Fatalf("results count mismatch: %d vs %d", len(run1.Results), len(run2.Results))
	}

	// Verify NCER rule property stability
	var found1, found2 map[string]any
	for _, r := range run1.Results {
		if r.RuleID == "ncer/causal-discrepancy" {
			found1 = r.Properties
		}
	}
	for _, r := range run2.Results {
		if r.RuleID == "ncer/causal-discrepancy" {
			found2 = r.Properties
		}
	}
	if found1 == nil || found2 == nil {
		t.Fatalf("ncer/causal-discrepancy result not found")
	}

	if found1["d_causal"] != found2["d_causal"] ||
		found1["evidence_verified"] != found2["evidence_verified"] ||
		found1["evidence_count"] != found2["evidence_count"] {
		t.Errorf("SARIF properties unstable across builds:\n%+v\nvs\n%+v", found1, found2)
	}
}
