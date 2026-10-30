package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mega-analyzer/pkg/internal/types"
)

func TestJSONReporter_NcerOmitempty(t *testing.T) {
	tmpDir := t.TempDir()
	res := &types.AnalysisResult{
		Timestamp: time.Now(),
		Stats:     types.AnalysisStats{TotalFiles: 1},
	}

	// 1. Without NCER data
	if err := NewJSONReporter(res).Generate(tmpDir); err != nil {
		t.Fatalf("JSON Generate without NCER failed: %v", err)
	}
	dataNoNcer, err := os.ReadFile(filepath.Join(tmpDir, "analysis.json"))
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if strings.Contains(string(dataNoNcer), `"ncer"`) {
		t.Errorf("expected 'ncer' field to be omitted when nil, got: %s", string(dataNoNcer))
	}

	// 2. With NCER data
	res.NcerResult = &types.NcerCausalResult{
		BoundCount:       10,
		UnboundCount:     2,
		OrphanCount:      1,
		TotalEvents:      26,
		DCausal:          0.2308,
		CoverageQuality:  0.8333,
		EvidenceRefs:     []string{"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		EvidenceVerified: true,
		EvidenceCount:    1,
	}
	if err := NewJSONReporter(res).Generate(tmpDir); err != nil {
		t.Fatalf("JSON Generate with NCER failed: %v", err)
	}
	dataWithNcer, err := os.ReadFile(filepath.Join(tmpDir, "analysis.json"))
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if !strings.Contains(string(dataWithNcer), `"ncer": {`) || !strings.Contains(string(dataWithNcer), `"d_causal": 0.2308`) {
		t.Errorf("expected 'ncer' field present with d_causal score, got: %s", string(dataWithNcer))
	}
	if !strings.Contains(string(dataWithNcer), `"evidence_verified": true`) || !strings.Contains(string(dataWithNcer), `"evidence_count": 1`) {
		t.Errorf("expected evidence metadata in JSON output, got: %s", string(dataWithNcer))
	}

	// Ensure valid JSON
	var decoded map[string]any
	if err := json.Unmarshal(dataWithNcer, &decoded); err != nil {
		t.Fatalf("JSON generated with NCER is invalid JSON: %v", err)
	}
}

func TestSARIFReporter_WithNcerResult(t *testing.T) {
	res := &types.AnalysisResult{
		NcerResult: &types.NcerCausalResult{
			BoundCount:       5,
			UnboundCount:     3,
			OrphanCount:      2,
			TotalEvents:      20,
			DCausal:          0.50,
			CoverageQuality:  0.50,
			EvidenceRefs:     []string{"hash123"},
			EvidenceVerified: true,
			EvidenceCount:    1,
		},
	}
	reporter := NewSARIFReporter(res)
	log := reporter.Build()

	foundRule := false
	for _, rule := range log.Runs[0].Tool.Driver.Rules {
		if rule.ID == "ncer/causal-discrepancy" {
			foundRule = true
			break
		}
	}
	if !foundRule {
		t.Errorf("expected rule ncer/causal-discrepancy in SARIF log rules")
	}

	foundResult := false
	for _, r := range log.Runs[0].Results {
		if r.RuleID == "ncer/causal-discrepancy" {
			foundResult = true
			if d, ok := r.Properties["d_causal"]; !ok || fmtFloat(d) != 0.5 {
				t.Errorf("expected d_causal property around 0.5, got %v", d)
			}
			if ver, ok := r.Properties["evidence_verified"]; !ok || ver != true {
				t.Errorf("expected evidence_verified property true in SARIF, got %v", ver)
			}
			break
		}
	}
	if !foundResult {
		t.Errorf("expected result ncer/causal-discrepancy in SARIF log results")
	}
}

func fmtFloat(v any) float64 {
	switch f := v.(type) {
	case float64:
		return f
	case float32:
		return float64(f)
	}
	return 0
}

func TestHTMLReporter_NcerSection(t *testing.T) {
	res := &types.AnalysisResult{
		Timestamp: time.Now(),
	}

	// Without NCER
	var bufNoNcer bytes.Buffer
	if err := NewHTMLReporter(res).GenerateStream(&bufNoNcer); err != nil {
		t.Fatalf("HTML GenerateStream failed: %v", err)
	}
	if strings.Contains(bufNoNcer.String(), "NCER Causal Reconciliation") {
		t.Errorf("expected NCER section absent when NcerResult is nil")
	}

	// With NCER
	res.NcerResult = &types.NcerCausalResult{
		BoundCount:       12,
		UnboundCount:     1,
		OrphanCount:      0,
		TotalEvents:      26,
		DCausal:          0.0769,
		CoverageQuality:  0.9231,
		EvidenceRefs:     []string{"abc123hash"},
		EvidenceVerified: true,
		EvidenceCount:    1,
	}
	var bufWithNcer bytes.Buffer
	if err := NewHTMLReporter(res).GenerateStream(&bufWithNcer); err != nil {
		t.Fatalf("HTML GenerateStream with NCER failed: %v", err)
	}
	htmlStr := bufWithNcer.String()
	if !strings.Contains(htmlStr, `id="ncer-reconcile"`) || !strings.Contains(htmlStr, "0.0769") {
		t.Errorf("expected NCER HTML section with d_Causal score")
	}
	if !strings.Contains(htmlStr, `id="ncer-evidence"`) || !strings.Contains(htmlStr, "Verified") || !strings.Contains(htmlStr, "abc123hash") {
		t.Errorf("expected HTML evidence subsection with Verified status and hash, got:\n%s", htmlStr)
	}
}
