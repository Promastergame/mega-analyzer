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
	"mega-analyzer/pkg/ncer"
)

// TestEndToEnd_CollectorThroughReports exercises the full NCER pipeline in a
// single test: synthetic HTTP events -> ncer.Collector -> evidence store ->
// causal reconciliation -> types.NcerCausalResult -> JSON/SARIF/HTML report
// rendering. Every other NCER test covers one or two adjacent stages; this
// one wires all of them together the same way pkg/cmd/analyzer's runner does.
//
// Reconcile() returns (nil, nil) when the Rust library isn't linked (the
// default `go test ./...` build), so this test degrades gracefully to
// verifying that a nil result correctly disables the NCER sections in every
// reporter. Build with `-tags 'cgo omnisec_ncer_reconcile_ffi'` against a
// linked rust/target/release/libomnisec_ncer_reconcile_ffi.so to additionally
// verify the populated-result path end to end.
func TestEndToEnd_CollectorThroughReports(t *testing.T) {
	store, err := ncer.OpenEvidenceStore(filepath.Join(t.TempDir(), "evidence"))
	if err != nil {
		t.Fatalf("OpenEvidenceStore: %v", err)
	}

	base := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	collector := ncer.NewCollector(base)
	collector.SetEvidenceStore(store)

	// One bound request/response pair and one orphan request, mirroring the
	// fixtures used by the Rust-side integration tests.
	collector.ObserveHTTP("GET", "https://api.example.test/v1/resource", "200", "api.example.test", "12:00:00.000")
	collector.ObserveHTTP("POST", "https://api.example.test/v1/track", "—", "api.example.test", "12:00:01.000")

	if collector.Len() != 2 {
		t.Fatalf("Len() = %d, want 2", collector.Len())
	}

	res, err := collector.Reconcile()
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	analysis := &types.AnalysisResult{
		Timestamp:  base,
		Stats:      types.AnalysisStats{TotalFiles: 1, AnalyzedFiles: 1},
		NcerResult: res,
	}

	if res == nil {
		// Stub path (no native library linked): every report must omit the
		// NCER sections rather than emit zero-valued garbage.
		assertReportsOmitNcer(t, analysis)
		return
	}

	// FFI-linked path: verify the reconciliation counts, then confirm the
	// result survives JSON/SARIF/HTML rendering intact and that its evidence
	// reference actually resolves in the store it was written to.
	if res.BoundCount != 1 {
		t.Errorf("BoundCount = %d, want 1", res.BoundCount)
	}
	if res.OrphanCount != 1 {
		t.Errorf("OrphanCount = %d, want 1", res.OrphanCount)
	}
	if !res.EvidenceVerified {
		t.Errorf("EvidenceVerified = false, want true")
	}
	if len(res.EvidenceRefs) == 0 {
		t.Fatal("EvidenceRefs is empty, want at least one reference")
	}
	for _, ref := range res.EvidenceRefs {
		data, err := store.Retrieve(ref)
		if err != nil {
			t.Errorf("Retrieve(%q): %v", ref, err)
		}
		if data == nil {
			t.Errorf("Retrieve(%q) = nil, want stored capture payload", ref)
		}
	}

	assertReportsIncludeNcer(t, analysis, res)
}

func assertReportsOmitNcer(t *testing.T, analysis *types.AnalysisResult) {
	t.Helper()

	tmpDir := t.TempDir()
	if err := NewJSONReporter(analysis).Generate(tmpDir); err != nil {
		t.Fatalf("JSON Generate: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(tmpDir, "analysis.json"))
	if err != nil {
		t.Fatalf("read analysis.json: %v", err)
	}
	if strings.Contains(string(data), `"ncer"`) {
		t.Errorf("expected no 'ncer' field in JSON when Reconcile returned nil, got: %s", data)
	}

	sarifLog := NewSARIFReporter(analysis).Build()
	for _, run := range sarifLog.Runs {
		for _, r := range run.Results {
			if r.RuleID == "ncer/causal-discrepancy" {
				t.Errorf("expected no ncer/causal-discrepancy SARIF result when Reconcile returned nil")
			}
		}
	}

	var htmlBuf bytes.Buffer
	if err := NewHTMLReporter(analysis).GenerateStream(&htmlBuf); err != nil {
		t.Fatalf("HTML GenerateStream: %v", err)
	}
	if strings.Contains(htmlBuf.String(), `id="ncer-reconcile"`) {
		t.Errorf("expected no NCER HTML section when Reconcile returned nil")
	}
}

func assertReportsIncludeNcer(t *testing.T, analysis *types.AnalysisResult, res *types.NcerCausalResult) {
	t.Helper()

	tmpDir := t.TempDir()
	if err := NewJSONReporter(analysis).Generate(tmpDir); err != nil {
		t.Fatalf("JSON Generate: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(tmpDir, "analysis.json"))
	if err != nil {
		t.Fatalf("read analysis.json: %v", err)
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("analysis.json is not valid JSON: %v", err)
	}
	if _, ok := decoded["ncer"]; !ok {
		t.Errorf("expected 'ncer' field in JSON output, got: %s", data)
	}

	sarifLog := NewSARIFReporter(analysis).Build()
	foundSarif := false
	for _, run := range sarifLog.Runs {
		for _, r := range run.Results {
			if r.RuleID == "ncer/causal-discrepancy" {
				foundSarif = true
			}
		}
	}
	if !foundSarif {
		t.Errorf("expected ncer/causal-discrepancy SARIF result")
	}

	var htmlBuf bytes.Buffer
	if err := NewHTMLReporter(analysis).GenerateStream(&htmlBuf); err != nil {
		t.Fatalf("HTML GenerateStream: %v", err)
	}
	htmlStr := htmlBuf.String()
	if !strings.Contains(htmlStr, `id="ncer-reconcile"`) {
		t.Errorf("expected NCER HTML section")
	}
	for _, ref := range res.EvidenceRefs {
		if !strings.Contains(htmlStr, ref) {
			t.Errorf("expected evidence reference %q to appear in HTML output", ref)
		}
	}
}
