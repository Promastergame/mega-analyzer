package report

import (
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func TestJSONExportPreservesEvidenceAndCoverage(t *testing.T) {
	var result types.AnalysisResult
	// These fields used to disappear from the streaming export even though
	// the pipeline/API supplied them. Exercise the consumer's JSON contract.
	const input = `{
		"run":{"status":"incomplete","stop_reason":"timeout","profile":"balanced","timeout_seconds":42,"core_settings":{"max_files":100}},
		"coverage":{"discovered":12,"parsed":8,"parse_failed":1,"skipped_by_limit":3,"limit_reached":true},
		"cache":{"enabled":true,"method_hits":42},
		"data_flow_stats":{"cancelled":true,"limit_reached":true},
		"findings":[{"schema_version":1,"id":"f1","fingerprint":"stable","rule_id":"crypto.weak","kind":"vulnerability","severity":"high","confidence":0.9,"occurrences":1,"evidence":[{"kind":"code","value":"example"}],"provenance":[{"engine":"static","rule_id":"crypto.weak"}]}],
		"findings_by_kind":{"vulnerability":1},
		"data_flows":[{"source":"input","sink":"exec","path":[{"method":"run","type":"call","line":4}]}],
		"data_flow_observations":[{"source":"input","sink":"log"}],
		"artifact_findings":[{"path":"AndroidManifest.xml","reason":"debuggable"}],
		"deobfuscation":{"recovered_strings":2},
		"gnn_findings":[{"method":"f","dummy":true}],
		"risk_profile":{"assessment":"partial"},
		"evidence_graph":{"version":"1","nodes":[{"id":"f1","kind":"finding","label":"Weak crypto"}]}
	}`
	if err := json.Unmarshal([]byte(input), &result); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := NewJSONReporter(&result).Generate(dir); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "analysis.json"))
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := json.Marshal(&result)
	if err != nil {
		t.Fatal(err)
	}
	var want, got map[string]any
	json.Unmarshal(canonical, &want)
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	for key, value := range want {
		if !reflect.DeepEqual(got[key], value) {
			t.Errorf("export lost or changed %s: got %#v, want %#v", key, got[key], value)
		}
	}
}

func TestFailedExportKeepsPreviousReport(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "analysis.json")
	previous := []byte(`{"previous":"complete"}`)
	if err := os.WriteFile(path, previous, 0600); err != nil {
		t.Fatal(err)
	}
	result := &types.AnalysisResult{DeobfQualityConfidence: math.NaN()}
	if err := NewJSONReporter(result).Generate(dir); err == nil {
		t.Fatal("invalid JSON value should fail the export")
	}
	got, _ := os.ReadFile(path)
	if string(got) != string(previous) {
		t.Fatalf("previous report was overwritten: %s", got)
	}
	files, _ := os.ReadDir(dir)
	if len(files) != 1 {
		t.Fatal("failed export left temporary files")
	}
	if err := NewJSONReporter(&types.AnalysisResult{}).Generate(dir); err != nil {
		t.Fatalf("successful replacement failed: %v", err)
	}
}

func TestReportWriteFailureIsReturned(t *testing.T) {
	dir := t.TempDir()
	want := errors.New("simulated disk failure")
	err := writeReportFile(dir, "REPORT.html", func(w io.Writer) error {
		io.WriteString(w, "partial report")
		return want
	})
	if !errors.Is(err, want) {
		t.Fatalf("got %v, want write error", err)
	}
	if files, _ := os.ReadDir(dir); len(files) != 0 {
		t.Fatal("failed write published partial output")
	}
}

func TestSARIFPathsAreURIReferences(t *testing.T) {
	for _, tc := range []struct{ path, uri string }{
		{"src/a b#c?.smali", "src/a%20b%23c%3F.smali"},
		{"src/100%.java", "src/100%25.java"},
		{`C:\work\a b.smali`, "file:///C:/work/a%20b.smali"},
		{"/tmp/a#b", "file:///tmp/a%23b"},
		{`\\server\share\a b`, "file://server/share/a%20b"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			got := sarifLocationFor(tc.path, 1, 0).PhysicalLocation.ArtifactLocation.URI
			if got != tc.uri {
				t.Fatalf("got %q, want %q", got, tc.uri)
			}
			parsed, err := url.Parse(got)
			if err != nil || parsed.Fragment != "" || parsed.RawQuery != "" {
				t.Fatalf("path became a query or fragment: %q", got)
			}
		})
	}
}
