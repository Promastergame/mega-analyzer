package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestJSONArtifactsBumpsSchema(t *testing.T) {
	r := makeResultWithData()
	view := &ArtifactsView{
		Summary: ArtifactsSummary{
			Total:   1,
			Flagged: 0,
			ByType:  map[string]int{"image": 1},
		},
		Items: []ArtifactItem{{
			ID:       "art_0001",
			Path:     "x.png",
			Type:     "image",
			Size:     10,
			Forensic: ForensicReport{Verdict: "ok"},
		}},
	}
	dir := t.TempDir()
	if err := NewJSONReporter(r).WithArtifacts(view).Generate(dir); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "analysis.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"schema_version": "2.1"`) {
		t.Fatal("expected schema 2.1 bump")
	}
	if !strings.Contains(string(data), `"artifacts"`) {
		t.Fatal("artifacts field missing")
	}
	// Validate it's still valid JSON.
	var generic map[string]any
	if err := json.Unmarshal(data, &generic); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
}

func TestJSONNoArtifactsByDefault(t *testing.T) {
	r := makeResultWithData()
	dir := t.TempDir()
	if err := NewJSONReporter(r).Generate(dir); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(dir, "analysis.json"))
	var document map[string]json.RawMessage
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	if _, ok := document["artifacts"]; ok {
		t.Fatal("artifacts leaked into JSON without WithArtifacts")
	}
	if _, ok := document["schema_version"]; ok {
		t.Fatal("schema_version should not appear unless artifacts enabled")
	}
}
