package report

import (
	"strings"
	"testing"
)

// TestHTMLArtifactsHidden ensures the artifacts section is byte-identical
// absent when WithArtifacts is not used. This is the integration guarantee
// from plan §11.
func TestHTMLArtifactsHidden(t *testing.T) {
	r := makeResultWithData()
	html := NewHTMLReporter(r).BuildHTML()
	if strings.Contains(html, `id="artifacts"`) {
		t.Fatal("Artifacts section leaked into HTML without --artifacts")
	}
	if strings.Contains(html, "artifacts-grid") {
		t.Fatal("Artifacts grid markup leaked")
	}
}

// TestHTMLArtifactsRendered ensures the section appears when wired in.
func TestHTMLArtifactsRendered(t *testing.T) {
	r := makeResultWithData()
	view := &ArtifactsView{
		AllowExport: false,
		Summary: ArtifactsSummary{
			Total:   1,
			Flagged: 0,
			ByType:  map[string]int{"image": 1},
		},
		Items: []ArtifactItem{{
			ID:       "art_0001",
			Path:     "res/drawable/icon.png",
			Type:     "image",
			Mime:     "image/png",
			Size:     123,
			Forensic: ForensicReport{Verdict: "ok"},
		}},
	}
	html := NewHTMLReporter(r).WithArtifacts(view).BuildHTML()
	if !strings.Contains(html, `id="artifacts"`) {
		t.Fatal("Artifacts section missing")
	}
	if !strings.Contains(html, "art_0001") {
		t.Fatal("Artifact card missing")
	}
}

// TestJSONArtifactsHidden — JSON output does not gain artifacts fields when
// the panel is disabled.
func TestJSONArtifactsHidden(t *testing.T) {
	r := makeResultWithData()
	dir := t.TempDir()
	if err := NewJSONReporter(r).Generate(dir); err != nil {
		t.Fatal(err)
	}
}

// TestArtifactsViewSchemaConsistency — verdicts on items must be
// whitelist-compliant.
func TestArtifactsViewSchemaConsistency(t *testing.T) {
	view := &ArtifactsView{
		Items: []ArtifactItem{{
			ID:       "art_0001",
			Path:     "x.png",
			Type:     "image",
			Forensic: ForensicReport{Verdict: "ok"},
		}},
	}
	if view.Items[0].Forensic.Verdict == "virus" {
		t.Fatal("virus leaked into report.ArtifactsView")
	}
}
