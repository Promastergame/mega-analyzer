package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/sourceevidence"
	"mega-analyzer/pkg/internal/types"
)

func TestEvidenceDiagnosticsExportAndEscapeUntrustedCode(t *testing.T) {
	r := types.NewAnalysisResult("fixture")
	foreign := `</pre><script>alert('foreign')</script>`
	source := sourceevidence.NewReport()
	source.Checks = []sourceevidence.Check{{Kind: "output_name", Status: "supported", Choice: "constant_filename", Summary: foreign,
		Citations: []sourceevidence.Citation{{File: foreign, Line: 1, Snippet: foreign}}}}
	r.SourceEvidence = &source
	r.GNNDiagnostics = &types.GNNDiagnostics{SchemaVersion: 1, Status: "complete", StaticOnly: true, MethodsDiscovered: 3, MethodsInferred: 1,
		MethodsSkipped: 2, PredictionsByClass: map[string]int{"benign": 1}, Model: types.GNNModelInfo{TrainerVersion: foreign, Taxonomy: []string{"benign"}},
		Methods: []types.GNNMethodDiagnostic{{Method: foreign, Status: "predicted", PredictedClass: "benign", Outcome: "negative_taxonomy_class"}}}
	html := NewHTMLReporter(r).BuildHTML()
	if strings.Contains(html, foreign) || !strings.Contains(html, "&lt;/pre&gt;") ||
		!strings.Contains(html, `id="finding-explanations"`) || !strings.Contains(html, `href="GNN_DIAGNOSTICS.json"`) ||
		strings.Contains(html, `id="source-evidence"`) || strings.Contains(html, `id="gnn-coverage"`) || strings.Contains(html, `id="decision-ai"`) {
		t.Fatal("source diagnostics absent or foreign code treated as markup")
	}
	md := NewMarkdownReporter(r).BuildMarkdown()
	if strings.Contains(md, foreign) || !strings.Contains(md, "## GNN coverage") || !strings.Contains(md, "## Static source evidence") {
		t.Fatal("Markdown lost coverage or escaped source")
	}
	dir := t.TempDir()
	if err := NewJSONReporter(r).Generate(dir); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "analysis.json"))
	if err != nil {
		t.Fatal(err)
	}
	var decoded types.AnalysisResult
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.GNNDiagnostics == nil || decoded.GNNDiagnostics.MethodsInferred != 1 || decoded.SourceEvidence == nil ||
		len(decoded.SourceEvidence.Checks) != 1 {
		t.Fatal("streaming JSON lost source or GNN diagnostics")
	}
}
