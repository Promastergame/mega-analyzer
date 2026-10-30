package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/decisionai"
	"mega-analyzer/pkg/internal/types"
)

func TestDecisionAIHTMLIsOptionalAndEscaped(t *testing.T) {
	r := NewHTMLReporter(types.NewAnalysisResult("fixture"))
	var b strings.Builder
	r.buildDecisionAISection(&b)
	if b.Len() != 0 {
		t.Fatal("disabled integration changed report")
	}
	r.result.DecisionAI = &decisionai.Report{Status: "partial", Error: `<script>alert(1)</script>`, Entries: []decisionai.Entry{{RuleID: `<img src=x onerror=alert(1)>`, Response: decisionai.Response{Answers: map[string]decisionai.Answer{"false_positive": {Evidence: []string{`<script>bad()</script>`}}}}}}}
	r.buildDecisionAISection(&b)
	if strings.Contains(b.String(), "<script>") || strings.Contains(b.String(), "<img src=x") || !strings.Contains(b.String(), "&lt;script&gt;") {
		t.Fatal("unescaped external text in HTML")
	}
}

func TestDecisionAIJSONStreamingReport(t *testing.T) {
	r := types.NewAnalysisResult("fixture")
	r.DecisionAI = &decisionai.Report{SchemaVersion: 1, AdvisoryOnly: true, Status: "complete", Entries: []decisionai.Entry{}}
	dir := t.TempDir()
	if err := NewJSONReporter(r).Generate(dir); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "analysis.json"))
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		DecisionAI *decisionai.Report `json:"decision_ai"`
	}
	if err := json.Unmarshal(b, &result); err != nil {
		t.Fatal(err)
	}
	if result.DecisionAI == nil || !result.DecisionAI.AdvisoryOnly {
		t.Fatal("streaming report lost DecisionAI result")
	}
}
