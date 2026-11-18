package textai

import (
	"os"
	"path/filepath"
	"testing"

	"decisionai/engine"
)

// Exercise the shipped model and examples together, including the distinction
// between a text prediction and the checks required for a candidate.
func TestBundledDemoScenarios(t *testing.T) {
	modelData, err := os.ReadFile(filepath.Join("..", "models", "demo-text-model.json"))
	if err != nil {
		t.Fatal(err)
	}
	var model Model
	if err := engine.Decode(modelData, &model); err != nil {
		t.Fatal(err)
	}
	if err := model.Validate(); err != nil {
		t.Fatal(err)
	}
	if !model.Synthetic {
		t.Fatal("the bundled demo must identify its synthetic training data")
	}
	data, err := os.ReadFile(filepath.Join("..", "examples", "text-cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var requests []Request
	if err := engine.Decode(data, &requests); err != nil {
		t.Fatal(err)
	}
	wants := map[string]struct{ answer, decision, gate string }{
		"confirmed":    {"yes", "demo_only", "records_match"},
		"missing":      {"no", "blocked", "blocked"},
		"stale":        {"no", "blocked", "blocked"},
		"runtime-fail": {"no", "blocked", "blocked"},
		"injection":    {"", "blocked", "blocked"},
	}
	seen := make(map[string]bool)
	for _, request := range requests {
		want, ok := wants[request.ID]
		if !ok || seen[request.ID] {
			t.Fatalf("unexpected or duplicate scenario %q", request.ID)
		}
		seen[request.ID] = true
		t.Run(request.ID, func(t *testing.T) {
			report, err := Analyze(request, &model)
			if err != nil {
				t.Fatal(err)
			}
			if want.answer != "" && report.Answer != want.answer {
				t.Errorf("answer = %q, want %q", report.Answer, want.answer)
			}
			if report.Decision != want.decision || report.Gate.Status != want.gate {
				t.Errorf("decision/gate = %s/%s, want %s/%s", report.Decision, report.Gate.Status, want.decision, want.gate)
			}
			if report.CanApply || report.Prediction.Kind != "synthetic_demo_estimate" {
				t.Fatalf("demo must remain advisory and identify its model: %+v", report)
			}
		})
	}
	for id := range wants {
		if !seen[id] {
			t.Errorf("missing bundled scenario %q", id)
		}
	}
}
