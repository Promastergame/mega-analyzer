package pipeline

import (
	"fmt"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/rules"
	"mega-analyzer/pkg/internal/types"
)

// evaluateFileScopedCombos now spreads the per-file work over every core and
// merges the results afterwards. The merge is what the report is built from,
// so it has to be stable: same input, same ordered output, same "which file
// did this rule fire in" attribution, every single run.
//
// It also has to stay stable across runs of the *same* binary. The original
// loop ranged straight over p.result.Files, which is a map, so the attribution
// was already whatever Go's randomised map order handed it. These tests pin
// the sorted-path behaviour that replaced it.

const fileScopedComboRules = `{
  "category": "parallel_test",
  "version": "1",
  "rules": [
    {"id":"r_gamma","name":"Gamma","severity":"low","score":10,"enabled":true,"scope":"file",
     "logic":"and",
     "conditions":[{"type":"string","value":"gamma"},{"type":"pattern","value":"gamma"}]},
    {"id":"r_alpha","name":"Alpha","severity":"medium","score":20,"enabled":true,"scope":"file",
     "logic":"and",
     "conditions":[{"type":"string","value":"alpha"},{"type":"pattern","value":"alpha"}]},
    {"id":"r_beta","name":"Beta","severity":"high","score":30,"enabled":true,"scope":"file",
     "logic":"and",
     "conditions":[{"type":"string","value":"beta"},{"type":"pattern","value":"beta"}]},
    {"id":"r_delta","name":"Delta","severity":"low","score":15,"enabled":true,"scope":"file",
     "logic":"and",
     "conditions":[{"type":"string","value":"delta"},{"type":"pattern","value":"delta"}]}
  ]
}`

func comboTestEngine(t *testing.T) *rules.Engine {
	t.Helper()
	e := rules.NewEngine()
	if err := e.LoadRulesFromBytes("parallel_test", []byte(fileScopedComboRules)); err != nil {
		t.Fatalf("load rules: %v", err)
	}
	if n := e.Stats().TotalRules; n != 4 {
		t.Fatalf("expected 4 loaded rules, got %d", n)
	}
	return e
}

// evidenceFile builds a file that carries recovered plaintext. A parsed smali
// class is required because fileMayMatchCombo refuses to build a context for
// files with no code-level evidence at all.
func evidenceFile(path string, recovered ...string) *types.FileAnalysis {
	return &types.FileAnalysis{
		Path:             path,
		Type:             types.FileTypeSmali,
		SmaliClass:       &types.SmaliClass{Name: "Lcom/example/Carrier;"},
		RecoveredStrings: recovered,
	}
}

// comboTestPipeline wires the minimum a file-scoped combo pass needs. Several
// files deliberately carry the same evidence so first-wins attribution is
// actually exercised rather than assumed.
func comboTestPipeline(t *testing.T) *Pipeline {
	t.Helper()
	return &Pipeline{
		rulesEngine: comboTestEngine(t),
		result: &types.AnalysisResult{
			Files: map[string]*types.FileAnalysis{
				"a/00_gamma.smali":      evidenceFile("a/00_gamma.smali", "gamma"),
				"b/10_alpha.smali":      evidenceFile("b/10_alpha.smali", "alpha"),
				"c/20_alpha_beta.smali": evidenceFile("c/20_alpha_beta.smali", "alpha", "beta"),
				"d/30_beta.smali":       evidenceFile("d/30_beta.smali", "beta"),
				"e/40_empty.smali":      {Path: "e/40_empty.smali", Type: types.FileTypeSmali},
				"f/50_delta.smali":      evidenceFile("f/50_delta.smali", "delta"),
				"g/60_nil.smali":        nil,
			},
		},
	}
}

func comboSignature(res []rules.RuleEvaluationResult) string {
	parts := make([]string, 0, len(res))
	for _, r := range res {
		parts = append(parts, fmt.Sprintf("%s@%s", r.RuleID, r.MatchedFile))
	}
	return strings.Join(parts, " | ")
}

// The whole point of the parallel merge: the answer must not depend on which
// goroutine finished first.
func TestFileScopedCombosAreDeterministicUnderParallelism(t *testing.T) {
	p := comboTestPipeline(t)

	first := comboSignature(p.evaluateFileScopedCombos(nil))
	if first == "" {
		t.Fatal("no file-scoped rule fired; the fixture is not exercising anything")
	}

	for i := 0; i < 25; i++ {
		if got := comboSignature(p.evaluateFileScopedCombos(nil)); got != first {
			t.Fatalf("run %d disagreed with run 0:\n  run 0: %s\n  run %d: %s", i+1, first, i+1, got)
		}
	}
}

// Dedup keeps the first file a rule fired in. "First" is now defined by sorted
// path, not by map iteration luck: r_alpha fires in both b/10 and c/20 and must
// always be credited to b/10.
func TestFileScopedCombosAttributeToFirstSortedPath(t *testing.T) {
	p := comboTestPipeline(t)
	got := comboSignature(p.evaluateFileScopedCombos(nil))

	want := strings.Join([]string{
		"r_gamma@a/00_gamma.smali",
		"r_alpha@b/10_alpha.smali",
		"r_beta@c/20_alpha_beta.smali",
		"r_delta@f/50_delta.smali",
	}, " | ")

	if got != want {
		t.Errorf("file-scoped combo merge changed\n  want: %s\n  got:  %s", want, got)
	}
}

// Each rule may appear at most once no matter how many files carry it.
func TestFileScopedCombosDedupeAcrossFiles(t *testing.T) {
	p := comboTestPipeline(t)
	seen := map[string]int{}
	for _, r := range p.evaluateFileScopedCombos(nil) {
		seen[r.RuleID]++
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("rule %q reported %d times, expected exactly 1", id, n)
		}
	}
	if len(seen) != 4 {
		t.Errorf("expected all 4 fixture rules to fire once, got %d distinct", len(seen))
	}
}

// A nil map entry and an evidence-free file both used to be skipped by the
// serial loop. The parallel version must skip them without panicking, and
// without shifting anyone else's index in the merge.
func TestFileScopedCombosSurviveNilAndEvidencelessEntries(t *testing.T) {
	p := comboTestPipeline(t)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("nil or evidence-free file panicked the combo pass: %v", r)
		}
	}()

	for _, r := range p.evaluateFileScopedCombos(nil) {
		if r.MatchedFile == "g/60_nil.smali" || r.MatchedFile == "e/40_empty.smali" {
			t.Errorf("rule %q attributed to a file with no evidence: %q", r.RuleID, r.MatchedFile)
		}
		if r.MatchedFile == "" {
			t.Errorf("rule %q lost its file attribution", r.RuleID)
		}
	}
}

func TestEvaluateFileScopedCombosHandlesEmptyFileSet(t *testing.T) {
	p := &Pipeline{
		rulesEngine: comboTestEngine(t),
		result:      &types.AnalysisResult{Files: map[string]*types.FileAnalysis{}},
	}
	if got := p.evaluateFileScopedCombos(nil); got != nil {
		t.Errorf("expected nil for an empty file set, got %v", got)
	}
}

func TestEvaluateOneFileScopedRejectsEvidencelessFile(t *testing.T) {
	e := comboTestEngine(t)

	if got := evaluateOneFileScoped(e, nil, nil); got != nil {
		t.Errorf("nil file should evaluate to nil, got %v", got)
	}

	bare := &types.FileAnalysis{Path: "x/bare.smali", Type: types.FileTypeSmali}
	if got := evaluateOneFileScoped(e, bare, nil); got != nil {
		t.Errorf("file with no smali class and no matches should evaluate to nil, got %v", got)
	}

	loaded := evidenceFile("x/loaded.smali", "alpha")
	if got := evaluateOneFileScoped(e, loaded, nil); len(got) == 0 {
		t.Error("file carrying recovered plaintext should still match its rule")
	}
}
