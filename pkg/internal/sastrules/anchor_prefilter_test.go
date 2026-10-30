package sastrules

import "testing"

func TestAnchorPrefilterKeepsRequiredAndUnanchoredCandidates(t *testing.T) {
	engine := NewEngineFromRuleSets([]RuleSet{{Name: "test", Rules: []Rule{
		{ID: "anchored", Title: "anchored", Severity: "high", PatternType: PatRegex, Pattern: `danger[A-Z]+`},
		{ID: "or", Title: "or", Severity: "medium", PatternType: PatRegexOr, Patterns: []string{`alpha[0-9]+`, `beta[0-9]+`}},
	}}})
	anchored := engine.scanFile("a.js", []byte("const x = dangerZONE;"))
	if len(anchored) != 1 || anchored[0].RuleID != "anchored" {
		t.Fatalf("anchored candidates = %#v", anchored)
	}
	// Different OR branches cannot use one branch's prefix as a guaranteed
	// anchor. The rule must stay unanchored and still match beta alone.
	orMatches := engine.scanFile("b.js", []byte("const x = beta42;"))
	if len(orMatches) != 1 || orMatches[0].RuleID != "or" {
		t.Fatalf("OR candidates = %#v", orMatches)
	}
	if got := engine.scanFile("clean.js", []byte("nothing relevant")); len(got) != 0 {
		t.Fatalf("clean input matched: %#v", got)
	}
}
