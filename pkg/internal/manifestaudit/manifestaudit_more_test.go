package manifestaudit

import (
	"sort"
	"testing"
)

func TestNormalizeLaunchMode(t *testing.T) {
	cases := []struct{ in, want string }{
		{"0", "standard"},
		{"1", "singleTop"},
		{"2", "singleTask"},
		{"3", "singleInstance"},
		{"4", "singleInstancePerTask"},
		{"standard", "standard"},
		{"unknown", "unknown"},
		{"", ""},
	}
	for _, c := range cases {
		if got := normalizeLaunchMode(c.in); got != c.want {
			t.Errorf("normalizeLaunchMode(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSeverityRank(t *testing.T) {
	if severityRank(SevCritical) <= severityRank(SevHigh) {
		t.Error("critical must rank > high")
	}
	if severityRank(SevHigh) <= severityRank(SevMedium) {
		t.Error("high must rank > medium")
	}
	if severityRank(SevMedium) <= severityRank(SevLow) {
		t.Error("medium must rank > low")
	}
	if severityRank(SevLow) <= severityRank(SevInfo) {
		t.Error("low must rank > info")
	}
	if severityRank("unknown") != 0 {
		t.Error("unknown severity should rank 0")
	}
}

func TestScoreReport(t *testing.T) {
	r := &Report{}
	score, verdict := scoreReport(r)
	if score != 0 || verdict != "hardened" {
		t.Errorf("empty report: score=%d verdict=%q, want 0/hardened", score, verdict)
	}

	// Add enough issues to push score to dangerous
	for i := 0; i < 10; i++ {
		r.Issues = append(r.Issues, Issue{Score: 8})
	}
	score, verdict = scoreReport(r)
	if score != 80 || verdict != "dangerous" {
		t.Errorf("high score: got %d/%q, want 80/dangerous", score, verdict)
	}

	// Score capped at 100
	for i := 0; i < 10; i++ {
		r.Issues = append(r.Issues, Issue{Score: 20})
	}
	score, _ = scoreReport(r)
	if score != 100 {
		t.Errorf("score should cap at 100, got %d", score)
	}
}

func TestSortedKeys(t *testing.T) {
	m := map[string]struct{}{"b": {}, "a": {}, "c": {}}
	keys := sortedKeys(m)
	if !sort.StringsAreSorted(keys) {
		t.Errorf("sortedKeys should be sorted: %v", keys)
	}
	if len(keys) != 3 {
		t.Errorf("expected 3 keys, got %d", len(keys))
	}
}
