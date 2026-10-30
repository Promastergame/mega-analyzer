package verdict

import (
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/finding"
	"mega-analyzer/pkg/internal/types"
)

func clean() *types.AnalysisResult {
	r := &types.AnalysisResult{}
	r.Stats.TotalFiles = 10
	r.Stats.AnalyzedFiles = 10
	return r
}

func matchWith(sev types.Severity) types.Match {
	var m types.Match
	m.Severity = sev
	return m
}

func TestCleanScan(t *testing.T) {
	ResetDegradations()
	if a := Assess(clean(), Options{}); a.Code != Clean {
		t.Fatalf("got %v", a.Code)
	}
}

func TestSeverityBands(t *testing.T) {
	ResetDegradations()
	cases := []struct {
		sev    types.Severity
		failOn types.Severity
		want   Code
	}{
		{types.SeverityCritical, 0, Hostile},
		{types.SeverityHigh, 0, Suspicious},
		{types.SeverityMedium, 0, Clean},
		{types.SeverityHigh, types.SeverityHigh, Hostile},
		{types.SeverityMedium, types.SeverityHigh, Suspicious},
		{types.SeverityLow, types.SeverityHigh, Clean},
		{types.SeverityLow, types.SeverityLow, Hostile},
	}
	for _, c := range cases {
		r := clean()
		r.RuleMatches = []types.Match{matchWith(c.sev)}
		if got := Assess(r, Options{FailOn: c.failOn}).Code; got != c.want {
			t.Errorf("sev=%v failOn=%v: got %v want %v", c.sev, c.failOn, got, c.want)
		}
	}
}

func TestCriticalCounterAndFindings(t *testing.T) {
	ResetDegradations()
	r := clean()
	r.Stats.CriticalMatches = 1
	if Assess(r, Options{}).Code != Hostile {
		t.Fatal("critical counter must produce Hostile")
	}
	r = clean()
	r.Findings = []finding.Finding{{Severity: "high"}}
	if Assess(r, Options{}).Code != Suspicious {
		t.Fatal("high finding must produce Suspicious")
	}
}

func TestIncompleteBeatsCleanAndSuspicious(t *testing.T) {
	ResetDegradations()
	r := clean()
	r.Coverage.ParseFailed = 2
	a := Assess(r, Options{})
	if a.Code != Incomplete || !strings.Contains(a.Summary(), "2 file(s) failed to parse") {
		t.Fatalf("clean+parse failures must be Incomplete: %+v", a)
	}
	r.RuleMatches = []types.Match{matchWith(types.SeverityHigh)}
	if Assess(r, Options{}).Code != Incomplete {
		t.Fatal("suspicious+incomplete must be Incomplete")
	}
}

func TestHostileStandsWhenIncomplete(t *testing.T) {
	ResetDegradations()
	r := clean()
	r.Coverage.LimitReached = true
	r.RuleMatches = []types.Match{matchWith(types.SeverityCritical)}
	a := Assess(r, Options{})
	if a.Code != Hostile {
		t.Fatalf("critical finding must stand: %+v", a)
	}
	if len(a.Incomplete) == 0 {
		t.Fatal("incomplete reasons should still be reported")
	}
}

func TestIncompleteSources(t *testing.T) {
	ResetDegradations()
	t.Cleanup(ResetDegradations)

	r := clean()
	r.Coverage.FilesFailed = 1
	if Assess(r, Options{}).Code != Incomplete {
		t.Error("FilesFailed")
	}
	r = clean()
	r.Coverage.SkippedByLimit = 5
	if Assess(r, Options{}).Code != Incomplete {
		t.Error("SkippedByLimit")
	}
	r = clean()
	r.Stats.AnalyzedFiles = 0
	if Assess(r, Options{}).Code != Incomplete {
		t.Error("nothing analyzed")
	}
	if Assess(clean(), Options{Interrupted: true}).Code != Incomplete {
		t.Error("interrupted")
	}
	MarkDegraded("rules", "3 rules skipped")
	if a := Assess(clean(), Options{}); a.Code != Incomplete || !strings.Contains(a.Summary(), "rules: 3 rules skipped") {
		t.Errorf("degradation: %+v", a)
	}
}

func TestSkippedBySizeAndUnsupportedAreNotIncomplete(t *testing.T) {
	ResetDegradations()
	r := clean()
	r.Coverage.SkippedBySize = 3
	r.Coverage.Unsupported = 9
	if Assess(r, Options{}).Code != Clean {
		t.Fatal("size skips and unsupported formats are configuration, not failure")
	}
}

func TestNilResultIsError(t *testing.T) {
	if Assess(nil, Options{}).Code != Error {
		t.Fatal("nil result must be Error")
	}
}

func TestDegradationsDeduplicated(t *testing.T) {
	ResetDegradations()
	MarkDegraded("a", "x")
	MarkDegraded("a", "x")
	MarkDegraded("b", "y")
	if got := Degradations(); len(got) != 2 {
		t.Fatalf("got %v", got)
	}
}

func TestParseFailOn(t *testing.T) {
	for in, want := range map[string]types.Severity{"": types.SeverityCritical, "HIGH": types.SeverityHigh, "medium": types.SeverityMedium, "low": types.SeverityLow} {
		got, err := ParseFailOn(in)
		if err != nil || got != want {
			t.Errorf("%q: %v %v", in, got, err)
		}
	}
	if _, err := ParseFailOn("info"); err == nil {
		t.Error("info must be rejected")
	}
}
