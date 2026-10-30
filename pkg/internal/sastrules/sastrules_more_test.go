package sastrules

import (
	"strings"
	"testing"
)

func TestNormalizeSeverity(t *testing.T) {
	cases := []struct {
		in   string
		want Severity
	}{
		{"critical", SevCritical},
		{"CRITICAL", SevCritical},
		{"high", SevHigh},
		{"HIGH", SevHigh},
		{"medium", SevMedium},
		{"warning", SevMedium},
		{"WARNING", SevMedium},
		{"low", SevLow},
		{"good", SevInfo},
		{"secure", SevInfo},
		{"unknown", SevInfo},
		{"", SevInfo},
	}
	for _, c := range cases {
		if got := normalizeSeverity(c.in); got != c.want {
			t.Errorf("normalizeSeverity(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSeverityRank(t *testing.T) {
	if severityRank(SevCritical) <= severityRank(SevHigh) {
		t.Error("critical must rank higher than high")
	}
	if severityRank(SevHigh) <= severityRank(SevMedium) {
		t.Error("high must rank higher than medium")
	}
	if severityRank(SevMedium) <= severityRank(SevLow) {
		t.Error("medium must rank higher than low")
	}
	if severityRank(SevLow) <= severityRank(SevInfo) {
		t.Error("low must rank higher than info")
	}
}

func TestInterestingPath(t *testing.T) {
	yes := []string{"Main.java", "Activity.kt", "res/values/strings.xml", "gradle.properties", "code.smali"}
	for _, p := range yes {
		if !interestingPath(p) {
			t.Errorf("interestingPath(%q) = false, want true", p)
		}
	}
	no := []string{"image.png", "binary.so", "README.md", "data.bin"}
	for _, p := range no {
		if interestingPath(p) {
			t.Errorf("interestingPath(%q) = true, want false", p)
		}
	}
}

func TestRenderMarkdown_Nil(t *testing.T) {
	md := RenderMarkdown(nil)
	if !strings.Contains(md, "no report") {
		t.Errorf("nil report should say 'no report', got:\n%s", md)
	}
}

func TestRenderMarkdown_Clean(t *testing.T) {
	r := &Report{
		Target:     "app.apk",
		BySeverity: map[Severity]int{},
		ByRuleSet:  map[string]int{},
		Verdict:    "clean",
	}
	md := RenderMarkdown(r)
	if !strings.Contains(md, "SAST Scan") {
		t.Errorf("expected header, got:\n%s", md)
	}
	if !strings.Contains(md, "app.apk") {
		t.Errorf("expected target, got:\n%s", md)
	}
}

func TestRenderMarkdown_WithFindings(t *testing.T) {
	r := &Report{
		Target:     "app.apk",
		BySeverity: map[Severity]int{SevHigh: 1},
		ByRuleSet:  map[string]int{"android": 1},
		Verdict:    "dangerous",
		Score:      75,
		TopRules:   []RuleSummary{{RuleID: "R001", Title: "Hardcoded Key", Severity: SevHigh, Hits: 1}},
		Matches:    []Match{{RuleID: "R001", Title: "Hardcoded Key", Severity: SevHigh, File: "Main.java", Line: 42}},
	}
	md := RenderMarkdown(r)
	if !strings.Contains(md, "dangerous") {
		t.Errorf("expected verdict in output")
	}
	if !strings.Contains(md, "Hardcoded Key") {
		t.Errorf("expected rule title in output")
	}
	if !strings.Contains(md, "Main.java") {
		t.Errorf("expected file in output")
	}
}

func TestFinalize_ScoreCap(t *testing.T) {
	r := &Report{
		Target:     "app.apk",
		BySeverity: map[Severity]int{},
		ByRuleSet:  map[string]int{},
	}
	// 20 critical hits = 160 score → should cap to 100
	for i := 0; i < 20; i++ {
		r.Matches = append(r.Matches, Match{
			RuleID:   "CRIT",
			Title:    "Critical Finding",
			Severity: SevCritical,
			File:     "A.java",
		})
	}
	finalize(r)
	if r.Score != 100 {
		t.Errorf("score = %d, want capped 100", r.Score)
	}
	if r.Verdict != "dangerous" {
		t.Errorf("verdict = %q, want dangerous", r.Verdict)
	}
}

func TestFinalize_CleanVerdict(t *testing.T) {
	r := &Report{
		Target:     "app.apk",
		BySeverity: map[Severity]int{},
		ByRuleSet:  map[string]int{},
	}
	finalize(r)
	if r.Verdict != "clean" {
		t.Errorf("verdict = %q, want clean", r.Verdict)
	}
	if r.Score != 0 {
		t.Errorf("score = %d, want 0", r.Score)
	}
}

func TestNewEngineFromEmbedded(t *testing.T) {
	e, err := NewEngineFromEmbedded()
	if err != nil {
		t.Fatalf("NewEngineFromEmbedded: %v", err)
	}
	if e == nil {
		t.Fatal("expected non-nil engine")
	}
}
