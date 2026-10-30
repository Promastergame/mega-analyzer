package correlation

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sampleResult() *Result {
	now := time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)
	return &Result{
		GeneratedAt:   now,
		SessionID:     "sess-1",
		HasRuntime:    true,
		HasStatic:     true,
		OverallRisk:   RiskHigh,
		OverallLikeli: LikelihoodHigh,
		Notes:         []string{"first note", "second note"},
		Findings: []Finding{{
			ID:       "f-1",
			Category: "demo",
			Title:    "demo finding",
			Risk:     RiskHigh,
		}},
		Chains: []AttackChain{{
			ID:              "c-1",
			Name:            "Demo chain",
			Risk:            RiskCritical,
			Likelihood:      LikelihoodHigh,
			Description:     "synthetic",
			InvolvedKinds:   []SignalKind{KindAudit, KindNetwork},
			MITRETechniques: []string{"T1059"},
			Factors: LikelihoodFactors{
				Reachable:         true,
				Controllable:      true,
				ObservedAtRuntime: true,
			},
			Sequence: []AttackChainStep{{
				Order: 1, Component: "static", Title: "step",
				Description: "did a thing", Timestamp: now,
				Signals: []*Signal{{ID: "s1", Title: "evidence", Type: "demo"}},
			}},
			Evidence:    []*Signal{{ID: "s2", Type: "demo", Title: "ev"}},
			Explanation: "why it matters",
			Mitigations: []string{"do X"},
			Workarounds: []string{"verify Y"},
		}},
		Timeline: []TimelineEvent{{
			Timestamp:  now,
			Kind:       KindNetwork,
			ProcessKey: "static",
			Title:      "evt",
			SignalID:   "s1",
		}},
		Stats: ResultStats{
			TotalSignals: 5, StaticSignals: 3, RuntimeSignals: 2,
			TotalFindings: 1, TotalChains: 1, HighRisks: 1, CriticalRisks: 1,
		},
	}
}

func TestWriteReportsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	jsonPath, mdPath, err := WriteReports(sampleResult(), dir)
	if err != nil {
		t.Fatalf("WriteReports: %v", err)
	}

	// Both files exist with content.
	for _, p := range []string{jsonPath, mdPath} {
		st, err := os.Stat(p)
		if err != nil {
			t.Errorf("missing %s: %v", p, err)
			continue
		}
		if st.Size() == 0 {
			t.Errorf("file %s is empty", p)
		}
	}

	// JSON parses back into a Result.
	data, _ := os.ReadFile(jsonPath)
	var rt Result
	if err := json.Unmarshal(data, &rt); err != nil {
		t.Fatalf("json round-trip: %v", err)
	}
	if rt.SessionID != "sess-1" {
		t.Errorf("SessionID lost in round-trip: %q", rt.SessionID)
	}

	// Markdown contains the expected sections.
	md, _ := os.ReadFile(mdPath)
	for _, want := range []string{
		"# 🔗 Correlation & Attack-Chain Report",
		"## 📊 At a glance",
		"## ⛓ Attack Chains",
		"## 🔍 Findings",
		"Demo chain",
		"sess-1",
		"first note",
	} {
		if !strings.Contains(string(md), want) {
			t.Errorf("markdown missing %q\n%s", want, md)
		}
	}
}

func TestWriteReportsNilResultErrors(t *testing.T) {
	if _, _, err := WriteReports(nil, t.TempDir()); err == nil {
		t.Error("nil result should error")
	}
}

func TestWriteReportsEmptyDirErrors(t *testing.T) {
	if _, _, err := WriteReports(sampleResult(), ""); err == nil {
		t.Error("empty dir should error")
	}
}

func TestWriteReportsBadDir(t *testing.T) {
	// Use a path that's actually a file → MkdirAll inside fails.
	dir := t.TempDir()
	conflict := filepath.Join(dir, "regular.txt")
	if err := os.WriteFile(conflict, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := WriteReports(sampleResult(), filepath.Join(conflict, "child")); err == nil {
		t.Error("MkdirAll over a file should fail")
	}
}

func TestRenderMarkdownNilResult(t *testing.T) {
	got := RenderMarkdown(nil)
	if !strings.Contains(got, "# Correlation Report") || !strings.Contains(got, "*No data") {
		t.Errorf("nil report missing baseline message: %q", got)
	}
}

func TestRenderMarkdownEmptyChains(t *testing.T) {
	r := sampleResult()
	r.Chains = nil
	r.Findings = nil
	r.Timeline = nil
	md := RenderMarkdown(r)
	if !strings.Contains(md, "*No attack chains matched.*") {
		t.Errorf("empty chains section missing baseline: %s", md)
	}
}
