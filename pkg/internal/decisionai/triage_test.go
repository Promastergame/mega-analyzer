package decisionai

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"mega-analyzer/pkg/internal/finding"
)

func TestTriageBoundedAdvisoryAndOriginalsUnchanged(t *testing.T) {
	findings := []finding.Finding{
		{ID: "low", Severity: "low", Confidence: 0.3, RuleID: "low/test"},
		{ID: "critical", Severity: "critical", Confidence: 0.9, RuleID: "secret/test"},
	}
	original := append([]finding.Finding(nil), findings...)
	calls := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var req Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		if !strings.Contains(string(req.State), `"severity":"critical"`) {
			t.Error("severity priority lost")
		}
		if q := req.Questions["false_positive"]; q.Task != "false_positive" || q.Polarity != "positive" {
			t.Error("ambiguous question")
		}
		fmt.Fprint(w, strings.ReplaceAll(strings.ReplaceAll(noulResponse, `"fp":`, `"false_positive":`), `"route":"review"`, `"route":"auto"`))
	}))
	defer s.Close()
	c, _ := New(s.URL, "")
	defer c.Close()
	r := Triage(context.Background(), c, findings, 1)
	if r.Status != "partial" || r.Processed != 1 || r.Skipped != 1 || calls != 1 || !r.AdvisoryOnly {
		t.Fatalf("wrong report: %+v", r)
	}
	if r.Entries[0].ReviewRoute != "review" || r.Entries[0].AssessmentKind != "scanner_rule_advisory" {
		t.Fatal("auto verdict or heuristic promoted to confirmation")
	}
	if !reflect.DeepEqual(findings, original) {
		t.Fatal("scanner findings modified")
	}
}

func TestTriageUnavailableStopsRequests(t *testing.T) {
	calls := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(503) }))
	defer s.Close()
	c, _ := New(s.URL, "")
	defer c.Close()
	r := Triage(context.Background(), c, make([]finding.Finding, 20), 20)
	if r.Status != "unavailable" || r.Error == "" || r.Skipped != 20 || calls != 1 {
		t.Fatalf("failure hidden or repeated: %+v", r)
	}
}

func TestFindingContextBoundedWithoutMutatingEvidence(t *testing.T) {
	text := strings.Repeat("Я", 6000)
	f := finding.Finding{RuleID: "test", Description: text, Evidence: []finding.Evidence{{Snippet: text}}}
	req, truncated := findingRequest(f)
	if !truncated || !utf8.Valid(req.State) || len(req.State) > 256<<10 {
		t.Fatal("context cap invalid")
	}
	if f.Evidence[0].Snippet != text {
		t.Fatal("original evidence changed")
	}
	var state map[string]any
	if json.Unmarshal(req.State, &state) != nil || state["context_truncated"] != true {
		t.Fatal("truncation not disclosed")
	}
}

func TestTriageNoEvidenceRequiresHuman(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"version":"1","backend":"test","answers":{"false_positive":{"type":"noul","noul":0.99,"route":"auto"}}}`)
	}))
	defer s.Close()
	c, _ := New(s.URL, "")
	defer c.Close()
	r := Triage(context.Background(), c, []finding.Finding{{ID: "test"}}, 1)
	if r.Processed != 1 || r.Entries[0].ReviewRoute != "human" {
		t.Fatalf("unsupported certainty accepted: %+v", r)
	}
}
