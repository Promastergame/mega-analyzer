package web

import (
	"reflect"
	"strings"
	"testing"
)

func TestDecisionAIChildArgs(t *testing.T) {
	s, err := New(Options{Port: 7474, DecisionAIURL: "http://localhost:17480", DecisionAIMaxFindings: 7, DecisionAIBudget: 12})
	if err != nil {
		t.Fatal(err)
	}
	base := []string{"-t", "app.apk"}
	want := []string{"-t", "app.apk", "-decision-ai-url", "http://127.0.0.1:17480", "-decision-ai-max-findings", "7", "-decision-ai-budget", "12"}
	if got := s.decisionAIArgs("full", base); !reflect.DeepEqual(got, want) {
		t.Fatalf("wrong child args: %v", got)
	}
	for _, mode := range []string{"sandbox", "decode", "web-scan", "minecraft", "decision-ai"} {
		if !reflect.DeepEqual(s.decisionAIArgs(mode, base), base) {
			t.Fatalf("unsupported mode %s modified", mode)
		}
	}
	if _, err := New(Options{Port: 7474, DecisionAIURL: "http://example.com"}); err == nil {
		t.Fatal("remote service accepted")
	}
}

func TestDecisionAIWebModeRegistration(t *testing.T) {
	if validModes["decision-ai"] {
		t.Fatal("decision-ai must not be a web tool")
	}
	if filelessModes["decision-ai"] {
		t.Fatal("decision-ai must not be a fileless web mode")
	}
	if toolSlugs["/decision-ai"] {
		t.Fatal("decision-ai must not have a web route")
	}

	html := spaHTML()
	if strings.Contains(html, "decision-ai") || strings.Contains(html, "DecisionAI") || strings.Contains(html, "decisionAiPanel") {
		t.Fatal("DecisionAI UI remains in the web assets")
	}
}
