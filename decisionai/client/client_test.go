package client

import "testing"

func TestSecretFindingState(t *testing.T) {
	lib := false
	s := SecretFinding{RuleID: "secret/stripe-key", Severity: "critical", Confidence: 0.95, Verified: true, Verdict: "real-looking", Sink: "network", Library: &lib}.State()
	if s["rule_id"] != "secret/stripe-key" || s["sink"] != "network" || s["library"] != false || s["verified"] != true {
		t.Fatalf("bad state: %v", s)
	}
	if _, ok := s["validation"]; ok {
		t.Fatal("empty fields must be omitted")
	}
	if len(SecretQuestions()) != 2 {
		t.Fatal("two questions expected")
	}
}
