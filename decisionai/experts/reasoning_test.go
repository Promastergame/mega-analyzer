package experts

import (
	"encoding/json"
	"testing"

	"decisionai/s1"
)

func TestReasoningExpertUsesProofAndAbstains(t *testing.T) {
	e := engine(t)
	for _, tc := range []struct {
		state, instr, status, reason, route string
		value                               float64
	}{
		{"Лена выше Тимура. Тимур выше Олега.", "Лена выше Олега?", "supported", "", "auto", 1},
		{"Лена выше Тимура.", "Тимур выше Лены?", "refuted", "", "auto", 0},
		{"Лена выше Тимура.", "Лена выше Олега?", "unknown", "missing_reasoning_facts", "human", .5},
		{"Лена выше Тимура. Тимур выше Лены.", "Лена выше Тимура?", "conflict", "conflicting_facts", "human", .5},
	} {
		state, _ := json.Marshal(tc.state)
		instr, _ := json.Marshal(tc.instr)
		a := decide(t, e, `{"state":`+string(state)+`,"questions":{"q":{"type":"noul","task":"reasoning","instructions":`+string(instr)+`}}}`).Answers["q"]
		if a.Source != "reasoning-proof" || a.Reasoning == nil || a.Reasoning.Status != tc.status || a.Noul == nil || *a.Noul != tc.value || a.Route != tc.route || a.Reason != tc.reason {
			t.Fatalf("%s: %+v", tc.instr, a)
		}
	}
}

func TestReasoningStructuredClaimAndChoice(t *testing.T) {
	e := engine(t)
	r := decide(t, e, `{"state":{"facts":[{"subject":"mira","predicate":"paid","source":"receipt"},{"subject":"mira","predicate":"verified","source":"identity"}],"rules":[{"all":[{"subject":"$x","predicate":"paid"},{"subject":"$x","predicate":"verified"}],"then":{"subject":"$x","predicate":"ready"},"source":"policy"}]},"questions":{"q":{"type":"noul","task":"reasoning","instructions":"Проверить доступ","claim":{"subject":"mira","predicate":"ready"}}}}`)
	a := r.Answers["q"]
	if a.Noul == nil || *a.Noul != 1 || a.Reasoning == nil || len(a.Reasoning.Proof) != 3 || r.Usage.ModelCalls != 0 {
		t.Fatal(a)
	}
	for _, tc := range []struct{ state, choice, reason string }{
		{"Mira taller than Oren.", "mira", ""},
		{"Mira older than Oren.", "unknown", "missing_reasoning_facts"},
		{"Mira taller than Oren. Oren taller than Mira.", "unknown", "conflicting_facts"},
	} {
		state, _ := json.Marshal(tc.state)
		a := decide(t, e, `{"state":`+string(state)+`,"questions":{"q":{"type":"choice","task":"reasoning","abstain_key":"unknown","instructions":"Какой вывод подтверждён?","criteria":{"mira":"Mira taller than Oren","oren":"Oren taller than Mira","unknown":"Недостаточно данных"}}}}`).Answers["q"]
		if a.Choice != tc.choice || a.Reason != tc.reason {
			t.Fatalf("%s: %+v", tc.state, a)
		}
	}
}

func TestReasoningRequiresExplicitTaskAndValidClaim(t *testing.T) {
	if _, ok := (Reasoning{}).Answer("Mira taller than Oren.", "Mira taller than Oren.", s1.ExpertQuestion{Type: s1.TypeNoul, Task: s1.TaskSeverity, Instr: "Is Mira taller than Oren?"}); ok {
		t.Fatal("overrode a different explicit task")
	}
	for _, raw := range []string{
		`{"state":"x","questions":{"q":{"type":"noul","instructions":"x","claim":{"subject":"a","predicate":"p"}}}}`,
		`{"state":"x","questions":{"q":{"type":"noul","task":"reasoning","instructions":"x","claim":{"subject":"$x","predicate":"p"}}}}`,
	} {
		var request s1.Request
		if err := json.Unmarshal([]byte(raw), &request); err != nil {
			t.Fatal(err)
		}
		if _, err := engine(t).Decide(request); err == nil {
			t.Fatal("invalid claim accepted", raw)
		}
	}
}

func TestReasoningLegacyQuestionsUseRelevantFacts(t *testing.T) {
	e := engine(t)
	for _, tc := range []struct{ state, instruction, status string }{
		{"Лена выше Тимура. Тимур выше Олега.", "Лена выше Олега?", "supported"},
		{"Лена выше Тимура.", "Тимур выше Лены?", "refuted"},
		{"Лена выше Тимура.", "Лена выше Миры?", "unknown"},
	} {
		state, _ := json.Marshal(tc.state)
		instruction, _ := json.Marshal(tc.instruction)
		a := decide(t, e, `{"state":`+string(state)+`,"questions":{"q":{"type":"noul","instructions":`+string(instruction)+`}}}`).Answers["q"]
		if a.Source != "reasoning-proof" || a.Reasoning == nil || a.Reasoning.Status != tc.status {
			t.Fatal(tc, a)
		}
	}
	if _, ok := (Reasoning{}).Answer("The user requests a refund.", "The user requests a refund.", s1.ExpertQuestion{Type: s1.TypeNoul, Instr: "Is Mira taller than Oren?"}); ok {
		t.Fatal("unrelated text activated relation reasoning")
	}
}
