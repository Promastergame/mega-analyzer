package s1

import (
	"context"
	"encoding/json"
	"testing"

	"decisionai/reasoning"
)

func TestDisabledProofExpertDoesNotSubstituteLexicalAnswer(t *testing.T) {
	r := Request{State: json.RawMessage(`"Mira taller than Oren."`), Questions: map[string]Question{
		"natural": {Type: TypeNoul, Task: TaskReasoning, Instructions: json.RawMessage(`"Is Mira taller than Oren?"`)},
		"typed":   {Type: TypeNoul, Task: TaskReasoning, Instructions: json.RawMessage(`"Check the claim"`), Claim: &reasoning.Atom{Subject: "mira", Predicate: "taller", Object: "oren"}},
	}}
	e := NewEngine(LexicalBackend{}, DefaultCalibration())
	response, err := e.Decide(r)
	if err != nil {
		t.Fatal(err)
	}
	if response.Usage.ModelCalls != 0 {
		t.Fatal("substitute model was called")
	}
	for id, a := range response.Answers {
		if !a.Abstained || a.Route != "human" || a.Reason != "reasoning_expert_unavailable" {
			t.Fatalf("%s: %+v", id, a)
		}
	}
}

func TestProofResponsesRetainLocalProvenanceDuringEscalation(t *testing.T) {
	x := &Escalator{On: map[string]bool{"all": true}}
	r := Request{Questions: map[string]Question{"q": {Type: TypeNoul, Task: TaskReasoning}}}
	response := Response{Answers: map[string]Answer{"q": {Type: TypeNoul, Source: "reasoning-proof", Route: "human", Abstained: true}}}
	x.Apply(context.Background(), r, &response)
	if response.Answers["q"].Source != "reasoning-proof" || !response.Answers["q"].Abstained || response.Usage.Escalated != 0 {
		t.Fatal(response)
	}
}
