package experts

import (
	"testing"

	"decisionai/s1"
)

func TestReasoningLegacyCriteriaPreserveCallerMeaning(t *testing.T) {
	state := "Лена выше Тимура. Тимур выше Олега."
	question := s1.ExpertQuestion{Type: s1.TypeNoul, Instr: "Лена выше Олега?", Options: []s1.Option{
		{Key: "true", Text: "Лена не выше Олега"},
		{Key: "false", Text: "Лена выше Олега"},
	}}
	if _, handled := (Reasoning{}).Answer(state, state, question); handled {
		t.Fatal("legacy caller criteria were silently replaced with the parsed claim")
	}
	// An explicit task fixes meaning independently of display descriptions.
	question.Task = s1.TaskReasoning
	answer, handled := (Reasoning{}).Answer(state, state, question)
	if !handled || len(answer.Probs) != 1 || answer.Probs[0] != 1 {
		t.Fatalf("explicit reasoning lost its fixed meaning: %+v", answer)
	}
}
