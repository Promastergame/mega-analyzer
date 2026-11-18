package experts

import (
	"testing"

	"decisionai/s1"
)

func TestMathDispatchIgnoresIncidentalEquations(t *testing.T) {
	states := []string{
		`Task: edit a display name. Call: update_user(id=1042, display_name="Anna").`,
		`Task: archive one record. SQL: UPDATE users SET archived=true WHERE id=50677`,
		`Release v1.18.0: latency 20-30 ms; errors < 1%.`,
	}
	for _, state := range states {
		for _, instr := range []string{"How risky is this tool call?", "Is this action safe?", "Клиент доволен?"} {
			if a, ok := (Math{}).Answer(state, state, s1.ExpertQuestion{Type: s1.TypeNoul, Instr: instr}); ok {
				t.Errorf("unrelated question was answered: %s: %+v", instr, a)
			}
		}
	}
}

func TestMathDispatchExplicitCalculations(t *testing.T) {
	for _, tc := range []struct { question string; want bool }{
		{"Верно ли, что (900 + 200) <= 1000?", false},
		{"Верно ли, что 3/4 > 0.7?", true},
		{"При p=true, q=false истинно ли p AND q?", false},
		{"Является ли a OR NOT a тавтологией?", true},
	} {
		q := s1.ExpertQuestion{Type: s1.TypeNoul, Instr: tc.question}
		a, ok := (Math{}).Answer("Вычисление", "Вычисление", q)
		if !ok || len(a.Probs) != 1 || (a.Probs[0] > 0.5) != tc.want {
			t.Errorf("%s: %+v, handled=%v", tc.question, a, ok)
		}
	}
	q := s1.ExpertQuestion{Type: s1.TypeNoul, Task: s1.TaskSeverity, Instr: "Верно ли, что 2 + 2 = 4?"}
	if _, ok := (Math{}).Answer("", "", q); ok { t.Fatal("math ignored an explicit non-math task") }
}
