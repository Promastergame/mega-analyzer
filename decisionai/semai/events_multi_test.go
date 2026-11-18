package semai

import "testing"

// Run-on stories without punctuation and stories with two places (user reports, v0.7.1).
func TestEventsRunOnAndTwoPlaces(t *testing.T) {
	vase := "в коробке было 8 яблок в вазе было 5 яблок маша взяла 3 яблока из коробки она взяла 2 яблока из вазы и съела их через час мама положила 4 яблока в коробку"
	for _, c := range []struct{ state, q, want string }{
		{vase, "Сколько яблок в коробке?", "9"},
		{vase, "Сколько яблок стало в вазе?", "3"},
		{vase, "Стало ли яблок в коробке больше?", "yes"},
		{"в копилке было 50 рублей петя положил 20 рублей вынул 15 рублей маша вытащила 30 рублей", "Сколько рублей в копилке?", "25"},
	} {
		a := SolveEvents(c.state, c.q)
		if a == nil || a.Answer != c.want {
			t.Errorf("%s → %+v, want %s", c.q, a, c.want)
		}
	}
	a := SolveEvents(vase, "Сколько яблок в коробке?")
	if len(a.Total.Others) != 1 || a.Total.Others[0].End == nil || *a.Total.Others[0].End != 3 {
		t.Errorf("vase in others: %+v", a.Total.Others)
	}
}
