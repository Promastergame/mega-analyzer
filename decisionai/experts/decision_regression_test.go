package experts

import (
	"decisionai/s1"
	"strings"
	"testing"
)

func TestQuestionPolarityAndCriteria(t *testing.T) {
	e := engine(t)
	state := `{"build":{"status":"pass","sha256_matches":true},"runtime":{"status":"pass"},"effect_verified":true}`
	for _, tc := range []struct {
		question string
		want     float64
		route    string
	}{
		{`{"type":"noul","instructions":"Патч сработал?"}`, .98, "auto"},
		{`{"type":"noul","instructions":"Патч не сработал?","criteria":{"true":"Эффект отсутствует","false":"Эффект наблюдался"}}`, .02, "auto"},
		{`{"type":"noul","instructions":"Патч сработал?","criteria":{"true":"Эффект отсутствует","false":"Эффект наблюдался"}}`, .5, "human"},
		{`{"type":"noul","instructions":"Можно ли распространять этот патч?"}`, .5, "human"},
	} {
		a := decide(t, e, `{"state":`+state+`,"questions":{"q":`+tc.question+`}}`).Answers["q"]
		if a.Noul == nil || *a.Noul != tc.want || a.Route != tc.route {
			t.Fatalf("%s: %+v", tc.question, a)
		}
	}
	a := decide(t, e, `{"state":{"rule_id":"secret/key","verified":true,"verdict":"real-looking","sink":"network"},"questions":{"q":{"type":"noul","instructions":"Это НЕ ложное срабатывание?"}}}`).Answers["q"]
	if a.Noul == nil || *a.Noul < .9 || a.Source != "finding-rule" {
		t.Fatalf("inverted finding: %+v", a)
	}
}

func TestCurrentRunIsIsolatedFromHistory(t *testing.T) {
	e := engine(t)
	a := decide(t, e, `{"state":{"archive":{"build":"pass","runtime":"pass","effect_verified":true,"sha256_matches":true},"current":{"build":"fail","runtime":"not_run","effect_verified":false,"sha256_matches":false}},"questions":{"q":{"type":"noul","task":"patch_effect","instructions":"Текущий эффект"}}}`).Answers["q"]
	if a.Noul == nil || *a.Noul > .05 {
		t.Fatalf("history overrode current: %+v", a)
	}
	if strings.Contains(strings.Join(a.Evidence, " "), "archive") {
		t.Fatal(a.Evidence)
	}
	if len(a.Checks) == 0 || len(a.References) == 0 {
		t.Fatal("missing next checks or references")
	}
	a = decide(t, e, `{"state":{"archive":{"build":"pass","runtime":"pass","effect_verified":true,"sha256_matches":true}},"questions":{"q":{"type":"noul","task":"patch_effect","instructions":"Текущий эффект"}}}`).Answers["q"]
	if a.Route != "human" || !a.Abstained {
		t.Fatalf("history treated as current: %+v", a)
	}
}

func TestZeroRequestsCannotProveLocalBehaviour(t *testing.T) {
	e := engine(t)
	a := decide(t, e, `{"state":{"network_requests":0,"runtime":{"status":"not_run"}},"questions":{"q":{"type":"score","task":"server_dependency","instructions":"Зависимость от сервера","criteria":{"0":"Локально","1":"Кэш","2":"Проверяет сервер","3":"Решает сервер"}}}}`).Answers["q"]
	if a.Route != "human" || !a.Abstained || a.Probabilities.Get("0") > .3 || len(a.Checks) == 0 {
		t.Fatalf("%+v", a)
	}
}

func TestExplicitTaskPolarity(t *testing.T) {
	q := s1.ExpertQuestion{Type: s1.TypeNoul, Task: s1.TaskFalsePositive, Polarity: "negative", Instr: "Произвольная подпись"}
	a, ok := (Finding{}).Answer(map[string]any{"rule_id": "secret/key", "placeholder": true, "verdict": "placeholder"}, "", q)
	if !ok || a.Probs[0] > .1 {
		t.Fatalf("%+v", a)
	}
}
