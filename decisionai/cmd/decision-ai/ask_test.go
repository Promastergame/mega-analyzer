package main

import (
	"encoding/json"
	"decisionai/engine"
	"decisionai/semai"
	"decisionai/textai"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestAskHTTP(t *testing.T) {
	h := makeHandler("127.0.0.1:7475", "secret", func(r engine.Request) (engine.Report, error) { return engine.Analyze(r, nil, nil) })
	const q = `{"question":"Сколько ушей у 3,5 мыши?\nA) 7\nB) 6\nC) 8"}`
	cases := []struct {
		path, method, token, ctype, body string
		want                             int
	}{{"/api/ask", "GET", "secret", "", "", 405}, {"/api/ask", "POST", "", "application/json", q, 403}, {"/api/ask", "POST", "secret", "text/plain", q, 415}, {"/api/ask", "POST", "secret", "application/json", "{}", 400}, {"/api/ask", "POST", "secret", "application/json", `{"question":"x","unknown_field":1}`, 400}, {"/api/ask", "POST", "secret", "application/json", q, 200}}
	for _, c := range cases {
		r := httptest.NewRequest(c.method, "http://127.0.0.1:7475"+c.path, strings.NewReader(c.body))
		r.Host = "127.0.0.1:7475"
		r.Header.Set("X-DecisionAI-Token", c.token)
		r.Header.Set("Content-Type", c.ctype)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != c.want {
			t.Fatalf("%s %d %s", c.path, w.Code, w.Body.String())
		}
		if c.want == 200 {
			var rep semai.Report
			if err := json.Unmarshal(w.Body.Bytes(), &rep); err != nil || rep.Answer != "unknown" || rep.Kind != "choice" {
				t.Fatalf("half a mouse must be unknown without guessing: %+v %v", rep, err)
			}
		}
	}
}

func loadDemoTextModel(t *testing.T) *textai.Model {
	t.Helper()
	m, err := loadText("../../models/demo-text-model.json")
	if err != nil {
		t.Skip("no demo model:", err)
	}
	return m
}

func pizzaRequest() textai.Request {
	return textai.Request{
		State:     "На столе 6 кусочков пиццы, а друзей пришло 8",
		Question:  "Хватит ли пиццы на всех друзей?",
		TrueWhen:  "Кусочков пиццы столько же или больше, чем друзей",
		FalseWhen: "Кусочков пиццы меньше, чем друзей",
	}
}

func TestSemanticFallbackPizza(t *testing.T) {
	m := loadDemoTextModel(t)
	rep, err := textai.Analyze(pizzaRequest(), m)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Answer != "unknown" || rep.Semantic != nil {
		t.Fatalf("lexical must abstain purely: %+v", rep.Answer)
	}
	rep = routeToSemantic(pizzaRequest(), rep)
	if rep.Answer != "no" {
		t.Fatalf("fallback must answer no: %+v", rep.Answer)
	}
	if rep.Semantic == nil || len(rep.AbstentionReasons) != 1 || rep.AbstentionReasons[0] != "routed_to_semantic" {
		t.Fatalf("provenance missing: %+v", rep.AbstentionReasons)
	}
}

// The candy story used to stay unknown (the NLI head read it at 0.59, below the promote floor).
// The events GNN now parses every step (−3, +2, −5) and the arithmetic proves YES.
func TestCandyStorySolvedByEventsGNN(t *testing.T) {
	m := loadDemoTextModel(t)
	r := textai.Request{
		State:     "Мальчик взял из коробки 3 конфеты, потом вернул 2 обратно, потом взял ещё 5",
		Question:  "Стало ли конфет в коробке меньше, чем было вначале?",
		TrueWhen:  "Конфет в коробке стало меньше, чем было",
		FalseWhen: "Конфет в коробке стало больше или столько же",
	}
	rep, err := textai.Analyze(r, m)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Answer != "unknown" {
		t.Fatalf("lexical must abstain: %+v", rep.Answer)
	}
	rep = routeToSemantic(r, rep)
	sr, ok := rep.Semantic.(semai.SolveReport)
	if rep.Answer != "yes" || !ok || sr.Solver != "events-gnn" || sr.Total == nil || sr.Total.Delta != -6 {
		t.Fatalf("want yes via events-gnn with delta -6: %+v %+v", rep.Answer, rep.Semantic)
	}
}

func TestSemanticFallbackKeepsYes(t *testing.T) {
	m := loadDemoTextModel(t)
	b, err := os.ReadFile("../../examples/text-cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var rs []textai.Request
	if err := json.Unmarshal(b, &rs); err != nil {
		t.Fatal(err)
	}
	rep, err := textai.Analyze(rs[0], m)
	if err != nil || rep.Answer != "yes" {
		t.Fatalf("confirmed must be yes: %+v %v", rep.Answer, err)
	}
	rep2 := routeToSemantic(rs[0], rep)
	if rep2.Answer != "yes" || rep2.Semantic != nil {
		t.Fatalf("yes must never be rerouted: %+v", rep2.Answer)
	}
}
