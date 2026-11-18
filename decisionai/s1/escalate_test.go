package s1

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func escReq(t *testing.T, s string) Request {
	t.Helper()
	var r Request
	if err := json.Unmarshal([]byte(s), &r); err != nil {
		t.Fatal(err)
	}
	return r
}

const escBody = `{"state":"Task: count orders.\nProposed tool call: run_sql(\"SELECT count(*) FROM orders\")","questions":{
 "safe":{"type":"noul","instructions":"Safe to run without approval?","criteria":{"true":"low impact","false":"destructive"}},
 "risk":{"type":"score","instructions":"How risky?","criteria":{"1":"none","2":"low","3":"high"}},
 "kind":{"type":"choice","instructions":"Kind","criteria":{"read":"reads data","delete":"deletes data"}}}}`

func TestEscalateCascade(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer k" {
			t.Errorf("auth header %q", r.Header.Get("Authorization"))
		}
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &got)
		io.WriteString(w, `{"model":"typesafe/jev-test","answers":{
		  "safe":{"type":"noul","noul":0.96},
		  "risk":{"type":"score","score":0.1,"probabilities":{"0":0.9,"1":0.1,"2":0},"confidence":0.9},
		  "kind":{"type":"choice","choice":"read","probabilities":{"read":0.99,"delete":0.01},"confidence":0.99}},
		  "usage":{"cost":0.00002}}`)
	}))
	defer srv.Close()
	e := NewEngine(LexicalBackend{}, DefaultCalibration())
	e.Escalate = NewEscalator("typesafe/jev-1.13", "k")
	e.Escalate.URL = srv.URL
	resp, err := e.Decide(escReq(t, escBody))
	if err != nil {
		t.Fatal(err)
	}
	qs := got["questions"].(map[string]any)
	if crit, ok := qs["risk"].(map[string]any)["criteria"].([]any); !ok || len(crit) != 3 || crit[0] != "none" {
		t.Fatalf("score criteria not sent as ordered array: %v", qs["risk"])
	}
	s := resp.Answers["safe"]
	if *s.Noul != 0.96 || s.Route != "auto" || !strings.HasPrefix(s.Source, "escalated:typesafe/jev-test") {
		t.Fatalf("noul not escalated: %+v", s)
	}
	r := resp.Answers["risk"]
	if r.Probabilities.Get("1") != 0.9 || r.Probabilities.Get("3") != 0 || *r.Score > 1.2 {
		t.Fatalf("score levels not mapped back: %+v", r)
	}
	if k := resp.Answers["kind"]; k.Choice != "read" {
		t.Fatalf("choice: %+v", k)
	}
	if resp.Usage.Escalated != 3 || resp.Usage.EscalationCost != 0.00002 {
		t.Fatalf("usage %+v", resp.Usage)
	}
}

func TestEscalateFailureKeepsLocal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(429)
		io.WriteString(w, `{"error":{"message":"Rate limit exceeded"}}`)
	}))
	defer srv.Close()
	e := NewEngine(LexicalBackend{}, DefaultCalibration())
	e.Escalate = NewEscalator("respan/span-01-lite:free", "k")
	e.Escalate.URL = srv.URL
	resp, err := e.Decide(escReq(t, escBody))
	if err != nil {
		t.Fatal(err)
	}
	s := resp.Answers["safe"]
	if strings.HasPrefix(s.Source, "escalated") || !strings.Contains(strings.Join(s.Evidence, " "), "HTTP 429") {
		t.Fatalf("failure not recorded: %+v", s)
	}
	if strings.Contains(strings.Join(resp.Answers["risk"].Evidence, " "), "escalation") {
		t.Fatal("noul-only model must not receive score questions")
	}
}

func TestEscalateOnlyUncertain(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++ }))
	defer srv.Close()
	x := NewEscalator("typesafe/jev-1.13", "k")
	x.URL = srv.URL
	p := 0.97
	resp := Response{Answers: map[string]Answer{"safe": {Type: TypeNoul, Noul: &p, Route: "auto"}}}
	x.Apply(context.Background(), escReq(t, escBody), &resp)
	if calls != 0 {
		t.Fatal("confident answers must stay local")
	}
}

func TestEscalateLogAndCache(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		io.WriteString(w, `{"model":"jev-x","answers":{"safe":{"type":"noul","noul":0.9},
		  "risk":{"type":"score","probabilities":{"0":0.8,"1":0.2,"2":0}},
		  "kind":{"type":"choice","probabilities":{"read":0.95,"delete":0.05}}},"usage":{"cost":0.00001}}`)
	}))
	defer srv.Close()
	log := t.TempDir() + "/esc.jsonl"
	mk := func() *Engine {
		e := NewEngine(LexicalBackend{}, DefaultCalibration())
		e.Escalate = NewEscalator("typesafe/jev-1.13", "k")
		e.Escalate.URL, e.Escalate.Log = srv.URL, log
		if err := e.Escalate.LoadLog(); err != nil {
			t.Fatal(err)
		}
		return e
	}
	e := mk()
	first, _ := e.Decide(escReq(t, escBody))
	again, _ := e.Decide(escReq(t, escBody))
	fresh, _ := mk().Decide(escReq(t, escBody)) // new process: warm from the log
	if calls != 1 {
		t.Fatalf("remote called %d times, want 1", calls)
	}
	for _, r := range []Response{again, fresh} {
		if !strings.HasPrefix(r.Answers["safe"].Source, "escalated-cache:") || r.Answers["risk"].Probabilities.Get("1") != first.Answers["risk"].Probabilities.Get("1") {
			t.Fatalf("cache answer differs: %+v", r.Answers)
		}
	}
	b, _ := os.ReadFile(log)
	var row struct {
		Labels map[string]json.RawMessage `json:"labels"`
	}
	if json.Unmarshal(b, &row) != nil || string(row.Labels["safe"]) != "0.9" || !strings.Contains(string(row.Labels["risk"]), `"1":0.8`) {
		t.Fatalf("log row not a labelled example: %s", b)
	}
}
