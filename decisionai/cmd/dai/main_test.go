package main

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"net/http/httptest"
	"strings"
	"testing"

	"decisionai/client"
	"decisionai/s1"
)

func TestServerAndClient(t *testing.T) {
	eng := s1.NewEngine(s1.LexicalBackend{}, s1.DefaultCalibration())
	srv := httptest.NewServer(Handler(eng, "tok", false))
	defer srv.Close()
	c := client.New(srv.URL, "tok")
	resp, err := c.Decide(context.Background(), client.Request{
		State: map[string]any{"tests": map[string]any{"passed": false}, "note": "runtime failed"},
		Questions: map[string]client.Question{
			"ok":   client.Noul("Tests passed", "All tests passed", "Tests failed or did not run"),
			"kind": client.Choice("What failed?", client.Opt("build", "The build"), client.Opt("runtime", "Runtime tests"), client.Opt("other", "")),
			"sev":  client.Score("Severity", client.Opt("0", "low"), client.Opt("1", "medium"), client.Opt("2", "high")),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Answers) != 3 || resp.Answers["kind"].Route != "human" {
		t.Fatalf("%+v", resp)
	}
	k := resp.Answers["kind"].Choice
	if k != "build" && k != "runtime" && k != "other" {
		t.Fatalf("undeclared choice %q", k)
	}
	bad := client.New(srv.URL, "wrong")
	if _, err := bad.Decide(context.Background(), client.Request{State: "x", Questions: map[string]client.Question{"a": client.Noul("x")}}); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("token must be enforced: %v", err)
	}
	if _, err := c.Decide(context.Background(), client.Request{State: "x"}); err == nil || !strings.Contains(err.Error(), "400") {
		t.Fatalf("validation must surface as 400: %v", err)
	}
}

func TestHostGuard(t *testing.T) {
	h := hostGuard("127.0.0.1:7480", Handler(s1.NewEngine(s1.LexicalBackend{}, s1.DefaultCalibration()), "t", true))
	for host, want := range map[string]int{"127.0.0.1:7480": 200, "localhost:7480": 200, "evil.example": 403} {
		r := httptest.NewRequest("GET", "/v1/health", nil)
		r.Host = host
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Errorf("%s: %d", host, w.Code)
		}
	}
}

func TestSkillFeedbackEndpoint(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"agent-browser", "humanizer"} {
		os.MkdirAll(filepath.Join(dir, n), 0o755)
		os.WriteFile(filepath.Join(dir, n, "SKILL.md"), []byte("---\nname: "+n+"\ndescription: "+n+" skill\n---\n"), 0o644)
	}
	reg, err := s1.LoadSkillRegistry([]string{dir}, "")
	if err != nil {
		t.Fatal(err)
	}
	eng := s1.NewEngine(s1.LexicalBackend{}, s1.DefaultCalibration())
	eng.Skills = reg
	skillExamplesPath = filepath.Join(dir, "ex.jsonl")
	defer func() { skillExamplesPath = "" }()
	srv := httptest.NewServer(Handler(eng, "tok", false))
	defer srv.Close()
	post := func(tok, body string) int {
		rq, _ := http.NewRequest("POST", srv.URL+"/v1/skills/feedback", strings.NewReader(body))
		rq.Header.Set("Authorization", "Bearer "+tok)
		res, err := http.DefaultClient.Do(rq)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	if c := post("bad", `{"state":"x","skill":"humanizer"}`); c != 401 {
		t.Fatalf("token: %d", c)
	}
	if c := post("tok", `{"state":"x","skill":"unknown"}`); c != 400 {
		t.Fatalf("unknown skill: %d", c)
	}
	if c := post("tok", `{"state":"убери канцелярит из текста","skill":"humanizer"}`); c != 200 {
		t.Fatalf("learn: %d", c)
	}
	b, _ := os.ReadFile(skillExamplesPath)
	if !strings.Contains(string(b), "канцелярит") || len(reg.ExamplesOf("humanizer")) != 1 {
		t.Fatalf("not persisted: %q", b)
	}
}
