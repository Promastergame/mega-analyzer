package main

import (
	"decisionai/engine"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalHTTP(t *testing.T) {
	h := makeHandler("127.0.0.1:7475", "secret", func(r engine.Request) (engine.Report, error) { return engine.Analyze(r, nil, nil) })
	cases := []struct {
		name, path, method, host, token, ctype, body string
		want                                         int
	}{{"form", "/", "GET", "127.0.0.1:7475", "", "", "", 200}, {"badhost", "/", "GET", "evil.example", "", "", "", 403}, {"unknown", "/other", "GET", "127.0.0.1:7475", "", "", "", 404}, {"method", "/api/analyze", "GET", "127.0.0.1:7475", "secret", "application/json", "", 405}, {"token", "/api/analyze", "POST", "127.0.0.1:7475", "", "application/json", "{}", 403}, {"type", "/api/analyze", "POST", "127.0.0.1:7475", "secret", "text/plain", "{}", 415}, {"invalid", "/api/analyze", "POST", "127.0.0.1:7475", "secret", "application/json", "{", 400}, {"empty", "/api/analyze", "POST", "127.0.0.1:7475", "secret", "application/json", "{}", 400}, {"valid", "/api/analyze", "POST", "127.0.0.1:7475", "secret", "application/json", `{"code":".method public static x()V\n.registers 0\nreturn-void\n.end method","state":{},"meta":{"app_owned":true}}`, 200}}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(c.method, "http://"+c.host+c.path, strings.NewReader(c.body))
			req.Host = c.host
			req.Header.Set("X-DecisionAI-Token", c.token)
			req.Header.Set("Content-Type", c.ctype)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != c.want {
				t.Fatalf("%d %s", w.Code, w.Body.String())
			}
			if c.name == "form" {
				if strings.Contains(w.Body.String(), "__SESSION_TOKEN__") || !strings.Contains(w.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
					t.Fatal("missing local protections")
				}
			}
		})
	}
}
func TestCLIRejectsInvalid(t *testing.T) {
	for _, args := range [][]string{{}, {"unknown"}, {"analyze", "-threshold", "2"}, {"analyze", "-threshold", "NaN"}, {"analyze", "-threshold", "-1"}, {"analyze", "unexpected"}, {"serve", "-addr", "0.0.0.0:7475"}, {"text-eval", "-input", "missing.json"}, {"text-train", "-input", "missing.json"}} {
		if run(args) == nil {
			t.Fatal(args)
		}
	}
}
func TestReadAndModel(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "invalid.json")
	if e := os.WriteFile(p, []byte(`{}`), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := load(p, "finding"); e == nil {
		t.Fatal("invalid model")
	}
	if _, e := load(filepath.Join(dir, "missing"), "finding"); e == nil {
		t.Fatal("missing model")
	}
	if m, e := load("", "finding"); e != nil || m != nil {
		t.Fatal(m, e)
	}
}
func TestTextHTTP(t *testing.T) {
	h := makeHandler("127.0.0.1:7475", "secret", func(r engine.Request) (engine.Report, error) { return engine.Analyze(r, nil, nil) })
	cases := []struct {
		path, method, token, ctype, body string
		want                             int
	}{{"/text", "GET", "", "", "", 200}, {"/text", "POST", "", "", "", 405}, {"/api/text", "POST", "", "application/json", "{}", 403}, {"/api/text", "POST", "secret", "text/plain", "{}", 415}, {"/api/text", "POST", "secret", "application/json", "{}", 400}, {"/api/text", "POST", "secret", "application/json", `{"task_id":"patch_effect_confirmation","state":"Тесты не запускались","question":"Подтверждён эффект?","true_when":"Тест прошёл","false_when":"Тест не прошёл"}`, 200}}
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
	}
}
