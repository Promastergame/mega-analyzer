package main

import (
	"bytes"
	"net/http/httptest"
	"strings"
	"testing"

	"decisionai/s1"
)

func TestGameHTTP(t *testing.T) {
	h := Handler(s1.NewEngine(s1.LexicalBackend{}, s1.DefaultCalibration()), "tok", false)
	for _, tc := range []struct {
		method, token, body string
		status              int
	}{
		{"POST", "tok", `{"game":"tic_tac_toe","board":["XX.","OO.","..."]}`, 200},
		{"POST", "bad", `{}`, 401}, {"GET", "tok", `{}`, 405},
		{"POST", "tok", `{"game":"tic_tac_toe","board":["OO.","...","..."]}`, 400},
		{"POST", "tok", `{"game":"maze","image":{"data":"bad","mime_type":"image/png"}}`, 400},
	} {
		r := httptest.NewRequest(tc.method, "/v1/game", strings.NewReader(tc.body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+tc.token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("%s: status=%d %s", tc.body, w.Code, w.Body)
		}
		if tc.status == 200 && !bytes.Contains(w.Body.Bytes(), []byte(`"action":"cell_2"`)) {
			t.Fatalf("wrong move: %s", w.Body)
		}
	}
}

func TestSeeHTTPRequiresValidImageAndToken(t *testing.T) {
	h := Handler(s1.NewEngine(s1.LexicalBackend{}, s1.DefaultCalibration()), "tok", false)
	for _, token := range []string{"bad", "tok"} {
		r := httptest.NewRequest("POST", "/v1/see", strings.NewReader(`{"data":"bad","mime_type":"image/png"}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		want := 400
		if token == "bad" {
			want = 401
		}
		if w.Code != want {
			t.Fatalf("status %d", w.Code)
		}
	}
}
