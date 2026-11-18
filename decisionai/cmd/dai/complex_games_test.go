package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"decisionai/games"
	"decisionai/s1"
)

func TestComplexGamesHTTP(t *testing.T) {
	h := Handler(s1.NewEngine(s1.LexicalBackend{}, s1.DefaultCalibration()), "tok", false)
	for _, body := range []string{
		`{"game":"tetris","piece":"I","grid":["..........","..........","..........","..........","#########.","#########.","#########.","#########."]}`,
		`{"game":"russian_checkers","player":"white","board":["........","........","........","........",".b......","w.......","........","........"]}`,
	} {
		r := httptest.NewRequest("POST", "/v1/game", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer tok")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		var d games.Decision
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &d) != nil || d.Action == "" || !d.Heuristic {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
	}
}
