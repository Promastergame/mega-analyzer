package main

import (
	"bytes"
	"context"
	"encoding/json"
	"decisionai/arena"
	"decisionai/games"
	"decisionai/s1"
	"net/http/httptest"
	"testing"
)

func TestGameImageHTTPAndHiddenStateRejection(t *testing.T) {
	h := Handler(s1.NewEngine(s1.LexicalBackend{}, s1.DefaultCalibration()), "tok", true)
	for _, game := range []string{"tetris", "russian_checkers"} {
		w, _ := arena.New(game)
		if game == "russian_checkers" {
			w.State.Board = []string{"........", "........", "........", "........", ".b......", "w.......", "........", "........"}
		}
		im, _ := w.Render()
		payload, _ := json.Marshal(gameRequest{State: games.State{Game: game}, Image: &im})
		req := httptest.NewRequest("POST", "/v1/game", bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer tok")
		out := httptest.NewRecorder()
		h.ServeHTTP(out, req)
		var d games.Decision
		if out.Code != 200 || json.Unmarshal(out.Body.Bytes(), &d) != nil || d.Source != "image" || d.Observed == nil {
			t.Fatalf("%d %s", out.Code, out.Body)
		}
		if err := w.Apply(context.Background(), d); err != nil {
			t.Fatal(err)
		}
		for _, hidden := range []games.State{{Grid: []string{"...."}}, {Board: []string{"........"}}, {Piece: "I"}, {Next: "O"}, {Active: &games.Placement{}}, {Revision: "1"}} {
			hidden.Game = game
			if _, err := solveGame(context.Background(), gameRequest{State: hidden, Image: &im}); err == nil {
				t.Fatal("accepted hidden state")
			}
		}
	}
}

func TestArenaOnlyOnLocalHandlerAndRejectsStaleMoves(t *testing.T) {
	eng := s1.NewEngine(s1.LexicalBackend{}, s1.DefaultCalibration())
	h := Handler(eng, "tok", true)
	for _, enabled := range []bool{false, true} {
		out := httptest.NewRecorder()
		Handler(eng, "tok", enabled).ServeHTTP(out, httptest.NewRequest("GET", "/games", nil))
		want := 404
		if enabled {
			want = 200
		}
		if out.Code != want {
			t.Fatal(out.Code)
		}
	}
	for _, tc := range []struct {
		token, body string
		want        int
	}{{"bad", `{"command":"frame"}`, 401}, {"tok", `{"command":"control","control":"left","revision":-1}`, 409}, {"tok", `{"command":"frame"}`, 200}} {
		req := httptest.NewRequest("POST", "/v1/arena", bytes.NewBufferString(tc.body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+tc.token)
		out := httptest.NewRecorder()
		h.ServeHTTP(out, req)
		if out.Code != tc.want {
			t.Fatalf("%d %s", out.Code, out.Body)
		}
		if out.Code == 200 && (bytes.Contains(out.Body.Bytes(), []byte(`"board":`)) || bytes.Contains(out.Body.Bytes(), []byte(`"grid":`))) {
			t.Fatal("arena exposes board state")
		}
	}
}
