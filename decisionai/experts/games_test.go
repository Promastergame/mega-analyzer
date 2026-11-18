package experts

import (
	"encoding/json"
	"testing"

	"decisionai/s1"
)

func TestGameExpertIntegration(t *testing.T) {
	e := s1.NewEngine(s1.LexicalBackend{}, s1.DefaultCalibration())
	e.Experts = Default(nil, nil)
	r := s1.Request{State: json.RawMessage(`{"game":"tic_tac_toe","board":["XX.","OO.","..."],"player":"X"}`), Questions: map[string]s1.Question{"move": {Type: "choice", Task: s1.TaskGame, Instructions: json.RawMessage(`"Choose a legal move"`), Criteria: json.RawMessage(`{"cell_2":"top right","cell_5":"middle right"}`)}}}
	resp, err := e.Decide(r)
	if err != nil {
		t.Fatal(err)
	}
	a := resp.Answers["move"]
	if a.Choice != "cell_2" || a.Source != "game-search" || a.Route != "auto" {
		t.Fatalf("%+v", a)
	}
	r.State = json.RawMessage(`{"game":"tic_tac_toe","board":["OO.","...","..."]}`)
	resp, err = e.Decide(r)
	if err != nil {
		t.Fatal(err)
	}
	a = resp.Answers["move"]
	if !a.Abstained || a.Route != "human" {
		t.Fatalf("guessed on invalid board: %+v", a)
	}
}

func TestHeuristicGameMovesRequireReview(t *testing.T) {
	e := s1.NewEngine(s1.LexicalBackend{}, s1.DefaultCalibration())
	e.Experts = Default(nil, nil)
	r := s1.Request{State: json.RawMessage(`{"game":"russian_checkers","player":"white","board":["........","........","........","........",".b......","w.......","........","........"]}`), Questions: map[string]s1.Question{"move": {Type: "choice", Task: s1.TaskGame, Instructions: json.RawMessage(`"Choose a move"`), Criteria: json.RawMessage(`{"a3xc5":"Capture b4","a3-b4":"Other"}`)}}}
	resp, err := e.Decide(r)
	if err != nil {
		t.Fatal(err)
	}
	a := resp.Answers["move"]
	if a.Source != "game-search" || a.Choice != "a3xc5" || a.Route != "review" {
		t.Fatalf("heuristic score claimed calibrated certainty: %+v", a)
	}
}
