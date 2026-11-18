package gameagent

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"decisionai/games"
	"decisionai/mcpclient"
)

type fakeTools struct {
	observations      []string
	observed, actions int
	fail              bool
	lastMove          mcpclient.Call
}

func (f *fakeTools) CheckCall(c mcpclient.Call) error {
	if c.Name != "observe" && c.Name != "move" {
		return fmt.Errorf("unknown tool")
	}
	return nil
}
func (f *fakeTools) CallTool(_ context.Context, c mcpclient.Call) (mcpclient.Result, error) {
	if c.Name == "move" {
		f.lastMove = c
		f.actions++
		if f.fail {
			return mcpclient.Result{}, fmt.Errorf("action failed")
		}
		return mcpclient.Result{}, nil
	}
	i := f.observed
	if i >= len(f.observations) {
		i = len(f.observations) - 1
	}
	f.observed++
	return mcpclient.Result{Structured: json.RawMessage(f.observations[i])}, nil
}

func TestCheckersMoveToolAndOpponentTurn(t *testing.T) {
	initial := `{"game":"russian_checkers","player":"white","board":["........","........","........","........",".b......","w.......","........","........"]}`
	after := `{"game":"russian_checkers","player":"black","board":["........","........","........","..w.....","........","........","........","........"]}`
	f := &fakeTools{observations: []string{initial, after}}
	c := Config{ObservationMode: "structured", Game: "russian_checkers", Player: "white", Observe: mcpclient.Call{Name: "observe"}, MoveTool: "move", MinStepIntervalMS: 1}
	r, err := Run(context.Background(), f, nil, c)
	if err != nil || r.Status != "terminal" || f.actions != 1 {
		t.Fatalf("%+v %v", r, err)
	}
	d, ok := f.lastMove.Arguments["decision"].(games.Decision)
	if !ok || d.Action != "a3xc5" || len(d.Path) != 2 || len(d.Captures) != 1 {
		t.Fatalf("incomplete move: %+v", f.lastMove)
	}
	f = &fakeTools{observations: []string{`{"game":"russian_checkers","player":"black","board":["........","........",".b......","........","........","w.......","........","........"]}`}}
	r, err = Run(context.Background(), f, nil, c)
	if err != nil || r.Status != "waiting_for_opponent" || f.actions != 0 {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestTetrisMoveToolReceivesControls(t *testing.T) {
	f := &fakeTools{observations: []string{`{"game":"tetris","piece":"I","grid":["..........","..........","..........","..........","#########.","#########.","#########.","#########."]}`}}
	c := Config{ObservationMode: "structured", Game: "tetris", Observe: mcpclient.Call{Name: "observe"}, MoveTool: "move", MaxSteps: 1, MinStepIntervalMS: 1}
	r, err := Run(context.Background(), f, nil, c)
	if err != nil || f.actions != 1 || r.Status != "no_progress" {
		t.Fatalf("%+v %v", r, err)
	}
	d, ok := f.lastMove.Arguments["decision"].(games.Decision)
	if !ok || d.Cleared != 4 || d.Placement == nil || len(d.Controls) == 0 {
		t.Fatalf("missing placement: %+v", f.lastMove)
	}
}
func mazeConfig() Config {
	return Config{ObservationMode: "structured", Game: "maze", Observe: mcpclient.Call{Name: "observe"}, Actions: map[string]mcpclient.Call{"right": {Name: "move"}}, MaxSteps: 4}
}
func TestObserveActVerify(t *testing.T) {
	f := &fakeTools{observations: []string{`{"game":"maze","grid":["S.G"]}`, `{"game":"maze","grid":[".SG"]}`, `{"game":"maze","grid":["..*"]}`}}
	r, err := Run(context.Background(), f, nil, mazeConfig())
	if err != nil || r.Status != "terminal" || r.Actions != 2 || f.observed != 3 {
		t.Fatalf("%+v %v", r, err)
	}
}
func TestStopInsteadOfBlindRepeat(t *testing.T) {
	for _, tc := range []struct {
		name    string
		fail    bool
		steps   int
		status  string
		wantErr bool
	}{
		{"stuck", false, 4, "no_progress", false}, {"error", true, 4, "stopped", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeTools{observations: []string{`{"game":"maze","grid":["S.G"]}`}, fail: tc.fail}
			c := mazeConfig()
			c.MaxSteps = tc.steps
			r, err := Run(context.Background(), f, nil, c)
			if (err != nil) != tc.wantErr || r.Status != tc.status || f.actions != 1 {
				t.Fatalf("%+v %v actions=%d", r, err, f.actions)
			}
		})
	}
}
func TestStepLimitAndBadObservation(t *testing.T) {
	f := &fakeTools{observations: []string{`{"game":"maze","grid":["S.G"]}`, `{"game":"maze","grid":[".SG"]}`}}
	c := mazeConfig()
	c.MaxSteps = 1
	r, err := Run(context.Background(), f, nil, c)
	if err != nil || r.Status != "step_limit" || f.actions != 1 || f.observed != 2 {
		t.Fatalf("%+v %v", r, err)
	}
	for _, s := range []string{`{"game":"maze","grid":["S#G"]}`, `{"game":"maze","grid":["???"]}`, `{"game":"other"}`, `{"error":"uncertain board"}`, `{"game":"maze","grid":["S.G"]} {}`} {
		f := &fakeTools{observations: []string{s}}
		_, _ = Run(context.Background(), f, nil, mazeConfig())
		if f.actions != 0 {
			t.Fatalf("acted on %s", s)
		}
	}
}
func TestWaitingForOpponent(t *testing.T) {
	f := &fakeTools{observations: []string{`{"game":"tic_tac_toe","board":["X..","...","..."]}`}}
	c := Config{ObservationMode: "structured", Game: "tic_tac_toe", Player: "X", Observe: mcpclient.Call{Name: "observe"}, Actions: map[string]mcpclient.Call{"cell_4": {Name: "move"}}}
	r, err := Run(context.Background(), f, nil, c)
	if err != nil || r.Status != "waiting_for_opponent" || f.actions != 0 {
		t.Fatalf("%+v %v", r, err)
	}
}
func TestJSONTextObservation(t *testing.T) {
	r := mcpclient.Result{Content: []mcpclient.Content{{Type: "text", Text: `{"game":"maze","grid":["S.G"]}`}}}
	s, err := decodeObservation(context.Background(), r, nil, "maze")
	if err != nil {
		t.Fatal(err)
	}
	if d, e := games.Solve(s); e != nil || d.Action != "right" {
		t.Fatalf("%+v %v", d, e)
	}
}
