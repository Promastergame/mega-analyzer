package gameagent

import (
	"context"
	"encoding/json"
	"decisionai/arena"
	"decisionai/mcpclient"
	"decisionai/vision"
	"testing"
)

type pictureTools struct {
	result  mcpclient.Result
	actions int
}

func (p *pictureTools) CheckCall(mcpclient.Call) error { return nil }
func (p *pictureTools) CallTool(_ context.Context, c mcpclient.Call) (mcpclient.Result, error) {
	if c.Name == "observe" {
		return p.result, nil
	}
	p.actions++
	return mcpclient.Result{}, nil
}

func TestScreenshotModeNeverFallsBackToHiddenBoard(t *testing.T) {
	w, _ := arena.New("russian_checkers")
	w.State.Player = "black"
	im, _ := w.Render()
	lie := json.RawMessage(`{"game":"russian_checkers","player":"white","board":["........","........","........","........",".b......","w.......","........","........"]}`)
	r := mcpclient.Result{Structured: lie, Content: []mcpclient.Content{{Type: "text", Text: string(lie)}, {Type: "image", Data: im.Data, MIMEType: im.MIMEType}}}
	c := Config{Game: "russian_checkers", Player: "white", Observe: mcpclient.Call{Name: "observe"}, MoveTool: "move", ImageLayout: im.Layout, MinStepIntervalMS: 1}
	f := &pictureTools{result: r}
	report, err := Run(context.Background(), f, vision.Local{}, c)
	if err != nil || report.Status != "waiting_for_opponent" || f.actions != 0 || report.Steps[0].State.Player != "black" {
		t.Fatalf("%+v %v", report, err)
	}
	for _, contents := range [][]mcpclient.Content{nil, {{Type: "image", Data: "broken", MIMEType: "image/png"}}} {
		f = &pictureTools{result: mcpclient.Result{Structured: lie, Content: contents}}
		if _, err := Run(context.Background(), f, vision.Local{}, c); err == nil || f.actions != 0 {
			t.Fatal("used JSON fallback")
		}
	}
}
