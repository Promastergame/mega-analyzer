package s1

import (
	"context"
	"strings"
	"testing"
)

type rejecting struct{ pairs int }

func (*rejecting) Name() string        { return "rejecting" }
func (*rejecting) Tokens(s string) int { return len(strings.Fields(s)) }
func (b *rejecting) JudgeBatch(p []Pair) []Judgement {
	b.pairs += len(p)
	out := make([]Judgement, len(p))
	for i := range out {
		out[i] = Judgement{Entail: .01, Neutral: .01, Contra: .98}
	}
	return out
}

func TestOtherCanWinAndAbstains(t *testing.T) {
	b := &rejecting{}
	e := NewEngine(b, DefaultCalibration())
	e.NoLex = true
	a, err := e.Decide(req(t, `{"state":"unrelated","questions":{"q":{"type":"choice","instructions":"pick","criteria":{"fruit":"Fruit","vehicle":"Vehicle","other":"Other"}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := a.Answers["q"]; got.Choice != "other" || !got.Abstained || got.Route != "human" {
		t.Fatalf("%+v", got)
	}
	if isEscape(Option{Key: "mother", Text: "Another person"}) {
		t.Fatal("substring must not declare an escape option")
	}
}

type orchard struct{}

func (*orchard) Name() string        { return "orchard" }
func (*orchard) Tokens(s string) int { return len(strings.Fields(s)) }
func (*orchard) JudgeBatch(p []Pair) []Judgement {
	out := make([]Judgement, len(p))
	for i := range out {
		out[i] = Judgement{Entail: 0.02, Neutral: 0.03, Contra: 0.95}
		if strings.Contains(p[i].Hypothesis, "orchard") {
			out[i] = Judgement{Entail: 0.9, Neutral: 0.05, Contra: 0.05}
		}
	}
	return out
}

func TestSupportedOptionBeatsAbstainKey(t *testing.T) {
	e := NewEngine(&orchard{}, DefaultCalibration())
	e.NoLex = true
	a, err := e.Decide(req(t, `{"state":"Fresh fruit from the orchard.","questions":{"q":{"type":"choice","instructions":"pick","criteria":{"fruit":"Fresh fruit from the orchard","vehicle":"Road vehicles for transport","other":"Other"}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := a.Answers["q"]; got.Choice != "fruit" || got.Abstained {
		t.Fatalf("%+v", got)
	}
}

func TestCancelledAndOverBudgetRequest(t *testing.T) {
	b := &rejecting{}
	e := NewEngine(b, DefaultCalibration())
	e.MaxPairs = 1
	r := req(t, `{"state":"x","questions":{"q":{"type":"choice","instructions":"pick","criteria":{"a":"A","b":"B"}}}}`)
	if _, err := e.Decide(r); err == nil || !strings.Contains(err.Error(), "budget") {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.DecideContext(ctx, r); err != context.Canceled {
		t.Fatal(err)
	}
	if b.pairs != 0 {
		t.Fatal("backend ran after cancellation or budget rejection")
	}
}
