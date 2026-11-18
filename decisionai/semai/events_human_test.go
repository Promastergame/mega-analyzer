package semai

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"decisionai/gnn"
)

// TestHumanDevSet guards the hand-written dev stories (the closed test set is only scored by
// `decision-ai eval`). EVM=<model.json> evaluates another model, OOVT=<x> another OOV temperature.
func TestHumanDevSet(t *testing.T) {
	if p := os.Getenv("EVM"); p != "" {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		m, err := gnn.Load(b)
		if err != nil {
			t.Fatal(err)
		}
		old := EventModel()
		SetEventModel(m)
		defer SetEventModel(old)
	}
	if v := os.Getenv("OOVT"); v != "" {
		old := OOVTemp
		fmt.Sscan(v, &OOVTemp)
		defer func() { OOVTemp = old }()
	}
	f, err := os.Open("testdata/events-human.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	ok, n, ece := 0, 0, 0.0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var c struct{ State, Question, Answer string }
		if json.Unmarshal(sc.Bytes(), &c) != nil {
			continue
		}
		a := SolveFacts(c.State, c.Question)
		got, conf := "—", 0.0
		if a != nil {
			got, conf = a.Answer, a.Confidence
		}
		n++
		hit := 0.0
		if got == c.Answer {
			ok++
			hit = 1
		} else {
			t.Logf("want %s got %s (%.2f): %s | %s", c.Answer, got, conf, c.State, c.Question)
		}
		ece += (conf - hit) * (conf - hit)
	}
	t.Logf("dev: %d/%d, Brier %.3f", ok, n, ece/float64(n))
	if float64(ok) < 0.85*float64(n) {
		t.Fatalf("dev accuracy %d/%d below 85%%", ok, n)
	}
}
