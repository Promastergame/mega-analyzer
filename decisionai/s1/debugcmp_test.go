package s1

// Temporary diagnostic: verdicts for compare pairs (single model).
import (
	"fmt"
	"testing"

	"decisionai/semai"
)

func TestDebugCompare(t *testing.T) {
	base, err := semai.LoadEncoder("../models/encoder-tiny.dte")
	if err != nil {
		t.Skip("encoder weights not present")
	}
	d, err := semai.LoadCrossEncoderAny("../models/s1-distilled.dte", base)
	if err != nil {
		t.Skip("distilled weights not present")
	}
	be := NewEmbedBackend(d)
	pairs := []Pair{
		{"The amber cable is shorter than the violet cable.", "The amber cable is shorter"},
		{"The amber cable is shorter than the violet cable.", "The violet cable is shorter"},
		{"The violet cable is shorter than the amber cable.", "The violet cable is shorter"},
		{"The violet cable is shorter than the amber cable.", "The amber cable is shorter"},
		{"Soren received the key from Bryn.", "Soren gave the key"},
		{"Soren received the key from Bryn.", "Bryn gave the key"},
	}
	for _, p := range pairs {
		a, h := be.get(p.Premise), be.get(p.Hypothesis)
		sim := 0.5*semai.Cosine(a.Mean, h.Mean) + 0.5*semai.MaxSim(h, a)
		j := be.JudgeBatch([]Pair{p})[0]
		fmt.Printf("P=%q\nH=%q\n  sim=%.4f e=%.4f n=%.4f c=%.4f\n", p.Premise, p.Hypothesis, sim, j.Entail, j.Neutral, j.Contra)
	}
}
