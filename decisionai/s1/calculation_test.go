package s1

import (
	"math"
	"testing"
)

func TestExpertRejectsNonFiniteProbabilities(t *testing.T) {
	q := compiled{Type: TypeNoul}
	if _, ok := expertAnswer(q, ExpertAnswer{Probs: []float64{math.Inf(1)}}); ok {
		t.Fatal("infinite noul accepted")
	}
	q = compiled{Type: TypeChoice, Options: []Option{{Key: "a"}, {Key: "b"}}}
	if _, ok := expertAnswer(q, ExpertAnswer{Probs: []float64{math.MaxFloat64, math.MaxFloat64}}); ok {
		t.Fatal("overflowing distribution accepted")
	}
}

func TestCalculationTraceVerification(t *testing.T) {
	p := CalculationTrace{InitialAvailable: 1000, InitialRequired: 900, Steps: []CalculationStep{{Target: "required", Operation: "add", Operand: 200, Result: 1100}}, Available: 1000, Required: 1100, Shortfall: 100, Unit: "RUB", Enough: false}
	if !p.Verify() {
		t.Fatal("valid arithmetic rejected")
	}
	p.Steps[0].Result = 1000
	if p.Verify() {
		t.Fatal("fabricated result accepted")
	}
	p.Steps[0].Result = 1100
	p.Steps[0].Operand = math.Inf(1)
	if p.Verify() {
		t.Fatal("infinite operand accepted")
	}
}
