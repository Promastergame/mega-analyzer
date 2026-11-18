package evalkit

import "testing"

func TestCompute(t *testing.T) {
	// 10 answers at 0.9 confidence, 9 right: perfectly calibrated bin
	var ps []Pred
	for i := 0; i < 10; i++ {
		ps = append(ps, Pred{Conf: 0.9, Correct: i < 9})
	}
	ps = append(ps, Pred{Abstained: true})
	r := Compute("x", ps, nil)
	if r.N != 11 || r.Answered != 10 || r.Accuracy != 0.9 || r.ECE > 1e-9 {
		t.Fatalf("%+v", r)
	}
	if r.AccAll < 0.81 || r.AccAll > 0.82 {
		t.Fatalf("acc_all %v", r.AccAll)
	}
	// overconfident: says 1.0, right half the time
	r = Compute("y", []Pred{{Conf: 1, Correct: true}, {Conf: 1, Correct: false}}, nil)
	if r.ECE != 0.5 || r.Brier != 0.5 {
		t.Fatalf("%+v", r)
	}
	p := FromProbs([]float64{0.2, 0.7, 0.1}, 1, 0)
	r = Compute("z", []Pred{p}, []string{"a", "b", "c"})
	if r.MacroF1 != 1 || r.NLL <= 0 || r.Cov99 != 1 {
		t.Fatalf("%+v", r)
	}
}
