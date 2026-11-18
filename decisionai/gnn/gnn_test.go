package gnn

import (
	"math"
	"testing"
)

func tiny() *Graph {
	return &Graph{
		Feats:   [][]string{{"a", "x"}, {"b"}, {"c", "y"}, {"a"}},
		Edges:   []Edge{{0, 1, 0}, {1, 2, 1}, {2, 0, 0}, {3, 2, 1}, {1, 3, 0}},
		Targets: []int{0, 2}, Labels: []int{1, 0},
	}
}

// Numerical gradient check of the hand-written backprop.
func TestGradients(t *testing.T) {
	m := New([]string{"p", "q", "r"}, 16, 5, 2, 2, 7)
	g := tiny()
	gr := m.zeroGrads()
	m.backward(g, gr, 0.5, 0.7)
	loss := func() float64 { return m.backward(g, m.zeroGrads(), 0.5, 0.7) }
	ps, gs := m.params(), gr.list()
	for pi, p := range ps {
		for _, j := range []int{0, len(p) / 2, len(p) - 1} {
			old := p[j]
			p[j] = old + 1e-5
			a := loss()
			p[j] = old - 1e-5
			b := loss()
			p[j] = old
			num := (a - b) / 2e-5
			if math.Abs(num-gs[pi][j]) > 1e-5+1e-3*math.Abs(num) {
				t.Fatalf("param %d[%d]: analytic %g numeric %g", pi, j, gs[pi][j], num)
			}
		}
	}
}

// The label depends on a neighbour two hops away: only message passing can learn it.
func TestLearnsTwoHop(t *testing.T) {
	var data []*Graph
	for i := 0; i < 200; i++ {
		lab := i % 2
		far := []string{"neg"}
		if lab == 1 {
			far = []string{"pos"}
		}
		data = append(data, &Graph{Feats: [][]string{{"target"}, {"mid"}, far}, Edges: []Edge{{2, 1, 0}, {1, 0, 0}}, Targets: []int{0}, Labels: []int{lab}})
	}
	m := New([]string{"0", "1"}, 64, 8, 1, 2, 1)
	m.Train(data, TrainOptions{Epochs: 30, LR: 0.02, Batch: 8, Seed: 1})
	if acc, _, _ := m.Eval(data); acc < 0.99 {
		t.Fatalf("two-hop acc %.2f", acc)
	}
}
