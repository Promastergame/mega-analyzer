package smalirole

import (
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"sort"

	"decisionai/gnn"
)

// Model is a multinomial logistic regression over sparse binary features plus a temperature.
type Model struct {
	Format      string      `json:"format"`
	Labels      []string    `json:"labels"`
	Features    []string    `json:"features"`
	W           [][]float32 `json:"weights"` // [feature][label]
	B           []float64   `json:"bias"`
	Temperature float64     `json:"temperature"`      // for masked context (hidden sink)
	TempFull    float64     `json:"temperature_full"` // for full context, used by Analyze
	Metrics     any         `json:"metrics,omitempty"`
	index       map[string]int
	// Graph is the optional literal-role GNN (smalirole-gnn.json next to the LR model). When present,
	// Score averages both: on 20 held-out apps this lifts masked accuracy 86.0% -> 88.7%.
	Graph      *gnn.Model `json:"-"`
	GraphError string     `json:"-"`
}

type Example struct {
	App      string   `json:"app"`
	Label    string   `json:"label"`
	Masked   []string `json:"masked"`
	Full     []string `json:"full"`
	Literal  string   `json:"literal"`
	Where    string   `json:"where"`
	Line     int      `json:"line"`
	Evidence string   `json:"label_evidence"`
}

func (m *Model) build() {
	m.index = make(map[string]int, len(m.Features))
	for i, f := range m.Features {
		m.index[f] = i
	}
}

func LoadModel(path string) (*Model, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Model
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	if m.Format != "smalirole-lr-v1" || len(m.Labels) != len(Labels) || len(m.W) != len(m.Features) || len(m.B) != len(Labels) {
		return nil, fmt.Errorf("unsupported or corrupt model")
	}
	for i := range Labels {
		if m.Labels[i] != Labels[i] {
			return nil, fmt.Errorf("label schema mismatch")
		}
	}
	if m.Temperature <= 0 || math.IsNaN(m.Temperature) {
		m.Temperature = 1
	}
	if m.TempFull <= 0 || math.IsNaN(m.TempFull) {
		m.TempFull = m.Temperature
	}
	m.build()
	if gb, err := os.ReadFile(filepath.Join(filepath.Dir(path), "smalirole-gnn.json")); err == nil {
		g, err := gnn.Load(gb)
		if err != nil {
			m.GraphError = err.Error()
		} else if g.Relations != SiteRelations || len(g.Classes) != len(Labels) {
			m.GraphError = "literal-role GNN schema mismatch"
		} else {
			for i, label := range Labels {
				if g.Classes[i] != label {
					m.GraphError = "literal-role GNN class order mismatch"
					break
				}
			}
			if m.GraphError == "" {
				m.Graph = g
			}
		}
	} else if !os.IsNotExist(err) {
		m.GraphError = err.Error()
	}
	return &m, nil
}

func (m *Model) Save(path string) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// Logits returns raw (untempered) scores.
func (m *Model) Logits(feats []string) []float64 {
	z := append([]float64(nil), m.B...)
	for _, f := range feats {
		if i, ok := m.index[f]; ok {
			for k, w := range m.W[i] {
				z[k] += float64(w)
			}
		}
	}
	return z
}

func Softmax(z []float64, t float64) []float64 {
	mx := math.Inf(-1)
	for _, v := range z {
		mx = math.Max(mx, v/t)
	}
	p := make([]float64, len(z))
	s := 0.0
	for i, v := range z {
		p[i] = math.Exp(v/t - mx)
		s += p[i]
	}
	for i := range p {
		p[i] /= s
	}
	return p
}

type TrainOptions struct {
	Epochs  int
	LR      float64
	L2      float64
	MinFreq int
	Seed    int64
}

// Train fits weights with AdaGrad on the masked features; "unknown" is never a training target.
func Train(rows []Example, o TrainOptions) *Model {
	cnt := map[string]int{}
	for _, r := range rows {
		for _, f := range r.Masked {
			cnt[f]++
		}
	}
	var feats []string
	for f, c := range cnt {
		if c >= o.MinFreq {
			feats = append(feats, f)
		}
	}
	sort.Strings(feats)
	m := &Model{Format: "smalirole-lr-v1", Labels: Labels, Features: feats, B: make([]float64, len(Labels)), Temperature: 1, TempFull: 1}
	m.build()
	K := len(Labels)
	W := make([][]float64, len(feats))
	G := make([][]float64, len(feats))
	for i := range W {
		W[i], G[i] = make([]float64, K), make([]float64, K)
	}
	gb := make([]float64, K)
	// class weights ~ freq^-0.75 so booleans do not drown rare roles
	freq := make([]float64, K)
	for _, r := range rows {
		freq[labelIndex(r.Label)]++
	}
	cw := make([]float64, K)
	for k := range cw {
		if freq[k] > 0 {
			cw[k] = math.Pow(float64(len(rows))/float64(K)/freq[k], 0.75)
		}
	}
	order := rand.New(rand.NewSource(o.Seed)).Perm(len(rows))
	idx := make([][]int, len(rows))
	for i, r := range rows {
		for _, f := range r.Masked {
			if j, ok := m.index[f]; ok {
				idx[i] = append(idx[i], j)
			}
		}
	}
	for ep := 0; ep < o.Epochs; ep++ {
		for _, i := range order {
			y := labelIndex(rows[i].Label)
			z := append([]float64(nil), m.B...)
			for _, j := range idx[i] {
				for k := 0; k < K; k++ {
					z[k] += W[j][k]
				}
			}
			p := Softmax(z, 1)
			for k := 0; k < K; k++ {
				g := p[k]
				if k == y {
					g -= 1
				}
				g *= cw[y]
				gb[k] += g * g
				m.B[k] -= o.LR * g / (math.Sqrt(gb[k]) + 1e-8)
				for _, j := range idx[i] {
					gj := g + o.L2*W[j][k]
					G[j][k] += gj * gj
					W[j][k] -= o.LR * gj / (math.Sqrt(G[j][k]) + 1e-8)
				}
			}
		}
	}
	m.W = make([][]float32, len(W))
	for i := range W {
		m.W[i] = make([]float32, K)
		for k := range W[i] {
			m.W[i][k] = float32(math.Round(W[i][k]*1e4) / 1e4)
		}
	}
	return m
}

// FitTemperature picks T minimising NLL on held-out calibration rows (classic temperature scaling).
func (m *Model) FitTemperature(rows []Example, full bool) float64 {
	best, bestT := math.Inf(1), 1.0
	for t := 0.3; t <= 5.0; t += 0.05 {
		nll := 0.0
		for _, r := range rows {
			f := r.Masked
			if full {
				f = r.Full
			}
			p := Softmax(m.Logits(f), t)
			nll -= math.Log(math.Max(p[labelIndex(r.Label)], 1e-12))
		}
		if nll < best {
			best, bestT = nll, t
		}
	}
	return math.Round(bestT*100) / 100
}

type ClassMetric struct {
	Label     string  `json:"label"`
	Support   int     `json:"support"`
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	F1        float64 `json:"f1"`
}

type EvalMetrics struct {
	N          int           `json:"n"`
	Accuracy   float64       `json:"accuracy"`
	MacroF1    float64       `json:"macro_f1"`
	NLL        float64       `json:"nll"`
	ECE        float64       `json:"ece_15bin"`
	Selective  []OpPoint     `json:"selective"`
	PerClass   []ClassMetric `json:"per_class"`
	Confusions []string      `json:"top_confusions"`
}

type OpPoint struct {
	Threshold float64 `json:"threshold"`
	Coverage  float64 `json:"coverage"`
	Accuracy  float64 `json:"accuracy"`
}

// Evaluate scores rows; extra adds expert logits (fusion) when non-nil.
func (m *Model) Evaluate(rows []Example, full bool, extra func(Example) []float64) EvalMetrics {
	K := len(Labels)
	tp, fp, fn := make([]int, K), make([]int, K), make([]int, K)
	type pc struct {
		conf    float64
		correct bool
	}
	var ps []pc
	conf := map[string]int{}
	nll := 0.0
	for _, r := range rows {
		f := r.Masked
		if full {
			f = r.Full
		}
		z := m.Logits(f)
		t := m.Temperature
		if full {
			t = m.TempFull
		}
		for k := range z {
			z[k] /= t
		}
		if extra != nil {
			for k, v := range extra(r) {
				z[k] += v
			}
		}
		p := Softmax(z, 1)
		y := labelIndex(r.Label)
		best := 0
		for k := range p {
			if p[k] > p[best] {
				best = k
			}
		}
		nll -= math.Log(math.Max(p[y], 1e-12))
		ps = append(ps, pc{p[best], best == y})
		if best == y {
			tp[y]++
		} else {
			fp[best]++
			fn[y]++
			conf[r.Label+" → "+Labels[best]]++
		}
	}
	e := EvalMetrics{N: len(rows)}
	if len(rows) == 0 {
		return e
	}
	correct := 0
	for _, p := range ps {
		if p.correct {
			correct++
		}
	}
	e.Accuracy = round3(float64(correct) / float64(len(ps)))
	e.NLL = round3(nll / float64(len(ps)))
	// ECE
	bins := 15
	var bc, ba, bn = make([]float64, bins), make([]float64, bins), make([]float64, bins)
	for _, p := range ps {
		b := int(p.conf * float64(bins))
		if b == bins {
			b--
		}
		bc[b] += p.conf
		bn[b]++
		if p.correct {
			ba[b]++
		}
	}
	for b := 0; b < bins; b++ {
		if bn[b] > 0 {
			e.ECE += bn[b] / float64(len(ps)) * math.Abs(ba[b]/bn[b]-bc[b]/bn[b])
		}
	}
	e.ECE = round3(e.ECE)
	for _, t := range []float64{0.5, 0.6, 0.7, 0.8, 0.9, 0.95} {
		n, c := 0, 0
		for _, p := range ps {
			if p.conf >= t {
				n++
				if p.correct {
					c++
				}
			}
		}
		op := OpPoint{Threshold: t, Coverage: round3(float64(n) / float64(len(ps)))}
		if n > 0 {
			op.Accuracy = round3(float64(c) / float64(n))
		}
		e.Selective = append(e.Selective, op)
	}
	f1s, nc := 0.0, 0
	for k := 0; k < K; k++ {
		sup := tp[k] + fn[k]
		if sup == 0 {
			continue
		}
		pr := ratio(tp[k], tp[k]+fp[k])
		rc := ratio(tp[k], sup)
		f1 := 0.0
		if pr+rc > 0 {
			f1 = 2 * pr * rc / (pr + rc)
		}
		f1s += f1
		nc++
		e.PerClass = append(e.PerClass, ClassMetric{Labels[k], sup, round3(pr), round3(rc), round3(f1)})
	}
	if nc > 0 {
		e.MacroF1 = round3(f1s / float64(nc))
	}
	type kv struct {
		k string
		v int
	}
	var cs []kv
	for k, v := range conf {
		cs = append(cs, kv{k, v})
	}
	sort.Slice(cs, func(i, j int) bool { return cs[i].v > cs[j].v || (cs[i].v == cs[j].v && cs[i].k < cs[j].k) })
	for i := 0; i < len(cs) && i < 6; i++ {
		e.Confusions = append(e.Confusions, fmt.Sprintf("%s: %d", cs[i].k, cs[i].v))
	}
	return e
}

func ratio(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}
func round3(v float64) float64 { return math.Round(v*1000) / 1000 }
