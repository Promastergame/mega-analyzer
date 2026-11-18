// Package gnn is a small relational graph neural network (R-GCN style message passing with
// residual tanh layers) written with the standard library only. It classifies chosen nodes of a
// graph: event clauses of a text (semai) or the const node of a Smali def-use graph (smalirole).
//
// Node features are sparse string features hashed into Dim buckets. Each layer does
//
//	h_i' = h_i + tanh(Ws·h_i + Σ_r Wr·mean_{j→i via r} h_j + b)
//
// and the target nodes are read out with a softmax layer. Training is Adam with exact
// hand-written backprop (checked numerically in gnn_test.go); probabilities are temperature-
// calibrated on held-out graphs.
package gnn

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"math"
	"math/rand"
	"os"
)

// Edge is a directed typed edge Src -> Dst.
type Edge struct{ Src, Dst, Type int }

// Graph is one example. Feats[i] are the string features of node i.
type Graph struct {
	Feats   [][]string
	Edges   []Edge
	Targets []int // nodes to classify
	Labels  []int // label per target (training only)
	idx     [][]int
}

// Model holds all weights. Matrices are row-major [out][in].
type Model struct {
	sourceDigest string
	Classes      []string    `json:"classes"`
	Dim          int         `json:"dim"`
	Hidden       int         `json:"hidden"`
	Relations    int         `json:"relations"`
	Layers       int         `json:"layers"`
	Emb          []float64   `json:"emb"` // Dim*Hidden
	B0           []float64   `json:"b0"`
	Ws           [][]float64 `json:"ws"` // [layer] H*H
	Wr           [][]float64 `json:"wr"` // [layer] R*H*H
	B            [][]float64 `json:"b"`
	Wo           []float64   `json:"wo"` // C*H
	Bo           []float64   `json:"bo"`
	Temperature  float64     `json:"temperature"`
	Metrics      any         `json:"metrics,omitempty"`
	// Vocab lists word features seen in training (features are hashed, so the model itself
	// cannot tell an unseen word from a seen one; callers use this for out-of-vocabulary caution).
	Vocab []string `json:"vocab,omitempty"`
}

// New makes a randomly initialised model.
func New(classes []string, dim, hidden, relations, layers int, seed int64) *Model {
	r := rand.New(rand.NewSource(seed))
	rnd := func(n int, s float64) []float64 {
		v := make([]float64, n)
		for i := range v {
			v[i] = r.NormFloat64() * s
		}
		return v
	}
	H := hidden
	m := &Model{Classes: classes, Dim: dim, Hidden: H, Relations: relations, Layers: layers, Temperature: 1,
		Emb: rnd(dim*H, 0.3), B0: make([]float64, H), Wo: rnd(len(classes)*H, 1/math.Sqrt(float64(H))), Bo: make([]float64, len(classes))}
	for l := 0; l < layers; l++ {
		m.Ws = append(m.Ws, rnd(H*H, 0.5/math.Sqrt(float64(H))))
		m.Wr = append(m.Wr, rnd(relations*H*H, 0.5/math.Sqrt(float64(H))))
		m.B = append(m.B, make([]float64, H))
	}
	return m
}

func hashFeat(s string, dim int) int {
	h := fnv.New32a()
	h.Write([]byte(s))
	return int(h.Sum32() % uint32(dim))
}

func (g *Graph) index(dim int) [][]int {
	if g.idx == nil {
		g.idx = make([][]int, len(g.Feats))
		for i, fs := range g.Feats {
			for _, f := range fs {
				g.idx[i] = append(g.idx[i], hashFeat(f, dim))
			}
		}
	}
	return g.idx
}

type cache struct {
	h   [][][]float64 // [layer+1][node][H]
	t   [][][]float64 // tanh outputs per layer
	m   [][][][]float64
	deg [][]int // [rel][node] in-degree
	out [][]float64
}

func (m *Model) forward(g *Graph) *cache {
	H, N, R := m.Hidden, len(g.Feats), m.Relations
	idx := g.index(m.Dim)
	c := &cache{}
	h0 := make([][]float64, N)
	for i := 0; i < N; i++ {
		v := make([]float64, H)
		copy(v, m.B0)
		for _, f := range idx[i] {
			e := m.Emb[f*H : f*H+H]
			for k := range v {
				v[k] += e[k]
			}
		}
		for k := range v {
			v[k] = math.Tanh(v[k])
		}
		h0[i] = v
	}
	c.h = append(c.h, h0)
	c.deg = make([][]int, R)
	for r := range c.deg {
		c.deg[r] = make([]int, N)
	}
	for _, e := range g.Edges {
		c.deg[e.Type][e.Dst]++
	}
	for l := 0; l < m.Layers; l++ {
		h := c.h[l]
		ms := make([][][]float64, R)
		for r := range ms {
			ms[r] = make([][]float64, N)
			for i := range ms[r] {
				ms[r][i] = make([]float64, H)
			}
		}
		for _, e := range g.Edges {
			d := 1 / float64(c.deg[e.Type][e.Dst])
			dst, src := ms[e.Type][e.Dst], h[e.Src]
			for k := range dst {
				dst[k] += d * src[k]
			}
		}
		nh, nt := make([][]float64, N), make([][]float64, N)
		for i := 0; i < N; i++ {
			z := make([]float64, H)
			copy(z, m.B[l])
			matVecAdd(z, m.Ws[l], h[i], H)
			for r := 0; r < R; r++ {
				if c.deg[r][i] > 0 {
					matVecAdd(z, m.Wr[l][r*H*H:(r+1)*H*H], ms[r][i], H)
				}
			}
			t := make([]float64, H)
			o := make([]float64, H)
			for k := range z {
				t[k] = math.Tanh(z[k])
				o[k] = h[i][k] + t[k]
			}
			nh[i], nt[i] = o, t
		}
		c.m = append(c.m, ms)
		c.t = append(c.t, nt)
		c.h = append(c.h, nh)
	}
	C := len(m.Classes)
	hl := c.h[m.Layers]
	for _, ti := range g.Targets {
		z := make([]float64, C)
		copy(z, m.Bo)
		matVecAdd(z, m.Wo, hl[ti], H)
		c.out = append(c.out, z)
	}
	return c
}

func matVecAdd(z, W, x []float64, in int) {
	for o := range z {
		row := W[o*in : o*in+in]
		s := 0.0
		for k, v := range x {
			s += row[k] * v
		}
		z[o] += s
	}
}

func softmax(z []float64, T float64) []float64 {
	mx := z[0]
	for _, v := range z {
		mx = math.Max(mx, v)
	}
	p := make([]float64, len(z))
	s := 0.0
	for i, v := range z {
		p[i] = math.Exp((v - mx) / T)
		s += p[i]
	}
	for i := range p {
		p[i] /= s
	}
	return p
}

// Predict returns calibrated class probabilities for every target node.
func (m *Model) Predict(g *Graph) [][]float64 {
	c := m.forward(g)
	out := make([][]float64, len(c.out))
	for i, z := range c.out {
		out[i] = softmax(z, m.Temperature)
	}
	return out
}

// grads has the same layout as Model weights.
type grads struct {
	Emb, B0, Wo, Bo []float64
	Ws, Wr, B       [][]float64
}

func (m *Model) zeroGrads() *grads {
	g := &grads{Emb: make([]float64, len(m.Emb)), B0: make([]float64, len(m.B0)), Wo: make([]float64, len(m.Wo)), Bo: make([]float64, len(m.Bo))}
	for l := 0; l < m.Layers; l++ {
		g.Ws = append(g.Ws, make([]float64, len(m.Ws[l])))
		g.Wr = append(g.Wr, make([]float64, len(m.Wr[l])))
		g.B = append(g.B, make([]float64, len(m.B[l])))
	}
	return g
}

// backward accumulates d(loss)/d(weights) for the mean cross-entropy over targets; returns loss.
func (m *Model) backward(g *Graph, gr *grads, weight, brier float64) float64 {
	c := m.forward(g)
	H, N, R, C := m.Hidden, len(g.Feats), m.Relations, len(m.Classes)
	dh := make([][]float64, N)
	for i := range dh {
		dh[i] = make([]float64, H)
	}
	loss := 0.0
	hl := c.h[m.Layers]
	for t, ti := range g.Targets {
		p := softmax(c.out[t], 1)
		y := g.Labels[t]
		loss -= math.Log(math.Max(p[y], 1e-12)) * weight
		// optional Brier term (calibration-aware objective): dB/dz_o = 2 p_o[(p_o-y_o) - sum_k (p_k-y_k) p_k]
		bs := 0.0
		if brier > 0 {
			for k := 0; k < C; k++ {
				e := p[k]
				if k == y {
					e--
				}
				bs += e * p[k]
				loss += brier * weight * e * e
			}
		}
		for o := 0; o < C; o++ {
			d := p[o] * weight
			if o == y {
				d -= weight
			}
			if brier > 0 {
				e := p[o]
				if o == y {
					e--
				}
				d += brier * weight * 2 * p[o] * (e - bs)
			}
			gr.Bo[o] += d
			row := m.Wo[o*H : o*H+H]
			grow := gr.Wo[o*H : o*H+H]
			for k := 0; k < H; k++ {
				grow[k] += d * hl[ti][k]
				dh[ti][k] += d * row[k]
			}
		}
	}
	for l := m.Layers - 1; l >= 0; l-- {
		h, ms, tt := c.h[l], c.m[l], c.t[l]
		ndh := make([][]float64, N)
		dm := make([][][]float64, R)
		for r := range dm {
			dm[r] = make([][]float64, N)
		}
		for i := 0; i < N; i++ {
			dz := make([]float64, H)
			for k := range dz {
				dz[k] = dh[i][k] * (1 - tt[i][k]*tt[i][k])
			}
			nd := make([]float64, H)
			copy(nd, dh[i]) // residual
			for o := 0; o < H; o++ {
				d := dz[o]
				if d == 0 {
					continue
				}
				gr.B[l][o] += d
				ws, gws := m.Ws[l][o*H:o*H+H], gr.Ws[l][o*H:o*H+H]
				for k := 0; k < H; k++ {
					gws[k] += d * h[i][k]
					nd[k] += d * ws[k]
				}
			}
			for r := 0; r < R; r++ {
				if c.deg[r][i] == 0 {
					continue
				}
				W, gW := m.Wr[l][r*H*H:(r+1)*H*H], gr.Wr[l][r*H*H:(r+1)*H*H]
				d := make([]float64, H)
				for o := 0; o < H; o++ {
					if dz[o] == 0 {
						continue
					}
					row, grow := W[o*H:o*H+H], gW[o*H:o*H+H]
					for k := 0; k < H; k++ {
						grow[k] += dz[o] * ms[r][i][k]
						d[k] += dz[o] * row[k]
					}
				}
				dm[r][i] = d
			}
			ndh[i] = nd
		}
		for _, e := range g.Edges {
			d := dm[e.Type][e.Dst]
			if d == nil {
				continue
			}
			s := 1 / float64(c.deg[e.Type][e.Dst])
			for k := 0; k < H; k++ {
				ndh[e.Src][k] += s * d[k]
			}
		}
		dh = ndh
	}
	idx := g.index(m.Dim)
	for i := 0; i < N; i++ {
		for k := 0; k < H; k++ {
			d := dh[i][k] * (1 - c.h[0][i][k]*c.h[0][i][k])
			gr.B0[k] += d
			for _, f := range idx[i] {
				gr.Emb[f*H+k] += d
			}
		}
	}
	return loss
}

// TrainOptions configures Adam training.
type TrainOptions struct {
	Epochs  int
	LR      float64
	Batch   int
	L2      float64
	Seed    int64
	Brier   float64 // weight of the Brier-score term added to cross-entropy (0 = plain CE)
	Verbose func(epoch int, loss float64)
}

// Train fits the model with Adam on mini-batches of graphs.
func (m *Model) Train(data []*Graph, o TrainOptions) {
	if o.Batch <= 0 {
		o.Batch = 16
	}
	params := m.params()
	mom := make([][]float64, len(params))
	vel := make([][]float64, len(params))
	for i, p := range params {
		mom[i], vel[i] = make([]float64, len(p)), make([]float64, len(p))
	}
	r := rand.New(rand.NewSource(o.Seed))
	step := 0
	order := r.Perm(len(data))
	for ep := 0; ep < o.Epochs; ep++ {
		r.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
		total := 0.0
		for b := 0; b < len(order); b += o.Batch {
			gr := m.zeroGrads()
			end := min(b+o.Batch, len(order))
			nt := 0
			for _, k := range order[b:end] {
				nt += len(data[k].Targets)
			}
			if nt == 0 {
				continue
			}
			for _, k := range order[b:end] {
				total += m.backward(data[k], gr, 1/float64(nt), o.Brier)
			}
			step++
			gs := gr.list()
			lr := o.LR * math.Sqrt(1-math.Pow(0.999, float64(step))) / (1 - math.Pow(0.9, float64(step)))
			for i, p := range params {
				g := gs[i]
				for j := range p {
					d := g[j] + o.L2*p[j]
					mom[i][j] = 0.9*mom[i][j] + 0.1*d
					vel[i][j] = 0.999*vel[i][j] + 0.001*d*d
					p[j] -= lr * mom[i][j] / (math.Sqrt(vel[i][j]) + 1e-8)
				}
			}
		}
		if o.Verbose != nil {
			o.Verbose(ep, total)
		}
	}
}

func (m *Model) params() [][]float64 {
	p := [][]float64{m.Emb, m.B0, m.Wo, m.Bo}
	for l := 0; l < m.Layers; l++ {
		p = append(p, m.Ws[l], m.Wr[l], m.B[l])
	}
	return p
}

func (g *grads) list() [][]float64 {
	p := [][]float64{g.Emb, g.B0, g.Wo, g.Bo}
	for l := range g.Ws {
		p = append(p, g.Ws[l], g.Wr[l], g.B[l])
	}
	return p
}

// FitTemperature picks T minimising held-out NLL (grid search).
func (m *Model) FitTemperature(val []*Graph) float64 {
	var zs [][]float64
	var ys []int
	for _, g := range val {
		c := m.forward(g)
		zs = append(zs, c.out...)
		ys = append(ys, g.Labels...)
	}
	best, bestT := math.Inf(1), 1.0
	for T := 0.3; T <= 5; T += 0.05 {
		nll := 0.0
		for i, z := range zs {
			nll -= math.Log(math.Max(softmax(z, T)[ys[i]], 1e-12))
		}
		if nll < best {
			best, bestT = nll, T
		}
	}
	m.Temperature = bestT
	return bestT
}

// Eval returns accuracy and expected calibration error (10 bins) over targets.
func (m *Model) Eval(data []*Graph) (acc, ece float64, n int) {
	type bin struct{ conf, hit, n float64 }
	bins := make([]bin, 10)
	hits := 0
	for _, g := range data {
		for t, p := range m.Predict(g) {
			b := 0
			for i := range p {
				if p[i] > p[b] {
					b = i
				}
			}
			hit := 0.0
			if b == g.Labels[t] {
				hit = 1
				hits++
			}
			k := min(int(p[b]*10), 9)
			bins[k].conf += p[b]
			bins[k].hit += hit
			bins[k].n++
			n++
		}
	}
	if n == 0 {
		return 0, 0, 0
	}
	for _, b := range bins {
		if b.n > 0 {
			ece += math.Abs(b.conf-b.hit) / float64(n)
		}
	}
	return float64(hits) / float64(n), ece, n
}

// Save / Load as JSON (weights rounded to 5 significant digits by the encoder are fine for inference).
func (m *Model) Save(path string) error {
	r := func(v []float64) {
		for i, x := range v {
			v[i] = math.Round(x*1e4) / 1e4
		}
	}
	for _, p := range m.params() {
		r(p)
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func Load(b []byte) (*Model, error) {
	m := &Model{}
	if err := json.Unmarshal(b, m); err != nil {
		return nil, err
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(b)
	m.sourceDigest = hex.EncodeToString(digest[:])
	return m, nil
}

// SHA256 identifies the exact loaded weights, including their class order.
func (m *Model) SHA256() string { return m.sourceDigest }

// Validate rejects incompatible shapes and non-finite weights before inference.
func (m *Model) Validate() error {
	if m == nil || m.Dim <= 0 || m.Dim > 1<<20 || m.Hidden <= 0 || m.Hidden > 1024 ||
		m.Relations <= 0 || m.Relations > 64 || m.Layers < 0 || m.Layers > 16 || len(m.Classes) < 2 || len(m.Classes) > 256 {
		return fmt.Errorf("invalid GNN dimensions")
	}
	seen := map[string]bool{}
	for _, label := range m.Classes {
		if label == "" || seen[label] {
			return fmt.Errorf("invalid GNN class schema")
		}
		seen[label] = true
	}
	finite := func(v []float64, size int) bool {
		if len(v) != size {
			return false
		}
		for _, x := range v {
			if math.IsNaN(x) || math.IsInf(x, 0) {
				return false
			}
		}
		return true
	}
	h, r, c := m.Hidden, m.Relations, len(m.Classes)
	if !finite(m.Emb, m.Dim*h) || !finite(m.B0, h) || !finite(m.Wo, c*h) || !finite(m.Bo, c) ||
		len(m.Ws) != m.Layers || len(m.Wr) != m.Layers || len(m.B) != m.Layers ||
		m.Temperature <= 0 || math.IsNaN(m.Temperature) || math.IsInf(m.Temperature, 0) {
		return fmt.Errorf("invalid GNN weights or temperature")
	}
	for i := 0; i < m.Layers; i++ {
		if !finite(m.Ws[i], h*h) || !finite(m.Wr[i], r*h*h) || !finite(m.B[i], h) {
			return fmt.Errorf("invalid GNN layer %d", i)
		}
	}
	return nil
}
