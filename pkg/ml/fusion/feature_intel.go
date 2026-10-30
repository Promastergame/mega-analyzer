package fusion

import (
	"errors"
	"math"
	"sort"

	"mega-analyzer/pkg/ml/anomaly"
)

// FeatureScore summarises what the monitor has learned about one feature.
type FeatureScore struct {
	Name        string  `json:"name"`
	Index       int     `json:"index"`
	Correlation float64 `json:"label_correlation"` // Pearson corr with label [-1,1]
	Importance  float64 `json:"importance"`        // |correlation|
	StdDev      float64 `json:"std_dev"`
	Useless     bool    `json:"useless"` // near-zero variance
	Drifted     bool    `json:"drifted"` // distribution shift detected
}

// pageHinkley is a compact single-stream drift detector (Page-Hinkley test).
type pageHinkley struct {
	delta, lambda float64
	n             int
	mean          float64
	cum           float64
	minCum        float64
	triggered     bool
}

func newPageHinkley(delta, lambda float64) pageHinkley {
	return pageHinkley{delta: delta, lambda: lambda}
}

func (p *pageHinkley) update(x float64) bool {
	p.n++
	p.mean += (x - p.mean) / float64(p.n)
	p.cum += x - p.mean - p.delta
	if p.n == 1 || p.cum < p.minCum {
		p.minCum = p.cum
	}
	p.triggered = (p.cum - p.minCum) > p.lambda
	return p.triggered
}

// FeatureMonitor tracks per-feature statistics online to power feature
// importance, quality scoring, drift detection, correlation detection and
// adaptive weighting — all in O(dims) memory per update (plus a bounded ring
// buffer used only for on-demand pairwise correlation).
type FeatureMonitor struct {
	names []string
	dims  int
	stats []anomaly.Welford
	ph    []pageHinkley

	// Pearson-with-label accumulators.
	n     int
	sumY  float64
	sumY2 float64
	sumX  []float64
	sumX2 []float64
	sumXY []float64

	// Bounded ring buffer of recent vectors for pairwise correlation.
	ring    [][]float64
	ringCap int
	ringPos int
	ringLen int

	uselessStd float64
}

// NewFeatureMonitor creates a monitor over the named features. ringCap bounds
// the memory used for on-demand pairwise correlation (default 512).
func NewFeatureMonitor(names []string, ringCap int) *FeatureMonitor {
	dims := len(names)
	if ringCap <= 0 {
		ringCap = 512
	}
	fm := &FeatureMonitor{
		names:      append([]string(nil), names...),
		dims:       dims,
		stats:      make([]anomaly.Welford, dims),
		ph:         make([]pageHinkley, dims),
		sumX:       make([]float64, dims),
		sumX2:      make([]float64, dims),
		sumXY:      make([]float64, dims),
		ring:       make([][]float64, 0, ringCap),
		ringCap:    ringCap,
		uselessStd: 1e-9,
	}
	for i := range fm.ph {
		fm.ph[i] = newPageHinkley(0.005, 50)
	}
	return fm
}

// Observe folds one labelled feature vector into all monitors.
func (fm *FeatureMonitor) Observe(x []float64, label int) error {
	if len(x) != fm.dims {
		return errors.New("fusion: feature width mismatch")
	}
	y := float64(label)
	fm.n++
	fm.sumY += y
	fm.sumY2 += y * y
	for i := 0; i < fm.dims; i++ {
		fm.stats[i].Add(x[i])
		fm.ph[i].update(x[i])
		fm.sumX[i] += x[i]
		fm.sumX2[i] += x[i] * x[i]
		fm.sumXY[i] += x[i] * y
	}
	cp := append([]float64(nil), x...)
	if fm.ringLen < fm.ringCap {
		fm.ring = append(fm.ring, cp)
		fm.ringLen++
	} else {
		fm.ring[fm.ringPos] = cp
	}
	fm.ringPos = (fm.ringPos + 1) % fm.ringCap
	return nil
}

func (fm *FeatureMonitor) labelCorr(i int) float64 {
	n := float64(fm.n)
	if n < 2 {
		return 0
	}
	num := n*fm.sumXY[i] - fm.sumX[i]*fm.sumY
	denX := n*fm.sumX2[i] - fm.sumX[i]*fm.sumX[i]
	denY := n*fm.sumY2 - fm.sumY*fm.sumY
	den := math.Sqrt(denX) * math.Sqrt(denY)
	if den == 0 {
		return 0
	}
	c := num / den
	if c > 1 {
		c = 1
	}
	if c < -1 {
		c = -1
	}
	return c
}

// Scores returns per-feature intelligence, sorted by importance descending.
func (fm *FeatureMonitor) Scores() []FeatureScore {
	out := make([]FeatureScore, fm.dims)
	for i := 0; i < fm.dims; i++ {
		corr := fm.labelCorr(i)
		sd := fm.stats[i].StdDev()
		out[i] = FeatureScore{
			Name:        fm.nameAt(i),
			Index:       i,
			Correlation: corr,
			Importance:  math.Abs(corr),
			StdDev:      sd,
			Useless:     sd <= fm.uselessStd,
			Drifted:     fm.ph[i].triggered,
		}
	}
	sort.SliceStable(out, func(a, b int) bool {
		if out[a].Importance != out[b].Importance {
			return out[a].Importance > out[b].Importance
		}
		return out[a].Index < out[b].Index
	})
	return out
}

// AdaptiveWeights returns normalised, importance-based feature weights in the
// ORIGINAL feature order. Useless (near-constant) features get weight 0. When
// no signal is informative yet, a uniform weighting is returned so downstream
// scoring stays defined.
func (fm *FeatureMonitor) AdaptiveWeights() []float64 {
	w := make([]float64, fm.dims)
	if fm.dims == 0 {
		return w
	}
	var total float64
	for i := 0; i < fm.dims; i++ {
		if fm.stats[i].StdDev() <= fm.uselessStd {
			continue
		}
		imp := math.Abs(fm.labelCorr(i))
		w[i] = imp
		total += imp
	}
	if total == 0 {
		for i := range w {
			w[i] = 1.0 / float64(fm.dims)
		}
		return w
	}
	for i := range w {
		w[i] /= total
	}
	return w
}

// UselessFeatures returns the names of near-constant features worth pruning.
func (fm *FeatureMonitor) UselessFeatures() []string {
	var out []string
	for i := 0; i < fm.dims; i++ {
		if fm.stats[i].StdDev() <= fm.uselessStd {
			out = append(out, fm.nameAt(i))
		}
	}
	return out
}

// DriftedFeatures returns names of features whose distribution has shifted.
func (fm *FeatureMonitor) DriftedFeatures() []string {
	var out []string
	for i := 0; i < fm.dims; i++ {
		if fm.ph[i].triggered {
			out = append(out, fm.nameAt(i))
		}
	}
	return out
}

// CorrelatedPair reports two redundant features and their correlation.
type CorrelatedPair struct {
	A           string  `json:"a"`
	B           string  `json:"b"`
	IndexA      int     `json:"index_a"`
	IndexB      int     `json:"index_b"`
	Correlation float64 `json:"correlation"`
}

// DetectCorrelated finds feature pairs whose |Pearson correlation| over the
// recent ring buffer meets threshold — candidates for de-duplication.
func (fm *FeatureMonitor) DetectCorrelated(threshold float64) []CorrelatedPair {
	if fm.ringLen < 3 {
		return nil
	}
	rows := fm.ring[:fm.ringLen]
	means := make([]float64, fm.dims)
	for _, r := range rows {
		for j := 0; j < fm.dims; j++ {
			means[j] += r[j]
		}
	}
	nf := float64(len(rows))
	for j := range means {
		means[j] /= nf
	}

	var pairs []CorrelatedPair
	for a := 0; a < fm.dims; a++ {
		for b := a + 1; b < fm.dims; b++ {
			var cov, va, vb float64
			for _, r := range rows {
				da := r[a] - means[a]
				db := r[b] - means[b]
				cov += da * db
				va += da * da
				vb += db * db
			}
			den := math.Sqrt(va) * math.Sqrt(vb)
			if den == 0 {
				continue
			}
			c := cov / den
			if math.Abs(c) >= threshold {
				pairs = append(pairs, CorrelatedPair{
					A: fm.nameAt(a), B: fm.nameAt(b),
					IndexA: a, IndexB: b, Correlation: c,
				})
			}
		}
	}
	sort.SliceStable(pairs, func(i, j int) bool {
		return math.Abs(pairs[i].Correlation) > math.Abs(pairs[j].Correlation)
	})
	return pairs
}

// Samples returns how many observations have been folded in.
func (fm *FeatureMonitor) Samples() int { return fm.n }

func (fm *FeatureMonitor) nameAt(i int) string {
	if i >= 0 && i < len(fm.names) && fm.names[i] != "" {
		return fm.names[i]
	}
	return "feature_" + itoa(i)
}
