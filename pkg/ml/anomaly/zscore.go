package anomaly

import (
	"errors"
	"math"
)

// Welford implements Welford's online algorithm for numerically stable
// streaming mean and variance. It never stores the underlying samples, so it
// is O(1) memory per feature and safe for very large workloads.
type Welford struct {
	n    int
	mean float64
	m2   float64
}

// Add folds one observation into the running statistics.
func (w *Welford) Add(x float64) {
	w.n++
	delta := x - w.mean
	w.mean += delta / float64(w.n)
	w.m2 += delta * (x - w.mean)
}

// Count returns the number of observations seen.
func (w *Welford) Count() int { return w.n }

// Mean returns the running mean (0 when empty).
func (w *Welford) Mean() float64 { return w.mean }

// Variance returns the sample variance (0 with fewer than two observations).
func (w *Welford) Variance() float64 {
	if w.n < 2 {
		return 0
	}
	return w.m2 / float64(w.n-1)
}

// StdDev returns the sample standard deviation.
func (w *Welford) StdDev() float64 { return math.Sqrt(w.Variance()) }

// Baseline maintains per-feature streaming statistics for a fixed-width
// feature vector. It provides explainable, per-feature z-score attributions
// that complement the IsolationForest's single aggregate score.
type Baseline struct {
	dims int
	cols []Welford
}

// NewBaseline creates a baseline for vectors of the given width.
func NewBaseline(dims int) *Baseline {
	return &Baseline{dims: dims, cols: make([]Welford, dims)}
}

// Dims returns the configured feature width.
func (b *Baseline) Dims() int { return b.dims }

// Observe folds one feature vector into the baseline.
func (b *Baseline) Observe(x []float64) error {
	if len(x) != b.dims {
		return errors.New("anomaly: vector width does not match baseline")
	}
	for i := range x {
		b.cols[i].Add(x[i])
	}
	return nil
}

// ObserveBatch folds many vectors into the baseline.
func (b *Baseline) ObserveBatch(rows [][]float64) error {
	for _, row := range rows {
		if err := b.Observe(row); err != nil {
			return err
		}
	}
	return nil
}

// ZScores returns the per-feature standard scores of x against the baseline.
// A feature with zero observed variance contributes a z-score of 0 rather
// than +Inf, keeping downstream aggregation numerically stable.
func (b *Baseline) ZScores(x []float64) ([]float64, error) {
	if len(x) != b.dims {
		return nil, errors.New("anomaly: vector width does not match baseline")
	}
	out := make([]float64, b.dims)
	for i := range x {
		sd := b.cols[i].StdDev()
		if sd == 0 {
			out[i] = 0
			continue
		}
		out[i] = (x[i] - b.cols[i].Mean()) / sd
	}
	return out, nil
}

// Deviation returns the root-mean-square of the per-feature z-scores — a
// single scalar summarising how far x sits from the learned centre.
func (b *Baseline) Deviation(x []float64) (float64, error) {
	z, err := b.ZScores(x)
	if err != nil {
		return 0, err
	}
	if len(z) == 0 {
		return 0, nil
	}
	var sum float64
	for _, v := range z {
		sum += v * v
	}
	return math.Sqrt(sum / float64(len(z))), nil
}

// MeanAt and StdDevAt expose the learned statistics for feature i, used when
// building human-readable explanations.
func (b *Baseline) MeanAt(i int) float64 {
	if i < 0 || i >= b.dims {
		return 0
	}
	return b.cols[i].Mean()
}

func (b *Baseline) StdDevAt(i int) float64 {
	if i < 0 || i >= b.dims {
		return 0
	}
	return b.cols[i].StdDev()
}
