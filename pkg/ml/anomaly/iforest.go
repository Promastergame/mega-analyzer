package anomaly

import (
	"errors"
	"math"
	"math/rand"
)

// eulerGamma is the Euler–Mascheroni constant, used in the harmonic-number
// approximation for the isolation-tree normalisation factor.
const eulerGamma = 0.5772156649015329

// IsolationForestConfig controls training of an IsolationForest.
type IsolationForestConfig struct {
	// NumTrees is the number of isolation trees in the ensemble.
	NumTrees int
	// SampleSize is the sub-sampling size per tree (Liu et al. recommend 256).
	SampleSize int
	// Seed makes training fully deterministic.
	Seed int64
	// MaxDepthCap optionally caps tree depth. When <= 0 it defaults to
	// ceil(log2(SampleSize)), the standard heuristic.
	MaxDepthCap int
}

// DefaultIsolationForestConfig returns the canonical configuration from the
// original isolation-forest paper, with a fixed seed for reproducibility.
func DefaultIsolationForestConfig() IsolationForestConfig {
	return IsolationForestConfig{NumTrees: 100, SampleSize: 256, Seed: 1}
}

type iNode struct {
	left, right *iNode
	splitAttr   int
	splitValue  float64
	size        int
	isLeaf      bool
}

// IsolationForest is an unsupervised anomaly detector. It isolates points by
// recursively partitioning the feature space with random splits: anomalies
// require fewer splits to isolate, yielding shorter expected path lengths and
// therefore higher anomaly scores.
type IsolationForest struct {
	cfg     IsolationForestConfig
	trees   []*iNode
	dims    int
	cNorm   float64
	trained bool
}

// NewIsolationForest constructs an untrained forest, normalising any invalid
// configuration values to safe defaults.
func NewIsolationForest(cfg IsolationForestConfig) *IsolationForest {
	if cfg.NumTrees <= 0 {
		cfg.NumTrees = 100
	}
	if cfg.SampleSize <= 0 {
		cfg.SampleSize = 256
	}
	if cfg.Seed == 0 {
		cfg.Seed = 1
	}
	return &IsolationForest{cfg: cfg}
}

// Dims returns the feature dimensionality the forest was trained on.
func (f *IsolationForest) Dims() int { return f.dims }

// Trained reports whether Fit has completed successfully.
func (f *IsolationForest) Trained() bool { return f.trained }

// Fit builds the forest from a data matrix. Each row is a feature vector and
// every row must share the same dimensionality.
func (f *IsolationForest) Fit(data [][]float64) error {
	if len(data) == 0 {
		return errors.New("anomaly: empty training data")
	}
	f.dims = len(data[0])
	if f.dims == 0 {
		return errors.New("anomaly: zero-width feature vectors")
	}
	for _, row := range data {
		if len(row) != f.dims {
			return errors.New("anomaly: inconsistent feature dimensionality")
		}
	}

	sampleSize := f.cfg.SampleSize
	if sampleSize > len(data) {
		sampleSize = len(data)
	}
	maxDepth := f.cfg.MaxDepthCap
	if maxDepth <= 0 {
		maxDepth = int(math.Ceil(math.Log2(math.Max(2, float64(sampleSize)))))
	}

	rng := rand.New(rand.NewSource(f.cfg.Seed))
	f.trees = make([]*iNode, 0, f.cfg.NumTrees)
	for t := 0; t < f.cfg.NumTrees; t++ {
		sample := subsample(data, sampleSize, rng)
		f.trees = append(f.trees, buildTree(sample, 0, maxDepth, rng))
	}
	f.cNorm = cFactor(sampleSize)
	f.trained = true
	return nil
}

// Score returns an anomaly score in [0,1]. Values near 1 indicate strong
// anomalies; values well below 0.5 indicate normal points. A vector whose
// width does not match the trained dimensionality returns 0.
func (f *IsolationForest) Score(x []float64) float64 {
	if !f.trained || len(f.trees) == 0 || len(x) != f.dims {
		return 0
	}
	var total float64
	for _, tr := range f.trees {
		total += pathLength(tr, x, 0)
	}
	avg := total / float64(len(f.trees))
	if f.cNorm <= 0 {
		return 0
	}
	return math.Pow(2, -avg/f.cNorm)
}

// ScoreBatch scores many vectors, reusing a single output slice.
func (f *IsolationForest) ScoreBatch(rows [][]float64) []float64 {
	out := make([]float64, len(rows))
	for i := range rows {
		out[i] = f.Score(rows[i])
	}
	return out
}

func subsample(data [][]float64, k int, rng *rand.Rand) [][]float64 {
	n := len(data)
	if k >= n {
		out := make([][]float64, n)
		copy(out, data)
		return out
	}
	perm := rng.Perm(n)
	out := make([][]float64, k)
	for i := 0; i < k; i++ {
		out[i] = data[perm[i]]
	}
	return out
}

func buildTree(data [][]float64, depth, maxDepth int, rng *rand.Rand) *iNode {
	n := len(data)
	if depth >= maxDepth || n <= 1 {
		return &iNode{isLeaf: true, size: n}
	}
	dims := len(data[0])

	// Collect every attribute that varies in this partition, then sample from
	// that set. Probing only `dims` random attributes could repeatedly hit
	// constant columns and prematurely turn a splittable node into a leaf.
	attrs := make([]int, 0, dims)
	mins := make([]float64, dims)
	maxs := make([]float64, dims)
	for a := 0; a < dims; a++ {
		mn, mx := data[0][a], data[0][a]
		for _, row := range data[1:] {
			if row[a] < mn {
				mn = row[a]
			}
			if row[a] > mx {
				mx = row[a]
			}
		}
		mins[a], maxs[a] = mn, mx
		if mx > mn {
			attrs = append(attrs, a)
		}
	}
	if len(attrs) == 0 {
		// All attributes constant: cannot split further.
		return &iNode{isLeaf: true, size: n}
	}
	attr := attrs[rng.Intn(len(attrs))]
	minV, maxV := mins[attr], maxs[attr]

	split := minV + rng.Float64()*(maxV-minV)
	var left, right [][]float64
	for _, row := range data {
		if row[attr] < split {
			left = append(left, row)
		} else {
			right = append(right, row)
		}
	}
	return &iNode{
		splitAttr:  attr,
		splitValue: split,
		size:       n,
		left:       buildTree(left, depth+1, maxDepth, rng),
		right:      buildTree(right, depth+1, maxDepth, rng),
	}
}

func pathLength(node *iNode, x []float64, depth float64) float64 {
	if node.isLeaf {
		return depth + cFactor(node.size)
	}
	if x[node.splitAttr] < node.splitValue {
		return pathLength(node.left, x, depth+1)
	}
	return pathLength(node.right, x, depth+1)
}

// cFactor is the average path length of an unsuccessful search in a binary
// search tree of n nodes — the normalisation term c(n) from the paper.
func cFactor(n int) float64 {
	if n <= 1 {
		return 0
	}
	if n == 2 {
		return 1
	}
	h := math.Log(float64(n-1)) + eulerGamma
	return 2*h - (2 * float64(n-1) / float64(n))
}
