package anomaly

import (
	"errors"
	"sort"
)

// Config controls the fused Detector.
type Config struct {
	// Forest configures the underlying isolation forest.
	Forest IsolationForestConfig
	// Threshold is the isolation-forest score at or above which a point is
	// flagged as an anomaly. When <= 0 it defaults to 0.6.
	Threshold float64
	// EnableLSH turns on the similarity-search index so Results carry
	// nearest historical neighbours.
	EnableLSH bool
	// LSHPlanes is the SimHash width when EnableLSH is set (default 32).
	LSHPlanes int
	// Seed is used for any index randomness so the detector is deterministic.
	Seed int64
	// TopK is how many feature contributions and neighbours to report.
	TopK int
}

// DefaultConfig returns a sensible, deterministic default configuration.
func DefaultConfig() Config {
	return Config{
		Forest:    DefaultIsolationForestConfig(),
		Threshold: 0.6,
		EnableLSH: true,
		LSHPlanes: 32,
		Seed:      1,
		TopK:      5,
	}
}

// Contribution explains one feature's role in an anomaly verdict.
type Contribution struct {
	Feature string  `json:"feature"`
	Value   float64 `json:"value"`
	ZScore  float64 `json:"z_score"`
	Mean    float64 `json:"mean"`
	StdDev  float64 `json:"std_dev"`
}

// Result is the fused, explainable output for a single vector.
type Result struct {
	Score           float64        `json:"score"`     // isolation-forest anomaly score [0,1]
	Deviation       float64        `json:"deviation"` // RMS z-score vs baseline
	IsAnomaly       bool           `json:"is_anomaly"`
	Threshold       float64        `json:"threshold"`
	TopContributors []Contribution `json:"top_contributors"`
	Neighbors       []Neighbor     `json:"neighbors,omitempty"`
}

// Detector fuses unsupervised anomaly scoring (IsolationForest), explainable
// per-feature attribution (Baseline), and optional similarity search
// (LSHIndex) behind one interface. It is the recommended entry point for the
// pipeline: train once on a corpus of historical feature vectors, then
// Analyze new targets.
type Detector struct {
	schema  []string
	cfg     Config
	forest  *IsolationForest
	base    *Baseline
	index   *LSHIndex
	trained bool
}

// NewDetector builds an untrained detector bound to a feature schema. The
// schema names align 1:1 with vector columns and are surfaced in
// explanations, so pass featurestore SortedKeys (or a fixed schema) here.
func NewDetector(schema []string, cfg Config) *Detector {
	if cfg.Threshold <= 0 {
		cfg.Threshold = 0.6
	}
	if cfg.TopK <= 0 {
		cfg.TopK = 5
	}
	if cfg.LSHPlanes <= 0 {
		cfg.LSHPlanes = 32
	}
	return &Detector{
		schema: append([]string(nil), schema...),
		cfg:    cfg,
	}
}

// Schema returns the feature schema the detector was constructed with.
func (d *Detector) Schema() []string { return d.schema }

// Trained reports whether Fit has completed.
func (d *Detector) Trained() bool { return d.trained }

// Fit trains the detector. vectors is the historical corpus; ids optionally
// labels each row for similarity search (when EnableLSH is set). If ids is
// nil or shorter than vectors, missing ids are synthesised deterministically.
func (d *Detector) Fit(vectors [][]float64, ids []string) error {
	if len(vectors) == 0 {
		return errors.New("anomaly: empty training corpus")
	}
	width := len(d.schema)
	if width == 0 {
		width = len(vectors[0])
	}
	for _, v := range vectors {
		if len(v) != width {
			return errors.New("anomaly: vector width does not match schema")
		}
	}

	d.forest = NewIsolationForest(d.cfg.Forest)
	if err := d.forest.Fit(vectors); err != nil {
		return err
	}

	d.base = NewBaseline(width)
	if err := d.base.ObserveBatch(vectors); err != nil {
		return err
	}

	if d.cfg.EnableLSH {
		d.index = NewLSHIndex(width, d.cfg.LSHPlanes, d.cfg.Seed)
		for i, v := range vectors {
			id := indexID(ids, i)
			if err := d.index.Add(id, v); err != nil {
				return err
			}
		}
	}

	d.trained = true
	return nil
}

// Analyze scores one vector and returns a fully explained Result.
func (d *Detector) Analyze(x []float64) (Result, error) {
	if !d.trained {
		return Result{}, errors.New("anomaly: detector not trained")
	}
	if len(x) != d.base.Dims() {
		return Result{}, errors.New("anomaly: vector width does not match schema")
	}

	score := d.forest.Score(x)
	deviation, err := d.base.Deviation(x)
	if err != nil {
		return Result{}, err
	}

	res := Result{
		Score:           score,
		Deviation:       deviation,
		IsAnomaly:       score >= d.cfg.Threshold,
		Threshold:       d.cfg.Threshold,
		TopContributors: d.contributions(x),
	}

	if d.index != nil {
		neighbors, qErr := d.index.Query(x, d.cfg.TopK)
		if qErr != nil {
			return Result{}, qErr
		}
		res.Neighbors = neighbors
	}
	return res, nil
}

// contributions ranks features by absolute z-score to explain the verdict.
func (d *Detector) contributions(x []float64) []Contribution {
	z, err := d.base.ZScores(x)
	if err != nil {
		return nil
	}
	all := make([]Contribution, len(x))
	for i := range x {
		all[i] = Contribution{
			Feature: d.featureName(i),
			Value:   x[i],
			ZScore:  z[i],
			Mean:    d.base.MeanAt(i),
			StdDev:  d.base.StdDevAt(i),
		}
	}
	sort.Slice(all, func(a, b int) bool {
		za, zb := absf(all[a].ZScore), absf(all[b].ZScore)
		if za != zb {
			return za > zb
		}
		return all[a].Feature < all[b].Feature
	})
	k := d.cfg.TopK
	if k > len(all) {
		k = len(all)
	}
	return all[:k]
}

func (d *Detector) featureName(i int) string {
	if i >= 0 && i < len(d.schema) {
		return d.schema[i]
	}
	return syntheticName(i)
}

func absf(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}

func indexID(ids []string, i int) string {
	if i < len(ids) && ids[i] != "" {
		return ids[i]
	}
	return syntheticName(i)
}

func syntheticName(i int) string {
	// Small, allocation-free base-10 name without importing strconv into hot
	// paths repeatedly; fine for schema fallbacks.
	return "feature_" + itoa(i)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
