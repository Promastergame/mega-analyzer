package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
)

type TrainingSample struct {
	Group string  `json:"group"`
	Label int     `json:"label"`
	Input Request `json:"input"`
}
type Dataset struct {
	Target  string           `json:"target"`
	Samples []TrainingSample `json:"samples"`
}
type Metrics struct {
	TrainCount       int     `json:"train_count"`
	CalibrationCount int     `json:"calibration_count"`
	TestCount        int     `json:"test_count"`
	Brier            float64 `json:"test_brier"`
	Accuracy         float64 `json:"test_accuracy_at_0_5"`
	Note             string  `json:"note"`
}
type Model struct {
	Version      string    `json:"version"`
	Target       string    `json:"target"`
	Features     []string  `json:"features"`
	Weights      []float64 `json:"weights"`
	Bias         float64   `json:"bias"`
	CalibrationA float64   `json:"calibration_a"`
	CalibrationB float64   `json:"calibration_b"`
	Metrics      Metrics   `json:"metrics"`
}

func sigmoid(z float64) float64 {
	if z >= 0 {
		return 1 / (1 + math.Exp(-z))
	}
	e := math.Exp(z)
	return e / (1 + e)
}
func (m *Model) Validate() error {
	if (m.Version != Version && m.Version != "0.1.0") || (m.Target != "finding" && m.Target != "patch") {
		return fmt.Errorf("model version/target mismatch")
	}
	if len(m.Features) != len(FeatureNames) || len(m.Weights) != len(FeatureNames) {
		return fmt.Errorf("model feature schema mismatch")
	}
	for i, n := range FeatureNames {
		if m.Features[i] != n || !finite(m.Weights[i]) {
			return fmt.Errorf("invalid model features/weights")
		}
	}
	if !finite(m.Bias) || !finite(m.CalibrationA) || !finite(m.CalibrationB) || m.CalibrationA < 0 || m.Metrics.TrainCount < 40 || m.Metrics.CalibrationCount < 20 || m.Metrics.TestCount < 20 || !finite(m.Metrics.Brier) || m.Metrics.Brier < 0 || m.Metrics.Brier > 1 || !finite(m.Metrics.Accuracy) || m.Metrics.Accuracy < 0 || m.Metrics.Accuracy > 1 {
		return fmt.Errorf("invalid or insufficient model metadata")
	}
	return nil
}
func vector(f map[string]float64) []float64 {
	x := make([]float64, len(FeatureNames))
	for i, n := range FeatureNames {
		x[i] = f[n]
	}
	return x
}
func dot(w, x []float64, b float64) float64 {
	for i, v := range x {
		b += w[i] * v
	}
	return b
}
func Train(d Dataset) (*Model, error) {
	if d.Target != "finding" && d.Target != "patch" {
		return nil, fmt.Errorf("target must be finding or patch")
	}
	if len(d.Samples) > 100000 {
		return nil, fmt.Errorf("dataset limit: 100000")
	}
	groups := map[string]bool{}
	for _, s := range d.Samples {
		if s.Group == "" || s.Label < 0 || s.Label > 1 {
			return nil, fmt.Errorf("each sample needs group and binary label")
		}
		if d.Target == "patch" && s.Input.Patch == nil {
			return nil, fmt.Errorf("patch training samples must include a concrete patch request")
		}
		if err := ValidateRequest(s.Input); err != nil {
			return nil, err
		}
		groups[s.Group] = true
	}
	keys := []string{}
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := sha256.Sum256([]byte(keys[i])), sha256.Sum256([]byte(keys[j]))
		return hex.EncodeToString(a[:]) < hex.EncodeToString(b[:])
	})
	if len(keys) < 10 {
		return nil, fmt.Errorf("need at least 10 independent app/project groups")
	}
	splits := map[string]int{}
	a, b := len(keys)*6/10, len(keys)*8/10
	for i, k := range keys {
		n := 0
		if i >= b {
			n = 2
		} else if i >= a {
			n = 1
		}
		splits[k] = n
	}
	sets := [3][]TrainingSample{}
	for _, s := range d.Samples {
		k := splits[s.Group]
		sets[k] = append(sets[k], s)
	}
	mins := []int{40, 20, 20}
	for k, set := range sets {
		labels := [2]int{}
		for _, s := range set {
			labels[s.Label]++
		}
		if len(set) < mins[k] || labels[0] < 5 || labels[1] < 5 {
			return nil, fmt.Errorf("split %d needs >=%d rows and >=5 examples per class", k, mins[k])
		}
	}
	m := &Model{Version: Version, Target: d.Target, Features: append([]string{}, FeatureNames...), Weights: make([]float64, len(FeatureNames)), CalibrationA: 1}
	xs := make([][]float64, len(sets[0]))
	for i, s := range sets[0] {
		xs[i] = vector(Features(s.Input))
	}
	for epoch := 0; epoch < 500; epoch++ {
		g := make([]float64, len(m.Weights))
		gb := 0.0
		for i, s := range sets[0] {
			err := sigmoid(dot(m.Weights, xs[i], m.Bias)) - float64(s.Label)
			gb += err
			for j, v := range xs[i] {
				g[j] += err * v
			}
		}
		n := float64(len(xs))
		m.Bias -= 0.4 * gb / n
		for j := range g {
			m.Weights[j] -= 0.4 * (g[j]/n + 0.001*m.Weights[j])
		}
	}
	// Platt calibration on groups never used for fitting; A constrained nonnegative.
	for epoch := 0; epoch < 300; epoch++ {
		ga, gb := 0.0, 0.0
		for _, s := range sets[1] {
			z := dot(m.Weights, vector(Features(s.Input)), m.Bias)
			err := sigmoid(m.CalibrationA*z+m.CalibrationB) - float64(s.Label)
			ga += err * z
			gb += err
		}
		n := float64(len(sets[1]))
		m.CalibrationA -= 0.03 * ga / n
		m.CalibrationB -= 0.03 * gb / n
		if m.CalibrationA < 0 {
			m.CalibrationA = 0
		}
	}
	m.Metrics = Metrics{TrainCount: len(sets[0]), CalibrationCount: len(sets[1]), TestCount: len(sets[2]), Note: "Group-disjoint holdout. Metrics describe only this dataset; not a guarantee on other apps. Labels are supplied by the dataset author."}
	for _, s := range sets[2] {
		p := m.Predict(Features(s.Input))
		err := p - float64(s.Label)
		m.Metrics.Brier += err * err
		if (p >= 0.5) == (s.Label == 1) {
			m.Metrics.Accuracy++
		}
	}
	m.Metrics.Brier /= float64(len(sets[2]))
	m.Metrics.Accuracy /= float64(len(sets[2]))
	return m, m.Validate()
}
func (m *Model) Predict(f map[string]float64) float64 {
	return sigmoid(m.CalibrationA*dot(m.Weights, vector(f), m.Bias) + m.CalibrationB)
}
func assess(f map[string]float64, target string, threshold float64, m *Model) Assessment {
	a := Assessment{Target: target, Kind: "heuristic_score", Contributions: map[string]float64{}, Notes: []string{"Не является вероятностью успешного поведения."}}
	weights := map[string]float64{"evidence_count": 0.5, "app_owned": 0.15, "library": -0.35, "server_dependency": -0.15}
	base := 0.30
	if target == "patch" {
		base = 0.4
		weights = map[string]float64{"app_owned": 0.30, "library": -0.6, "server_dependency": -0.35, "branches": -0.2, "invokes": -0.2}
	}
	v := base
	a.Contributions["intercept"] = base
	for n, w := range weights {
		c := w * f[n]
		v += c
		a.Contributions[n] = c
	}
	if v < 0 {
		v = 0
	}
	if v > 1 {
		v = 1
	}
	a.Value = math.Round(v*1e9) / 1e9
	if m != nil {
		a.Kind = "heldout_calibrated_model_estimate"
		a.Value = m.Predict(f)
		a.Contributions = map[string]float64{"intercept_logit": m.CalibrationA*m.Bias + m.CalibrationB}
		for i, n := range FeatureNames {
			a.Contributions[n] = m.CalibrationA * m.Weights[i] * f[n]
		}
		a.Notes = []string{"Оценка модели, калиброванной на отдельной группе данных; не гарантия для нового приложения.", "Contributions — слагаемые логита, не причинные объяснения."}
	}
	a.AboveThreshold = a.Value >= threshold
	return a
}
