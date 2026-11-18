package s1

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
)

// Calibration holds per-question-type temperatures fitted on held-out labelled data.
type Calibration struct {
	Version     string             `json:"version"`
	Fingerprint string             `json:"fingerprint,omitempty"`
	Temps       map[string]float64 `json:"temperatures"`
	Fitted      map[string]int     `json:"fitted_on,omitempty"`
	Note        string             `json:"note,omitempty"`
}

func DefaultCalibration() Calibration {
	return Calibration{Version: Version, Temps: map[string]float64{TypeNoul: 1, TypeChoice: 1, TypeScore: 1}, Note: "uncalibrated defaults"}
}

func (c Calibration) temp(t string) float64 {
	if v, ok := c.Temps[t]; ok && v > 0 && !math.IsInf(v, 0) {
		return v
	}
	return 1
}

func LoadCalibration(path string) (Calibration, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Calibration{}, err
	}
	var c Calibration
	if err := json.Unmarshal(b, &c); err != nil {
		return Calibration{}, err
	}
	for k, v := range c.Temps {
		if v <= 0 || v > 100 || math.IsNaN(v) {
			return Calibration{}, fmt.Errorf("invalid temperature for %s", k)
		}
	}
	return c, nil
}

// Labelled is one evaluation/calibration example. Labels map question id to either
// a hard label ("refund", true/false, 0/1) or a reference distribution
// ({"refund":0.7,"billing":0.3} or a number 0..1 for a Noul), e.g. averaged teacher LLMs.
type Labelled struct {
	Group   string                     `json:"group,omitempty"`
	Request Request                    `json:"request"`
	Labels  map[string]json.RawMessage `json:"labels"`
}

// target is a reference distribution over the answer keys of one question.
type target struct {
	typ   string
	keys  []string
	dist  []float64
	z     []float64
	soft  bool
	fixed []float64 // expert answer: probabilities are final
}

// targetFor resolves a label into a distribution aligned with the answer.
func targetFor(a Answer, raw json.RawMessage) (target, error) {
	t := target{typ: a.Type, z: a.logits, fixed: a.fixed}
	if len(bytes.TrimSpace(raw)) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return t, fmt.Errorf("label must not be null or missing")
	}
	if a.Type == TypeNoul {
		t.keys = []string{"true", "false"}
		var b bool
		if json.Unmarshal(raw, &b) == nil {
			if b {
				t.dist = []float64{1, 0}
			} else {
				t.dist = []float64{0, 1}
			}
			return t, nil
		}
		var f float64
		if err := json.Unmarshal(raw, &f); err != nil || f < 0 || f > 1 {
			return t, fmt.Errorf("noul label must be bool or 0..1")
		}
		t.dist, t.soft = []float64{f, 1 - f}, f != 0 && f != 1
		return t, nil
	}
	t.keys = a.keys
	t.dist = make([]float64, len(a.keys))
	var s string
	if json.Unmarshal(raw, &s) == nil {
		for i, k := range a.keys {
			if k == s {
				t.dist[i] = 1
				return t, nil
			}
		}
		return t, fmt.Errorf("label %q is not a declared option", s)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return t, fmt.Errorf("label must be an option key or a distribution")
	}
	sum := 0.0
	for k, value := range m {
		var v float64
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) || json.Unmarshal(value, &v) != nil || math.IsNaN(v) || math.IsInf(v, 0) {
			return t, fmt.Errorf("distribution value for %q must be a finite number", k)
		}
		found := false
		for i, kk := range a.keys {
			if kk == k {
				t.dist[i], found = v, true
			}
		}
		if !found || v < 0 {
			return t, fmt.Errorf("distribution key %q invalid", k)
		}
		sum += v
	}
	if sum <= 0 || math.IsInf(sum, 0) {
		return t, fmt.Errorf("distribution must have a finite positive sum")
	}
	for i := range t.dist {
		t.dist[i] /= sum
	}
	t.soft = true
	return t, nil
}

func probsAt(t target, temp float64) []float64 {
	if t.fixed != nil {
		return t.fixed
	}
	if t.typ == TypeNoul {
		p := sigmoid(t.z[0] / temp)
		return []float64{p, 1 - p}
	}
	return softmax(t.z, temp)
}

// crossEntropy of the reference distribution under the model (log-loss for hard labels).
func crossEntropy(t target, p []float64) float64 {
	s := 0.0
	for i, q := range t.dist {
		if q > 0 {
			s -= q * math.Log(math.Max(p[i], 1e-9))
		}
	}
	return s
}

// FitTemperatures picks, per question type, the temperature minimising mean cross-entropy
// (a proper scoring rule) on the supplied answers/targets. Uses a log-grid + golden refinement.
func FitTemperatures(ts []target) Calibration {
	c := DefaultCalibration()
	c.Fitted = map[string]int{}
	byType := map[string][]target{}
	for _, t := range ts {
		if t.fixed != nil {
			continue // experts carry their own calibration
		}
		byType[t.typ] = append(byType[t.typ], t)
	}
	types := make([]string, 0, len(byType))
	for k := range byType {
		types = append(types, k)
	}
	sort.Strings(types)
	for _, typ := range types {
		group := byType[typ]
		loss := func(T float64) float64 {
			s := 0.0
			for _, t := range group {
				s += crossEntropy(t, probsAt(t, T))
			}
			return s / float64(len(group))
		}
		best, bestL := 1.0, loss(1)
		for lt := -2.0; lt <= 2.0; lt += 0.05 {
			T := math.Exp(lt)
			if l := loss(T); l < bestL {
				best, bestL = T, l
			}
		}
		c.Temps[typ] = math.Round(best*1000) / 1000
		c.Fitted[typ] = len(group)
	}
	c.Note = "temperature scaling fitted by minimum cross-entropy"
	return c
}
