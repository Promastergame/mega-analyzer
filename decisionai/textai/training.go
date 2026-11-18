package textai

import (
	"fmt"
	"math"
	"sort"
)

const MaxFeatures = 32768

type TrainingOptions struct {
	MaxFeatures          int     `json:"max_features,omitempty"`
	Epochs               int     `json:"epochs,omitempty"`
	LearningRate         float64 `json:"learning_rate,omitempty"`
	L2                   float64 `json:"l2,omitempty"`
	MinDocumentFrequency int     `json:"min_document_frequency,omitempty"`
	ClassWeight          string  `json:"class_weight,omitempty"`
}

func resolveOptions(in *TrainingOptions) (TrainingOptions, error) {
	o := TrainingOptions{MaxFeatures: 16384, Epochs: 300, LearningRate: .8, L2: .0005, MinDocumentFrequency: 2, ClassWeight: "balanced"}
	if in != nil {
		if in.MaxFeatures != 0 {
			o.MaxFeatures = in.MaxFeatures
		}
		if in.Epochs != 0 {
			o.Epochs = in.Epochs
		}
		if in.LearningRate != 0 {
			o.LearningRate = in.LearningRate
		}
		if in.L2 != 0 {
			o.L2 = in.L2
		}
		if in.MinDocumentFrequency != 0 {
			o.MinDocumentFrequency = in.MinDocumentFrequency
		}
		if in.ClassWeight != "" {
			o.ClassWeight = in.ClassWeight
		}
	}
	if o.MaxFeatures < 128 || o.MaxFeatures > MaxFeatures || o.Epochs < 10 || o.Epochs > 1000 || !finite(o.LearningRate) || o.LearningRate <= 0 || o.LearningRate > 2 || !finite(o.L2) || o.L2 < 0 || o.L2 > 1 || o.MinDocumentFrequency < 1 || o.MinDocumentFrequency > 10000 || (o.ClassWeight != "balanced" && o.ClassWeight != "none") {
		return o, fmt.Errorf("invalid training options: max_features 128..32768, epochs 10..1000, learning_rate (0,2], l2 [0,1], min_document_frequency 1..10000, class_weight balanced|none")
	}
	return o, nil
}

type featureStats struct {
	labels    [2]int
	groups    int
	lastGroup string
	score     float64
}

func vocabulary(rows []Sample, o TrainingOptions) ([]string, []float64, error) {
	stats := map[string]*featureStats{}
	counts := [2]int{}
	entries := 0
	for _, s := range rows {
		f := extract(s.Input)
		for _, truncated := range f.truncated {
			if truncated {
				return nil, nil, fmt.Errorf("training text exceeds %d tokens in a field", maxTokens)
			}
		}
		counts[s.Label]++
		entries += len(f.terms)
		if entries > 8_000_000 {
			return nil, nil, fmt.Errorf("training feature budget exceeded; shorten texts or split the corpus")
		}
		for key := range f.terms {
			if len(key) > 512 {
				continue
			}
			st := stats[key]
			if st == nil {
				if len(stats) >= 250000 {
					return nil, nil, fmt.Errorf("feature candidate limit: 250000; remove identifiers/noisy text")
				}
				st = &featureStats{}
				stats[key] = st
			}
			st.labels[s.Label]++
			if st.lastGroup != s.Group {
				st.groups++
				st.lastGroup = s.Group
			}
		}
	}
	keys := make([]string, 0, len(stats))
	for key, st := range stats {
		// Project-specific tokens never become learned evidence for other projects.
		if st.labels[0]+st.labels[1] < o.MinDocumentFrequency || st.groups < 2 {
			continue
		}
		a, b := float64(st.labels[1]), float64(st.labels[0])
		c, d := float64(counts[1])-a, float64(counts[0])-b
		denom := (a + b) * (c + d) * (a + c) * (b + d)
		if denom > 0 {
			st.score = float64(len(rows)) * math.Pow(a*d-b*c, 2) / denom
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return nil, nil, fmt.Errorf("no reusable features; need words shared by at least two training projects")
	}
	if len(keys) > o.MaxFeatures {
		sort.Slice(keys, func(i, j int) bool {
			a, b := stats[keys[i]], stats[keys[j]]
			if a.score != b.score {
				return a.score > b.score
			}
			if a.labels[0]+a.labels[1] != b.labels[0]+b.labels[1] {
				return a.labels[0]+a.labels[1] > b.labels[0]+b.labels[1]
			}
			return keys[i] < keys[j]
		})
		keys = keys[:o.MaxFeatures]
	}
	sort.Strings(keys)
	idf := make([]float64, len(keys))
	for i, k := range keys {
		st := stats[k]
		idf[i] = 1 + math.Log((1+float64(len(rows)))/(1+float64(st.labels[0]+st.labels[1])))
	}
	return keys, idf, nil
}

func logisticLoss(z, y float64) float64 {
	return math.Max(z, 0) - y*z + math.Log1p(math.Exp(-math.Abs(z)))
}

func Train(d Dataset) (*Model, error) {
	o, err := resolveOptions(d.Options)
	if err != nil {
		return nil, err
	}
	rows, audit, err := prepareDataset(d)
	if err != nil {
		return nil, err
	}
	sets, groups, err := splitDataset(rows)
	if err != nil {
		return nil, err
	}
	// Reject silent truncation in every split, not only the fit set.
	for _, s := range rows {
		for _, value := range []string{s.Input.State, s.Input.Question, s.Input.TrueWhen, s.Input.FalseWhen} {
			if len(normalizedWords(value)) > maxTokens {
				return nil, fmt.Errorf("training text exceeds %d tokens in a field", maxTokens)
			}
		}
	}
	words, idf, err := vocabulary(sets[0], o)
	if err != nil {
		return nil, err
	}
	m := &Model{Version: Version, TaskID: Task, Synthetic: d.Synthetic, FeatureSchema: FeatureSchema, Dimensions: len(words), Vocabulary: words, IDF: idf, Weights: make([]float64, len(words)), CalibrationA: 1, Options: &o, Provenance: provenance(rows)}
	m.Metrics = Metrics{TrainCount: len(sets[0]), CalibrationCount: len(sets[1]), TestCount: len(sets[2]), TrainGroups: groups[0], CalibrationGroups: groups[1], TestGroups: groups[2], Audit: &audit,
		Note: "Group-stratified fit/calibration/test. Vocabulary, feature selection, IDF and optimization use fit only. Calibration uses separate projects. Metrics describe the supplied corpus, not arbitrary apps."}
	xs := make([]vector, len(sets[0]))
	counts := [2]int{}
	for i, s := range sets[0] {
		xs[i] = m.encode(extract(s.Input))
		counts[s.Label]++
	}
	n := float64(len(xs))
	weights := [2]float64{1, 1}
	if o.ClassWeight == "balanced" {
		weights = [2]float64{n / (2 * float64(counts[0])), n / (2 * float64(counts[1]))}
	} else {
		m.Bias = math.Log(float64(counts[1]) / float64(counts[0]))
	}
	gradient := make([]float64, len(words))
	previous := math.Inf(1)
	stale := 0
	for epoch := 0; epoch < o.Epochs; epoch++ {
		clear(gradient)
		gb, loss := 0.0, 0.0
		for i, s := range sets[0] {
			z := xs[i].dot(m.Weights, m.Bias)
			w := weights[s.Label]
			err := (sigmoid(z) - float64(s.Label)) * w
			gb += err
			loss += logisticLoss(z, float64(s.Label)) * w
			for _, c := range xs[i] {
				gradient[c.index] += err * c.value
			}
		}
		loss /= n
		for _, w := range m.Weights {
			loss += .5 * o.L2 * w * w
		}
		m.Metrics.FitLoss = loss
		m.Metrics.Epochs = epoch + 1
		if previous-loss >= 0 && previous-loss < 1e-7 {
			stale++
		} else {
			stale = 0
		}
		if stale >= 8 && epoch >= 50 {
			break
		}
		previous = loss
		m.Bias -= o.LearningRate * gb / n
		for j, g := range gradient {
			m.Weights[j] -= o.LearningRate * (g/n + o.L2*m.Weights[j])
		}
	}
	zs := make([]float64, len(sets[1]))
	labels := make([]int, len(zs))
	for i, s := range sets[1] {
		zs[i] = m.encode(extract(s.Input)).dot(m.Weights, m.Bias)
		labels[i] = s.Label
	}
	m.CalibrationA, m.CalibrationB = calibrate(zs, labels)
	scores := scoreSamples(sets[2], m)
	holdout := measure(scores, .85)
	m.Metrics.Holdout = &holdout
	m.Metrics.Brier = holdout.Brier
	m.Metrics.Accuracy = holdout.Accuracy
	return m, m.Validate()
}

// Smoothed Platt targets and a damped Newton solve avoid extreme confidence on
// small separable calibration sets. Test labels never participate in this fit.
func calibrate(zs []float64, labels []int) (float64, float64) {
	counts := [2]int{}
	for _, y := range labels {
		counts[y]++
	}
	targets := make([]float64, len(labels))
	for i, y := range labels {
		if y == 1 {
			targets[i] = float64(counts[1]+1) / float64(counts[1]+2)
		} else {
			targets[i] = 1 / float64(counts[0]+2)
		}
	}
	const reg = .001
	n := float64(len(zs))
	a, b := 1.0, 0.0
	loss := func(a, b float64) float64 {
		v := .5 * reg * ((a-1)*(a-1) + b*b)
		for i, z := range zs {
			v += logisticLoss(a*z+b, targets[i]) / n
		}
		return v
	}
	for iter := 0; iter < 60; iter++ {
		ga, gb, haa, hab, hbb := reg*(a-1), reg*b, reg, 0.0, reg
		for i, z := range zs {
			p := sigmoid(a*z + b)
			e := (p - targets[i]) / n
			v := p * (1 - p) / n
			ga += e * z
			gb += e
			haa += v * z * z
			hab += v * z
			hbb += v
		}
		det := haa*hbb - hab*hab
		if det <= 1e-15 || math.Abs(ga)+math.Abs(gb) < 1e-9 {
			break
		}
		da, db := (hbb*ga-hab*gb)/det, (haa*gb-hab*ga)/det
		before := loss(a, b)
		improved := false
		for step := 1.0; step >= 1e-6; step *= .5 {
			na, nb := math.Max(0, math.Min(100, a-step*da)), math.Max(-100, math.Min(100, b-step*db))
			if loss(na, nb) < before {
				a, b = na, nb
				improved = true
				break
			}
		}
		if !improved {
			break
		}
	}
	return a, b
}
