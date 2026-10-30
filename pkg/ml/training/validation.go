package training

import (
	"fmt"
	"math"
	"math/rand"
	"sort"

	"mega-analyzer/pkg/ml"
)

type sample struct {
	ID, Group, Source string
	X                 []float64
	Y                 int
	Weight            float64
}

// SplitInfo records the actual partition sizes, including empty optional folds.
type SplitInfo struct {
	Unit        string `json:"unit"`
	Train       int    `json:"train"`
	Validation  int    `json:"validation"`
	Calibration int    `json:"calibration"`
	Test        int    `json:"test"`
}

// Evaluation contains only independent test-set measurements. Missing human
// labels leave it nil, rather than reporting an unevaluated model as ECE=0.
type Evaluation struct {
	Samples   int     `json:"samples"`
	Positives int     `json:"positives"`
	Negatives int     `json:"negatives"`
	LogLoss   float64 `json:"log_loss"`
	Brier     float64 `json:"brier"`
	ECE       float64 `json:"ece"`
	Accuracy  float64 `json:"accuracy"`
}

// splitSamples keeps groups intact and both classes in every requested fold.
// Sorted group keys and a local RNG make the result independent of map order.
// A bounded search balances row counts; it never falls back to splitting an APK.
func splitSamples(rows []sample, validation, calibration, test float64, seed int64) ([4][]sample, error) {
	var empty [4][]sample
	fractions := [4]float64{1 - validation - calibration - test, validation, calibration, test}
	active := []int{}
	for i, f := range fractions {
		if math.IsNaN(f) || math.IsInf(f, 0) || f < 0 || f > 1 {
			return empty, fmt.Errorf("invalid split fractions")
		}
		if f > 0 {
			active = append(active, i)
		}
	}
	if fractions[0] <= 0 {
		return empty, fmt.Errorf("split leaves no training data")
	}
	groups := map[string][]sample{}
	counts := [2]int{}
	for _, row := range rows {
		if row.Y != 0 && row.Y != 1 {
			return empty, fmt.Errorf("invalid label for %s", row.ID)
		}
		if row.Group == "" {
			return empty, fmt.Errorf("missing source group for %s", row.ID)
		}
		for _, x := range row.X {
			if math.IsNaN(x) || math.IsInf(x, 0) {
				return empty, fmt.Errorf("non-finite features for %s", row.ID)
			}
		}
		groups[row.Group] = append(groups[row.Group], row)
		counts[row.Y]++
	}
	if counts[0] < len(active) || counts[1] < len(active) {
		return empty, fmt.Errorf("need both classes in each of %d partitions: positives=%d negatives=%d", len(active), counts[1], counts[0])
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) < len(active) {
		return empty, fmt.Errorf("need at least %d independent source groups, have %d", len(active), len(keys))
	}
	for _, k := range keys {
		sort.Slice(groups[k], func(i, j int) bool { return groups[k][i].ID < groups[k][j].ID })
	}
	sizes := [4]int{}
	remaining := len(keys)
	for _, i := range active[1:] {
		sizes[i] = max(1, int(math.Round(fractions[i]*float64(len(keys)))))
		remaining -= sizes[i]
	}
	for remaining < 1 {
		largest := -1
		for _, i := range active[1:] {
			if sizes[i] > 1 && (largest < 0 || sizes[i] > sizes[largest]) {
				largest = i
			}
		}
		if largest < 0 {
			return empty, fmt.Errorf("too few groups for split")
		}
		sizes[largest]--
		remaining++
	}
	sizes[0] = remaining
	rng := rand.New(rand.NewSource(seed))
	bestCost := math.Inf(1)
	best := empty
	for attempt := 0; attempt < 512; attempt++ {
		order := append([]string(nil), keys...)
		rng.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
		var candidate [4][]sample
		at, cost, valid := 0, 0.0, true
		for _, fold := range active {
			var c [2]int
			for _, key := range order[at : at+sizes[fold]] {
				candidate[fold] = append(candidate[fold], groups[key]...)
				for _, row := range groups[key] {
					c[row.Y]++
				}
			}
			at += sizes[fold]
			if c[0] == 0 || c[1] == 0 {
				valid = false
				break
			}
			for label := range c {
				cost += math.Abs(float64(c[label])/float64(counts[label]) - fractions[fold])
			}
		}
		if valid && cost < bestCost {
			best, bestCost = candidate, cost
		}
		if bestCost < 1e-12 {
			break
		}
	}
	if math.IsInf(bestCost, 1) {
		return empty, fmt.Errorf("cannot keep both classes in independent partitions; collect more labeled source groups")
	}
	return best, nil
}

func splitInfo(folds [4][]sample, unit string) SplitInfo {
	return SplitInfo{unit, len(folds[0]), len(folds[1]), len(folds[2]), len(folds[3])}
}

type probabilityModel interface {
	PredictProbability([]float64) (float64, error)
}
type probabilityFunc func([]float64) (float64, error)

func evaluateRows(rows []sample, predict probabilityFunc) (*Evaluation, error) {
	if len(rows) == 0 {
		return nil, nil
	}
	e := &Evaluation{Samples: len(rows)}
	probs, labels := make([]float64, len(rows)), make([]int, len(rows))
	for i, row := range rows {
		p, err := predict(row.X)
		if err != nil {
			return nil, err
		}
		if math.IsNaN(p) || p < 0 || p > 1 {
			return nil, fmt.Errorf("invalid prediction for %s", row.ID)
		}
		probs[i], labels[i] = p, row.Y
		if row.Y == 1 {
			e.Positives++
		} else {
			e.Negatives++
		}
		if (p >= .5) == (row.Y == 1) {
			e.Accuracy++
		}
		d := p - float64(row.Y)
		e.Brier += d * d
		p = math.Max(1e-12, math.Min(1-1e-12, p))
		e.LogLoss -= float64(row.Y)*math.Log(p) + (1-float64(row.Y))*math.Log(1-p)
	}
	e.Accuracy /= float64(e.Samples)
	e.Brier /= float64(e.Samples)
	e.LogLoss /= float64(e.Samples)
	e.ECE, _ = ml.ExpectedCalibrationError(probs, labels, 10)
	return e, nil
}

func calibratedPredict(model probabilityModel, fitted bool, a, b float64) probabilityFunc {
	return func(x []float64) (float64, error) {
		p, err := model.PredictProbability(x)
		if err == nil && fitted {
			p = sigmoid(a*p + b)
		}
		return p, err
	}
}

func fitCalibration(rows []sample, model probabilityModel) (bool, float64, float64, error) {
	if len(rows) == 0 {
		return false, 0, 0, nil
	}
	probs, labels := make([]float64, len(rows)), make([]int, len(rows))
	for i, row := range rows {
		p, err := model.PredictProbability(row.X)
		if err != nil {
			return false, 0, 0, err
		}
		probs[i], labels[i] = p, row.Y
	}
	c := ml.NewPlattCalibrator()
	if err := c.Fit(probs, labels); err != nil {
		return false, 0, 0, err
	}
	a, b := c.Coefficients()
	return true, a, b, nil
}

func matricesFor(rows []sample) ([][]float64, []int, []float64) {
	x, y, w := make([][]float64, len(rows)), make([]int, len(rows)), make([]float64, len(rows))
	for i, row := range rows {
		x[i], y[i], w[i] = row.X, row.Y, row.Weight
	}
	return x, y, w
}

func hardRows(rows []sample) []sample {
	var out []sample
	for _, row := range rows {
		if row.Source == "hard" {
			out = append(out, row)
		}
	}
	return out
}

func trainingPrior(rows []sample) float64 {
	var pos float64
	for _, row := range rows {
		pos += float64(row.Y)
	}
	return pos / float64(len(rows))
}

// Promotion requires a useful human-labeled test set and no regression against
// either the training-prior baseline or the currently installed model.
func checkPromotion(candidate, baseline, current *Evaluation) error {
	if candidate == nil || candidate.Samples < 20 || candidate.Positives < 5 || candidate.Negatives < 5 {
		return fmt.Errorf("model not promoted: need at least 20 independent human-labeled test samples including 5 of each class")
	}
	for name, reference := range map[string]*Evaluation{"prior baseline": baseline, "installed model": current} {
		if reference == nil {
			continue
		}
		if candidate.LogLoss > reference.LogLoss+1e-9 || candidate.Brier > reference.Brier+1e-9 || candidate.Accuracy+1e-9 < reference.Accuracy {
			return fmt.Errorf("model not promoted: test quality regressed against %s (log-loss %.4f vs %.4f, Brier %.4f vs %.4f)", name, candidate.LogLoss, reference.LogLoss, candidate.Brier, reference.Brier)
		}
	}
	return nil
}
