package ml

import (
	"errors"
	"fmt"
	"math"
	"math/rand"
)

// ═══════════════════════════════════════════════════════════════════════════
// KNOWLEDGE DISTILLATION — compress a heavy GBT into a light LR
// ═══════════════════════════════════════════════════════════════════════════
//
// Production scoring path doesn't always have time to traverse 200 trees per
// finding. Knowledge distillation produces a tiny "student" logistic
// regression that imitates a "teacher" GBT closely enough for the same
// downstream decisions, but scores in nanoseconds and weighs ~1KB.
//
// The recipe:
//
//   1. Generate synthetic feature vectors that span the input space the
//      teacher saw at training time (sample around training points + Gaussian
//      jitter).
//   2. Score every synthetic vector with the teacher to get continuous
//      log-odds targets.
//   3. Fit a regression LR on those continuous targets (we cheat slightly:
//      LR's binary cross-entropy stays well-defined for fractional labels,
//      so we feed teacher probabilities directly).
//
// Trade-off: the student loses non-linear interactions the teacher captured
// inside trees. On well-separated data the gap is tiny; on XOR-like
// distributions the student degrades visibly. Always evaluate both before
// deploying the student.

// DistillationConfig pins synthetic-data generation knobs.
type DistillationConfig struct {
	// SyntheticSamples is how many extra examples to generate by perturbing
	// the training pool. Larger = better student, slower distillation.
	SyntheticSamples int
	// JitterStd controls per-feature Gaussian perturbation scale (in units
	// of the training feature's std-dev). 0.1 covers local interactions
	// nicely without wandering off-distribution.
	JitterStd float64
	// Seed pins randomness for reproducibility (0 = non-deterministic).
	Seed int64
	// MinFidelity is the minimum teacher-decision agreement the student
	// must reach on the distillation rows (0 = default 0.9). Below it
	// Distill fails instead of shipping a student that silently lost the
	// teacher's nonlinear concepts.
	MinFidelity float64
}

// DefaultDistillationConfig: 10x synthetic blow-up, mild jitter.
func DefaultDistillationConfig() DistillationConfig {
	return DistillationConfig{
		SyntheticSamples: 10_000,
		JitterStd:        0.1,
		Seed:             0,
		MinFidelity:      0.9,
	}
}

// Distill trains a logistic-regression student that mimics the GBT teacher
// on the input distribution implied by `Xtrain`. Returns the fitted student.
//
// The teacher is queried for *probabilities*; the student is trained to
// match them via continuous-target binary cross-entropy. We keep the
// student's epoch / regularisation defaults loose so the student doesn't
// underfit complex teachers.
func Distill(teacher *GradientBoostingClassifier, Xtrain [][]float64, featureNames []string, cfg DistillationConfig) (*LogisticRegression, error) {
	if !teacher.trained {
		return nil, errors.New("distill: teacher is not trained")
	}
	if len(Xtrain) == 0 {
		return nil, errors.New("distill: empty Xtrain")
	}

	if cfg.SyntheticSamples == 0 {
		cfg.SyntheticSamples = 10_000
	}
	if cfg.JitterStd == 0 {
		cfg.JitterStd = 0.1
	}

	seed := cfg.Seed
	if seed == 0 {
		seed = rand.Int63()
	}
	rng := rand.New(rand.NewSource(seed))

	// Per-feature std-dev across Xtrain — used to scale the jitter so a
	// "size_in_bytes" feature with std 1e6 doesn't get the same noise as a
	// "is_packed" boolean.
	nFeat := len(Xtrain[0])
	stds := perFeatureStd(Xtrain)

	// Synthetic dataset = original + jittered copies sampled around each
	// row. We sample-with-replacement from Xtrain to keep distribution
	// roughly matching, then add gaussian noise.
	totalN := len(Xtrain) + cfg.SyntheticSamples
	X := make([][]float64, totalN)
	yProb := make([]float64, totalN)

	copy(X, Xtrain)
	for i := 0; i < cfg.SyntheticSamples; i++ {
		base := Xtrain[rng.Intn(len(Xtrain))]
		row := make([]float64, nFeat)
		for j, x := range base {
			row[j] = x + cfg.JitterStd*stds[j]*rng.NormFloat64()
		}
		X[len(Xtrain)+i] = row
	}

	for i, row := range X {
		p, err := teacher.PredictProbability(row)
		if err != nil {
			return nil, err
		}
		yProb[i] = p
	}

	// LR on continuous targets: we use yProb directly. Internally Fit
	// expects int labels, so we feed thresholded labels and rely on
	// SoftLabelLogisticRegression below for the soft-target path.
	student := NewSoftLabelLogisticRegression(0.1, 500, 0.001)
	if err := student.FitSoft(X, yProb, featureNames); err != nil {
		return nil, err
	}

	// Fidelity gate: the student must reproduce the teacher's decisions on
	// the distillation rows. A linear student cannot represent nonlinear
	// teacher concepts (measured: teacher 0.995 accuracy, student 0.60 with
	// 0 recall on an interval concept) — shipping that silently is a
	// dishonest artifact, so Distill fails loudly instead.
	minFid := cfg.MinFidelity
	if minFid == 0 {
		minFid = 0.9
	}
	agree := 0
	for i, row := range X {
		ps, err := student.PredictProbability(row)
		if err != nil {
			return nil, err
		}
		if (ps >= 0.5) == (yProb[i] >= 0.5) {
			agree++
		}
	}
	if fidelity := float64(agree) / float64(len(X)); fidelity < minFid {
		return nil, fmt.Errorf("distill: student reproduces the teacher on only %.3f of %d rows (< %.2f): the concept is nonlinear beyond logistic capacity, keep the teacher or add features",
			fidelity, len(X), minFid)
	}
	return student.LogisticRegression, nil
}

// SoftLabelLogisticRegression is a thin wrapper around LogisticRegression
// that supports continuous targets (probabilities) instead of {0,1}.
//
// The mathematics is unchanged — binary cross-entropy with a soft target
// `t` minimises against `t * log(p) + (1-t) * log(1-p)`. The gradient
// formula `(pred - t)` is identical to the binary case, so we override Fit
// to bypass the integer-label path.
type SoftLabelLogisticRegression struct {
	*LogisticRegression
}

// NewSoftLabelLogisticRegression returns the wrapper.
func NewSoftLabelLogisticRegression(lr float64, epochs int, lambda float64) *SoftLabelLogisticRegression {
	return &SoftLabelLogisticRegression{
		LogisticRegression: NewLogisticRegression(lr, epochs, lambda),
	}
}

// FitSoft trains on continuous targets in [0, 1].
func (s *SoftLabelLogisticRegression) FitSoft(X [][]float64, t []float64, featureNames []string) error {
	if len(X) != len(t) {
		return errors.New("soft_lr: length mismatch")
	}
	if len(X) == 0 {
		return errors.New("soft_lr: empty input")
	}

	nFeatures := len(X[0])
	s.weights = make([]float64, nFeatures)
	s.bias = 0
	s.featureNames = featureNames
	s.trained = false

	m := len(X)
	for epoch := 0; epoch < s.epochs; epoch++ {
		dw := make([]float64, nFeatures)
		db := 0.0
		for i := 0; i < m; i++ {
			z := s.bias
			for j := 0; j < nFeatures; j++ {
				z += s.weights[j] * X[i][j]
			}
			pred := sigmoid(z)
			err := pred - t[i] // soft-target gradient
			for j := 0; j < nFeatures; j++ {
				dw[j] += err * X[i][j]
			}
			db += err
		}
		for j := 0; j < nFeatures; j++ {
			s.weights[j] -= s.learningRate * (dw[j]/float64(m) + s.lambda*s.weights[j])
		}
		s.bias -= s.learningRate * db / float64(m)
	}
	s.trained = true
	s.LastEpochs = s.epochs
	return nil
}

func perFeatureStd(X [][]float64) []float64 {
	if len(X) == 0 {
		return nil
	}
	nFeat := len(X[0])
	mean := make([]float64, nFeat)
	for _, row := range X {
		// Guard against jagged input: a row longer than X[0] would index
		// past nFeat and panic. Only fold in the columns we sized for.
		n := len(row)
		if n > nFeat {
			n = nFeat
		}
		for j := 0; j < n; j++ {
			mean[j] += row[j]
		}
	}
	for j := range mean {
		mean[j] /= float64(len(X))
	}
	std := make([]float64, nFeat)
	for _, row := range X {
		n := len(row)
		if n > nFeat {
			n = nFeat
		}
		for j := 0; j < n; j++ {
			d := row[j] - mean[j]
			std[j] += d * d
		}
	}
	for j := range std {
		std[j] /= float64(len(X))
		if std[j] > 0 {
			std[j] = math.Sqrt(std[j])
		} else {
			std[j] = 1 // avoid zero scale
		}
	}
	return std
}
