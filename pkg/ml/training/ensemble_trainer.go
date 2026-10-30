package training

import (
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"time"

	"mega-analyzer/pkg/ml"
	"mega-analyzer/pkg/ml/ensemble"
)

const (
	// EnsembleModelVersion is bumped when the on-disk format or feature contract changes incompatibly.
	EnsembleModelVersion  = 1
	ensembleModelFileName = "ensemble_risk.json"
)

// DefaultEnsembleModelPath returns ~/.analyzer/models/ensemble_risk.json.
func DefaultEnsembleModelPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ml.DefaultHistoryDir, "models", ensembleModelFileName), nil
}

// EnsembleLabeledSample is one training example extracted from analysis feedback user overrides.
type EnsembleLabeledSample struct {
	Features []float64
	Label    int     // 1 = relevant, 0 = noise
	Weight   float64 // sample weight
	Group    string  // APK/project leakage unit the override came from
}

// EnsembleLabelStats summarises what ExtractEnsembleSamples produced.
type EnsembleLabelStats struct {
	TotalOverrides int
	LabeledSamples int
	Positives      int
	Negatives      int
	// Groups is the number of distinct APK/project groups; GroupSplit
	// reports whether the train/calib split was group-wise.
	Groups     int
	GroupSplit bool
}

// EnsembleTrainOptions configures TrainEnsemble.
type EnsembleTrainOptions struct {
	MinSamples      int     // abort below this many labeled rows
	MinPerClass     int     // abort when either class has fewer labeled rows (0 = default 3)
	CalibFraction   float64 // hold-out fraction for Platt calibration
	MinCalibSamples int     // Platt calibration needs at least this many hold-out rows (0 = package default)
	Seed            int64   // deterministic shuffle seed
}

// DefaultEnsembleTrainOptions returns tuned defaults for ensemble training.
//
// MinSamples is deliberately higher than the historical 10: a GBT distilled
// into logistic regression trained on a handful of overrides memorises them,
// and per-class minimums keep a degenerate one-sided corpus from training at
// all. Calibration and ECE are skipped below MinCalibSamples — a 2-sample
// Platt fit is noise, not calibration.
func DefaultEnsembleTrainOptions() EnsembleTrainOptions {
	return EnsembleTrainOptions{
		MinSamples:      20,
		MinPerClass:     3,
		CalibFraction:   0.2,
		MinCalibSamples: MinCalibSamples,
		Seed:            1,
	}
}

// EnsembleSavedModel is the serializable ensemble model artifact written to disk.
type EnsembleSavedModel struct {
	Version       int                        `json:"version"`
	TrainedAt     time.Time                  `json:"trained_at"`
	SampleCount   int                        `json:"sample_count"`
	Positives     int                        `json:"positives"`
	Negatives     int                        `json:"negatives"`
	FeatureNames  []string                   `json:"feature_names"`
	ScalerMeans   []float64                  `json:"scaler_means"`
	ScalerStdDevs []float64                  `json:"scaler_std_devs"`
	LRWeights     []float64                  `json:"lr_weights"`
	LRBias        float64                    `json:"lr_bias"`
	CalibFitted   bool                       `json:"calib_fitted"`
	CalibA        float64                    `json:"calib_a"`
	CalibB        float64                    `json:"calib_b"`
	Groups        int                        `json:"groups"`
	GroupSplit    bool                       `json:"group_split"`
	ECE           float64                    `json:"ece"`
	ECESamples    int                        `json:"ece_samples"`
	ECELow        float64                    `json:"ece_low,omitempty"`
	ECEHigh       float64                    `json:"ece_high,omitempty"`
	ECEReliable   bool                       `json:"ece_reliable"`
	DriftBins     map[string]*ml.FeatureBins `json:"drift_bins,omitempty"`
}

// ExtractEnsembleSamples extracts labeled samples from user overrides with features.
// Each sample records its APK group so the trainer can split without leakage.
func ExtractEnsembleSamples(records []*ml.AnalysisFeedback) ([]EnsembleLabeledSample, EnsembleLabelStats) {
	var st EnsembleLabelStats
	var samples []EnsembleLabeledSample
	groups := make(map[string]bool)
	for _, r := range records {
		if r == nil {
			continue
		}
		st.TotalOverrides += len(r.UserOverrides)
	}

	for _, override := range ml.ResolveTrainingUserOverrides(records) {
		if override.Features == nil {
			continue
		}
		var label int
		switch override.Action {
		case ml.FeedbackRelevant:
			label = 1
		case ml.FeedbackNoise:
			label = 0
		default:
			continue
		}
		group := ml.NormalizeFeedbackTarget(override.APKName)
		groups[group] = true
		st.LabeledSamples++
		if label == 1 {
			st.Positives++
		} else {
			st.Negatives++
		}
		samples = append(samples, EnsembleLabeledSample{
			Features: override.Features.Flatten(),
			Label:    label,
			Weight:   1.0,
			Group:    group,
		})
	}
	st.Groups = len(groups)
	return samples, st
}

// TrainEnsemble fits the ensemble risk model (StandardScaler -> GBT -> Distill to LR -> Platt Calibration).
//
// The train/calibration split is group-wise by APK/project: overrides from
// one application never straddle the split, so repeated scans or many
// methods of the same APK cannot leak into calibration. With a single group
// the split degenerates to sample-level — there is no cross-APK leakage to
// prevent there, and calibration still needs a hold-out.
func TrainEnsemble(records []*ml.AnalysisFeedback, opts EnsembleTrainOptions) (*EnsembleSavedModel, EnsembleLabelStats, error) {
	if opts.MinPerClass <= 0 {
		opts.MinPerClass = 3
	}
	if opts.MinCalibSamples <= 0 {
		opts.MinCalibSamples = MinCalibSamples
	}

	samples, st := ExtractEnsembleSamples(records)
	if len(samples) < opts.MinSamples {
		return nil, st, fmt.Errorf("insufficient ensemble training data: have %d samples, need at least %d (use --mark-relevant/--mark-noise)", len(samples), opts.MinSamples)
	}
	if opts.MinPerClass > 0 && (st.Positives < opts.MinPerClass || st.Negatives < opts.MinPerClass) {
		return nil, st, fmt.Errorf("per-class minimum not met: positives=%d negatives=%d, need >= %d per class", st.Positives, st.Negatives, opts.MinPerClass)
	}

	// ── Group-wise split by APK/project ──
	groupKeys := make([]string, 0, st.Groups)
	groupSeen := make(map[string]bool, st.Groups)
	groupSamples := make(map[string][]EnsembleLabeledSample, st.Groups)
	for _, s := range samples {
		if !groupSeen[s.Group] {
			groupSeen[s.Group] = true
			groupKeys = append(groupKeys, s.Group)
		}
		groupSamples[s.Group] = append(groupSamples[s.Group], s)
	}
	sort.Strings(groupKeys)

	var trainSamples, calibSamples []EnsembleLabeledSample
	if len(groupKeys) >= 2 {
		rng := rand.New(rand.NewSource(opts.Seed))
		rng.Shuffle(len(groupKeys), func(i, j int) { groupKeys[i], groupKeys[j] = groupKeys[j], groupKeys[i] })
		nCalibGroups := int(float64(len(groupKeys)) * opts.CalibFraction)
		if nCalibGroups < 1 {
			nCalibGroups = 1
		}
		if nCalibGroups > len(groupKeys)-1 {
			nCalibGroups = len(groupKeys) - 1
		}
		for i, k := range groupKeys {
			if i < nCalibGroups {
				calibSamples = append(calibSamples, groupSamples[k]...)
			} else {
				trainSamples = append(trainSamples, groupSamples[k]...)
			}
		}
		st.GroupSplit = true
	}

	// Single-group fallback: hold out individual samples.
	if len(trainSamples) == 0 || len(calibSamples) == 0 {
		rng := rand.New(rand.NewSource(opts.Seed))
		rng.Shuffle(len(samples), func(i, j int) { samples[i], samples[j] = samples[j], samples[i] })
		nCalib := int(math.Round(float64(len(samples)) * opts.CalibFraction))
		if nCalib > len(samples)-2 {
			nCalib = len(samples) - 2
		}
		if nCalib < 0 {
			nCalib = 0
		}
		calibSamples = samples[:nCalib]
		trainSamples = samples[nCalib:]
		st.GroupSplit = false
	}

	var trainPos, trainNeg int
	for _, s := range trainSamples {
		if s.Label == 1 {
			trainPos++
		} else {
			trainNeg++
		}
	}
	if trainPos == 0 || trainNeg == 0 {
		return nil, st, fmt.Errorf("training split lost a class: train positives=%d negatives=%d", trainPos, trainNeg)
	}

	// Prepare matrices for trainSamples
	Xtrain := make([][]float64, len(trainSamples))
	ytrain := make([]int, len(trainSamples))
	for i, sm := range trainSamples {
		Xtrain[i] = sm.Features
		ytrain[i] = sm.Label
	}

	// 1. Fit StandardScaler on Xtrain
	scaler := ml.NewStandardScaler()
	scaler.Fit(Xtrain)
	Xscaled := scaler.TransformBatch(Xtrain)

	// 2. Fit GBT
	gbt := ml.DefaultGradientBoosting()
	gbt.Seed = opts.Seed
	if err := gbt.Fit(Xscaled, ytrain, ensemble.FeatureNames); err != nil {
		return nil, st, fmt.Errorf("gbt fit: %w", err)
	}

	// 3. Distill GBT into LogisticRegression (seeded: an unseeded
	// distillation made same-seed retrains diverge by ~0.04 in probability).
	distillCfg := ml.DefaultDistillationConfig()
	distillCfg.Seed = opts.Seed
	lr, err := ml.Distill(gbt, Xscaled, ensemble.FeatureNames, distillCfg)
	if err != nil {
		return nil, st, fmt.Errorf("distill gbt: %w", err)
	}

	sw := lr.SaveWeights()
	weights, _ := sw["weights"].([]float64)
	bias, _ := sw["bias"].(float64)

	model := &EnsembleSavedModel{
		Version:       EnsembleModelVersion,
		TrainedAt:     time.Now(),
		SampleCount:   len(trainSamples) + len(calibSamples),
		Positives:     st.Positives,
		Negatives:     st.Negatives,
		FeatureNames:  append([]string(nil), ensemble.FeatureNames...),
		ScalerMeans:   scaler.Means,
		ScalerStdDevs: scaler.StdDevs,
		LRWeights:     weights,
		LRBias:        bias,
		Groups:        st.Groups,
		GroupSplit:    st.GroupSplit,
	}

	// 4. Calibration on the group-held-out set (needs both classes and
	// enough rows — a 2-sample Platt fit is statistical noise).
	var calibProbs []float64
	var calibLabels []int
	var calibPos, calibNeg int
	for _, s := range calibSamples {
		xTrans := scaler.Transform(s.Features)
		p, err := lr.Predict(xTrans)
		if err != nil {
			continue
		}
		calibProbs = append(calibProbs, p)
		calibLabels = append(calibLabels, s.Label)
		if s.Label == 1 {
			calibPos++
		} else {
			calibNeg++
		}
	}
	if len(calibProbs) >= opts.MinCalibSamples && calibPos > 0 && calibNeg > 0 {
		platt := ml.NewPlattCalibrator()
		if err := platt.Fit(calibProbs, calibLabels); err == nil {
			a, b := platt.Coefficients()
			model.CalibA, model.CalibB, model.CalibFitted = a, b, true
			// ECE over the SERVED (Platt-scaled) distribution: the scorer
			// applies CalibA/CalibB before reporting, so raw-probability ECE
			// understates the served error. (Ensemble labels are human
			// overrides by construction, so no pseudo-only caveat applies
			// here — unlike the keyword trainer.)
			served := make([]float64, len(calibProbs))
			for i, p := range calibProbs {
				served[i] = sigmoid(a*p + b)
			}
			ecal, err := ml.BootstrapECE(served, calibLabels, 10, bootstrapReplicates, opts.Seed)
			if err == nil {
				model.ECE = ecal.ECE
				model.ECESamples = ecal.Samples
				model.ECELow, model.ECEHigh = ecal.Lower, ecal.Upper
				model.ECEReliable = ecal.Samples >= ECEReliableMinSamples
			}
		}
	}

	// 5. Drift bins (training rows only — calibration rows must not shape
	// the reference distribution either)
	model.DriftBins = buildEnsembleDriftBins(trainSamples)
	return model, st, nil
}

func buildEnsembleDriftBins(samples []EnsembleLabeledSample) map[string]*ml.FeatureBins {
	const nBins = 5
	if len(samples) < nBins {
		return nil
	}
	out := make(map[string]*ml.FeatureBins, len(ensemble.FeatureNames))
	for fi, name := range ensemble.FeatureNames {
		vals := make([]float64, len(samples))
		for i, s := range samples {
			if fi < len(s.Features) {
				vals[i] = s.Features[fi]
			}
		}
		bins, err := ml.BuildFeatureBins(vals, nBins)
		if err != nil {
			continue
		}
		for i, e := range bins.Edges {
			if math.IsInf(e, -1) {
				bins.Edges[i] = -finiteInf
			} else if math.IsInf(e, 1) {
				bins.Edges[i] = finiteInf
			}
		}
		out[name] = bins
	}
	return out
}

// SaveEnsembleModel writes the model atomically (temp file + rename) with mode 0644.
func SaveEnsembleModel(m *EnsembleSavedModel, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("ensemble model mkdir: %w", err)
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("ensemble model marshal: %w", err)
	}
	tmp := fmt.Sprintf("%s.%d.tmp", path, time.Now().UnixNano())
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return fmt.Errorf("ensemble model write: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("ensemble model rename: %w", err)
	}
	return nil
}

// LoadEnsembleModel reads and validates an EnsembleSavedModel. It returns (nil, nil) when the
// file does not exist, so callers can treat "no model" as the default.
func LoadEnsembleModel(path string) (*EnsembleSavedModel, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var m EnsembleSavedModel
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("corrupt ensemble model file: %w", err)
	}
	if m.Version != EnsembleModelVersion {
		return nil, fmt.Errorf("ensemble model version mismatch: file=%d want=%d", m.Version, EnsembleModelVersion)
	}
	if len(m.LRWeights) != len(ensemble.FeatureNames) {
		return nil, fmt.Errorf("ensemble model feature count mismatch: %d weights vs %d features", len(m.LRWeights), len(ensemble.FeatureNames))
	}
	return &m, nil
}
