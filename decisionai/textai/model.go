package textai

import (
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"strings"
)

type Sample struct {
	Group string  `json:"group"`
	Label int     `json:"label"`
	Input Request `json:"input"`
}
type Dataset struct {
	TaskID    string           `json:"task_id"`
	Synthetic bool             `json:"synthetic"`
	Options   *TrainingOptions `json:"options,omitempty"`
	Samples   []Sample         `json:"samples"`
}
type Metrics struct {
	TrainCount        int                `json:"train_count"`
	CalibrationCount  int                `json:"calibration_count"`
	TestCount         int                `json:"test_count"`
	TrainGroups       int                `json:"train_groups,omitempty"`
	CalibrationGroups int                `json:"calibration_groups,omitempty"`
	TestGroups        int                `json:"test_groups,omitempty"`
	Brier             float64            `json:"test_brier"`
	Accuracy          float64            `json:"test_accuracy_at_0_5"`
	Epochs            int                `json:"epochs_run,omitempty"`
	FitLoss           float64            `json:"fit_loss,omitempty"`
	Audit             *DatasetAudit      `json:"dataset,omitempty"`
	Holdout           *EvaluationMetrics `json:"holdout,omitempty"`
	Note              string             `json:"note"`
}
type Provenance struct {
	DatasetSHA256 string   `json:"dataset_sha256"`
	GroupHashes   []string `json:"group_hashes"`
	SampleHashes  []string `json:"sample_hashes"`
}
type Model struct {
	Version       string           `json:"version"`
	TaskID        string           `json:"task_id"`
	Synthetic     bool             `json:"synthetic"`
	FeatureSchema string           `json:"feature_schema,omitempty"`
	Dimensions    int              `json:"dimensions"`
	Weights       []float64        `json:"weights"`
	IDF           []float64        `json:"idf"`
	Vocabulary    []string         `json:"vocabulary"`
	Bias          float64          `json:"bias"`
	CalibrationA  float64          `json:"calibration_a"`
	CalibrationB  float64          `json:"calibration_b"`
	Options       *TrainingOptions `json:"training_options,omitempty"`
	Provenance    *Provenance      `json:"provenance,omitempty"`
	Metrics       Metrics          `json:"metrics"`
}

func unit(v float64) bool { return finite(v) && v >= 0 && v <= 1 }
func validHashes(xs []string) bool {
	if !sort.StringsAreSorted(xs) {
		return false
	}
	for i, s := range xs {
		b, err := hex.DecodeString(s)
		if err != nil || len(b) != 32 || strings.ToLower(s) != s || (i > 0 && xs[i-1] == s) {
			return false
		}
	}
	return true
}
func (m *Model) Validate() error {
	if m == nil || (m.Version != Version && m.Version != LegacyVersion) || m.TaskID != Task {
		return fmt.Errorf("text model version/task mismatch")
	}
	if m.Dimensions < 1 || m.Dimensions > MaxFeatures || len(m.Weights) != m.Dimensions || len(m.IDF) != m.Dimensions || len(m.Vocabulary) == 0 {
		return fmt.Errorf("text model dimensions mismatch")
	}
	if m.Version == LegacyVersion {
		if m.Dimensions != Dims || len(m.Vocabulary) > 20000 || m.FeatureSchema != "" {
			return fmt.Errorf("legacy text model schema mismatch")
		}
	} else {
		// v1 models stay readable: v2 extraction only adds match_* terms, which
		// encode() skips as unknown, so a v1 model predicts bit-identically.
		if (m.FeatureSchema != FeatureSchema && m.FeatureSchema != FeatureSchemaV1) || m.Dimensions != len(m.Vocabulary) || m.Options == nil || m.Provenance == nil {
			return fmt.Errorf("text feature schema/options/provenance mismatch")
		}
		if _, err := resolveOptions(m.Options); err != nil {
			return err
		}
		p := m.Provenance
		if !validHashes([]string{p.DatasetSHA256}) || len(p.GroupHashes) < 10 || len(p.GroupHashes) > 10000 || !validHashes(p.GroupHashes) || len(p.SampleHashes) != m.Metrics.TrainCount+m.Metrics.CalibrationCount+m.Metrics.TestCount || !validHashes(p.SampleHashes) {
			return fmt.Errorf("invalid training provenance")
		}
		if m.Metrics.Holdout == nil || m.Metrics.Holdout.Count != m.Metrics.TestCount || !m.Metrics.Holdout.valid() || math.Abs(m.Metrics.Holdout.Brier-m.Metrics.Brier) > 1e-12 || math.Abs(m.Metrics.Holdout.Accuracy-m.Metrics.Accuracy) > 1e-12 || !finite(m.Metrics.FitLoss) || m.Metrics.FitLoss < 0 {
			return fmt.Errorf("invalid holdout metrics")
		}
	}
	for i, v := range m.Weights {
		if !finite(v) || math.Abs(v) > 1e6 || !finite(m.IDF[i]) || m.IDF[i] < 1 || m.IDF[i] > 20 {
			return fmt.Errorf("invalid model weights/idf")
		}
	}
	if !finite(m.Bias) || math.Abs(m.Bias) > 1e6 || !finite(m.CalibrationA) || !finite(m.CalibrationB) || math.Abs(m.CalibrationB) > 1e6 || m.CalibrationA < 0 || m.CalibrationA > 100 || m.Metrics.TrainCount < 40 || m.Metrics.CalibrationCount < 20 || m.Metrics.TestCount < 20 || !unit(m.Metrics.Brier) || !unit(m.Metrics.Accuracy) {
		return fmt.Errorf("invalid calibration/metrics")
	}
	if !sort.StringsAreSorted(m.Vocabulary) {
		return fmt.Errorf("vocabulary must be sorted")
	}
	for i, v := range m.Vocabulary {
		if len(v) > 512 || v == "" || (i > 0 && v == m.Vocabulary[i-1]) {
			return fmt.Errorf("invalid vocabulary")
		}
		if m.Version == Version {
			parts := strings.SplitN(v, ":", 3)
			if len(parts) != 3 || parts[2] == "" || !contains(fieldNames, parts[0]) || !contains([]string{"w", "b", "t", "c"}, parts[1]) {
				return fmt.Errorf("invalid feature name")
			}
		}
	}
	return nil
}
func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
func stringsBigram(k string) bool { return strings.ContainsRune(k, ' ') }

func (m *Model) predict(r Request) float64 {
	if m.Version == LegacyVersion {
		return sigmoid(m.CalibrationA*dot(m.Weights, weighted(raw(terms(r)), m.IDF), m.Bias) + m.CalibrationB)
	}
	return sigmoid(m.CalibrationA*m.encode(extract(r)).dot(m.Weights, m.Bias) + m.CalibrationB)
}
func (m *Model) Predict(r Request) Prediction {
	if m.Version != LegacyVersion {
		return m.predictV3(r)
	}
	ts := terms(r)
	coverage := 1.0
	fields := []FieldCoverage{}
	for _, name := range fieldNames {
		field := FieldCoverage{Field: name}
		for k := range ts {
			if stringsBigram(k) || !strings.HasPrefix(k, name+":") {
				continue
			}
			field.Tokens++
			if m.known(k) {
				field.Known++
			}
		}
		if field.Tokens > 0 {
			field.Coverage = float64(field.Known) / float64(field.Tokens)
		}
		field.Support = field.Coverage
		coverage = math.Min(coverage, field.Coverage)
		fields = append(fields, field)
	}
	x := weighted(raw(ts), m.IDF)
	z := m.CalibrationA*dot(m.Weights, x, m.Bias) + m.CalibrationB
	p := Prediction{Value: sigmoid(z), Kind: "heldout_calibrated_text_estimate", Coverage: coverage, Support: coverage, Fields: fields,
		Logit: z, Intercept: m.CalibrationA*m.Bias + m.CalibrationB, Contributions: contributions(ts, x, m),
		Notes: []string{"Совместимая модель v0.2 с хешированными признаками. Для нового извлекателя нужно переобучение.", "Оценка модели не является результатом исполнения кода."}}
	p.Entropy = entropy(p.Value)
	p.OtherContribution = z - p.Intercept
	for _, c := range p.Contributions {
		p.OtherContribution -= c.Contribution
	}
	if m.Synthetic {
		p.Kind = "synthetic_demo_estimate"
		p.Notes = append(p.Notes, "Модель обучена на синтетических шаблонах; реальная точность неизвестна.")
	}
	return p
}
