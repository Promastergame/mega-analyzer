package textai

import (
	"fmt"
	"math"
	"sort"
)

type Confusion struct {
	TruePositive  int `json:"true_positive"`
	FalsePositive int `json:"false_positive"`
	TrueNegative  int `json:"true_negative"`
	FalseNegative int `json:"false_negative"`
}
type OperatingPoint struct {
	Threshold    float64 `json:"threshold"`
	Answered     int     `json:"answered"`
	Abstained    int     `json:"abstained"`
	Yes          int     `json:"yes"`
	No           int     `json:"no"`
	FalseYes     int     `json:"false_yes"`
	FalseNo      int     `json:"false_no"`
	AnswerRate   float64 `json:"answer_rate"`
	Accuracy     float64 `json:"selective_accuracy"`
	YesPrecision float64 `json:"yes_precision"`
	YesRecall    float64 `json:"yes_recall"`
	NoPrecision  float64 `json:"no_precision"`
}
type EvaluationMetrics struct {
	Count            int            `json:"count"`
	Positive         int            `json:"positive"`
	Negative         int            `json:"negative"`
	Confusion        Confusion      `json:"confusion_at_0_5"`
	Accuracy         float64        `json:"accuracy_at_0_5"`
	Precision        float64        `json:"precision_at_0_5"`
	Recall           float64        `json:"recall_at_0_5"`
	F1               float64        `json:"f1_at_0_5"`
	BalancedAccuracy float64        `json:"balanced_accuracy_at_0_5"`
	Brier            float64        `json:"brier"`
	LogLoss          float64        `json:"log_loss"`
	ROCAUC           *float64       `json:"roc_auc"`
	AveragePrecision *float64       `json:"average_precision"`
	CalibrationError float64        `json:"expected_calibration_error"`
	Selective        OperatingPoint `json:"selective"`
}
type EvaluationCase struct {
	ID          string   `json:"id,omitempty"`
	Group       string   `json:"group"`
	Label       int      `json:"label"`
	Probability float64  `json:"probability"`
	Answer      string   `json:"answer"`
	Support     float64  `json:"lexical_support"`
	Reasons     []string `json:"abstention_reasons,omitempty"`
}
type EvaluationReport struct {
	Version         string            `json:"version"`
	TaskID          string            `json:"task_id"`
	ModelVersion    string            `json:"model_version"`
	Synthetic       bool              `json:"synthetic"`
	Dataset         DatasetAudit      `json:"dataset"`
	Metrics         EvaluationMetrics `json:"metrics"`
	OperatingPoints []OperatingPoint  `json:"operating_points"`
	Errors          []EvaluationCase  `json:"errors"`
	Abstentions     []EvaluationCase  `json:"abstentions"`
	Warnings        []string          `json:"warnings"`
}

func (m EvaluationMetrics) valid() bool {
	c, s := m.Confusion, m.Selective
	if m.Count < 1 || m.Positive < 0 || m.Negative < 0 || m.Positive+m.Negative != m.Count || c.TruePositive < 0 || c.FalsePositive < 0 || c.TrueNegative < 0 || c.FalseNegative < 0 || c.TruePositive+c.FalseNegative != m.Positive || c.TrueNegative+c.FalsePositive != m.Negative || !finite(m.LogLoss) || m.LogLoss < 0 {
		return false
	}
	for _, v := range []float64{m.Accuracy, m.Precision, m.Recall, m.F1, m.BalancedAccuracy, m.Brier, m.CalibrationError, s.Threshold, s.AnswerRate, s.Accuracy, s.YesPrecision, s.YesRecall, s.NoPrecision} {
		if !unit(v) {
			return false
		}
	}
	for _, v := range []*float64{m.ROCAUC, m.AveragePrecision} {
		if v != nil && !unit(*v) {
			return false
		}
	}
	return s.Answered >= 0 && s.Abstained >= 0 && s.Answered+s.Abstained == m.Count && s.Yes >= 0 && s.No >= 0 && s.Yes+s.No == s.Answered && s.FalseYes >= 0 && s.FalseYes <= s.Yes && s.FalseNo >= 0 && s.FalseNo <= s.No
}
func ratio(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}

type scoredSample struct {
	sample               Sample
	probability, support float64
	reasons              []string
}

func scoreSamples(rows []Sample, m *Model) []scoredSample {
	out := make([]scoredSample, len(rows))
	for i, s := range rows {
		p := m.Predict(s.Input)
		out[i] = scoredSample{s, p.Value, p.Support, reliabilityReasons(s.Input, p)}
	}
	return out
}
func answerAt(p, threshold float64, eligible bool) string {
	if !eligible {
		return "unknown"
	}
	t := math.Max(.5, threshold)
	if p > .5 && p >= t {
		return "yes"
	}
	if p < .5 && p <= 1-t {
		return "no"
	}
	return "unknown"
}
func operatingPoint(rows []scoredSample, threshold float64) OperatingPoint {
	o := OperatingPoint{Threshold: math.Max(.5, threshold)}
	positive := 0
	for _, row := range rows {
		if row.sample.Label == 1 {
			positive++
		}
		switch answerAt(row.probability, threshold, len(row.reasons) == 0) {
		case "yes":
			o.Yes++
			if row.sample.Label == 0 {
				o.FalseYes++
			}
		case "no":
			o.No++
			if row.sample.Label == 1 {
				o.FalseNo++
			}
		default:
			o.Abstained++
		}
	}
	o.Answered = o.Yes + o.No
	o.AnswerRate = ratio(o.Answered, len(rows))
	o.Accuracy = ratio(o.Answered-o.FalseYes-o.FalseNo, o.Answered)
	o.YesPrecision = ratio(o.Yes-o.FalseYes, o.Yes)
	o.YesRecall = ratio(o.Yes-o.FalseYes, positive)
	o.NoPrecision = ratio(o.No-o.FalseNo, o.No)
	return o
}
func measure(rows []scoredSample, threshold float64) EvaluationMetrics {
	m := EvaluationMetrics{Count: len(rows), Selective: operatingPoint(rows, threshold)}
	if len(rows) == 0 {
		return m
	}
	binCount := [10]int{}
	binProbability, binLabels := [10]float64{}, [10]float64{}
	for _, row := range rows {
		p, y := row.probability, row.sample.Label
		if y == 1 {
			m.Positive++
			if p >= .5 {
				m.Confusion.TruePositive++
			} else {
				m.Confusion.FalseNegative++
			}
		} else {
			m.Negative++
			if p >= .5 {
				m.Confusion.FalsePositive++
			} else {
				m.Confusion.TrueNegative++
			}
		}
		m.Brier += (p - float64(y)) * (p - float64(y))
		clipped := math.Max(1e-15, math.Min(1-1e-15, p))
		m.LogLoss -= float64(y)*math.Log(clipped) + (1-float64(y))*math.Log1p(-clipped)
		bin := int(p * 10)
		if bin == 10 {
			bin = 9
		}
		binCount[bin]++
		binProbability[bin] += p
		binLabels[bin] += float64(y)
	}
	c := m.Confusion
	m.Accuracy = ratio(c.TruePositive+c.TrueNegative, m.Count)
	m.Precision = ratio(c.TruePositive, c.TruePositive+c.FalsePositive)
	m.Recall = ratio(c.TruePositive, m.Positive)
	m.F1 = ratio(2*c.TruePositive, 2*c.TruePositive+c.FalsePositive+c.FalseNegative)
	m.BalancedAccuracy = (ratio(c.TruePositive, m.Positive) + ratio(c.TrueNegative, m.Negative)) / 2
	m.Brier /= float64(m.Count)
	m.LogLoss /= float64(m.Count)
	for i, n := range binCount {
		if n > 0 {
			m.CalibrationError += math.Abs(binProbability[i]-binLabels[i]) / float64(m.Count)
		}
	}
	// Tied scores receive average ranks; AP includes each tie as one threshold.
	ordered := append([]scoredSample(nil), rows...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].probability < ordered[j].probability })
	if m.Positive > 0 && m.Negative > 0 {
		rankSum := 0.0
		for i := 0; i < len(ordered); {
			j := i + 1
			for j < len(ordered) && ordered[j].probability == ordered[i].probability {
				j++
			}
			for k := i; k < j; k++ {
				if ordered[k].sample.Label == 1 {
					rankSum += float64(i+1+j) / 2
				}
			}
			i = j
		}
		auc := (rankSum - float64(m.Positive*(m.Positive+1))/2) / float64(m.Positive*m.Negative)
		m.ROCAUC = &auc
		// Tie-averaged ranks keep AUC in [0,1]; clamp float epsilon either way.
		if *m.ROCAUC > 1 {
			*m.ROCAUC = 1
		} else if *m.ROCAUC < 0 {
			*m.ROCAUC = 0
		}
	}
	if m.Positive > 0 {
		ap := 0.0
		tp, selected := 0, 0
		for i := len(ordered) - 1; i >= 0; {
			j := i - 1
			for j >= 0 && ordered[j].probability == ordered[i].probability {
				j--
			}
			added := 0
			for k := j + 1; k <= i; k++ {
				if ordered[k].sample.Label == 1 {
					added++
				}
			}
			tp += added
			selected += i - j
			ap += ratio(added, m.Positive) * ratio(tp, selected)
			i = j
		}
		// Summed precision steps can overshoot 1 by a float epsilon; clamp it.
		if ap > 1 {
			ap = 1
		} else if ap < 0 {
			ap = 0
		}
		m.AveragePrecision = &ap
	}
	return m
}

// Evaluate checks a separate labeled corpus without fitting or changing the model.
// All training, calibration AND internal test projects are excluded from external evaluation.
func Evaluate(d Dataset, m *Model, threshold float64) (EvaluationReport, error) {
	if m == nil {
		return EvaluationReport{}, fmt.Errorf("text-eval requires a trained text model")
	}
	if err := m.Validate(); err != nil {
		return EvaluationReport{}, err
	}
	if !unit(threshold) {
		return EvaluationReport{}, fmt.Errorf("threshold must be in [0,1]")
	}
	rows, audit, err := prepareDataset(d)
	if err != nil {
		return EvaluationReport{}, err
	}
	out := EvaluationReport{Version: Version, TaskID: Task, ModelVersion: m.Version, Synthetic: d.Synthetic || m.Synthetic, Dataset: audit, Errors: []EvaluationCase{}, Abstentions: []EvaluationCase{}, Warnings: append([]string{}, audit.Warnings...)}
	if p := m.Provenance; p != nil {
		for _, s := range rows {
			g, h := SHA256(s.Group), normalizedSignature(s.Input)
			gi, hi := sort.SearchStrings(p.GroupHashes, g), sort.SearchStrings(p.SampleHashes, h)
			if gi < len(p.GroupHashes) && p.GroupHashes[gi] == g {
				return EvaluationReport{}, fmt.Errorf("evaluation leakage: project %q was used in model development", s.Group)
			}
			if hi < len(p.SampleHashes) && p.SampleHashes[hi] == h {
				return EvaluationReport{}, fmt.Errorf("evaluation leakage: normalized text in project %q was used in model development", s.Group)
			}
		}
	} else {
		out.Warnings = append(out.Warnings, "Модель v0.2 не хранит состав корпуса: независимость внешнего набора нельзя проверить автоматически.")
	}
	scores := scoreSamples(rows, m)
	out.Metrics = measure(scores, threshold)
	for _, t := range []float64{.5, .7, .85, .9, .95} {
		out.OperatingPoints = append(out.OperatingPoints, operatingPoint(scores, t))
	}
	sort.SliceStable(scores, func(i, j int) bool {
		a := math.Abs(scores[i].probability - float64(scores[i].sample.Label))
		b := math.Abs(scores[j].probability - float64(scores[j].sample.Label))
		return a > b
	})
	for _, s := range scores {
		answer := answerAt(s.probability, threshold, len(s.reasons) == 0)
		c := EvaluationCase{ID: s.sample.Input.ID, Group: s.sample.Group, Label: s.sample.Label, Probability: s.probability, Answer: answer, Support: s.support, Reasons: s.reasons}
		if answer == "unknown" && len(out.Abstentions) < 20 {
			if len(c.Reasons) == 0 {
				c.Reasons = []string{"confidence_below_threshold"}
			}
			out.Abstentions = append(out.Abstentions, c)
		}
		if (s.probability >= .5) != (s.sample.Label == 1) && len(out.Errors) < 20 {
			out.Errors = append(out.Errors, c)
		}
	}
	if out.Synthetic {
		out.Warnings = append(out.Warnings, "Синтетическая проверка не подтверждает точность на реальных приложениях.")
	}
	out.Warnings = append(out.Warnings, "Метрики оценивают текстовую классификацию; checks, сборка и runtime в них не подтверждаются. Нулевой знаменатель precision/recall отображается как 0; ROC AUC для одного класса — null.")
	return out, nil
}
