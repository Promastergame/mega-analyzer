package s1

import (
	"encoding/json"
	"math"

	"decisionai/reasoning"
)

// ExpertQuestion is the compiled, validated view of one question handed to experts.
type ExpertQuestion struct {
	Claim      *reasoning.Atom
	AbstainKey string
	ID         string
	Type       string
	Instr      string
	Options    []Option // choice/score: declared options; noul with criteria: true/false
	Task       string
	Polarity   string
}

// ExpertAnswer is a specialised model's or rule's answer.
type ExpertAnswer struct {
	Reasoning *reasoning.Trace
	Neural    *NeuralInference
	// Probs is aligned with ExpertQuestion.Options for choice/score; for noul Probs[0] = P(true).
	Calculation *CalculationTrace
	Probs       []float64
	Evidence    []string
	// Source names the expert (shown to the caller as answer.source).
	Source string
	// Calibrated marks probabilities that were measured on held-out data or come from deterministic
	// checks. Only calibrated expert answers may be routed "auto".
	Calibrated bool
	Abstained  bool
	Reason     string
	Checks     []NextCheck
	References []EvidenceReference
}

// Expert is a specialised model or rule set. It answers only the questions it recognises
// (ok=false otherwise); everything else falls through to the general backend.
type Expert interface {
	Name() string
	Answer(state any, stateText string, q ExpertQuestion) (ExpertAnswer, bool)
}

// expertAnswer converts an expert result into a typed answer, or ok=false when it is malformed.
func expertAnswer(q compiled, ea ExpertAnswer) (Answer, bool) {
	ans := Answer{Type: q.Type, Source: ea.Source, Evidence: ea.Evidence, Abstained: ea.Abstained, Reason: ea.Reason, Checks: ea.Checks, References: ea.References, Calculation: ea.Calculation, Neural: ea.Neural, Reasoning: ea.Reasoning}
	if q.Task == TaskLiteralRoleNeural && ea.Neural != nil && (ea.Neural.Status == "skipped" || ea.Neural.Status == "unavailable") {
		if !ea.Abstained || ea.Neural.Task != q.Task || len(ea.Probs) != 0 {
			return Answer{}, false
		}
		// An absent inference is not an unknown-class prediction. Keep its
		// reason and scope without manufacturing probabilities or confidence.
		ans.Route = "human"
		return ans, true
	}
	switch q.Type {
	case TypeNoul:
		if len(ea.Probs) < 1 || math.IsNaN(ea.Probs[0]) || math.IsInf(ea.Probs[0], 0) {
			return Answer{}, false
		}
		pv := round4(math.Min(1, math.Max(0, ea.Probs[0])))
		ans.Noul = &pv
		ans.fixed = []float64{pv, 1 - pv}
		ans.Route = DefaultRoute(NoulCertainty(pv))
	default:
		if len(ea.Probs) != len(q.Options) {
			return Answer{}, false
		}
		p := make([]float64, len(ea.Probs))
		sum := 0.0
		for i, v := range ea.Probs {
			if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
				return Answer{}, false
			}
			p[i] = v
			sum += v
		}
		if sum <= 0 || math.IsInf(sum, 0) {
			return Answer{}, false
		}
		best := 0
		pr := make(Probs, len(p))
		for i := range p {
			p[i] /= sum
			pr[i] = KV{q.Options[i].Key, p[i]}
			ans.keys = append(ans.keys, q.Options[i].Key)
			if p[i] > p[best] {
				best = i
			}
		}
		ans.Probabilities, ans.fixed = pr, p
		var conf float64
		if q.Type == TypeChoice {
			ans.Choice = q.Options[best].Key
			conf = ChoiceConfidence(p)
		} else {
			vals := levelValues(q.Options)
			ans.values = vals
			sc := 0.0
			for i, v := range vals {
				sc += p[i] * v
			}
			sc = round4(sc)
			ans.Score = &sc
			conf = ScoreConfidence(p)
		}
		conf = round4(conf)
		ans.Confidence = &conf
		ans.Route = DefaultRoute(conf)
	}
	if ans.Calculation != nil {
		trace := *ans.Calculation
		trace.Verified = trace.Verify()
		ans.Calculation = &trace
		if !trace.Verified {
			ans.Abstained = true
			ans.Reason = "calculation_verification_failed"
			ans.Route = "human"
		}
	}
	if !ea.Calibrated && ans.Route == "auto" {
		ans.Route = "review"
	}
	if ea.Abstained {
		ans.Route = "human"
	}
	return ans, true
}

func decodeState(raw json.RawMessage) any {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return nil
	}
	return v
}
