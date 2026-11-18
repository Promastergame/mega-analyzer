package fusion

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// ModelSignal is one weak learner's contribution to a decision. Score is a
// threat/positive probability in [0,1]; Weight is the relative trust placed
// in this signal (weights need not sum to 1 — the engine normalises them).
type ModelSignal struct {
	Name   string  `json:"name"`
	Score  float64 `json:"score"`
	Weight float64 `json:"weight"`
}

// Evidence is one human-readable factor behind a decision.
type Evidence struct {
	Factor       string  `json:"factor"`
	Contribution float64 `json:"contribution"` // share of the threat score [0,1]
	Detail       string  `json:"detail,omitempty"`
}

// Decision is the fused verdict with full uncertainty accounting.
type Decision struct {
	ThreatScore    float64       `json:"threat_score"` // [0,1]
	Confidence     float64       `json:"confidence"`   // [0,1]
	Agreement      float64       `json:"agreement"`    // [0,1] inter-model consensus
	Disagreement   bool          `json:"disagreement"`
	ConfidenceBand string        `json:"confidence_band"` // "High"/"Medium"/"Low"
	Recommendation string        `json:"recommendation"`  // "report" | "deep_analysis"
	Signals        []ModelSignal `json:"signals"`
	Evidence       []Evidence    `json:"evidence"`
	Explanation    string        `json:"explanation"`
}

// FusionConfig tunes the decision engine.
type FusionConfig struct {
	DisagreementStd float64 // weighted std above which models are "in conflict"
	Threshold       float64 // threat score at/above which a sample is flagged
	MinSignals      int     // fewer present signals => confidence discounted
}

// DefaultFusionConfig returns sensible defaults.
func DefaultFusionConfig() FusionConfig {
	return FusionConfig{DisagreementStd: 0.20, Threshold: 0.60, MinSignals: 3}
}

// FusionEngine combines weighted signals into an explainable Decision.
type FusionEngine struct{ cfg FusionConfig }

// NewFusionEngine builds an engine, normalising invalid config to defaults.
func NewFusionEngine(cfg FusionConfig) *FusionEngine {
	if cfg.DisagreementStd <= 0 {
		cfg.DisagreementStd = 0.20
	}
	if cfg.Threshold <= 0 {
		cfg.Threshold = 0.60
	}
	if cfg.MinSignals <= 0 {
		cfg.MinSignals = 3
	}
	return &FusionEngine{cfg: cfg}
}

// Threshold exposes the configured flag threshold.
func (e *FusionEngine) Threshold() float64 { return e.cfg.Threshold }

// Fuse combines weighted model signals (plus optional discrete evidence such
// as "CFG flattening detected") into a Decision. Uncertainty is modelled
// explicitly: when the signals disagree, confidence is reduced and the engine
// recommends deeper analysis, explaining why.
func (e *FusionEngine) Fuse(signals []ModelSignal, extraEvidence []Evidence) Decision {
	d := Decision{Signals: signals}
	if len(signals) == 0 {
		d.Explanation = "No model signals available; deeper analysis required."
		d.Recommendation = "deep_analysis"
		d.ConfidenceBand = "Low"
		d.Evidence = append([]Evidence(nil), extraEvidence...)
		return d
	}

	var totalW, weighted float64
	for _, s := range signals {
		w := s.Weight
		if w < 0 {
			w = 0
		}
		totalW += w
		weighted += w * clamp01(s.Score)
	}
	if totalW == 0 {
		// All weights zero: fall back to an unweighted mean.
		for _, s := range signals {
			weighted += clamp01(s.Score)
		}
		totalW = float64(len(signals))
	}
	mean := weighted / totalW
	d.ThreatScore = clamp01(mean)

	// Weighted dispersion of the signals around the mean.
	var varAcc, wsum float64
	for _, s := range signals {
		w := s.Weight
		if w < 0 {
			w = 0
		}
		if totalW == float64(len(signals)) {
			w = 1 // matched the unweighted fallback above
		}
		diff := clamp01(s.Score) - mean
		varAcc += w * diff * diff
		wsum += w
	}
	std := 0.0
	if wsum > 0 {
		std = math.Sqrt(varAcc / wsum)
	}

	// Agreement: std of 0 => perfect consensus; std of 0.5 => none.
	d.Agreement = clamp01(1 - std/0.5)
	d.Disagreement = std > e.cfg.DisagreementStd

	// Confidence blends consensus with signal coverage. Few models or high
	// conflict both reduce confidence.
	coverage := clamp01(float64(len(signals)) / float64(e.cfg.MinSignals))
	confidence := d.Agreement * (0.55 + 0.45*coverage)
	if len(signals) < e.cfg.MinSignals {
		confidence *= coverage
	}
	if d.Disagreement {
		confidence *= 0.7
	}
	d.Confidence = clamp01(confidence)

	switch {
	case d.Confidence >= 0.75:
		d.ConfidenceBand = "High"
	case d.Confidence >= 0.5:
		d.ConfidenceBand = "Medium"
	default:
		d.ConfidenceBand = "Low"
	}

	if len(signals) < e.cfg.MinSignals || d.Disagreement || d.Confidence < 0.5 {
		d.Recommendation = "deep_analysis"
	} else {
		d.Recommendation = "report"
	}

	// Evidence: each signal's share of the (weighted) threat score. The
	// contributions sum to the threat score, so they read as "+X%" factors.
	ev := make([]Evidence, 0, len(signals)+len(extraEvidence))
	for _, s := range signals {
		w := s.Weight
		if w < 0 {
			w = 0
		}
		contrib := 0.0
		if totalW > 0 {
			contrib = (w * clamp01(s.Score)) / totalW
		}
		ev = append(ev, Evidence{
			Factor:       s.Name,
			Contribution: contrib,
			Detail:       fmt.Sprintf("%s=%.0f%% (w=%.2f)", s.Name, clamp01(s.Score)*100, s.Weight),
		})
	}
	ev = append(ev, extraEvidence...)
	sort.SliceStable(ev, func(i, j int) bool { return ev[i].Contribution > ev[j].Contribution })
	d.Evidence = ev
	d.Explanation = e.explain(d)
	return d
}

func (e *FusionEngine) explain(d Decision) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Threat score: %.0f%%\n", d.ThreatScore*100)
	b.WriteString("Main factors:\n")
	n := 0
	for _, ev := range d.Evidence {
		n++
		fmt.Fprintf(&b, "%d. %s +%.0f%%\n", n, ev.Factor, ev.Contribution*100)
		if n >= 5 {
			break
		}
	}
	fmt.Fprintf(&b, "Confidence: %s\n", d.ConfidenceBand)
	if len(d.Signals) == 1 {
		b.WriteString("Reason: Only one signal is available; agreement between models cannot be assessed.\n")
	} else if d.Disagreement {
		fmt.Fprintf(&b, "Reason: Models disagree (agreement %.0f%%); deeper analysis recommended.\n", d.Agreement*100)
	} else {
		fmt.Fprintf(&b, "Reason: %d available signals agree (agreement %.0f%%); signal independence has not been established.\n", len(d.Signals), d.Agreement*100)
	}
	if len(d.Signals) < e.cfg.MinSignals {
		fmt.Fprintf(&b, "Signal coverage: %d/%d; deeper analysis required.\n", len(d.Signals), e.cfg.MinSignals)
	}
	return b.String()
}
