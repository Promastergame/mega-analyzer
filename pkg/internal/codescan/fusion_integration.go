package codescan

import (
	"fmt"
	"math"
	"sync"

	"mega-analyzer/pkg/ml/fusion"
)

var (
	codescanFusionSchema = []string{
		"lines_norm",
		"bytes_norm",
		"is_minified",
		"is_obfuscated",
		"findings_count_norm",
		"high_sev_norm",
		"score_norm",
		"has_critical",
		"has_schema",
		"has_any_signal",
	}

	sharedCodescanIntel *fusion.Intelligence
	codescanIntelOnce   sync.Once
	// fusion.Intelligence mutates its online model, feature monitor and
	// similarity memory inside Analyze, none of it internally synchronised.
	// This singleton is reachable from concurrent scan workers, so every
	// entry into Analyze is serialised here.
	codescanIntelMu sync.Mutex
)

func getCodescanIntelligence() *fusion.Intelligence {
	codescanIntelOnce.Do(func() {
		cfg := fusion.IntelligenceConfig{
			Schema: codescanFusionSchema,
			Fusion: fusion.FusionConfig{
				DisagreementStd: 0.20,
				Threshold:       0.60,
				MinSignals:      2,
			},
			AnomalyWeight:    1.0,
			SimilarityWeight: 0.8,
			OnlineWeight:     1.2,
			OnlineLR:         0.08,
			OnlineL2:         0.001,
		}

		heur := &codescanHeuristicScoreProvider{
			schema: codescanFusionSchema,
			weight: 1.1,
		}

		sharedCodescanIntel = fusion.NewIntelligence(cfg, heur)
	})
	return sharedCodescanIntel
}

type codescanHeuristicScoreProvider struct {
	schema []string
	weight float64
}

func (p *codescanHeuristicScoreProvider) Name() string    { return "codescan_heur" }
func (p *codescanHeuristicScoreProvider) Weight() float64 { return p.weight }
func (p *codescanHeuristicScoreProvider) Score(x []float64) float64 {
	if len(x) < len(p.schema) {
		return 0.0
	}
	// Weighted combination of obfuscated flag, findings count, high severity count, score, and critical flag.
	score := x[3]*0.25 + x[4]*0.15 + x[5]*0.25 + x[6]*0.15 + x[7]*0.20
	if score > 1.0 {
		return 1.0
	}
	if score < 0.0 {
		return 0.0
	}
	return score
}

func projectCodescanFeatures(r *Result) []float64 {
	x := make([]float64, len(codescanFusionSchema))
	if r == nil {
		return x
	}

	x[0] = clamp01Codescan(float64(r.Lines) / 5000.0)
	x[1] = clamp01Codescan(float64(r.Bytes) / 500000.0)

	if r.IsMinified {
		x[2] = 1.0
	}
	if r.IsObfuscated {
		x[3] = 1.0
	}

	x[4] = clamp01Codescan(float64(len(r.Findings)) / 20.0)

	highSevCount := 0
	hasCrit := false
	for _, f := range r.Findings {
		if f.Severity == SevHigh || f.Severity == SevCritical {
			highSevCount++
		}
		if f.Severity == SevCritical {
			hasCrit = true
		}
	}
	x[5] = clamp01Codescan(float64(highSevCount) / 5.0)
	x[6] = clamp01Codescan(float64(r.Score) / 100.0)

	if hasCrit {
		x[7] = 1.0
	}
	if r.Schema != nil {
		x[8] = 1.0
	}
	if len(r.Findings) > 0 || r.IsObfuscated {
		x[9] = 1.0
	}

	return x
}

func clamp01Codescan(v float64) float64 {
	if math.IsNaN(v) || v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func runCodescanFusionIntelligence(r *Result) *fusion.Report {
	if r == nil {
		return nil
	}
	intel := getCodescanIntelligence()
	features := projectCodescanFeatures(r)

	var extra []fusion.Evidence
	if r.IsObfuscated {
		extra = append(extra, fusion.Evidence{
			Factor:       "obfuscated_payload",
			Contribution: 0.3,
			Detail:       "Payload detected as heavily obfuscated code",
		})
	}
	if r.Score >= 50 {
		extra = append(extra, fusion.Evidence{
			Factor:       "high_static_score",
			Contribution: 0.35,
			Detail:       fmt.Sprintf("Static code scan heuristic score is %d", r.Score),
		})
	}
	for _, f := range r.Findings {
		if f.Severity == SevCritical {
			extra = append(extra, fusion.Evidence{
				Factor:       "critical_finding",
				Contribution: 0.35,
				Detail:       fmt.Sprintf("Critical static finding: %s (%s)", f.Title, f.ID),
			})
			break
		}
	}

	sampleID := fmt.Sprintf("codescan_%s_%d_bytes_%d", r.Language, r.Lines, r.Bytes)
	sample := fusion.Sample{
		ID:       sampleID,
		Features: features,
		Extra:    extra,
	}

	codescanIntelMu.Lock()
	report, err := intel.Analyze(sample)
	codescanIntelMu.Unlock()
	if err != nil {
		return nil
	}

	return &report
}
