package cfg

import (
	"fmt"
	"math"
	"sync"

	"mega-analyzer/pkg/ml/fusion"
)

var (
	cfgFusionSchema = []string{
		"cyclomatic_norm",
		"npath_norm",
		"halstead_vol_norm",
		"halstead_effort_norm",
		"mi_score_norm",
		"essential_cc_norm",
		"fan_in_norm",
		"fan_out_norm",
		"obfuscation_score",
		"ai_readiness_score",
		"has_complexity_signal",
	}

	sharedCfgIntel *fusion.Intelligence
	cfgIntelOnce   sync.Once
	// fusion.Intelligence mutates its online model, feature monitor and
	// similarity memory inside Analyze, none of it internally synchronised.
	// This singleton is reachable from concurrent scan workers, so every
	// entry into Analyze is serialised here.
	cfgIntelMu sync.Mutex
)

func getCfgIntelligence() *fusion.Intelligence {
	cfgIntelOnce.Do(func() {
		cfg := fusion.IntelligenceConfig{
			Schema: cfgFusionSchema,
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

		heur := &cfgHeuristicScoreProvider{
			schema: cfgFusionSchema,
			weight: 1.1,
		}

		sharedCfgIntel = fusion.NewIntelligence(cfg, heur)
	})
	return sharedCfgIntel
}

type cfgHeuristicScoreProvider struct {
	schema []string
	weight float64
}

func (p *cfgHeuristicScoreProvider) Name() string    { return "cfg_heur" }
func (p *cfgHeuristicScoreProvider) Weight() float64 { return p.weight }
func (p *cfgHeuristicScoreProvider) Score(x []float64) float64 {
	if len(x) < len(p.schema) {
		return 0.0
	}
	// Weighted combination of cyclomatic, npath, halstead effort, essential complexity and obfuscation score.
	score := x[0]*0.25 + x[1]*0.15 + x[3]*0.20 + x[5]*0.15 + x[8]*0.25
	if score > 1.0 {
		return 1.0
	}
	if score < 0.0 {
		return 0.0
	}
	return score
}

func projectCFGFeatures(m *UltimateCFGMetrics) []float64 {
	x := make([]float64, len(cfgFusionSchema))
	if m == nil {
		return x
	}

	// cyclomatic_norm
	x[0] = clamp01CFG(float64(m.Basic.CyclomaticComplexity) / 50.0)

	// npath_norm
	if m.NPath > 0 {
		x[1] = clamp01CFG(math.Log10(float64(m.NPath)) / 6.0)
	}

	// halstead_vol_norm
	x[2] = clamp01CFG(m.Halstead.Volume / 5000.0)

	// halstead_effort_norm
	x[3] = clamp01CFG(m.Halstead.Effort / 100000.0)

	// mi_score_norm (inverse: lower MI => higher complexity threat)
	x[4] = clamp01CFG((100.0 - m.Maintainability.MI) / 100.0)

	// essential_cc_norm
	x[5] = clamp01CFG(float64(m.EssentialComplexity) / 20.0)

	// fan_in_norm
	x[6] = clamp01CFG(float64(m.FanAnalysis.MaxFanIn) / 15.0)

	// fan_out_norm
	x[7] = clamp01CFG(float64(m.FanAnalysis.MaxFanOut) / 15.0)

	// obfuscation_score (already 0..100 -> normalize to 0..1)
	x[8] = clamp01CFG(float64(m.Obfuscation.Score) / 100.0)

	// ai_readiness_score (0..100 -> normalize to 0..1)
	x[9] = clamp01CFG(float64(m.AIReadiness.Score) / 100.0)

	// has_complexity_signal
	if x[0] > 0.3 || x[8] > 0.4 || x[3] > 0.3 {
		x[10] = 1.0
	}

	return x
}

func clamp01CFG(v float64) float64 {
	if math.IsNaN(v) || v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func runCFGFusionIntelligence(m *UltimateCFGMetrics) *fusion.Report {
	if m == nil {
		return nil
	}
	intel := getCfgIntelligence()
	features := projectCFGFeatures(m)

	var extra []fusion.Evidence
	if m.Basic.CyclomaticComplexity > 25 {
		extra = append(extra, fusion.Evidence{
			Factor:       "high_cyclomatic",
			Contribution: 0.2,
			Detail:       fmt.Sprintf("High cyclomatic complexity (%d)", m.Basic.CyclomaticComplexity),
		})
	}
	if m.Obfuscation.Score >= 50 {
		extra = append(extra, fusion.Evidence{
			Factor:       "obfuscation_detected",
			Contribution: 0.35,
			Detail:       fmt.Sprintf("CFG structural obfuscation score = %.1f", m.Obfuscation.Score),
		})
	}
	if m.EssentialComplexity > 10 {
		extra = append(extra, fusion.Evidence{
			Factor:       "high_essential_cc",
			Contribution: 0.2,
			Detail:       fmt.Sprintf("High essential complexity (%d)", m.EssentialComplexity),
		})
	}

	sampleID := fmt.Sprintf("cfg_cc_%d_npath_%d", m.Basic.CyclomaticComplexity, m.NPath)
	sample := fusion.Sample{
		ID:       sampleID,
		Features: features,
		Extra:    extra,
	}

	cfgIntelMu.Lock()
	report, err := intel.Analyze(sample)
	cfgIntelMu.Unlock()
	if err != nil {
		return nil
	}

	return &report
}
