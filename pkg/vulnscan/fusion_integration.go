package vulnscan

import (
	"fmt"
	"math"
	"sync"

	"mega-analyzer/pkg/ml/fusion"
)

var (
	vulnscanFusionSchema = []string{
		"cvss_norm",
		"confidence",
		"is_correlated",
		"sources_count_norm",
		"cwe_count_norm",
		"owasp_count_norm",
		"is_high_or_crit",
		"has_signals",
	}

	sharedVulnscanIntel *fusion.Intelligence
	vulnscanIntelOnce   sync.Once
	// fusion.Intelligence mutates its online model, feature monitor and
	// similarity memory inside Analyze, none of it internally synchronised.
	// This singleton is reachable from concurrent scan workers, so every
	// entry into Analyze is serialised here.
	vulnscanIntelMu sync.Mutex
)

func getVulnscanIntelligence() *fusion.Intelligence {
	vulnscanIntelOnce.Do(func() {
		cfg := fusion.IntelligenceConfig{
			Schema: vulnscanFusionSchema,
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

		heur := &vulnscanHeuristicScoreProvider{
			schema: vulnscanFusionSchema,
			weight: 1.1,
		}

		sharedVulnscanIntel = fusion.NewIntelligence(cfg, heur)
	})
	return sharedVulnscanIntel
}

type vulnscanHeuristicScoreProvider struct {
	schema []string
	weight float64
}

func (p *vulnscanHeuristicScoreProvider) Name() string    { return "vulnscan_heur" }
func (p *vulnscanHeuristicScoreProvider) Weight() float64 { return p.weight }
func (p *vulnscanHeuristicScoreProvider) Score(x []float64) float64 {
	if len(x) < len(p.schema) {
		return 0.0
	}
	// Weighted combination of cvss, confidence, correlation flag, severity and signals.
	score := x[0]*0.30 + x[1]*0.25 + x[2]*0.20 + x[6]*0.15 + x[7]*0.10
	if score > 1.0 {
		return 1.0
	}
	if score < 0.0 {
		return 0.0
	}
	return score
}

func projectVulnscanFeatures(f *Finding) []float64 {
	x := make([]float64, len(vulnscanFusionSchema))
	if f == nil {
		return x
	}

	x[0] = clamp01Vulnscan(f.CVSS / 10.0)
	x[1] = clamp01Vulnscan(f.Confidence)

	if f.Correlated {
		x[2] = 1.0
	}
	x[3] = clamp01Vulnscan(float64(len(f.Sources)) / 5.0)
	x[4] = clamp01Vulnscan(float64(len(f.CWE)) / 5.0)
	x[5] = clamp01Vulnscan(float64(len(f.OWASP)) / 5.0)

	if f.Severity == SeverityHigh || f.Severity == SeverityCritical {
		x[6] = 1.0
	}
	if len(f.Signals) > 0 {
		x[7] = 1.0
	}

	return x
}

func clamp01Vulnscan(v float64) float64 {
	if math.IsNaN(v) || v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func runVulnscanFusionIntelligence(f *Finding) *fusion.Report {
	if f == nil {
		return nil
	}
	intel := getVulnscanIntelligence()
	features := projectVulnscanFeatures(f)

	var extra []fusion.Evidence
	if f.CVSS >= 7.0 {
		extra = append(extra, fusion.Evidence{
			Factor:       "high_cvss",
			Contribution: 0.35,
			Detail:       fmt.Sprintf("CVSS score is %.1f (%s)", f.CVSS, f.Severity),
		})
	}
	if f.Correlated {
		extra = append(extra, fusion.Evidence{
			Factor:       "correlated_finding",
			Contribution: 0.3,
			Detail:       "Finding corroborated across multiple check signals or surfaces",
		})
	}
	if f.Confidence >= 0.8 {
		extra = append(extra, fusion.Evidence{
			Factor:       "high_confidence",
			Contribution: 0.25,
			Detail:       fmt.Sprintf("Confirmed confidence tier (%.2f)", f.Confidence),
		})
	}

	sampleID := fmt.Sprintf("vulnscan_%s_%s", f.ID, f.URL)
	sample := fusion.Sample{
		ID:       sampleID,
		Features: features,
		Extra:    extra,
	}

	vulnscanIntelMu.Lock()
	report, err := intel.Analyze(sample)
	vulnscanIntelMu.Unlock()
	if err != nil {
		return nil
	}

	return &report
}
