package pipeline

import (
	"fmt"
	"math"
	"sync"

	"mega-analyzer/pkg/internal/types"
	"mega-analyzer/pkg/ml/fusion"
)

var (
	vulnDetectorsFusionSchema = []string{
		"matches_count_norm",
		"critical_matches_norm",
		"high_matches_norm",
		"crypto_vuln_norm",
		"secret_vuln_norm",
		"network_vuln_norm",
		"manifest_vuln_norm",
		"webview_vuln_norm",
		"ipc_vuln_norm",
		"injection_vuln_norm",
		"hotspots_norm",
		"has_critical_vuln",
	}

	sharedVulnDetectorsIntel *fusion.Intelligence
	vulnDetectorsIntelOnce   sync.Once
	// fusion.Intelligence mutates its online model, feature monitor and
	// similarity memory inside Analyze, none of it internally synchronised.
	// This singleton is reachable from concurrent scan workers, so every
	// entry into Analyze is serialised here.
	vulnDetectorsIntelMu sync.Mutex
)

func getVulnDetectorsIntelligence() *fusion.Intelligence {
	vulnDetectorsIntelOnce.Do(func() {
		cfg := fusion.IntelligenceConfig{
			Schema: vulnDetectorsFusionSchema,
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

		heur := &vulnDetectorsHeuristicScoreProvider{
			schema: vulnDetectorsFusionSchema,
			weight: 1.15,
		}

		sharedVulnDetectorsIntel = fusion.NewIntelligence(cfg, heur)
	})
	return sharedVulnDetectorsIntel
}

type vulnDetectorsHeuristicScoreProvider struct {
	schema []string
	weight float64
}

func (p *vulnDetectorsHeuristicScoreProvider) Name() string    { return "vuln_detectors_heur" }
func (p *vulnDetectorsHeuristicScoreProvider) Weight() float64 { return p.weight }
func (p *vulnDetectorsHeuristicScoreProvider) Score(x []float64) float64 {
	if len(x) < len(p.schema) {
		return 0.0
	}
	// Weighted combination of critical matches, high matches, secrets, network, manifest, webview, and critical flag.
	score := x[1]*0.25 + x[2]*0.15 + x[4]*0.15 + x[5]*0.10 + x[6]*0.10 + x[7]*0.10 + x[11]*0.15
	if score > 1.0 {
		return 1.0
	}
	if score < 0.0 {
		return 0.0
	}
	return score
}

func projectVulnDetectorsFeatures(res *types.AnalysisResult) []float64 {
	x := make([]float64, len(vulnDetectorsFusionSchema))
	if res == nil {
		return x
	}

	totalMatches := 0
	critMatches := 0
	highMatches := 0

	for _, m := range res.RuleMatches {
		totalMatches++
		if m.IsCritical || m.Severity == types.SeverityCritical {
			critMatches++
		} else if m.Severity == types.SeverityHigh {
			highMatches++
		}
	}
	// Also count across Files if RuleMatches is empty or incomplete
	for _, fa := range res.Files {
		if fa == nil {
			continue
		}
		for _, m := range fa.Matches {
			totalMatches++
			if m.IsCritical || m.Severity == types.SeverityCritical {
				critMatches++
			} else if m.Severity == types.SeverityHigh {
				highMatches++
			}
		}
	}

	x[0] = clamp01Vuln(float64(totalMatches) / 100.0)
	x[1] = clamp01Vuln(float64(critMatches) / 10.0)
	x[2] = clamp01Vuln(float64(highMatches) / 25.0)

	if res.MatchesByCategory != nil {
		x[3] = clamp01Vuln(float64(res.MatchesByCategory[types.CategoryWeakCrypto]) / 10.0)
		x[4] = clamp01Vuln(float64(res.MatchesByCategory[types.CategoryHardcodedSecret]) / 10.0)
		x[5] = clamp01Vuln(float64(res.MatchesByCategory[types.CategoryNetwork]) / 15.0)
		x[6] = clamp01Vuln(float64(res.MatchesByCategory[types.CategoryExportedComponent]) / 10.0)
		x[7] = clamp01Vuln(float64(res.MatchesByCategory[types.CategoryWebViewRemoteJS]) / 10.0)
		x[8] = clamp01Vuln(float64(res.MatchesByCategory[types.CategoryPendingIntentVuln]) / 10.0)
		x[9] = clamp01Vuln(float64(res.MatchesByCategory[types.CategoryZipSlip]) / 10.0)
	}

	x[10] = clamp01Vuln(float64(len(res.Hotspots)) / 20.0)

	if critMatches > 0 {
		x[11] = 1.0
	}

	return x
}

func clamp01Vuln(v float64) float64 {
	if math.IsNaN(v) || v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func runVulnDetectorsFusionIntelligence(res *types.AnalysisResult) *fusion.Report {
	if res == nil {
		return nil
	}
	intel := getVulnDetectorsIntelligence()
	features := projectVulnDetectorsFeatures(res)

	critMatches := 0
	for _, fa := range res.Files {
		if fa == nil {
			continue
		}
		for _, m := range fa.Matches {
			if m.IsCritical || m.Severity == types.SeverityCritical {
				critMatches++
			}
		}
	}

	var extra []fusion.Evidence
	if critMatches > 0 {
		extra = append(extra, fusion.Evidence{
			Factor:       "critical_priority_matches",
			Contribution: 0.35,
			Detail:       fmt.Sprintf("Found %d critical-priority pattern matches across APK files; these are not individually verified vulnerabilities", critMatches),
		})
	}
	if res.MatchesByCategory != nil && res.MatchesByCategory[types.CategoryHardcodedSecret] > 0 {
		extra = append(extra, fusion.Evidence{
			Factor:       "hardcoded_secret_matches",
			Contribution: 0.30,
			Detail:       fmt.Sprintf("Found %d hardcoded-secret pattern matches; credential validity and use require verification", res.MatchesByCategory[types.CategoryHardcodedSecret]),
		})
	}
	if len(res.Hotspots) >= 5 {
		extra = append(extra, fusion.Evidence{
			Factor:       "multiple_hotspots",
			Contribution: 0.25,
			Detail:       fmt.Sprintf("Identified %d high-risk vulnerability hotspots", len(res.Hotspots)),
		})
	}

	sampleID := fmt.Sprintf("vuln_app_%s_matches_%d", res.AppPackage, len(res.RuleMatches))
	sample := fusion.Sample{
		ID:       sampleID,
		Features: features,
		Extra:    extra,
	}

	vulnDetectorsIntelMu.Lock()
	report, err := intel.Analyze(sample)
	vulnDetectorsIntelMu.Unlock()
	if err != nil {
		return nil
	}

	return &report
}
