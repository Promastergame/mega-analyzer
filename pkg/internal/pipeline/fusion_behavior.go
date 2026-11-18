package pipeline

import (
	"fmt"
	"math"
	"sync"

	"mega-analyzer/pkg/ml/fusion"
)

var (
	behaviorFusionSchema = []string{
		"dyn_code_load_norm",
		"network_norm",
		"c2_exfil_norm",
		"file_ops_norm",
		"obfuscation_norm",
		"webview_abuse_norm",
		"accessibility_norm",
		"stealer_perms_norm",
		"anti_analysis_norm",
		"correlations_count_norm",
		"total_score_norm",
		"has_critical_corr",
	}

	sharedBehaviorIntel *fusion.Intelligence
	behaviorIntelOnce   sync.Once
	// fusion.Intelligence mutates its online model, feature monitor and
	// similarity memory inside Analyze, none of it internally synchronised.
	// This singleton is reachable from concurrent scan workers, so every
	// entry into Analyze is serialised here.
	behaviorIntelMu sync.Mutex
)

func getBehaviorIntelligence() *fusion.Intelligence {
	behaviorIntelOnce.Do(func() {
		cfg := fusion.IntelligenceConfig{
			Schema: behaviorFusionSchema,
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

		heur := &behaviorHeuristicScoreProvider{
			schema: behaviorFusionSchema,
			weight: 1.15,
		}

		sharedBehaviorIntel = fusion.NewIntelligence(cfg, heur)
	})
	return sharedBehaviorIntel
}

type behaviorHeuristicScoreProvider struct {
	schema []string
	weight float64
}

func (p *behaviorHeuristicScoreProvider) Name() string    { return "behavior_heur" }
func (p *behaviorHeuristicScoreProvider) Weight() float64 { return p.weight }
func (p *behaviorHeuristicScoreProvider) Score(x []float64) float64 {
	if len(x) < len(p.schema) {
		return 0.0
	}
	// Weighted combination of dynamic code load, c2/exfil, accessibility, stealer permissions, correlations count, and critical correlations flag.
	score := x[0]*0.15 + x[2]*0.20 + x[6]*0.20 + x[7]*0.15 + x[9]*0.15 + x[11]*0.15
	if score > 1.0 {
		return 1.0
	}
	if score < 0.0 {
		return 0.0
	}
	return score
}

func projectBehaviorFeatures(signals *ApkSignals) []float64 {
	x := make([]float64, len(behaviorFusionSchema))
	if signals == nil {
		return x
	}

	signals.mu.RLock()
	defer signals.mu.RUnlock()

	// Sum counts by category using signalToCategory helper
	var dynLoad, netLoad, c2Exfil, fileOps, obfus, webview, access, stealer, anti int
	for sigType, count := range signals.SignalCounts {
		switch signalToCategory(sigType) {
		case "DYNAMIC_CODE_LOAD":
			dynLoad += count
		case "NETWORK":
			netLoad += count
		case "SUSPICIOUS_URL":
			c2Exfil += count
		case "WEBVIEW_REMOTE_JS":
			webview += count
		case "STEALER_INDICATOR":
			stealer += count
		case "ANTI_ANALYSIS":
			anti += count
		}
		// Also categorize file operations and obfuscation and accessibility directly
		switch sigType {
		case SignalFileWrite, SignalFileOutputStream, SignalDexSuffix, SignalExternalStorage:
			fileOps += count
		case SignalBase64Decode, SignalBase64LongString, SignalXOR, SignalAES, SignalDES, SignalRC4:
			obfus += count
		case SignalAccessibilityPermission, SignalAccessibilityService, SignalAccessibilityEvent, SignalAccessibilityRootWindow, SignalAccessibilityGlobalAction, SignalAccessibilityNodeInfo:
			access += count
		}
	}

	x[0] = clamp01Behavior(float64(dynLoad) / 10.0)
	x[1] = clamp01Behavior(float64(netLoad) / 20.0)
	x[2] = clamp01Behavior(float64(c2Exfil) / 5.0)
	x[3] = clamp01Behavior(float64(fileOps) / 15.0)
	x[4] = clamp01Behavior(float64(obfus) / 20.0)
	x[5] = clamp01Behavior(float64(webview) / 10.0)
	x[6] = clamp01Behavior(float64(access) / 5.0)
	x[7] = clamp01Behavior(float64(stealer) / 10.0)
	x[8] = clamp01Behavior(float64(anti) / 5.0)

	x[10] = clamp01Behavior(float64(signals.TotalScore) / 100.0)

	riskCorrelations := 0
	for _, c := range signals.Correlations {
		if c.Severity == SeverityInfo || c.Score <= 0 {
			continue
		}
		riskCorrelations++
		if c.Severity == SeverityCritical || c.Severity == SeverityHigh {
			x[11] = 1.0
		}
	}
	x[9] = clamp01Behavior(float64(riskCorrelations) / 5.0)

	return x
}

func clamp01Behavior(v float64) float64 {
	if math.IsNaN(v) || v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func runBehaviorFusionIntelligence(signals *ApkSignals) *fusion.Report {
	if signals == nil {
		return nil
	}
	intel := getBehaviorIntelligence()
	features := projectBehaviorFeatures(signals)

	signals.mu.RLock()
	correlationsCount := 0
	totalScore := signals.TotalScore
	var critCorrs []Correlation
	for _, c := range signals.Correlations {
		if c.Severity == SeverityInfo || c.Score <= 0 {
			continue
		}
		correlationsCount++
		if c.Severity == SeverityCritical || c.Severity == SeverityHigh {
			critCorrs = append(critCorrs, c)
		}
	}
	signals.mu.RUnlock()

	var extra []fusion.Evidence
	for _, c := range critCorrs {
		extra = append(extra, fusion.Evidence{
			Factor:       "high_threat_correlation",
			Contribution: 0.35,
			Detail:       fmt.Sprintf("Correlated behavior: %s (%s)", c.Name, c.Description),
		})
	}
	if totalScore >= 50 {
		extra = append(extra, fusion.Evidence{
			Factor:       "elevated_behavioral_score",
			Contribution: 0.30,
			Detail:       fmt.Sprintf("Total behavioral threat score reached %d", totalScore),
		})
	}
	if correlationsCount >= 3 {
		extra = append(extra, fusion.Evidence{
			Factor:       "multiple_correlations",
			Contribution: 0.25,
			Detail:       fmt.Sprintf("Detected %d heuristic risk correlations across the APK; connected execution requires separate evidence", correlationsCount),
		})
	}

	sampleID := fmt.Sprintf("behavior_score_%d_corr_%d", totalScore, correlationsCount)
	sample := fusion.Sample{
		ID:       sampleID,
		Features: features,
		Extra:    extra,
	}

	behaviorIntelMu.Lock()
	report, err := intel.Analyze(sample)
	behaviorIntelMu.Unlock()
	if err != nil {
		return nil
	}

	return &report
}
