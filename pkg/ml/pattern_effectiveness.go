package ml

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
// PATTERN EFFECTIVENESS TRACKING — Task 1
// ═══════════════════════════════════════════════════════════════════════════════
//
// This module implements pattern effectiveness tracking infrastructure for the
// ML Patch Pattern Enhancement spec (Requirements 1.1-1.5).
//
// Key components:
//   - PatternEffectiveness: Metrics for individual patterns
//   - PatternEffectivenessAnalyzer: Tier classification and analysis
//   - Effectiveness metadata integration with VulnerablePattern

// ═══════════════════════════════════════════════════════════════════════════════
// PATTERN TIER CLASSIFICATION
// ═══════════════════════════════════════════════════════════════════════════════

// PatternTier represents the effectiveness classification of a pattern
type PatternTier string

const (
	TierUnknown PatternTier = "unknown"
	// TierIMBA: Highly effective patterns (>80% success, <10% false positive)
	TierIMBA PatternTier = "elite"

	// TierNormal: Acceptable patterns (60-80% success, <25% false positive)
	TierNormal PatternTier = "normal"

	// TierTrash: Weak/ineffective patterns (<60% success or >40% false positive)
	TierTrash PatternTier = "trash"
)

// tierAliases maps every accepted spelling of a tier — the canonical English
// name plus legacy Cyrillic spellings — to its PatternTier,
// case-insensitively. This is the single source of truth for
// -ml-patch-min-tier validation so the CLI never has to guess what counts as
// valid. Cyrillic aliases ("имба"/"нормально"/"мусор"/"нет данных") are
// deprecated but still accepted for backward compatibility with older
// configs and stored reports.
var tierAliases = map[string]PatternTier{
	string(TierUnknown): TierUnknown,
	"нет данных":        TierUnknown,
	string(TierIMBA):    TierIMBA,
	"имба":              TierIMBA,
	string(TierNormal):  TierNormal,
	"нормально":         TierNormal,
	string(TierTrash):   TierTrash,
	"мусор":             TierTrash,
}

// ResolveTier normalizes a user-supplied tier name — the canonical English
// value ("elite"/"normal"/"trash"/"unknown") or a legacy Cyrillic alias
// ("имба"/"нормально"/"мусор"/"нет данных"), case-insensitively — to its
// canonical PatternTier. ok is false when s does not match any known tier
// or alias.
func ResolveTier(s string) (tier PatternTier, ok bool) {
	tier, ok = tierAliases[strings.ToLower(strings.TrimSpace(s))]
	return tier, ok
}

// UnmarshalJSON implements json.Unmarshaler with legacy alias support, so
// reports stored with Cyrillic tier names ("имба"/"нормально"/"мусор")
// still load and normalize to the English canonical values.
func (t *PatternTier) UnmarshalJSON(data []byte) error {
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("pattern tier: %w", err)
	}
	if tier, ok := ResolveTier(raw); ok {
		*t = tier
		return nil
	}
	return fmt.Errorf("pattern tier: unknown tier %q", raw)
}

// ═══════════════════════════════════════════════════════════════════════════════
// PATTERN EFFECTIVENESS METRICS
// ═══════════════════════════════════════════════════════════════════════════════

// PatternEffectiveness tracks effectiveness metrics for a vulnerability pattern
type PatternEffectiveness struct {
	Measured       bool    `json:"measured"`
	DataSource     string  `json:"data_source"`
	PrecisionLower float64 `json:"precision_lower,omitempty"`
	PrecisionUpper float64 `json:"precision_upper,omitempty"`
	PatternID      string  `json:"pattern_id"`

	// Detection metrics
	TotalDetections int `json:"total_detections"`
	TruePositives   int `json:"true_positives"`
	FalsePositives  int `json:"false_positives"`
	CrashCount      int `json:"crash_count"`

	// Calculated rates (Requirements 1.2)
	TruePositiveRate  float64 `json:"true_positive_rate"`  // TP / (TP + FP)
	FalsePositiveRate float64 `json:"false_positive_rate"` // FP / (TP + FP)
	CrashRate         float64 `json:"crash_rate"`          // Crashes / Total

	// Confidence metrics
	Confidence float64 `json:"confidence"` // Overall confidence in pattern
	Stability  float64 `json:"stability"`  // Consistency across APKs

	// Tier classification (Requirements 1.3)
	Tier       PatternTier `json:"tier"`
	TierReason string      `json:"tier_reason"` // Requirements 1.5

	// Temporal data
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	LastUpdated time.Time `json:"last_updated"`
	APKsSeenIn  int       `json:"apks_seen_in"`

	// Context
	SuccessContexts map[string]int `json:"success_contexts"` // Where it succeeds
	FailureContexts map[string]int `json:"failure_contexts"` // Where it fails
}

// CalculateRates computes effectiveness rates from raw counts (Requirements 1.2)
func (pe *PatternEffectiveness) CalculateRates() {
	total := pe.TruePositives + pe.FalsePositives

	if total > 0 {
		pe.TruePositiveRate = float64(pe.TruePositives) / float64(total)
		pe.FalsePositiveRate = float64(pe.FalsePositives) / float64(total)
	} else {
		pe.TruePositiveRate = 0.0
		pe.FalsePositiveRate = 0.0
	}

	if pe.TotalDetections > 0 {
		pe.CrashRate = float64(pe.CrashCount) / float64(pe.TotalDetections)
	} else {
		pe.CrashRate = 0.0
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// PATTERN EFFECTIVENESS ANALYZER
// ═══════════════════════════════════════════════════════════════════════════════

// FeedbackStore defines an interface for retrieving real pattern metrics
type FeedbackStore interface {
	GetMetrics(patternID string) (total, tp, fp, crash, apks int, found bool)
}

// PatternEffectivenessAnalyzer analyzes patterns and classifies by effectiveness
type PatternEffectivenessAnalyzer struct {
	patterns []*VulnerablePattern
	Store    FeedbackStore
}

// NewPatternEffectivenessAnalyzer creates a new analyzer
func NewPatternEffectivenessAnalyzer(stores ...FeedbackStore) *PatternEffectivenessAnalyzer {
	// Convert VulnerablePatterns slice to pointers
	patterns := make([]*VulnerablePattern, len(VulnerablePatterns))
	for i := range VulnerablePatterns {
		patterns[i] = &VulnerablePatterns[i]
	}

	analyzer := &PatternEffectivenessAnalyzer{
		patterns: patterns,
	}
	if len(stores) > 0 {
		analyzer.Store = stores[0]
	}
	return analyzer
}

// AnalyzeAll evaluates all patterns and returns effectiveness metrics (Requirements 1.1)
func (pea *PatternEffectivenessAnalyzer) AnalyzeAll() map[string]*PatternEffectiveness {
	results := make(map[string]*PatternEffectiveness)

	for _, pattern := range pea.patterns {
		effectiveness := pea.analyzePattern(pattern)
		results[pattern.ID] = effectiveness
	}

	return results
}

// analyzePattern evaluates a single pattern's effectiveness
func (pea *PatternEffectivenessAnalyzer) analyzePattern(pattern *VulnerablePattern) *PatternEffectiveness {
	pe := &PatternEffectiveness{
		DataSource:      "no_observations",
		PatternID:       pattern.ID,
		SuccessContexts: make(map[string]int),
		FailureContexts: make(map[string]int),
		LastUpdated:     time.Now(),
	}

	// Try to query the real feedback store first
	if pea.Store != nil {
		if total, tp, fp, crash, apks, found := pea.Store.GetMetrics(pattern.ID); found && total >= 0 && tp >= 0 && fp >= 0 && crash >= 0 && apks >= 0 && tp+fp <= total && crash <= total {
			pe.TotalDetections = total
			pe.TruePositives = tp
			pe.FalsePositives = fp
			pe.CrashCount = crash
			pe.APKsSeenIn = apks
			pe.Measured = tp+fp > 0
			pe.DataSource = "feedback"
		}
	}

	// Calculate rates
	pe.CalculateRates()
	pe.PrecisionLower, pe.PrecisionUpper = wilsonInterval(pe.TruePositives, pe.TruePositives+pe.FalsePositives)

	// Calculate confidence and stability
	pe.Confidence = pea.calculateConfidence(pe)
	pe.Stability = pea.calculateStability(pe)

	// Classify tier (Requirements 1.3)
	pe.Tier, pe.TierReason = pea.classifyTier(pe)

	return pe
}

// wilsonInterval returns the 95% Wilson score interval for successes out of
// trials. With no trials it returns (0, 0); callers must consult Measured
// rather than treating the interval as an observed precision.
func wilsonInterval(successes, trials int) (lower, upper float64) {
	if trials <= 0 || successes < 0 || successes > trials {
		return 0, 0
	}
	const z = 1.96
	n := float64(trials)
	p := float64(successes) / n
	denom := 1 + z*z/n
	center := p + z*z/(2*n)
	margin := z * math.Sqrt(p*(1-p)/n+z*z/(4*n*n))
	lower = (center - margin) / denom
	upper = (center + margin) / denom
	if lower < 0 {
		lower = 0
	}
	if upper > 1 {
		upper = 1
	}
	return lower, upper
}

// calculateConfidence computes overall confidence in the pattern
func (pea *PatternEffectivenessAnalyzer) calculateConfidence(pe *PatternEffectiveness) float64 {
	if pe.TotalDetections == 0 {
		return 0.0
	}

	// Confidence based on sample size and accuracy
	sampleFactor := float64(pe.TotalDetections) / 100.0
	if sampleFactor > 1.0 {
		sampleFactor = 1.0
	}

	accuracyFactor := pe.TruePositiveRate

	confidence := (sampleFactor*0.3 + accuracyFactor*0.7)

	// Penalty for high crash rate
	if pe.CrashRate > 0.05 {
		confidence *= (1.0 - pe.CrashRate)
	}

	return confidence
}

// calculateStability computes consistency across APKs
func (pea *PatternEffectivenessAnalyzer) calculateStability(pe *PatternEffectiveness) float64 {
	if pe.APKsSeenIn == 0 {
		return 0.0
	}

	// Stability is high when pattern consistently performs well
	avgDetectionsPerAPK := float64(pe.TotalDetections) / float64(pe.APKsSeenIn)

	// Normalize to 0-1 range (assume 2-6 detections per APK is stable)
	stability := 0.5
	if avgDetectionsPerAPK >= 2.0 && avgDetectionsPerAPK <= 6.0 {
		stability = 0.9
	} else if avgDetectionsPerAPK < 2.0 {
		stability = 0.6
	} else {
		stability = 0.7
	}

	// Adjust for accuracy consistency
	stability *= pe.TruePositiveRate

	return stability
}

// classifyTier classifies pattern into effectiveness tier (Requirements 1.3, 1.5)
func (pea *PatternEffectivenessAnalyzer) classifyTier(pe *PatternEffectiveness) (PatternTier, string) {
	if pe.TruePositives+pe.FalsePositives < 20 {
		return TierUnknown, "Insufficient measured outcomes (need at least 20 labeled observations)"
	}
	successRate := pe.TruePositiveRate * 100.0
	fpRate := pe.FalsePositiveRate * 100.0
	crashRate := pe.CrashRate * 100.0

	// TRASH tier: <60% success OR >40% false positive OR >10% crash
	// These are the patterns that MUST be removed
	if successRate < 60.0 {
		return TierTrash, fmt.Sprintf("Low effectiveness: low success rate (%.1f%%)", successRate)
	}
	if fpRate > 40.0 {
		return TierTrash, fmt.Sprintf("Low effectiveness: high false positive rate (%.1f%%)", fpRate)
	}
	if crashRate > 10.0 {
		return TierTrash, fmt.Sprintf("Low effectiveness: high crash rate (%.1f%%)", crashRate)
	}

	// IMBA tier: >80% success, <10% false positive, <5% crash
	if successRate > 80.0 && fpRate < 10.0 && crashRate < 5.0 {
		return TierIMBA, fmt.Sprintf("High effectiveness: %.1f%% success rate, %.1f%% false positive rate", successRate, fpRate)
	}

	// NORMAL tier: everything else (60-80% success, or 10-40% FP, or 5-10% crash)
	return TierNormal, fmt.Sprintf("Acceptable effectiveness: %.1f%% success rate, %.1f%% false positive rate", successRate, fpRate)
}

// ═══════════════════════════════════════════════════════════════════════════════
// EFFECTIVENESS REPORT GENERATION
// ═══════════════════════════════════════════════════════════════════════════════

// EffectivenessReport contains analysis results for all patterns
type EffectivenessReport struct {
	UnknownCount     int                     `json:"unknown_count"`
	MeasuredPatterns int                     `json:"measured_patterns"`
	UnknownPatterns  []*PatternEffectiveness `json:"unknown_patterns"`
	GeneratedAt      time.Time               `json:"generated_at"`
	TotalPatterns    int                     `json:"total_patterns"`

	// Tier counts
	IMBACount   int `json:"imba_count"`
	NormalCount int `json:"normal_count"`
	TrashCount  int `json:"trash_count"`

	// Patterns by tier
	IMBAPatterns   []*PatternEffectiveness `json:"imba_patterns"`
	NormalPatterns []*PatternEffectiveness `json:"normal_patterns"`
	TrashPatterns  []*PatternEffectiveness `json:"trash_patterns"`

	// Summary statistics
	AvgTruePositiveRate  float64 `json:"avg_true_positive_rate"`
	AvgFalsePositiveRate float64 `json:"avg_false_positive_rate"`
	AvgCrashRate         float64 `json:"avg_crash_rate"`
}

// GenerateReport creates an effectiveness report for all patterns (Requirements 1.4)
func (pea *PatternEffectivenessAnalyzer) GenerateReport() *EffectivenessReport {
	allEffectiveness := pea.AnalyzeAll()

	report := &EffectivenessReport{
		GeneratedAt:    time.Now(),
		TotalPatterns:  len(allEffectiveness),
		IMBAPatterns:   make([]*PatternEffectiveness, 0),
		NormalPatterns: make([]*PatternEffectiveness, 0),
		TrashPatterns:  make([]*PatternEffectiveness, 0),
	}

	var sumTP, sumFP, sumCrash float64

	// Classify patterns by tier
	for _, pe := range allEffectiveness {
		if pe.Measured {
			report.MeasuredPatterns++
		}
		sumTP += pe.TruePositiveRate
		sumFP += pe.FalsePositiveRate
		sumCrash += pe.CrashRate

		switch pe.Tier {
		case TierUnknown:
			report.UnknownCount++
			report.UnknownPatterns = append(report.UnknownPatterns, pe)
		case TierIMBA:
			report.IMBAPatterns = append(report.IMBAPatterns, pe)
			report.IMBACount++
		case TierNormal:
			report.NormalPatterns = append(report.NormalPatterns, pe)
			report.NormalCount++
		case TierTrash:
			report.TrashPatterns = append(report.TrashPatterns, pe)
			report.TrashCount++
		}
	}

	// Calculate averages
	if report.MeasuredPatterns > 0 {
		report.AvgTruePositiveRate = sumTP / float64(report.MeasuredPatterns)
		report.AvgFalsePositiveRate = sumFP / float64(report.MeasuredPatterns)
		report.AvgCrashRate = sumCrash / float64(report.MeasuredPatterns)
	}

	// Sort each tier by effectiveness
	sort.Slice(report.IMBAPatterns, func(i, j int) bool {
		return report.IMBAPatterns[i].TruePositiveRate > report.IMBAPatterns[j].TruePositiveRate
	})
	sort.Slice(report.NormalPatterns, func(i, j int) bool {
		return report.NormalPatterns[i].TruePositiveRate > report.NormalPatterns[j].TruePositiveRate
	})
	sort.Slice(report.TrashPatterns, func(i, j int) bool {
		return report.TrashPatterns[i].FalsePositiveRate > report.TrashPatterns[j].FalsePositiveRate
	})

	return report
}

// RecommendRemoval identifies trash patterns for removal (Requirements 16.1)
func (pea *PatternEffectivenessAnalyzer) RecommendRemoval() []*VulnerablePattern {
	allEffectiveness := pea.AnalyzeAll()

	recommendations := make([]*VulnerablePattern, 0)

	for _, pattern := range pea.patterns {
		effectiveness, ok := allEffectiveness[pattern.ID]
		if !ok {
			continue
		}

		// Recommend removal if classified as trash
		if effectiveness.Tier == TierTrash {
			recommendations = append(recommendations, pattern)
		}
	}

	return recommendations
}

// ═══════════════════════════════════════════════════════════════════════════════
// REPORT FORMATTING
// ═══════════════════════════════════════════════════════════════════════════════

// FormatReport creates a human-readable report string
func FormatReport(report *EffectivenessReport) string {
	var output string

	output += "═══════════════════════════════════════════════════════════════════════════════\n"
	output += "PATTERN EFFECTIVENESS ANALYSIS REPORT\n"
	output += "═══════════════════════════════════════════════════════════════════════════════\n\n"

	output += fmt.Sprintf("Generated: %s\n", report.GeneratedAt.Format("2006-01-02 15:04:05"))
	output += fmt.Sprintf("Total Patterns Analyzed: %d\n\n", report.TotalPatterns)
	output += fmt.Sprintf("Unknown / insufficient observations: %d patterns\n", report.UnknownCount)
	if report.MeasuredPatterns == 0 {
		return output + "No measured outcomes. Effectiveness and crash rates are not evaluated.\n"
	}

	output += "TIER DISTRIBUTION:\n"
	output += fmt.Sprintf("  🔥 IMBA:             %d patterns (%.1f%%)\n", report.IMBACount, float64(report.IMBACount)/float64(report.TotalPatterns)*100)
	output += fmt.Sprintf("  ✅ NORMAL:            %d patterns (%.1f%%)\n", report.NormalCount, float64(report.NormalCount)/float64(report.TotalPatterns)*100)
	output += fmt.Sprintf("  🗑️  TRASH:             %d patterns (%.1f%%)\n\n", report.TrashCount, float64(report.TrashCount)/float64(report.TotalPatterns)*100)

	output += "AVERAGE METRICS:\n"
	output += fmt.Sprintf("  True Positive Rate:  %.1f%%\n", report.AvgTruePositiveRate*100)
	output += fmt.Sprintf("  False Positive Rate: %.1f%%\n", report.AvgFalsePositiveRate*100)
	output += fmt.Sprintf("  Crash Rate:          %.1f%%\n\n", report.AvgCrashRate*100)

	// IMBA patterns
	if len(report.IMBAPatterns) > 0 {
		output += "═══════════════════════════════════════════════════════════════════════════════\n"
		output += "🔥 IMBA PATTERNS - Highly Effective\n"
		output += "═══════════════════════════════════════════════════════════════════════════════\n\n"

		for i, pe := range report.IMBAPatterns {
			output += fmt.Sprintf("%d. %s\n", i+1, pe.PatternID)
			output += fmt.Sprintf("   Success Rate: %.1f%% | False Positive: %.1f%% | Crash: %.1f%%\n",
				pe.TruePositiveRate*100, pe.FalsePositiveRate*100, pe.CrashRate*100)
			output += fmt.Sprintf("   Reason: %s\n\n", pe.TierReason)
		}
	}

	// Normal patterns
	if len(report.NormalPatterns) > 0 {
		output += "═══════════════════════════════════════════════════════════════════════════════\n"
		output += "✅ NORMAL PATTERNS - Acceptable\n"
		output += "═══════════════════════════════════════════════════════════════════════════════\n\n"

		for i, pe := range report.NormalPatterns {
			output += fmt.Sprintf("%d. %s\n", i+1, pe.PatternID)
			output += fmt.Sprintf("   Success Rate: %.1f%% | False Positive: %.1f%% | Crash: %.1f%%\n",
				pe.TruePositiveRate*100, pe.FalsePositiveRate*100, pe.CrashRate*100)
			output += fmt.Sprintf("   Reason: %s\n\n", pe.TierReason)
		}
	}

	// Trash patterns
	if len(report.TrashPatterns) > 0 {
		output += "═══════════════════════════════════════════════════════════════════════════════\n"
		output += "🗑️  TRASH PATTERNS - Recommended for Removal\n"
		output += "═══════════════════════════════════════════════════════════════════════════════\n\n"

		for i, pe := range report.TrashPatterns {
			output += fmt.Sprintf("%d. %s ⚠️\n", i+1, pe.PatternID)
			output += fmt.Sprintf("   Success Rate: %.1f%% | False Positive: %.1f%% | Crash: %.1f%%\n",
				pe.TruePositiveRate*100, pe.FalsePositiveRate*100, pe.CrashRate*100)
			output += fmt.Sprintf("   Reason: %s\n\n", pe.TierReason)
		}
	}

	output += "═══════════════════════════════════════════════════════════════════════════════\n"

	return output
}
