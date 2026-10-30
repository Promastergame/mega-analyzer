package report

import (
	"math"

	"mega-analyzer/pkg/internal/types"
)

// piracySiteDiscount folds piracy-site URL matches down to 1 signal per 10
// matches when feeding the pattern/critical buckets. Those matches are inert
// URL strings (nothing executes), so a large link dump alone must not
// saturate the risk score.
const piracySiteDiscount = 10

// SuspicionBreakdown is the canonical 0-100 risk score composition. The CLI
// gauge, the HTML gauge and the Markdown "Risk Score" line all read from it,
// so every surface reports the same number.
type SuspicionBreakdown struct {
	PatternMatches   int     // up to 30
	CriticalFindings int     // up to 30
	PiracyIndicators int     // up to 25
	ConfidenceBoost  int     // up to 15
	Confidence       float64 // 0..1, average hotspot confidence
	Score            int     // clamped sum of the four buckets
}

// SuspicionScore derives the canonical breakdown straight from the analysis
// result, with piracy-site URL matches discounted (see piracySiteDiscount).
func SuspicionScore(result *types.AnalysisResult) SuspicionBreakdown {
	piracySites := result.MatchesByCategory[types.CategoryPiracySite]
	// Keep ceil(piracySites/piracySiteDiscount) of them, drop the rest.
	removed := piracySites - (piracySites+piracySiteDiscount-1)/piracySiteDiscount
	matches := result.Stats.TotalMatches - removed
	critical := result.Stats.CriticalMatches
	if types.CategoryPiracySite.IsCritical() {
		critical -= removed
	}
	// Sidecar findings (JAR bytecode rows, native crack-point rows, APK
	// artifact rows) never entered the file-match stats, so a stealer whose
	// only signals are deep-scan rows scored 0/100. Fold them in: non-info
	// rows count as pattern matches, critical rows as criticals. INFO rows
	// (mod inventory, URL inventory) are explicitly excluded so inventory
	// alone can never raise the score.
	artifactPeak := 0
	for _, af := range result.ArtifactFindings {
		switch af.Severity {
		case types.SeverityCritical:
			matches++
			critical++
			artifactPeak = maxInt(artifactPeak, 25)
		case types.SeverityHigh:
			matches++
			artifactPeak = maxInt(artifactPeak, 15)
		case types.SeverityMedium:
			matches++
			artifactPeak = maxInt(artifactPeak, 5)
		case types.SeverityLow:
			matches++
		}
	}
	if matches < 0 {
		matches = 0
	}
	if critical < 0 {
		critical = 0
	}

	piracyFindings := 0
	piracyConfidence := -1.0 // unknown: the piracy detector produced no verdict
	if result.Piracy != nil {
		piracyFindings = len(result.Piracy.Findings)
		piracyConfidence = result.Piracy.Confidence
	}

	var confidence float64
	if len(result.Hotspots) > 0 {
		var sum float64
		for _, hs := range result.Hotspots {
			sum += estimateConfidence(hs)
		}
		confidence = sum / float64(len(result.Hotspots))
	}

	piracyBucket := minInt(piracyFindings*8, 25)
	if piracyConfidence >= 0 {
		// Keep this bucket consistent with the dedicated "Piracy Detection"
		// scorer: its calibrated confidence caps the contribution. A dump of
		// inert piracy-site links (detector verdict LOW / ~10%) can no longer
		// saturate the composition at 25/25 while the detector disagrees.
		scaled := int(math.Round(piracyConfidence * 25))
		if scaled < piracyBucket {
			piracyBucket = scaled
		}
	}

	b := SuspicionBreakdown{
		PatternMatches:   minInt(matches*2, 30),
		CriticalFindings: minInt(critical*5, 30),
		PiracyIndicators: piracyBucket,
		ConfidenceBoost:  int(confidence * 15),
		Confidence:       confidence,
	}
	b.Score = minInt(b.PatternMatches+b.CriticalFindings+b.PiracyIndicators+b.ConfidenceBoost, 100)
	// Peak-severity floor: a single HIGH sidecar primitive (OS command
	// execution, deserialization sink, native load) guarantees minimum
	// attention even when it is the only signal in the whole target.
	if artifactPeak > b.Score {
		b.Score = artifactPeak
	}
	return b
}

// computeSuspicionScore is the raw bucket formula. It is kept as the single
// documented source of the weights; SuspicionScore applies it to a result.
func computeSuspicionScore(totalMatches, criticalMatches, piracyFindings int, confidence float64) int {
	score := 0
	score += minInt(totalMatches*2, 30)    // Pattern matches: up to 30
	score += minInt(criticalMatches*5, 30) // Critical findings: up to 30
	score += minInt(piracyFindings*8, 25)  // Piracy indicators: up to 25
	score += int(confidence * 15)          // Confidence boost: up to 15
	return minInt(score, 100)
}
