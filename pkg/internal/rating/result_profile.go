package rating

import (
	"encoding/json"
	"strings"

	"mega-analyzer/pkg/internal/finding"
	"mega-analyzer/pkg/internal/types"
)

// ResultProfile returns the score used by every report surface. Serialized
// profiles are supported when existing JSON is rendered again.
func ResultProfile(result *types.AnalysisResult) (RiskProfile, bool) {
	if result == nil {
		return RiskProfile{}, false
	}
	if len(result.Findings) > 0 {
		return ComputeResultProfile(result), true
	}
	switch profile := result.RiskProfile.(type) {
	case RiskProfile:
		return profile, true
	case *RiskProfile:
		if profile != nil {
			return *profile, true
		}
	case map[string]interface{}:
		if _, ok := profile["overall_score"]; ok {
			data, err := json.Marshal(profile)
			var decoded RiskProfile
			if err == nil && json.Unmarshal(data, &decoded) == nil {
				return decoded, true
			}
		}
	}
	return RiskProfile{}, false
}

// ComputeResultProfile scores actionable typed findings. Inventory and
// hardening describe capabilities or protections, not application defects.
// Raw match counts and repeated translations must not increase their risk.
func ComputeResultProfile(result *types.AnalysisResult) RiskProfile {
	var classified []types.ClassifiedFinding
	if result != nil {
		items := finding.Dedupe(result.Findings)
		for _, item := range items {
			if item.Kind != finding.KindMalware && item.Kind != finding.KindVulnerability {
				continue
			}
			score := findingSeverityScore(item.Severity)
			if score == 0 {
				continue
			}
			category := types.Category(item.Category)
			if item.Kind == finding.KindMalware && MapCategory(category) == CatSecurity {
				category = types.CategoryMalware
			}
			classified = append(classified, types.ClassifiedFinding{
				Verdict:    types.VerdictConfirmedAppRisk,
				FinalScore: score,
				Original: &types.Match{
					Categorized:    types.Categorized{Category: category},
					SourceLocation: types.SourceLocation{File: item.Fingerprint},
					Pattern:        item.RuleID,
				},
			})
		}
	}
	profile := ComputeProfile(classified)
	if result != nil {
		applyEvidenceLimits(result, &profile)
	}
	return profile
}

// inconclusiveScoreCap is the highest score an inconclusive run may report.
// 84 is the top of the HIGH band: evidence that is incomplete or weakly
// corroborated can still say "HIGH risk", never an unconditional CRITICAL.
const inconclusiveScoreCap = 84

// applyEvidenceLimits reconciles the score with its own evidence quality.
// Two conditions make a verdict inconclusive:
//   - the run hit a coverage or data-flow budget, so unanalyzed code could
//     change the answer ("315 analyzed of 313 total" and truncated slicing
//     must not be reported as a final CRITICAL);
//   - the mean hotspot confidence is very low while the score claims the
//     maximum — "Risk 100/100 at Confidence 12%" is a contradiction, so the
//     score is capped at the HIGH band and the profile is flagged.
func applyEvidenceLimits(result *types.AnalysisResult, profile *RiskProfile) {
	if profile == nil {
		return
	}
	var reasons []string

	if result.DataFlowStats.SliceLimitReached || result.DataFlowStats.Cancelled ||
		result.DataFlowStats.LimitReached || result.DataFlowStats.SlicesTruncated > 0 {
		reasons = append(reasons,
			"data-flow slicing hit its analysis budget; paths were truncated, so the retained evidence is incomplete")
	}
	if result.Coverage.LimitReached {
		reasons = append(reasons,
			"file coverage limit reached; parts of the archive were not analyzed")
	}
	if result.Run != nil && result.Run.Status == "incomplete" {
		reasons = append(reasons,
			"run stopped before full coverage ("+result.Run.StopReason+")")
	}
	// The neuroclassifier is the confirmation layer: with it unavailable the
	// static score carries the whole verdict, so flag the degradation.
	if result.GNNDiagnostics != nil && result.GNNDiagnostics.Status == "unavailable" {
		reasons = append(reasons,
			"neuroclassifier (GNN) unavailable; ML confirmation did not run")
	}
	// Only compare confidence against the score when hotspots exist: an
	// empty hotspot list means "confidence not measured", not "weak
	// evidence" (typed-finding-only results, legacy and unit-test paths).
	if len(result.Hotspots) > 0 {
		confidence := MeanHotspotConfidence(result.Hotspots)
		if confidence < 0.25 && profile.OverallScore >= 85 {
			reasons = append(reasons,
				"evidence confidence is low relative to the claimed score")
		}
	}

	if len(reasons) == 0 {
		return
	}
	profile.Inconclusive = true
	profile.InconclusiveReason = strings.Join(reasons, "; ")
	if profile.OverallScore > inconclusiveScoreCap {
		profile.OverallScore = inconclusiveScoreCap
		profile.OverallLevel = LevelForScore(profile.OverallScore)
		for key, cat := range profile.Categories {
			// A capped overall verdict cannot keep CRITICAL category levels.
			if cat.Score > 8 {
				cat.Score = 8
				cat.Level = "HIGH"
				profile.Categories[key] = cat
			}
		}
	}
}

// MeanHotspotConfidence is the report-side evidence-confidence metric
// (mean over hotspots of decision-point confidence, or critical-ratio and
// score blend), shared with rating so score and confidence can never be
// computed from different rules.
func MeanHotspotConfidence(hotspots []types.Hotspot) float64 {
	if len(hotspots) == 0 {
		return 0
	}
	var sum float64
	for _, hs := range hotspots {
		sum += HotspotConfidence(hs)
	}
	return sum / float64(len(hotspots))
}

// HotspotConfidence mirrors the historical report heuristic: decision-point
// confidence when available, otherwise a blend of critical ratio and score.
func HotspotConfidence(hs types.Hotspot) float64 {
	var sum float64
	count := 0
	for _, dp := range hs.DecisionPoints {
		if dp.Confidence > 0 {
			sum += dp.Confidence
			count++
		}
	}
	if count > 0 {
		return clamp01(sum / float64(count))
	}
	if hs.MatchCount > 0 {
		critRatio := float64(hs.CriticalCount) / float64(hs.MatchCount)
		return clamp01(critRatio*0.6 + clamp01(hs.Score/100)*0.4)
	}
	return clamp01(hs.Score / 100)
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

// LevelForScore maps a 0-100 score back to its band label.
func LevelForScore(score int) string {
	switch {
	case score >= 85:
		return "CRITICAL"
	case score >= 65:
		return "HIGH"
	case score >= 35:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	default:
		return "SAFE"
	}
}

func findingSeverityScore(value string) float64 {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical":
		return 90
	case "high":
		return 70
	case "medium":
		return 40
	case "low":
		return 10
	default:
		return 0
	}
}
