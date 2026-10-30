package report

import (
	"math"
	"sort"
	"strings"

	"mega-analyzer/pkg/internal/types"
)

// This file adds the *saturating* risk score that replaces the old linear
// `matches*2 + critical*5 + piracy*8 + confidence*15` composition for callers
// that opt in. The linear form (see score.go / SuspicionScore) is kept intact
// so existing surfaces and their golden tests stay byte-identical; new code can
// call SaturatingScore for a score that:
//
//  1. does NOT inflate on duplicate/fanned-out findings (the DEX string pool
//     fan-out that produced 769 near-identical piracy rows): each category is
//     dampened by u_c = 1 + ln(1 + occurrences_c), so 10 copies count far less
//     than 10x a single finding, and 100 copies barely more than 10;
//  2. weights categories by real risk (inert piracy-site URL = 0.2,
//     signature-spoof / integrity-tamper = 1.0) instead of one flat multiplier;
//  3. recognises a *neutralizer*: if the APK ships a signature killer / license
//     bypass, the protections are defeated, so the score is floored at 85 and
//     the security posture is reported as "neutralized" rather than the
//     inverted "Protected" badge (fixes B4).
//
// Formula:  S = 100 * (1 - exp(-k * Σ_c w_c * sev_c * u_c))

// saturationK tunes how fast the score approaches 100. A single critical
// signature finding (w=1.0, sev=1.4, u=1+ln2) lands ~0.69*100; a handful of
// independent high-risk categories saturate into the 90s.
const saturationK = 0.45

// neutralizerFloor is the minimum score once a protection bypass is present.
const neutralizerFloor = 85

// SaturatingBreakdown is the composition produced by SaturatingScore.
type SaturatingBreakdown struct {
	Score       int                        `json:"score"`              // 0..100
	Raw         float64                    `json:"raw"`                // Σ contributions pre-saturation
	Neutralized bool                       `json:"neutralized"`        // protection bypass present
	Status      string                     `json:"status"`             // clean|suspicious|dangerous|neutralized
	Triggers    []string                   `json:"triggers,omitempty"` // neutralizer evidence markers
	ByCategory  map[types.Category]float64 `json:"by_category,omitempty"`
}

// SaturatingScore derives the saturating risk score from an analysis result.
// It reads per-category occurrence counts from result.MatchesByCategory (the
// canonical counter maintained by AddMatch) so it never double-counts the
// individual fanned-out rows, and it scans match/piracy evidence for a
// protection neutralizer.
func SaturatingScore(result *types.AnalysisResult) SaturatingBreakdown {
	bd := SaturatingBreakdown{ByCategory: map[types.Category]float64{}, Status: "clean"}
	if result == nil {
		return bd
	}

	var sum float64
	for cat, occ := range result.MatchesByCategory {
		if occ <= 0 {
			continue
		}
		w := categoryWeight(cat)
		sev := categorySeverityMultiplier(cat)
		damp := 1.0 + math.Log(1.0+float64(occ)) // u_c
		contribution := w * sev * damp
		bd.ByCategory[cat] = contribution
		sum += contribution
	}

	// A dedicated piracy verdict, when present, contributes through its own
	// calibrated confidence rather than the raw (often inflated) link count.
	if result.Piracy != nil && result.Piracy.Confidence > 0 {
		sum += 0.2 * result.Piracy.Confidence * (1.0 + math.Log(1.0+float64(len(result.Piracy.Findings))))
	}

	bd.Raw = sum
	score := 100.0 * (1.0 - math.Exp(-saturationK*sum))
	bd.Score = int(math.Round(score))

	triggers := DetectNeutralizer(result)
	if len(triggers) > 0 {
		bd.Neutralized = true
		bd.Triggers = triggers
		if bd.Score < neutralizerFloor {
			bd.Score = neutralizerFloor
		}
	}

	bd.Score = minInt(bd.Score, 100)
	bd.Status = riskStatus(bd.Score, bd.Neutralized)
	return bd
}

func riskStatus(score int, neutralized bool) string {
	switch {
	case neutralized:
		return "neutralized"
	case score >= 70:
		return "dangerous"
	case score >= 30:
		return "suspicious"
	default:
		return "clean"
	}
}

// categoryWeight maps a finding category to its risk weight in [0,1]. Inert
// artefacts (piracy-site link dumps) are heavily discounted; active protection
// subversion is weighted full.
func categoryWeight(c types.Category) float64 {
	switch c {
	case types.CategoryPiracySite:
		return 0.2
	case types.CategorySignatureCheck, types.CategoryIntegrityCheck,
		types.CategoryTamperDetection, types.CategoryHashCheck:
		return 1.0
	case types.CategoryLicenseCheck, types.CategoryGoogleLVL,
		types.CategoryLicenseStorage, types.CategoryLicenseCallback:
		return 0.85
	case types.CategoryBillingClient, types.CategoryPurchaseVerify,
		types.CategoryPurchaseToken, types.CategoryBillingCallback:
		return 0.7
	case types.CategoryPremiumCheck, types.CategoryPremiumUnlock, types.CategoryProFeature:
		return 0.6
	default:
		return 0.5
	}
}

// categorySeverityMultiplier gives a per-category default severity multiplier.
// It intentionally uses the category (not per-match severity) so the score is
// stable regardless of how individual rows were tagged.
func categorySeverityMultiplier(c types.Category) float64 {
	switch c {
	case types.CategorySignatureCheck, types.CategoryIntegrityCheck,
		types.CategoryTamperDetection, types.CategoryHashCheck:
		return severityMultiplier(types.SeverityCritical)
	case types.CategoryLicenseCheck, types.CategoryGoogleLVL,
		types.CategoryLicenseStorage, types.CategoryLicenseCallback,
		types.CategoryBillingClient, types.CategoryPurchaseVerify,
		types.CategoryPurchaseToken, types.CategoryBillingCallback:
		return severityMultiplier(types.SeverityHigh)
	case types.CategoryPiracySite:
		return severityMultiplier(types.SeverityLow)
	default:
		return severityMultiplier(types.SeverityMedium)
	}
}

func severityMultiplier(s types.Severity) float64 {
	switch s {
	case types.SeverityCritical:
		return 1.4
	case types.SeverityHigh:
		return 1.0
	case types.SeverityMedium:
		return 0.7
	case types.SeverityLow:
		return 0.4
	default:
		return 0.2
	}
}

// neutralizerMarkers are substrings that betray an active protection bypass
// shipped inside the APK (signature killer, LVL bypass, PackageManager proxy).
// They are matched case-insensitively against match and piracy evidence.
var neutralizerMarkers = []string{
	"signaturekiller",
	"fakesignature",
	"initproxy",
	"hookapkpath",
	"killpm",
	"origin.apk",
	"lvl bypass",
	"license bypass",
	"dontallow", // LVL callback forced to allow / neutered deny path
}

// DetectNeutralizer scans match and piracy evidence for signs that a code
// protection (signature check, license verification, integrity check) has been
// actively defeated. It returns the distinct markers found, or nil.
func DetectNeutralizer(result *types.AnalysisResult) []string {
	if result == nil {
		return nil
	}
	seen := map[string]struct{}{}
	scan := func(s string) {
		if s == "" {
			return
		}
		ls := strings.ToLower(s)
		for _, mk := range neutralizerMarkers {
			if strings.Contains(ls, mk) {
				seen[mk] = struct{}{}
			}
		}
	}

	scanMatch := func(m types.Match) {
		scan(m.Text)
		scan(m.Pattern)
		scan(m.Context)
		scan(m.ResolvedContext)
		scan(m.EvidenceType)
		for k, v := range m.Metadata {
			scan(k)
			scan(v)
		}
	}

	for _, fa := range result.Files {
		if fa == nil {
			continue
		}
		for _, m := range fa.Matches {
			scanMatch(m)
		}
	}
	for _, m := range result.RuleMatches {
		scanMatch(m)
	}
	if result.Piracy != nil {
		for _, pf := range result.Piracy.Findings {
			scan(pf.Type)
			scan(pf.Pattern)
			scan(pf.Description)
		}
	}

	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for mk := range seen {
		out = append(out, mk)
	}
	sort.Strings(out)
	return out
}

// SecurityStatusLabel returns the dashboard security badge text, fixing the B4
// inversion where a bypassed app was still labelled "Protected". Pass the same
// `detected` flag the linear badge used (GroupSecurity presence).
func SecurityStatusLabel(result *types.AnalysisResult, detected bool) string {
	if len(DetectNeutralizer(result)) > 0 {
		return "Neutralized"
	}
	if detected {
		return "Protected"
	}
	return "None"
}
