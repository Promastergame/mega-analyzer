package rating

import (
	"fmt"
	"testing"

	"mega-analyzer/pkg/internal/finding"
	"mega-analyzer/pkg/internal/types"
)

func profileFinding(kind finding.Kind, category, rule, severity string) finding.Finding {
	return finding.FromLegacy(finding.LegacyInput{Kind: kind, Category: category,
		RuleID: rule, Title: rule, Severity: severity, Evidence: rule, Confidence: 0.9,
		Location: finding.Location{File: "sample.smali", Line: 12}})
}

func TestTypedProfileExcludesInventoryAndHardening(t *testing.T) {
	r := types.NewAnalysisResult("sample.apk")
	for i := 0; i < 500; i++ {
		r.Findings = append(r.Findings,
			profileFinding(finding.KindInventory, "MANIFEST_PERMISSION", "camera", "critical"),
			profileFinding(finding.KindHardening, "SSL_PINNING", "pinning", "high"))
	}
	if p := ComputeResultProfile(r); p.OverallScore != 0 || p.OverallLevel != "SAFE" {
		t.Fatalf("inventory/hardening produced risk: %#v", p)
	}
	malware := profileFinding(finding.KindMalware, "MALWARE_COMBO", "credential_capture", "critical")
	r.Findings = append(r.Findings, malware, malware)
	p := ComputeResultProfile(r)
	if p.OverallScore != 90 || p.Categories[CatMalware].Count != 1 || p.Categories[CatMalware].Level != "CRITICAL" {
		t.Fatalf("critical malware lost or duplicates inflated risk: %#v", p)
	}
}

func TestLegacyResultsWithoutTypedFindingsKeepFallback(t *testing.T) {
	r := types.NewAnalysisResult("legacy")
	if _, ok := ResultProfile(r); ok {
		t.Fatal("uncomputed empty profile replaced legacy score")
	}
	r.RiskProfile = ComputeResultProfile(r)
	if p, ok := ResultProfile(r); !ok || p.OverallScore != 0 {
		t.Fatalf("computed empty profile = %#v / %v", p, ok)
	}
}

// An incomplete run (data-flow budget) must not present an unconditional
// CRITICAL: the score is capped at the HIGH band and the profile is flagged.
func TestIncompleteRunIsInconclusiveAndCapped(t *testing.T) {
	r := types.NewAnalysisResult("sample.apk")
	r.Findings = append(r.Findings,
		profileFinding(finding.KindVulnerability, "C2", "c2_transfer", "critical"))
	r.DataFlowStats.SliceLimitReached = true
	p := ComputeResultProfile(r)
	if !p.Inconclusive || p.InconclusiveReason == "" {
		t.Fatalf("truncated run must be inconclusive: %#v", p)
	}
	if p.OverallScore > 84 || p.OverallLevel == "CRITICAL" {
		t.Fatalf("inconclusive run kept CRITICAL score: %#v", p)
	}
}

// "Risk 100/100 at Confidence 12%" is a contradiction: with hotspots present
// and mean confidence below 0.25 the score is capped and flagged.
func TestLowConfidenceCriticalIsCapped(t *testing.T) {
	r := types.NewAnalysisResult("sample.apk")
	r.Findings = append(r.Findings,
		profileFinding(finding.KindVulnerability, "C2", "c2_transfer", "critical"))
	// Many weakly-corroborated hotspots (low critical ratio, low scores).
	for i := 0; i < 40; i++ {
		r.Hotspots = append(r.Hotspots, types.Hotspot{
			Path:  fmt.Sprintf("smali/com/app/F%d.smali", i),
			Score: 20, MatchCount: 100, CriticalCount: 1,
		})
	}
	p := ComputeResultProfile(r)
	conf := MeanHotspotConfidence(r.Hotspots)
	if conf >= 0.25 {
		t.Fatalf("test premise broken: confidence %v", conf)
	}
	if !p.Inconclusive || p.OverallScore > 84 {
		t.Fatalf("low-confidence CRITICAL must be capped and flagged: %#v", p)
	}
}

// A well-corroborated critical verdict (high confidence, complete run) keeps
// its CRITICAL level.
func TestCompleteRunKeepsCritical(t *testing.T) {
	r := types.NewAnalysisResult("sample.apk")
	r.Findings = append(r.Findings,
		profileFinding(finding.KindMalware, "RAT", "reverse_shell", "critical"))
	r.Hotspots = []types.Hotspot{{
		Path: "a.smali", Score: 90, MatchCount: 10, CriticalCount: 10,
		DecisionPoints: []types.DecisionPoint{{Confidence: 0.9}, {Confidence: 0.95}},
	}}
	p := ComputeResultProfile(r)
	if p.Inconclusive || p.OverallLevel != "CRITICAL" {
		t.Fatalf("confirmed critical downgraded: %#v", p)
	}
}
