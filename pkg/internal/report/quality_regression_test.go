package report

import (
	"fmt"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/finding"
	"mega-analyzer/pkg/internal/rating"
	"mega-analyzer/pkg/internal/types"
)

func TestReportRiskAndFindingOrderUseTypedEvidence(t *testing.T) {
	r := types.NewAnalysisResult("sample.apk")
	r.Stats.TotalMatches = 1000
	r.Stats.CriticalMatches = 1000
	r.MatchesByCategory[types.CategorySecurity] = 1000
	for i := 0; i < 250; i++ {
		r.Findings = append(r.Findings, finding.FromLegacy(finding.LegacyInput{
			Kind: finding.KindInventory, Category: "inventory", RuleID: fmt.Sprintf("inventory.%03d", i),
			Title: "Background inventory", Severity: "info", Evidence: "inventory",
			Location: finding.Location{File: fmt.Sprintf("asset-%d", i)}}))
	}
	r.Findings = append(r.Findings, finding.FromLegacy(finding.LegacyInput{
		Kind: finding.KindMalware, Category: "MALWARE_COMBO", RuleID: "capture_pin",
		Title: "PIN capture indicator", Severity: "high", Evidence: "credential capture",
		Location: finding.Location{File: "capture.smali"}}))
	r.RiskProfile = rating.ComputeResultProfile(r)
	view := NewViewBuilder(r, DefaultOptions()).Build()
	if view.Suspicion.Score != 70 || view.RiskSummary.OverallRisk != types.RiskHigh || view.Summary.RiskLevel != types.RiskHigh {
		t.Fatalf("inconsistent global risk: %d / %v / %v", view.Suspicion.Score, view.RiskSummary.OverallRisk, view.Summary.RiskLevel)
	}
	if view.TypedFindings[0].RuleID != "capture_pin" {
		t.Fatal("inventory crowded out the malware finding")
	}
	md := NewMarkdownRenderer(DefaultOptions()).Render(view)
	if !strings.Contains(md, "70/100") || !strings.Contains(md, "PIN capture indicator") {
		t.Fatal("Markdown omitted canonical risk or important evidence")
	}
	if strings.Contains(md, "Protected") || strings.Contains(view.Summary.Verdict, "protection") ||
		!strings.Contains(md, "priority flags") || !strings.Contains(md, "do not verify a protection mechanism") {
		t.Fatal("raw security patterns were presented as verified application protections")
	}
	html := NewHTMLReporter(r).BuildHTML()
	if !strings.Contains(html, ">70</text>") || !strings.Contains(html, "Actionable Findings by Category") {
		t.Fatal("HTML gauge/composition did not use the typed profile")
	}
	if strings.Contains(html, "high priority findings") || !strings.Contains(html, "Priority flags") || !strings.Contains(html, view.Summary.Verdict) {
		t.Fatal("HTML priority counter or verdict misrepresented raw pattern flags")
	}
}

func TestRecoveredNetworkIndicatorsAreVisibleAndDeduplicated(t *testing.T) {
	r := types.NewAnalysisResult("sample.apk")
	r.Files["smali/Loader.smali"] = &types.FileAnalysis{RecoveredArtifacts: []types.RecoveredArtifact{
		{Kind: "domain", Preview: "controller.example.org"},
		{Kind: "url", Preview: "https://controller.example.org/gate?token=do-not-display"},
		{Kind: "ip_address", Preview: "198.51.100.42"},
		{Kind: "domain", Preview: "com.buttonvpn.hjexqm"},
	}}
	r.Files["smali/Plain.smali"] = &types.FileAnalysis{Matches: []types.Match{{
		Categorized: types.Categorized{Category: types.CategoryNetworkEndpoint},
		Pattern:     "Server endpoint", Text: "https://plain.example.org/api",
	}}}
	view := NewViewBuilder(r, DefaultOptions()).Build()
	if len(view.NetworkIndicators) != 3 {
		t.Fatalf("network indicators = %#v", view.NetworkIndicators)
	}
	md := NewMarkdownRenderer(DefaultOptions()).Render(view)
	if !strings.Contains(md, "controller.example.org") || !strings.Contains(md, "plain.example.org") || !strings.Contains(md, "198.51.100.42") || strings.Contains(md, "do-not-display") {
		t.Fatal("network references missing or URL query disclosed")
	}
}
