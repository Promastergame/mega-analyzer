package report

import (
	"mega-analyzer/pkg/internal/types"
	"strings"
	"testing"
)

func TestStandaloneBundleDoesNotClaimLowAPKRisk(t *testing.T) {
	result := makeResultWithData()
	result.BundleAnalysis = &types.BundleAnalysisSummary{Standalone: true, Status: "partial", Files: 1, StringsTotal: 20, StringsScanned: 20, Observations: 5, Verdict: "NOT ASSESSED", ElapsedSeconds: 2}
	result.StaticOutputs = []types.StaticOutputStage{{Stage: "bundle_export", Status: "partial", Export: &types.HermesExportCoverage{TotalFunctions: 100, DecodedFunctions: 5, LimitReason: "functions"}}}
	html := NewHTMLReporter(result).BuildHTML()
	md := NewMarkdownRenderer(DefaultOptions()).Render(NewViewBuilder(result, DefaultOptions()).Build())
	for _, text := range []string{html, md} {
		for _, want := range []string{"NOT ASSESSED", "5 / 100", "Strings scanned: 20 / 20", "Limit reached: functions"} {
			if !strings.Contains(text, want) {
				t.Fatalf("missing %s", want)
			}
		}
		for _, bad := range []string{"LOW RISK", "Overall Risk:", "Risk Score:", "Files Analyzed"} {
			if strings.Contains(text, bad) {
				t.Fatalf("misleading %s", bad)
			}
		}
	}
}
