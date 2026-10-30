package verdict

import (
	"mega-analyzer/pkg/internal/types"
	"testing"
)

func TestExplicitIncompleteStatusesAndFindingPriority(t *testing.T) {
	ResetDegradations()
	t.Cleanup(ResetDegradations)
	for _, status := range []string{"incomplete", "partial", "failed", "unsupported", "interrupted"} {
		for _, source := range []string{"run", "bundle", "output"} {
			t.Run(source+"/"+status, func(t *testing.T) {
				r := clean()
				switch source {
				case "run":
					r.Run = &types.RunMetadata{Status: status, StopReason: "test_limit"}
				case "bundle":
					r.BundleAnalysis = &types.BundleAnalysisSummary{Standalone: true, Status: status}
				case "output":
					r.StaticOutputs = []types.StaticOutputStage{{Stage: "export", Status: status}}
				}
				if a := Assess(r, Options{}); a.Code != Incomplete || len(a.Incomplete) == 0 {
					t.Fatalf("%+v", a)
				}
				r.RuleMatches = []types.Match{matchWith(types.SeverityCritical)}
				if a := Assess(r, Options{}); a.Code != Hostile {
					t.Fatalf("lost fail-level finding: %+v", a)
				}
			})
		}
	}
}

func TestCompleteBundlePreservesScope(t *testing.T) {
	r := clean()
	r.Run = &types.RunMetadata{Status: "complete"}
	r.BundleAnalysis = &types.BundleAnalysisSummary{Standalone: true, Status: "complete", Verdict: "NOT ASSESSED — standalone bundle scope only"}
	r.StaticOutputs = []types.StaticOutputStage{{Stage: "export", Status: "complete"}, {Stage: "patch", Status: "scan_only"}, {Stage: "discovery", Status: "not_found"}}
	if a := Assess(r, Options{}); a.Code != Clean {
		t.Fatalf("%+v", a)
	}
	if !r.BundleAnalysis.Standalone || r.BundleAnalysis.Verdict == "" {
		t.Fatal("scope lost")
	}
}
