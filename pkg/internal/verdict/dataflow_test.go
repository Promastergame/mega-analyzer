package verdict

import (
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func TestDataFlowIncompleteReasons(t *testing.T) {
	ResetDegradations()
	t.Cleanup(ResetDegradations)
	cases := []struct {
		name  string
		stats types.DataFlowStats
		want  string
	}{
		{"limit", types.DataFlowStats{LimitReached: true}, "data-flow analysis limit reached"},
		{"methods", types.DataFlowStats{MethodsTruncated: 19}, "19 method(s) skipped by data-flow limits"},
		{"slice limit", types.DataFlowStats{SliceLimitReached: true}, "data-flow slicing limit reached"},
		{"slices", types.DataFlowStats{SlicesTruncated: 2}, "2 slice(s) truncated"},
		{"cfg", types.DataFlowStats{CFGIncompleteMethods: 3}, "3 method(s) have incomplete control-flow graphs"},
		{"cancelled", types.DataFlowStats{Cancelled: true}, "data-flow analysis cancelled"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := clean()
			r.DataFlowStats = tc.stats
			for _, severity := range []types.Severity{types.SeverityInfo, types.SeverityHigh, types.SeverityCritical} {
				r.RuleMatches = nil
				wantCode := Incomplete
				if severity != types.SeverityInfo {
					r.RuleMatches = []types.Match{matchWith(severity)}
				}
				if severity == types.SeverityCritical {
					wantCode = Hostile
				}
				a := Assess(r, Options{})
				if a.Code != wantCode || !strings.Contains(a.Summary(), tc.want) {
					t.Errorf("severity %v: got %+v, want code %v and reason %q", severity, a, wantCode, tc.want)
				}
			}
		})
	}
}

func TestDataFlowCompletedIsNotIncomplete(t *testing.T) {
	ResetDegradations()
	t.Cleanup(ResetDegradations)
	r := clean()
	r.DataFlowStats = types.DataFlowStats{
		MethodsDiscovered: 4, MethodsAnalyzed: 4, SliceSteps: 20,
		UnreachableSinksSkipped: 2, ObservationsOmitted: 1,
	}
	if a := Assess(r, Options{}); a.Code != Clean || len(a.Incomplete) != 0 {
		t.Fatalf("completed analysis must remain clean: %+v", a)
	}
}
