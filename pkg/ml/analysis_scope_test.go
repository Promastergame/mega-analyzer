package ml

import "testing"

func TestDefaultReviewPolicyNeverAllowsApply(t *testing.T) {
	for _, scope := range []AnalysisScope{ScopeAudit, ScopeDefensive, ScopeTestFixture} {
		policy := DefaultReviewPolicy(scope)
		if policy.AllowApply || !policy.ReviewRequired || !policy.DiagnosticOnly {
			t.Fatalf("unsafe policy for %q: %+v", scope, policy)
		}
	}
}

func TestClassifyServerDependency(t *testing.T) {
	if got := ClassifyServerDependency(&MethodInfo{Name: "verifyReceipt", SecurityCalls: []string{"verifySignature"}}); got != ServerDependencySigned {
		t.Fatalf("dependency=%q", got)
	}
	if got := ClassifyServerDependency(&MethodInfo{Name: "checkAttestation", SecurityCalls: []string{"StrongBox"}}); got != ServerDependencyHardware {
		t.Fatalf("dependency=%q", got)
	}
}

func TestBuildDefensiveRecommendations(t *testing.T) {
	recs := BuildDefensiveRecommendations(&MethodInfo{Name: "load", StringConsts: []string{"http://example.test", "MD5"}})
	if len(recs) != 2 || !recs[0].ReviewOnly || !recs[1].ReviewOnly {
		t.Fatalf("recommendations=%+v", recs)
	}
}
