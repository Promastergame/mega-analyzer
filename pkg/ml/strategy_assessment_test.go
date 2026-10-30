package ml

import (
	"testing"

	"mega-analyzer/pkg/ml/internal/shared"
)

func TestAssessStrategyRejectsUnsafeWholeBodyFlow(t *testing.T) {
	strategy := NewReturnTrueStrategy()
	mi := &shared.MethodInfo{
		Name: "isValid", ReturnType: "Z", ReturnsBoolean: true,
		RawBody: []string{":try_start_0", ".catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0"},
	}
	a := assessStrategy(strategy, mi, PatchModeDefensive)
	if a.Applicable {
		t.Fatalf("strategy should be blocked: %+v", a)
	}
}

func TestInferMethodRole(t *testing.T) {
	if got := inferMethodRole(&shared.MethodInfo{ReturnType: "Z", ReturnsBoolean: true}); got != MethodRoleBooleanGate {
		t.Fatalf("role=%q", got)
	}
	if got := inferMethodRole(&shared.MethodInfo{IsCallback: true, ReturnType: "V"}); got != MethodRoleCallback {
		t.Fatalf("role=%q", got)
	}
}

func TestDefaultStrategiesExposeMetadata(t *testing.T) {
	selector := NewStrategySelector()
	for _, strategy := range selector.GetStrategies() {
		describer, ok := strategy.(StrategyDescriber)
		if !ok {
			t.Errorf("%T does not expose StrategyMetadata", strategy)
			continue
		}
		metadata := describer.Metadata()
		if metadata.ID == "" {
			t.Errorf("%T has empty metadata ID", strategy)
		}
	}
}

func TestDetectSDKInventoryReportsLibrary(t *testing.T) {
	ci := &ClassInfo{ClassName: "Lcom/google/android/gms/ads/AdView;", FilePath: "smali/com/google/android/gms/ads/AdView.smali"}
	matches := DetectSDKInventory(ci)
	if len(matches) == 0 || matches[0].Ownership != SDKOwnershipLibrary {
		t.Fatalf("matches=%+v", matches)
	}
}

func TestDetectSDKInventoryReportsWrapper(t *testing.T) {
	ci := &ClassInfo{
		ClassName: "Lcom/example/app/AdsWrapper;",
		FilePath:  "smali/com/example/app/AdsWrapper.smali",
		Methods: []MethodInfo{{
			ClassName:     "Lcom/example/app/AdsWrapper;",
			FullSignature: "show()V",
			Calls:         []CallInfo{{FullCall: "Lcom/google/android/gms/ads/InterstitialAd;->show()V"}},
		}},
	}
	matches := DetectSDKInventory(ci)
	if len(matches) == 0 || matches[0].Ownership != SDKOwnershipWrapper {
		t.Fatalf("matches=%+v", matches)
	}
}
