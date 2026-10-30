package crackpoint

import (
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/cfg"
)

// ═══════════════════════════════════════════════════════════════════════════════
// New gate patterns — LVL, trial/expiry, anti-hooking, subscriptions
// ═══════════════════════════════════════════════════════════════════════════════

func TestFindCrackPoints_GoogleLVL(t *testing.T) {
	graph := simpleGraph([]cfg.InstructionRef{
		{Index: 0, Opcode: "invoke-virtual",
			Raw: "invoke-virtual {v0}, Lcom/android/vending/licensing/LicenseChecker;->checkAccess(Lcom/android/vending/licensing/LicenseCheckerCallback;)V"},
	})
	f := NewFinder()
	result := f.FindCrackPoints(graph, "Lcom/app/Main;")

	found := false
	for _, cp := range result.CrackPoints {
		if cp.Category == "license" {
			found = true
		}
	}
	if !found {
		t.Error("expected LVL checkAccess to be detected as a license crack point")
	}
}

func TestFindCrackPoints_TrialExpiry(t *testing.T) {
	graph := simpleGraph([]cfg.InstructionRef{
		{Index: 0, Opcode: "invoke-virtual",
			Raw: "invoke-virtual {v0}, Lcom/app/Trial;->isExpired()Z"},
	})
	f := NewFinder()
	result := f.FindCrackPoints(graph, "Lcom/app/Main;")

	if result.TotalFound == 0 {
		t.Fatal("expected isExpired to be detected")
	}
	if result.CrackPoints[0].Category != "license" {
		t.Errorf("expected category 'license', got %q", result.CrackPoints[0].Category)
	}
}

func TestFindCrackPoints_AntiHooking(t *testing.T) {
	graph := simpleGraph([]cfg.InstructionRef{
		{Index: 0, Opcode: "invoke-static",
			Raw: "invoke-static {}, Lcom/app/Security;->detectFrida()Z"},
	})
	f := NewFinder()
	result := f.FindCrackPoints(graph, "Lcom/app/Security;")

	if result.TotalFound == 0 {
		t.Fatal("expected detectFrida to be detected")
	}
	if result.CrackPoints[0].Category != "tamper" {
		t.Errorf("expected category 'tamper', got %q", result.CrackPoints[0].Category)
	}
}

func TestFindCrackPoints_SubscriptionBilling(t *testing.T) {
	graph := simpleGraph([]cfg.InstructionRef{
		{Index: 0, Opcode: "invoke-virtual",
			Raw: "invoke-virtual {v0}, Lcom/app/Billing;->isSubscriptionActive()Z"},
	})
	f := NewFinder()
	result := f.FindCrackPoints(graph, "Lcom/app/Billing;")

	if result.TotalFound == 0 {
		t.Fatal("expected isSubscriptionActive to be detected")
	}
	if result.CrackPoints[0].Category != "billing" {
		t.Errorf("expected category 'billing', got %q", result.CrackPoints[0].Category)
	}
}

func TestFindCrackPoints_LVLDenyCallback(t *testing.T) {
	graph := simpleGraph([]cfg.InstructionRef{
		{Index: 0, Opcode: "invoke-interface",
			Raw: "invoke-interface {v0}, Lcom/android/vending/licensing/LicenseCheckerCallback;->dontAllow(I)V"},
	})
	f := NewFinder()
	result := f.FindCrackPoints(graph, "Lcom/app/Main;")

	found := false
	for _, cp := range result.CrackPoints {
		if cp.Type == CrackPointCallback {
			found = true
		}
	}
	if !found {
		t.Error("expected dontAllow() to be detected as a callback crack point")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// dedupeCrackPoints
// ═══════════════════════════════════════════════════════════════════════════════

func TestDedupeCrackPoints_SameTypeCollapses(t *testing.T) {
	points := []CrackPoint{
		{ClassName: "Lcom/app;", MethodName: "isPremium", Category: "premium",
			Type: CrackPointGateMethod, NodeID: 1, Line: 0, Confidence: 0.85,
			Signals: []string{"Gate method pattern: ispremium"}},
		{ClassName: "Lcom/app;", MethodName: "isPremium", Category: "premium",
			Type: CrackPointGateMethod, NodeID: 1, Line: 0, Confidence: 0.95,
			Signals: []string{"Followed by boolean condition check"}},
	}

	out := dedupeCrackPoints(points)
	if len(out) != 1 {
		t.Fatalf("expected 1 crack point after dedup, got %d", len(out))
	}
	if out[0].Confidence != 0.95 {
		t.Errorf("expected merged confidence to keep max (0.95), got %.2f", out[0].Confidence)
	}
	if len(out[0].Signals) != 2 {
		t.Errorf("expected merged signals to keep both entries, got %v", out[0].Signals)
	}
}

func TestDedupeCrackPoints_DifferentTypePreserved(t *testing.T) {
	// Same location, but different Type (gate vs advanced-tamper classification)
	// must NOT be collapsed — they are complementary signals.
	points := []CrackPoint{
		{ClassName: "Lcom/app;", MethodName: "getClient", Category: "tamper",
			Type: CrackPointGateMethod, NodeID: 1, Line: 0, Confidence: 0.90},
		{ClassName: "Lcom/app;", MethodName: "getClient", Category: "tamper",
			Type: CrackPointInvokeResult, NodeID: 1, Line: 0, Confidence: 0.90},
	}

	out := dedupeCrackPoints(points)
	if len(out) != 2 {
		t.Fatalf("expected 2 distinct crack points (different Type), got %d", len(out))
	}
}

func TestDedupeCrackPoints_DifferentLocationPreserved(t *testing.T) {
	points := []CrackPoint{
		{ClassName: "Lcom/app;", MethodName: "isPremium", Category: "premium",
			Type: CrackPointGateMethod, NodeID: 1, Line: 0, Confidence: 0.85},
		{ClassName: "Lcom/app;", MethodName: "isPremium", Category: "premium",
			Type: CrackPointGateMethod, NodeID: 2, Line: 5, Confidence: 0.85},
	}

	out := dedupeCrackPoints(points)
	if len(out) != 2 {
		t.Fatalf("expected 2 crack points at different nodes, got %d", len(out))
	}
}

func TestDedupeCrackPoints_EndToEnd(t *testing.T) {
	// A SafetyNet invoke matches both the generic "safetynet" gate pattern
	// (scanForGateNodes) and the advanced-tamper pass — both are legitimate,
	// complementary detections and must both survive FindCrackPoints.
	graph := simpleGraph([]cfg.InstructionRef{
		{Index: 0, Opcode: "invoke-virtual",
			Raw: "invoke-virtual {v0}, Lcom/google/android/gms/safetynet/SafetyNet;->getClient()V"},
	})
	f := NewFinder()
	result := f.FindCrackPoints(graph, "Lcom/app;")

	gateCount, tamperInvokeCount := 0, 0
	for _, cp := range result.CrackPoints {
		if cp.Type == CrackPointGateMethod {
			gateCount++
		}
		if cp.Type == CrackPointInvokeResult {
			tamperInvokeCount++
		}
	}
	if gateCount == 0 || tamperInvokeCount == 0 {
		t.Errorf("expected both a gate-method and an invoke-result SafetyNet crack point, got gate=%d invoke=%d", gateCount, tamperInvokeCount)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// isNegativeGate + negation-aware suggestions
// ═══════════════════════════════════════════════════════════════════════════════

func TestIsNegativeGate(t *testing.T) {
	cases := map[string]bool{
		"isExpired":        true,
		"isTrialExpired":   true,
		"dontAllow":        true,
		"applicationError": true,
		"shouldShowAds":    true,
		"isRooted":         true,
		"isFrida":          true,
		"isPremium":        false,
		"isLicensed":       false,
		"checkAccess":      false,
	}
	for name, want := range cases {
		if got := isNegativeGate(name); got != want {
			t.Errorf("isNegativeGate(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestGenerateSuggestions_NegativeLicenseGate(t *testing.T) {
	f := NewFinder()
	result := &AnalysisResult{
		CrackPoints: []CrackPoint{
			{Category: "license", MethodName: "isExpired", ReturnType: "boolean"},
		},
	}
	f.generateSuggestions(result)
	cp := result.CrackPoints[0]

	if !strings.Contains(cp.SuggestedAction, "Return false") {
		t.Errorf("expected negative gate to suggest 'Return false', got %q", cp.SuggestedAction)
	}
}

func TestGenerateSuggestions_PositiveLicenseGateUnaffected(t *testing.T) {
	f := NewFinder()
	result := &AnalysisResult{
		CrackPoints: []CrackPoint{
			{Category: "license", MethodName: "isLicensed", ReturnType: "boolean"},
		},
	}
	f.generateSuggestions(result)
	cp := result.CrackPoints[0]

	if !strings.Contains(cp.SuggestedAction, "Return true") {
		t.Errorf("expected positive gate to still suggest 'Return true', got %q", cp.SuggestedAction)
	}
}

func TestGenerateSuggestions_NegativeAdsGate(t *testing.T) {
	f := NewFinder()
	result := &AnalysisResult{
		CrackPoints: []CrackPoint{
			{Category: "ads", MethodName: "shouldShowAds", ReturnType: "boolean"},
		},
	}
	f.generateSuggestions(result)
	cp := result.CrackPoints[0]

	if !strings.Contains(cp.SuggestedAction, "Return false") {
		t.Errorf("expected shouldShowAds to suggest 'Return false', got %q", cp.SuggestedAction)
	}
}

func TestGenerateSuggestions_AntiHookingTamper(t *testing.T) {
	f := NewFinder()
	result := &AnalysisResult{
		CrackPoints: []CrackPoint{
			{Category: "tamper", MethodName: "detectFrida"},
		},
	}
	f.generateSuggestions(result)
	cp := result.CrackPoints[0]

	if !strings.Contains(strings.ToLower(cp.SuggestedAction), "hook") &&
		!strings.Contains(strings.ToLower(cp.SuggestedAction), "instrument") {
		t.Errorf("expected anti-hooking-specific suggestion, got %q", cp.SuggestedAction)
	}
}

func TestGenerateSuggestions_LVLDenyCallback(t *testing.T) {
	f := NewFinder()
	result := &AnalysisResult{
		CrackPoints: []CrackPoint{
			{Category: "billing", MethodName: "dontAllow"},
		},
	}
	f.generateSuggestions(result)
	cp := result.CrackPoints[0]

	if !strings.Contains(cp.SuggestedAction, "NOP") {
		t.Errorf("expected dontAllow to suggest NOP-ing the callback, got %q", cp.SuggestedAction)
	}
}
