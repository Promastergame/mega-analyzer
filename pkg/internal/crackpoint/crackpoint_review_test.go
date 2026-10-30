package crackpoint

import (
	"mega-analyzer/pkg/internal/cfg"
	"testing"
)

// Review round: threshold single-source-of-truth, noise filter on every
// invoke path, new root/billing/debug/jailbreak patterns, and the removal
// of the __stack_chk_fail pseudo-gate.

func TestReviewHighConfidenceThresholdBoundary(t *testing.T) {
	// isadmobloaded (0.70) sits below the threshold, getdaysleft (0.75)
	// sits exactly on it.
	graph := simpleGraph([]cfg.InstructionRef{
		{Index: 0, Opcode: "invoke-static", Raw: "invoke-static {}, Lcom/ads;->isAdMobLoaded()Z"},
		{Index: 1, Opcode: "invoke-static", Raw: "invoke-static {}, Lcom/lic;->getDaysLeft()I"},
	})
	res := NewFinder().FindCrackPoints(graph, "Lcom/app;")
	if res.TotalFound != 2 {
		t.Fatalf("expected 2 points, got %d", res.TotalFound)
	}
	if res.HighConfidence != 1 {
		t.Errorf("expected exactly 1 high-confidence point (>= %.2f), got %d",
			HighConfidenceThreshold, res.HighConfidence)
	}
}

func TestReviewAdvancedTamperSkipsNoisySDK(t *testing.T) {
	raw := "invoke-static {v0}, Lcom/appsflyer/attribution/Tracker;->checkSafetyNet()Z"
	noisy := simpleGraph([]cfg.InstructionRef{{Index: 0, Opcode: "invoke-static", Raw: raw}})
	if res := NewFinder().FindCrackPoints(noisy, "Lcom/app;"); res.TotalFound != 0 {
		t.Errorf("noisy SDK invoke should yield 0 points, got %d", res.TotalFound)
	}
	clean := simpleGraph([]cfg.InstructionRef{{
		Index: 0, Opcode: "invoke-static",
		Raw: "invoke-static {v0}, Lcom/app/Attest;->checkSafetyNet()Z",
	}})
	if res := NewFinder().FindCrackPoints(clean, "Lcom/app;"); res.TotalFound == 0 {
		t.Error("non-SDK safetynet invoke should still be flagged")
	}
}

func TestReviewSymbolsSkipsNoisySDK(t *testing.T) {
	f := NewFinder()
	noisy := []SymbolRef{{
		Name: "verifyPurchase",
		Raw:  "Lcom/appsflyer/billing/Helper;->verifyPurchase(Ljava/lang/String;)Z",
		Kind: SymbolMethod,
	}}
	if res := f.FindCrackPointsInSymbols(noisy, "app.apk", PlatformJVM); res.TotalFound != 0 {
		t.Errorf("noisy SDK symbol should yield 0 points, got %d", res.TotalFound)
	}
	// The AppsFlyer LVL exception: that module IS license verification.
	lvl := []SymbolRef{{
		Name: "checkAccess",
		Raw:  "Lcom/appsflyer/lvl/LVL;->checkAccess()Z",
		Kind: SymbolMethod,
	}}
	if res := f.FindCrackPointsInSymbols(lvl, "app.apk", PlatformJVM); res.TotalFound == 0 {
		t.Error("AppsFlyer LVL symbol must remain eligible")
	}
}

func TestReviewNewGatePatterns(t *testing.T) {
	cases := []struct {
		raw      string
		category string
		conf     float64
	}{
		// Class path carries the signal; method name alone matches nothing.
		{"invoke-static {}, Lcom/scottyab/rootbeer/Utils;->foo()Z", "root", 0.88},
		{"invoke-static {}, Lcom/billing/Client;->queryProductDetailsAsync()V", "billing", 0.80},
		{"invoke-static {}, Lcom/sec/Device;->isAdbEnabled()Z", "debug", 0.80},
	}
	for _, tc := range cases {
		graph := simpleGraph([]cfg.InstructionRef{{Index: 0, Opcode: "invoke-static", Raw: tc.raw}})
		res := NewFinder().FindCrackPoints(graph, "Lcom/app;")
		if res.TotalFound == 0 {
			t.Errorf("%q: expected a crack point, got none", tc.raw)
			continue
		}
		cp := res.CrackPoints[0]
		if cp.Category != tc.category {
			t.Errorf("%q: category = %q, want %q", tc.raw, cp.Category, tc.category)
		}
		if cp.Confidence != tc.conf {
			t.Errorf("%q: confidence = %.2f, want %.2f", tc.raw, cp.Confidence, tc.conf)
		}
	}
}

func TestReviewNewNativeIOSPatterns(t *testing.T) {
	f := NewFinder()
	native := []SymbolRef{
		{Name: "zygisk", Kind: SymbolString},
		{Name: "KernelSU daemon", Kind: SymbolString},
		{Name: "APatch module", Kind: SymbolString},
		{Name: "adb_enabled", Kind: SymbolString},
	}
	res := f.FindCrackPointsInSymbols(native, "libapp.so", PlatformNative)
	cats := map[string]int{}
	for _, cp := range res.CrackPoints {
		cats[cp.Category]++
	}
	if cats["root"] != 3 {
		t.Errorf("expected 3 native root points, got %v", cats)
	}
	if cats["debug"] != 1 {
		t.Errorf("expected 1 native debug point, got %v", cats)
	}
	ios := []SymbolRef{
		{Name: "palera1n loader", Kind: SymbolString},
		{Name: "Dopamine jailbreak", Kind: SymbolString},
	}
	res = f.FindCrackPointsInSymbols(ios, "App.app/App", PlatformIOS)
	if len(res.CrackPoints) != 2 {
		t.Fatalf("expected 2 iOS tamper points, got %d", len(res.CrackPoints))
	}
	for _, cp := range res.CrackPoints {
		if cp.Category != "tamper" {
			t.Errorf("expected tamper, got %q", cp.Category)
		}
		if cp.SuggestedPatch != "" {
			t.Errorf("iOS point must not carry a smali patch, got %q", cp.SuggestedPatch)
		}
	}
}

func TestReviewStackChkFailIsNotAGate(t *testing.T) {
	syms := []SymbolRef{{Name: "__stack_chk_fail", Kind: SymbolImport}}
	res := NewFinder().FindCrackPointsInSymbols(syms, "a.out", PlatformNative)
	if res.TotalFound != 0 {
		t.Errorf("__stack_chk_fail is stack protection, not a gate: got %d points", res.TotalFound)
	}
}
