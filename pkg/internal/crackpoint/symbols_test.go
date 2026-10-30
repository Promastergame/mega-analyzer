package crackpoint

import (
	"mega-analyzer/pkg/internal/cfg"
	"testing"
)

// findCategory returns the first crack point with the given category, or false.
func findCategory(res *AnalysisResult, category string) (CrackPoint, bool) {
	for _, cp := range res.CrackPoints {
		if cp.Category == category {
			return cp, true
		}
	}
	return CrackPoint{}, false
}

func TestFindCrackPointsInSymbols_Empty(t *testing.T) {
	f := NewFinder()
	res := f.FindCrackPointsInSymbols(nil, "container", PlatformJVM)
	if res == nil {
		t.Fatal("expected non-nil result")
	}
	if res.TotalFound != 0 {
		t.Fatalf("expected 0 crack points, got %d", res.TotalFound)
	}
}

func TestFindCrackPointsInSymbols_JVM(t *testing.T) {
	f := NewFinder()
	symbols := []SymbolRef{
		{Name: "verifyLicense", Kind: SymbolMethod, Class: "com.app.Lic", Raw: "com/app/Lic->verifyLicense()Z"},
		{Name: "isPremium", Kind: SymbolField, Class: "com.app.User", Raw: "com/app/User->isPremium:Z"},
		{Name: "onPurchaseResult", Kind: SymbolMethod, Class: "com.app.Cb", Raw: "com/app/Cb->onPurchaseResult()V"},
	}
	res := f.FindCrackPointsInSymbols(symbols, "com.app", PlatformJVM)

	if _, ok := findCategory(res, "license"); !ok {
		t.Error("expected a license crack point for verifyLicense")
	}
	if _, ok := findCategory(res, "premium"); !ok {
		t.Error("expected a premium crack point for isPremium field")
	}
	if _, ok := findCategory(res, "callback"); !ok {
		t.Error("expected a callback crack point for onPurchaseResult")
	}
	// JVM gates get actionable guidance (smali patch text only when the return
	// type is known to be boolean, which the symbol view does not always carry).
	if cp, ok := findCategory(res, "license"); ok && cp.SuggestedAction == "" {
		t.Error("expected guidance in SuggestedAction for a JVM license gate")
	}
}

func TestFindCrackPointsInSymbols_Native(t *testing.T) {
	f := NewFinder()
	symbols := []SymbolRef{
		{Name: "ptrace", Kind: SymbolImport, Class: "libfoo.so", Raw: "ptrace"},
		{Name: "", Kind: SymbolString, Class: "libfoo.so", Raw: "/system/bin/su"},
		{Name: "IsDebuggerPresent", Kind: SymbolImport, Class: "foo.dll", Raw: "IsDebuggerPresent"},
	}
	res := f.FindCrackPointsInSymbols(symbols, "libfoo.so", PlatformNative)

	if _, ok := findCategory(res, "tamper"); !ok {
		t.Error("expected a tamper crack point for ptrace")
	}
	if _, ok := findCategory(res, "root"); !ok {
		t.Error("expected a root crack point for /system/bin/su")
	}
	if _, ok := findCategory(res, "debug"); !ok {
		t.Error("expected a debug crack point for IsDebuggerPresent")
	}
	// Native must NOT emit smali patch text.
	for _, cp := range res.CrackPoints {
		if cp.SuggestedPatch != "" {
			t.Errorf("native crack point %q must have empty SuggestedPatch, got %q", cp.MethodName, cp.SuggestedPatch)
		}
		if cp.SuggestedAction == "" {
			t.Errorf("native crack point %q should have guidance in SuggestedAction", cp.MethodName)
		}
	}
}

func TestFindCrackPointsInSymbols_IOS(t *testing.T) {
	f := NewFinder()
	symbols := []SymbolRef{
		{Name: "verifyReceipt", Kind: SymbolImport, Class: "com.app", Raw: "verifyReceipt"},
		{Name: "SKPaymentQueue", Kind: SymbolImport, Class: "com.app", Raw: "SKPaymentQueue"},
		{Name: "LAContext", Kind: SymbolImport, Class: "com.app", Raw: "LAContext"},
		{Name: "", Kind: SymbolString, Class: "com.app", Raw: "/Applications/Cydia.app"},
	}
	res := f.FindCrackPointsInSymbols(symbols, "com.app", PlatformIOS)

	if _, ok := findCategory(res, "billing"); !ok {
		t.Error("expected a billing crack point for verifyReceipt/SKPaymentQueue")
	}
	if _, ok := findCategory(res, "license"); !ok {
		t.Error("expected a license crack point for LAContext")
	}
	if _, ok := findCategory(res, "tamper"); !ok {
		t.Error("expected a tamper crack point for Cydia")
	}
	for _, cp := range res.CrackPoints {
		if cp.SuggestedPatch != "" {
			t.Errorf("iOS crack point %q must have empty SuggestedPatch, got %q", cp.MethodName, cp.SuggestedPatch)
		}
	}
}

func TestFindCrackPointsInSymbols_Dedup(t *testing.T) {
	f := NewFinder()
	symbols := []SymbolRef{
		{Name: "isPremium", Kind: SymbolMethod, Class: "A", Raw: "A->isPremium()Z"},
		{Name: "isPremium", Kind: SymbolMethod, Class: "B", Raw: "B->isPremium()Z"},
	}
	res := f.FindCrackPointsInSymbols(symbols, "c", PlatformJVM)
	if res.TotalFound != 1 {
		t.Fatalf("expected deduped to 1 crack point, got %d", res.TotalFound)
	}
}

// TestFindCrackPoints_CFGRegression proves the original CFG path is unchanged by
// the addition of the symbol-based finder.
func TestFindCrackPoints_CFGRegression(t *testing.T) {
	node := &cfg.CFGNode{
		ID:   1,
		Type: cfg.NodeTypeBasic,
		Instructions: []cfg.InstructionRef{
			{Index: 0, Opcode: "invoke-virtual", Raw: "invoke-virtual {v0}, Lcom/app/User;->isPremium()Z"},
		},
	}
	entry := &cfg.CFGNode{ID: 0, Type: cfg.NodeTypeEntry, Successors: []*cfg.CFGNode{node}}
	node.Predecessors = []*cfg.CFGNode{entry}
	graph := &cfg.ControlFlowGraph{
		Entry: entry,
		Nodes: []*cfg.CFGNode{entry, node},
		Edges: []*cfg.CFGEdge{{From: entry, To: node}},
	}

	f := NewFinder()
	res := f.FindCrackPoints(graph, "Lcom/app/Main;")
	if res.TotalFound == 0 {
		t.Fatal("CFG path regressed: expected a crack point for isPremium")
	}
	if cp := res.CrackPoints[0]; cp.Category != "premium" {
		t.Errorf("CFG path regressed: expected premium, got %s", cp.Category)
	}
}
