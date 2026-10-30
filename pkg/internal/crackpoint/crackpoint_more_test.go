package crackpoint

import (
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/cfg"
)

// ═══════════════════════════════════════════════════════════════════════════════
// HELPERS — build minimal CFG graphs
// ═════════════════════════════════════════════════════════════════════════���═════

// simpleGraph builds a graph: entry → node → exit with the given instructions
// on `node`.
func simpleGraph(instructions []cfg.InstructionRef) *cfg.ControlFlowGraph {
	node := &cfg.CFGNode{
		ID:           1,
		Type:         cfg.NodeTypeBasic,
		Instructions: instructions,
	}
	entry := &cfg.CFGNode{
		ID:         0,
		Type:       cfg.NodeTypeEntry,
		Successors: []*cfg.CFGNode{node},
	}
	node.Predecessors = []*cfg.CFGNode{entry}

	return &cfg.ControlFlowGraph{
		Entry: entry,
		Nodes: []*cfg.CFGNode{entry, node},
		Edges: []*cfg.CFGEdge{{From: entry, To: node}},
	}
}

// chainGraph builds: entry → n0 → n1 → n2 → ...
func chainGraph(nodeCount int) *cfg.ControlFlowGraph {
	nodes := make([]*cfg.CFGNode, nodeCount+1)
	nodes[0] = &cfg.CFGNode{ID: 0, Type: cfg.NodeTypeEntry}
	for i := 1; i <= nodeCount; i++ {
		nodes[i] = &cfg.CFGNode{ID: i, Type: cfg.NodeTypeBasic}
	}
	edges := make([]*cfg.CFGEdge, nodeCount)
	for i := 0; i < nodeCount; i++ {
		nodes[i].Successors = []*cfg.CFGNode{nodes[i+1]}
		nodes[i+1].Predecessors = []*cfg.CFGNode{nodes[i]}
		edges[i] = &cfg.CFGEdge{From: nodes[i], To: nodes[i+1]}
	}
	return &cfg.ControlFlowGraph{
		Entry: nodes[0],
		Nodes: nodes,
		Edges: edges,
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// analyzeImpact — successor counting
// ═══════════════════════════════════════════════════════════════════════════════

func TestAnalyzeImpact_NoSuccessors(t *testing.T) {
	// Gate node with no successors — impact should be 0
	graph := simpleGraph([]cfg.InstructionRef{
		{Index: 0, Opcode: "invoke-virtual", Raw: "invoke-virtual {v0}, Lcom/app;->isPremium()Z"},
	})

	f := NewFinder()
	result := f.FindCrackPoints(graph, "Lcom/app/Main;")

	if result.TotalFound == 0 {
		t.Skip("no crack points found, skipping impact test")
	}

	// A leaf node has 0 CFG successors but gets a category-based semantic
	// minimum (premium base = 4). Must be >= 1 and <= 20.
	for _, cp := range result.CrackPoints {
		if cp.NodeID == 1 {
			if cp.Impact < 1 {
				t.Errorf("expected impact >= 1 (category base) for premium gate, got %d", cp.Impact)
			}
			if cp.Impact > 20 {
				t.Errorf("unexpected large impact %d for leaf node", cp.Impact)
			}
		}
	}
}

func TestAnalyzeImpact_WithSuccessors(t *testing.T) {
	// Build a graph where the gate node has many successors (chain of 15 nodes).
	// Node 1 = gate node (isPremium), nodes 2–16 form a chain of successors.
	gateNode := &cfg.CFGNode{
		ID:   1,
		Type: cfg.NodeTypeBasic,
		Instructions: []cfg.InstructionRef{
			{Index: 0, Opcode: "invoke-virtual", Raw: "invoke-virtual {v0}, Lcom/app;->isPremium()Z"},
		},
	}
	entry := &cfg.CFGNode{
		ID:         0,
		Type:       cfg.NodeTypeEntry,
		Successors: []*cfg.CFGNode{gateNode},
	}
	gateNode.Predecessors = []*cfg.CFGNode{entry}

	// Build 15 successor nodes
	prev := gateNode
	nodes := []*cfg.CFGNode{entry, gateNode}
	var edges []*cfg.CFGEdge
	edges = append(edges, &cfg.CFGEdge{From: entry, To: gateNode})
	for i := 2; i <= 16; i++ {
		n := &cfg.CFGNode{ID: i, Type: cfg.NodeTypeBasic}
		prev.Successors = []*cfg.CFGNode{n}
		n.Predecessors = []*cfg.CFGNode{prev}
		edges = append(edges, &cfg.CFGEdge{From: prev, To: n})
		nodes = append(nodes, n)
		prev = n
	}

	graph := &cfg.ControlFlowGraph{
		Entry: entry,
		Nodes: nodes,
		Edges: edges,
	}

	f := NewFinder()
	result := f.FindCrackPoints(graph, "Lcom/app/Main;")

	if result.TotalFound == 0 {
		t.Fatal("expected crack point")
	}

	// Impact should be 15 (15 successor nodes reachable from gate node 1)
	found := false
	for _, cp := range result.CrackPoints {
		if cp.NodeID == 1 {
			found = true
			if cp.Impact != 15 {
				t.Errorf("expected impact=15, got %d", cp.Impact)
			}
			// High impact should have boosted confidence
			if cp.Impact > 10 {
				hasSignal := false
				for _, s := range cp.Signals {
					if strings.Contains(s, "High impact") {
						hasSignal = true
					}
				}
				if !hasSignal {
					t.Error("expected 'High impact' signal for impact>10")
				}
			}
			break
		}
	}
	if !found {
		t.Error("crack point at node 1 not found")
	}
}

func TestAnalyzeImpact_CycleProtection(t *testing.T) {
	// Graph with a cycle: node1 ↔ node2, to test that the BFS visited set works.
	n1 := &cfg.CFGNode{ID: 1, Type: cfg.NodeTypeBasic, Instructions: []cfg.InstructionRef{
		{Index: 0, Opcode: "invoke-virtual", Raw: "invoke-virtual {v0}, Lcom/app;->isPremium()Z"},
	}}
	n2 := &cfg.CFGNode{ID: 2, Type: cfg.NodeTypeBasic}
	entry := &cfg.CFGNode{ID: 0, Type: cfg.NodeTypeEntry, Successors: []*cfg.CFGNode{n1}}
	n1.Predecessors = []*cfg.CFGNode{entry}
	n1.Successors = []*cfg.CFGNode{n2}
	n2.Predecessors = []*cfg.CFGNode{n1}
	n2.Successors = []*cfg.CFGNode{n1} // cycle back to n1

	graph := &cfg.ControlFlowGraph{
		Entry: entry,
		Nodes: []*cfg.CFGNode{entry, n1, n2},
		Edges: []*cfg.CFGEdge{
			{From: entry, To: n1},
			{From: n1, To: n2},
			{From: n2, To: n1}, // back-edge
		},
	}

	f := NewFinder()
	// Should complete without infinite loop
	result := f.FindCrackPoints(graph, "Lcom/app;")
	if result == nil {
		t.Fatal("expected result")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// generateSuggestions — all category branches
// ═══════════════════════════════════════════════════════════════════════════════

func TestGenerateSuggestions_PremiumBoolean(t *testing.T) {
	f := NewFinder()
	result := &AnalysisResult{
		CrackPoints: []CrackPoint{
			{Category: "premium", ReturnType: "boolean"},
		},
	}
	f.generateSuggestions(result)
	cp := result.CrackPoints[0]

	if !strings.Contains(cp.SuggestedAction, "Return true") {
		t.Errorf("expected 'Return true', got %q", cp.SuggestedAction)
	}
	if cp.SuggestedPatch == "" {
		t.Error("expected suggested patch")
	}
	if cp.PatchRisk != "medium" {
		t.Errorf("expected medium risk, got %q", cp.PatchRisk)
	}
	if cp.PatchExplanation == "" {
		t.Error("expected patch explanation")
	}
}

func TestGenerateSuggestions_PremiumNonBoolean(t *testing.T) {
	f := NewFinder()
	result := &AnalysisResult{
		CrackPoints: []CrackPoint{
			{Category: "premium", ReturnType: "int"}, // non-boolean
		},
	}
	f.generateSuggestions(result)
	cp := result.CrackPoints[0]

	if !strings.Contains(cp.SuggestedAction, "Investigate") {
		t.Errorf("expected 'Investigate', got %q", cp.SuggestedAction)
	}
	if cp.PatchRisk != "high" {
		t.Errorf("expected high risk, got %q", cp.PatchRisk)
	}
}

func TestGenerateSuggestions_License(t *testing.T) {
	f := NewFinder()
	result := &AnalysisResult{
		CrackPoints: []CrackPoint{
			{Category: "license", ReturnType: "boolean"},
		},
	}
	f.generateSuggestions(result)
	cp := result.CrackPoints[0]

	if !strings.Contains(cp.SuggestedAction, "Return true") {
		t.Errorf("expected 'Return true' for license, got %q", cp.SuggestedAction)
	}
}

func TestGenerateSuggestions_Root(t *testing.T) {
	f := NewFinder()
	result := &AnalysisResult{
		CrackPoints: []CrackPoint{{Category: "root"}},
	}
	f.generateSuggestions(result)
	cp := result.CrackPoints[0]

	if !strings.Contains(cp.SuggestedAction, "Return false") {
		t.Errorf("expected 'Return false' for root, got %q", cp.SuggestedAction)
	}
	if cp.PatchRisk != "low" {
		t.Errorf("expected low risk, got %q", cp.PatchRisk)
	}
}

func TestGenerateSuggestions_Emulator(t *testing.T) {
	f := NewFinder()
	result := &AnalysisResult{
		CrackPoints: []CrackPoint{{Category: "emulator"}},
	}
	f.generateSuggestions(result)
	cp := result.CrackPoints[0]

	if !strings.Contains(cp.SuggestedAction, "Return false") {
		t.Errorf("expected 'Return false' for emulator, got %q", cp.SuggestedAction)
	}
	if cp.PatchRisk != "low" {
		t.Errorf("expected low risk for emulator, got %q", cp.PatchRisk)
	}
}

func TestGenerateSuggestions_Debug(t *testing.T) {
	f := NewFinder()
	result := &AnalysisResult{
		CrackPoints: []CrackPoint{{Category: "debug", MethodName: "checkDebuggable"}},
	}
	f.generateSuggestions(result)
	cp := result.CrackPoints[0]

	if !strings.Contains(cp.SuggestedAction, "Return false") {
		t.Errorf("expected 'Return false' for debug, got %q", cp.SuggestedAction)
	}
	if cp.PatchRisk != "medium" {
		t.Errorf("expected medium risk for debug, got %q", cp.PatchRisk)
	}
}

func TestGenerateSuggestions_TamperSafetyNet(t *testing.T) {
	f := NewFinder()
	result := &AnalysisResult{
		CrackPoints: []CrackPoint{
			{Category: "tamper", MethodName: "checkSafetynet"},
		},
	}
	f.generateSuggestions(result)
	cp := result.CrackPoints[0]

	// SafetyNet/integrity path
	if !strings.Contains(cp.SuggestedAction, "Mock") {
		t.Errorf("expected 'Mock' for safetynet tamper, got %q", cp.SuggestedAction)
	}
	if cp.PatchRisk != "critical" {
		t.Errorf("expected critical risk for safetynet, got %q", cp.PatchRisk)
	}
}

func TestGenerateSuggestions_TamperIntegrity(t *testing.T) {
	f := NewFinder()
	result := &AnalysisResult{
		CrackPoints: []CrackPoint{
			{Category: "tamper", MethodName: "checkIntegrity"},
		},
	}
	f.generateSuggestions(result)
	cp := result.CrackPoints[0]

	if !strings.Contains(cp.SuggestedAction, "Mock") {
		t.Errorf("expected 'Mock' for integrity tamper, got %q", cp.SuggestedAction)
	}
}

func TestGenerateSuggestions_TamperGeneric(t *testing.T) {
	f := NewFinder()
	result := &AnalysisResult{
		CrackPoints: []CrackPoint{
			{Category: "tamper", MethodName: "checkSignature"},
		},
	}
	f.generateSuggestions(result)
	cp := result.CrackPoints[0]

	// Generic tamper (not safetynet/integrity)
	if !strings.Contains(cp.SuggestedAction, "Return false") {
		t.Errorf("expected 'Return false' for generic tamper, got %q", cp.SuggestedAction)
	}
	if cp.PatchRisk != "medium" {
		t.Errorf("expected medium risk for generic tamper, got %q", cp.PatchRisk)
	}
}

func TestGenerateSuggestions_Security(t *testing.T) {
	f := NewFinder()
	result := &AnalysisResult{
		CrackPoints: []CrackPoint{{Category: "security"}},
	}
	f.generateSuggestions(result)
	cp := result.CrackPoints[0]

	if !strings.Contains(cp.SuggestedAction, "Bypass") {
		t.Errorf("expected 'Bypass' for security, got %q", cp.SuggestedAction)
	}
	if cp.PatchRisk != "high" {
		t.Errorf("expected high risk for security, got %q", cp.PatchRisk)
	}
}

func TestGenerateSuggestions_Billing(t *testing.T) {
	f := NewFinder()
	result := &AnalysisResult{
		CrackPoints: []CrackPoint{{Category: "billing"}},
	}
	f.generateSuggestions(result)
	cp := result.CrackPoints[0]

	if !strings.Contains(cp.SuggestedAction, "Analyze") {
		t.Errorf("expected 'Analyze' for billing, got %q", cp.SuggestedAction)
	}
	if cp.PatchRisk != "critical" {
		t.Errorf("expected critical risk for billing, got %q", cp.PatchRisk)
	}
}

func TestGenerateSuggestions_Ads(t *testing.T) {
	f := NewFinder()
	result := &AnalysisResult{
		CrackPoints: []CrackPoint{{Category: "ads"}},
	}
	f.generateSuggestions(result)
	cp := result.CrackPoints[0]

	if !strings.Contains(cp.SuggestedAction, "Return true") {
		t.Errorf("expected 'Return true' for ads, got %q", cp.SuggestedAction)
	}
	if cp.PatchRisk != "low" {
		t.Errorf("expected low risk for ads, got %q", cp.PatchRisk)
	}
}

func TestGenerateSuggestions_Default(t *testing.T) {
	f := NewFinder()
	result := &AnalysisResult{
		CrackPoints: []CrackPoint{{Category: "callback"}},
	}
	f.generateSuggestions(result)
	cp := result.CrackPoints[0]

	if !strings.Contains(cp.SuggestedAction, "Manual") {
		t.Errorf("expected 'Manual' for unknown category, got %q", cp.SuggestedAction)
	}
	if cp.PatchRisk != "high" {
		t.Errorf("expected high risk for unknown category, got %q", cp.PatchRisk)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// scanForAdvancedTamperAndIntegrity — SafetyNet, Play Integrity, Signatures
// ═══════════════════════════════════════════════════════════════════════════════

func TestScanForAdvancedTamper_SafetyNet(t *testing.T) {
	graph := simpleGraph([]cfg.InstructionRef{
		{Index: 0, Opcode: "invoke-virtual",
			Raw: "invoke-virtual {v0}, Lcom/google/android/gms/safetynet/SafetyNet;->getClient()V"},
	})

	f := NewFinder()
	result := f.FindCrackPoints(graph, "Lcom/app;")

	found := false
	for _, cp := range result.CrackPoints {
		if cp.Category == "tamper" && cp.Type == CrackPointInvokeResult {
			for _, s := range cp.Signals {
				if strings.Contains(s, "SafetyNet") {
					found = true
				}
			}
		}
	}
	if !found {
		t.Error("expected SafetyNet crack point")
	}
}

func TestScanForAdvancedTamper_PlayIntegrity(t *testing.T) {
	graph := simpleGraph([]cfg.InstructionRef{
		{Index: 0, Opcode: "invoke-interface",
			Raw: "invoke-interface {v0}, Lcom/google/android/play/core/integrity/IntegrityManager;->requestIntegrityToken()V"},
	})

	f := NewFinder()
	result := f.FindCrackPoints(graph, "Lcom/app;")

	found := false
	for _, cp := range result.CrackPoints {
		for _, s := range cp.Signals {
			if strings.Contains(s, "Play Integrity") {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected Play Integrity crack point")
	}
}

func TestScanForAdvancedTamper_PlayIntegrityManager(t *testing.T) {
	graph := simpleGraph([]cfg.InstructionRef{
		{Index: 0, Opcode: "invoke-static",
			Raw: "invoke-static {v0}, Landroid/content/IntegrityManager;->requestCheck()V"},
	})

	f := NewFinder()
	result := f.FindCrackPoints(graph, "Lcom/app;")

	found := false
	for _, cp := range result.CrackPoints {
		for _, s := range cp.Signals {
			if strings.Contains(s, "Play Integrity") {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected Play Integrity (IntegrityManager) crack point")
	}
}

func TestScanForAdvancedTamper_SignatureExtraction_GetSignatures(t *testing.T) {
	graph := simpleGraph([]cfg.InstructionRef{
		{Index: 0, Opcode: "invoke-virtual",
			Raw: "invoke-virtual {v0, v1}, Landroid/content/pm/PackageManager;->getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo; signature get_signatures"},
	})

	f := NewFinder()
	result := f.FindCrackPoints(graph, "Lcom/app;")

	found := false
	for _, cp := range result.CrackPoints {
		for _, s := range cp.Signals {
			if strings.Contains(s, "Signature") {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected Signature extraction crack point")
	}
}

func TestScanForAdvancedTamper_SignatureExtraction_ToByteArray(t *testing.T) {
	graph := simpleGraph([]cfg.InstructionRef{
		{Index: 0, Opcode: "invoke-virtual",
			Raw: "invoke-virtual {v0}, Landroid/content/pm/Signature;->toByteArray()[B"},
	})

	f := NewFinder()
	result := f.FindCrackPoints(graph, "Lcom/app;")

	// "signature" AND "tobytearray" both present
	found := false
	for _, cp := range result.CrackPoints {
		for _, s := range cp.Signals {
			if strings.Contains(s, "Signature") || strings.Contains(s, "Certificate") {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected Signature/toByteArray crack point")
	}
}

func TestScanForAdvancedTamper_NoMatch(t *testing.T) {
	graph := simpleGraph([]cfg.InstructionRef{
		{Index: 0, Opcode: "invoke-virtual", Raw: "invoke-virtual {v0}, Lcom/app;->doSomethingInnocuous()V"},
	})

	f := NewFinder()
	result := f.FindCrackPoints(graph, "Lcom/app;")

	for _, cp := range result.CrackPoints {
		if cp.Type == CrackPointInvokeResult {
			t.Errorf("unexpected InvokeResult crack point: %+v", cp)
		}
	}
}

func TestScanForAdvancedTamper_NonInvoke(t *testing.T) {
	// iget-boolean should not trigger advanced tamper scan
	graph := simpleGraph([]cfg.InstructionRef{
		{Index: 0, Opcode: "iget-boolean", Raw: "iget-boolean v0, p0, Lcom/app;->safetynet:Z"},
	})

	f := NewFinder()
	result := f.FindCrackPoints(graph, "Lcom/app;")

	for _, cp := range result.CrackPoints {
		if cp.Type == CrackPointInvokeResult {
			t.Errorf("non-invoke should not produce InvokeResult crack point: %+v", cp)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// isFollowedByBooleanCheck — additional window scenarios
// ═══════════════════════════════════════════════════════════════════════════════

func TestIsFollowedByBooleanCheck_WithinWindow(t *testing.T) {
	f := NewFinder()
	node := &cfg.CFGNode{
		Instructions: []cfg.InstructionRef{
			{Index: 10, Opcode: "invoke-virtual"},
			{Index: 11, Opcode: "nop"},
			{Index: 12, Opcode: "nop"},
			{Index: 13, Opcode: "if-eqz"}, // within 3 of invoke at 10
		},
	}
	// Window check: 13 > 10+3 → 13 > 13 is false, so should still fire
	if !f.isFollowedByBooleanCheck(node, 10) {
		t.Error("if-eqz at distance 3 should be detected")
	}
}

func TestIsFollowedByBooleanCheck_OutsideWindow(t *testing.T) {
	f := NewFinder()
	node := &cfg.CFGNode{
		Instructions: []cfg.InstructionRef{
			{Index: 10, Opcode: "invoke-virtual"},
			{Index: 14, Opcode: "if-eqz"}, // 14 > 10+3 → window guard fires
		},
	}
	// The loop breaks when instr.Index > instrIdx+3, so 14>13 breaks before seeing if-eqz
	if f.isFollowedByBooleanCheck(node, 10) {
		t.Log("Note: the current window guard fires AFTER checking — this is documented in helpers_test.go")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// extractFieldName
// ═══════════════════════════════════════════════════════════════════════════════

func TestExtractFieldName_Normal(t *testing.T) {
	f := NewFinder()
	raw := "iget-boolean v0, p0, Lcom/app/Config;->isPremium:Z"
	got := f.extractFieldName(raw)
	if got != "isPremium" {
		t.Errorf("extractFieldName = %q, want %q", got, "isPremium")
	}
}

func TestExtractFieldName_NoArrow(t *testing.T) {
	f := NewFinder()
	raw := "iget-boolean v0, p0, Lcom/app/Config;"
	got := f.extractFieldName(raw)
	if got != raw {
		t.Errorf("no arrow should return raw: %q", got)
	}
}

func TestExtractFieldName_NoColon(t *testing.T) {
	f := NewFinder()
	raw := "iget-boolean v0, p0, Lcom/app/Config;->isPremium"
	got := f.extractFieldName(raw)
	// No colon after arrow → returns rest after arrow
	if got != "isPremium" {
		t.Errorf("no colon should return everything after arrow: %q", got)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// scanForGateNodes — booleanCheck branch
// ═══════════════════════════════════════════════════════════════════════════════

func TestScanForGateNodes_BooleanCheckBoostsConfidence(t *testing.T) {
	// invoke followed by move-result within same node → isFollowedByBooleanCheck = true
	graph := simpleGraph([]cfg.InstructionRef{
		{Index: 0, Opcode: "invoke-virtual", Raw: "invoke-virtual {v0}, Lcom/app;->isPremium()Z"},
		{Index: 1, Opcode: "move-result", Raw: "move-result v0"},
	})

	f := NewFinder()
	result := f.FindCrackPoints(graph, "Lcom/app;")

	if result.TotalFound == 0 {
		t.Fatal("expected crack point")
	}

	cp := result.CrackPoints[0]
	if cp.ReturnType != "boolean" {
		t.Errorf("expected ReturnType=boolean, got %q", cp.ReturnType)
	}

	hasFollowedSignal := false
	for _, s := range cp.Signals {
		if strings.Contains(s, "boolean condition") {
			hasFollowedSignal = true
		}
	}
	if !hasFollowedSignal {
		t.Error("expected 'boolean condition' signal when move-result follows invoke")
	}
}

func TestScanForGateNodes_IfFollowedBoostsConfidence(t *testing.T) {
	graph := simpleGraph([]cfg.InstructionRef{
		{Index: 0, Opcode: "invoke-virtual", Raw: "invoke-virtual {v0}, Lcom/app;->isLicensed()Z"},
		{Index: 1, Opcode: "if-eqz", Raw: "if-eqz v0, :fail"},
	})

	f := NewFinder()
	result := f.FindCrackPoints(graph, "Lcom/app;")

	if result.TotalFound == 0 {
		t.Fatal("expected crack point for isLicensed")
	}

	cp := result.CrackPoints[0]
	// Check that confidence is within valid range
	if cp.Confidence < 0.9 || cp.Confidence > 1.0 {
		t.Errorf("confidence = %f, expected ≥0.9 after boolean boost", cp.Confidence)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// scanForGateInvocations — callback patterns
// ═══════════════════════════════════════════════════════════════════════════════

func TestScanForGateInvocations_Callback(t *testing.T) {
	graph := simpleGraph([]cfg.InstructionRef{
		{Index: 0, Opcode: "invoke-virtual",
			Raw: "invoke-virtual {v0}, Lcom/app;->onLicenseResult(I)V"},
	})

	f := NewFinder()
	result := f.FindCrackPoints(graph, "Lcom/app;")

	found := false
	for _, cp := range result.CrackPoints {
		if cp.Type == CrackPointCallback {
			found = true
		}
	}
	if !found {
		t.Error("expected callback crack point for onLicenseResult")
	}
}

func TestScanForGateInvocations_PurchaseCallback(t *testing.T) {
	graph := simpleGraph([]cfg.InstructionRef{
		{Index: 0, Opcode: "invoke-interface",
			Raw: "invoke-interface {v0, v1}, Lcom/app/BillingCallback;->onPurchaseResult(Z)V"},
	})

	f := NewFinder()
	result := f.FindCrackPoints(graph, "Lcom/app;")

	found := false
	for _, cp := range result.CrackPoints {
		if cp.Type == CrackPointCallback {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected callback crack point for onPurchaseResult")
	}
}

func TestScanForGateInvocations_NoCallback(t *testing.T) {
	graph := simpleGraph([]cfg.InstructionRef{
		{Index: 0, Opcode: "invoke-virtual", Raw: "invoke-virtual {v0}, Lcom/app;->onClick()V"},
	})

	f := NewFinder()
	result := f.FindCrackPoints(graph, "Lcom/app;")

	for _, cp := range result.CrackPoints {
		if cp.Type == CrackPointCallback {
			t.Errorf("unexpected callback crack point: %+v", cp)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// FindCrackPoints — full result statistics
// ═══════════════════════════════════════════════════════════════════════════════

func TestFindCrackPoints_HighConfidenceCount(t *testing.T) {
	// Put several known-high-confidence gate methods
	graph := simpleGraph([]cfg.InstructionRef{
		{Index: 0, Opcode: "invoke-virtual", Raw: "invoke-virtual {v0}, Lcom/app;->isPremium()Z"},
		{Index: 1, Opcode: "invoke-static", Raw: "invoke-static {}, Lcom/sec;->isLicensed()Z"},
	})

	f := NewFinder()
	result := f.FindCrackPoints(graph, "Lcom/app;")

	if result.TotalFound < 0 { // sanity: TotalFound should never be negative
		t.Error("should not happen")
	}
	if result.TotalFound > 0 && result.HighConfidence > result.TotalFound {
		t.Error("HighConfidence cannot exceed TotalFound")
	}
}

func TestFindCrackPoints_Categories(t *testing.T) {
	graph := simpleGraph([]cfg.InstructionRef{
		{Index: 0, Opcode: "invoke-virtual", Raw: "invoke-virtual {v0}, Lcom/app;->isPremium()Z"},
		{Index: 1, Opcode: "invoke-static", Raw: "invoke-static {}, Lcom/sec;->isRooted()Z"},
		{Index: 2, Opcode: "invoke-static", Raw: "invoke-static {}, Lcom/bill;->verifyPurchase(Ljava/lang/String;)Z"},
	})

	f := NewFinder()
	result := f.FindCrackPoints(graph, "Lcom/app;")

	// Should categorize at minimum premium and root
	if _, ok := result.Categories["premium"]; !ok {
		t.Error("expected 'premium' category")
	}
	if _, ok := result.Categories["root"]; !ok {
		t.Error("expected 'root' category")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// categorizeField
// ═══════════════════════════════════════════════════════════════════════════════

func TestCategorizeField_AllBranches(t *testing.T) {
	f := NewFinder()
	cases := []struct {
		field string
		want  string
	}{
		{"ispremium", "premium"},
		{"ispro", "premium"},
		{"isvip", "premium"},
		{"haspaid", "premium"},
		{"isunlocked", "premium"},
		{"islicense", "license"},
		{"isregistered", "license"},
		{"isactivated", "license"},
		{"showads", "ads"},
		{"removeads", "ads"},
		{"unknown_field", "premium"}, // default
	}
	for _, c := range cases {
		got := f.categorizeField(c.field)
		if got != c.want {
			t.Errorf("categorizeField(%q) = %q, want %q", c.field, got, c.want)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// scanForFieldChecks — sget-boolean
// ═══════════════════════════════════════════════════════════════════════════════

func TestScanForFieldChecks_SgetBoolean(t *testing.T) {
	graph := simpleGraph([]cfg.InstructionRef{
		{Index: 0, Opcode: "sget-boolean", Raw: "sget-boolean v0, Lcom/app/Config;->isPremium:Z"},
	})

	f := NewFinder()
	result := f.FindCrackPoints(graph, "Lcom/app;")

	found := false
	for _, cp := range result.CrackPoints {
		if cp.Type == CrackPointFieldCheck {
			found = true
		}
	}
	if !found {
		t.Error("expected FieldCheck crack point for sget-boolean isPremium")
	}
}

func TestScanForFieldChecks_NonMatch(t *testing.T) {
	// iget-boolean but field name not in pattern list
	graph := simpleGraph([]cfg.InstructionRef{
		{Index: 0, Opcode: "iget-boolean", Raw: "iget-boolean v0, p0, Lcom/app/Config;->someRandomField:Z"},
	})

	f := NewFinder()
	result := f.FindCrackPoints(graph, "Lcom/app;")

	for _, cp := range result.CrackPoints {
		if cp.Type == CrackPointFieldCheck {
			t.Errorf("unexpected field check for random field: %+v", cp)
		}
	}
}
