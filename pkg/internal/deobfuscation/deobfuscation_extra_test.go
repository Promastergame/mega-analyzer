package deobfuscation

import (
	"encoding/base64"
	"testing"

	"mega-analyzer/pkg/internal/cfg"
)

// TestDetectCFFFullPattern wires up the full CFF dispatcher pattern: a switch
// node with ≥5 targets, sitting in a loop (RPO back-edge from one of the
// targets), each target containing a `const v0, N` instruction so the CFF
// edge recovery path runs.
//
// `g.GetNode(id)` indexes into the underlying slice, so we set node IDs to
// match the slice positions where they will be inserted.
func TestDetectCFFFullPattern(t *testing.T) {
	const stateReg = "v0"

	// Node 0 = entry, node 1 = dispatcher, nodes 2..7 = case targets.
	cases := make([]*cfg.CFGNode, 6)
	for i := range cases {
		next := (i + 1) % len(cases)
		cases[i] = &cfg.CFGNode{
			ID:        2 + i,
			Type:      cfg.NodeTypeBasic,
			RPONumber: 10 + i,
			Instructions: []cfg.InstructionRef{
				{Index: 0, Opcode: "const/4", Raw: "const/4 " + stateReg + ", " + caseDigit(next)},
			},
		}
	}

	dispatcher := &cfg.CFGNode{
		ID:        1,
		Type:      cfg.NodeTypeSwitch,
		LoopDepth: 1, // sits inside a loop
		RPONumber: 5,
		SwitchInfo: &cfg.SwitchInfo{
			Type:     cfg.SwitchPacked,
			Register: stateReg,
		},
	}
	for i, c := range cases {
		dispatcher.SwitchInfo.Targets = append(dispatcher.SwitchInfo.Targets, cfg.SwitchTarget{
			Key: i, TargetID: c.ID,
		})
		c.Predecessors = append(c.Predecessors, dispatcher)
	}
	dispatcher.Predecessors = append(dispatcher.Predecessors, cases...) // back-edges

	entry := &cfg.CFGNode{ID: 0, Type: cfg.NodeTypeEntry, RPONumber: 0,
		Successors: []*cfg.CFGNode{dispatcher}}
	dispatcher.Predecessors = append(dispatcher.Predecessors, entry)

	allNodes := []*cfg.CFGNode{entry, dispatcher}
	allNodes = append(allNodes, cases...)
	graph := &cfg.ControlFlowGraph{
		Entry: entry,
		Nodes: allNodes,
	}

	e := NewDefaultEngine()
	res := e.Analyze(graph)

	if !res.CFFFDetected {
		t.Errorf("expected CFF detection, got %+v", res)
	}
	if res.CFFStateVariable != stateReg {
		t.Errorf("CFF state var = %q, want %q", res.CFFStateVariable, stateReg)
	}
	if res.CFFRecoveredBlocks != len(cases) {
		t.Errorf("CFFRecoveredBlocks = %d, want %d", res.CFFRecoveredBlocks, len(cases))
	}
	if len(res.CFFRecoveredEdges) == 0 {
		t.Errorf("expected recovered CFF edges")
	}
}

func TestDetectCFFSkipsSmallSwitch(t *testing.T) {
	dispatcher := &cfg.CFGNode{
		ID:         300,
		Type:       cfg.NodeTypeSwitch,
		LoopDepth:  1,
		SwitchInfo: &cfg.SwitchInfo{Type: cfg.SwitchPacked, Register: "v0"},
	}
	// Only 3 targets — below the 5-target threshold.
	for i := 0; i < 3; i++ {
		dispatcher.SwitchInfo.Targets = append(dispatcher.SwitchInfo.Targets,
			cfg.SwitchTarget{Key: i, TargetID: 1000 + i})
	}
	graph := &cfg.ControlFlowGraph{
		Entry: dispatcher,
		Nodes: []*cfg.CFGNode{dispatcher},
	}
	res := NewDefaultEngine().Analyze(graph)
	if res.CFFFDetected {
		t.Error("CFF should NOT be flagged for small switches")
	}
}

// TestCheckConstantConditionTwoConsts pins the DIRECTION of a two-constant
// verdict, not merely that one was produced. The previous implementation
// reported every const-vs-const comparison as always-true without ever
// comparing the two values, so `1 == 2` was called always-true — and each such
// verdict also incremented DeadBranchesEliminated, feeding a wrong number into
// scoring. A test that only asserted "a finding appeared" passed throughout.
func TestCheckConstantConditionTwoConsts(t *testing.T) {
	buildGraph := func(op cfg.ConditionOp, lhs, rhs int) *cfg.ControlFlowGraph {
		cond := &cfg.ConditionInfo{
			Op:        op,
			Register1: "v0",
			Register2: "v1",
			LHS:       &cfg.ValueRef{Kind: cfg.ValueConst, ConstValue: lhs},
			RHS:       &cfg.ValueRef{Kind: cfg.ValueConst, ConstValue: rhs},
		}
		node := &cfg.CFGNode{
			ID:        1,
			Type:      cfg.NodeTypeCondition,
			Condition: cond,
			Successors: []*cfg.CFGNode{
				{ID: 2, Type: cfg.NodeTypeBasic},
				{ID: 3, Type: cfg.NodeTypeBasic},
			},
		}
		entry := &cfg.CFGNode{ID: 0, Type: cfg.NodeTypeEntry,
			Successors: []*cfg.CFGNode{node}}
		return &cfg.ControlFlowGraph{
			Entry: entry,
			Nodes: []*cfg.CFGNode{entry, node, node.Successors[0], node.Successors[1]},
		}
	}

	cases := []struct {
		name      string
		op        cfg.ConditionOp
		lhs, rhs  int
		wantTrue  bool
		wantFalse bool
	}{
		{"eq_same_is_always_true", cfg.CondEq, 1, 1, true, false},
		{"eq_different_is_always_false", cfg.CondEq, 1, 2, false, true},
		{"ne_different_is_always_true", cfg.CondNe, 1, 2, true, false},
		{"lt_holds", cfg.CondLt, 1, 2, true, false},
		{"lt_does_not_hold", cfg.CondLt, 2, 1, false, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := NewDefaultEngine().Analyze(buildGraph(tc.op, tc.lhs, tc.rhs))
			if res.OpaquePredicatesFound == 0 {
				t.Fatal("expected an opaque-predicate finding from two-constant condition")
			}
			var got OpaquePredInfo
			for _, d := range res.OpaquePredicateDetails {
				if d.NodeID == 1 {
					got = d
					break
				}
			}
			if got.AlwaysTrue != tc.wantTrue || got.AlwaysFalse != tc.wantFalse {
				t.Errorf("%d %v %d: got AlwaysTrue=%v AlwaysFalse=%v, want %v/%v",
					tc.lhs, tc.op, tc.rhs, got.AlwaysTrue, got.AlwaysFalse, tc.wantTrue, tc.wantFalse)
			}
		})
	}
}

// TestCheckConstantConditionUnknownConsts: two constants whose values are not
// recoverable prove nothing about the direction of the branch, so no verdict
// should be emitted rather than a guessed one.
func TestCheckConstantConditionUnknownConsts(t *testing.T) {
	cond := &cfg.ConditionInfo{
		Op:        cfg.CondEq,
		Register1: "v0",
		Register2: "v1",
		LHS:       &cfg.ValueRef{Kind: cfg.ValueConst},
		RHS:       &cfg.ValueRef{Kind: cfg.ValueConst},
	}
	node := &cfg.CFGNode{
		ID: 1, Type: cfg.NodeTypeCondition, Condition: cond,
		Successors: []*cfg.CFGNode{
			{ID: 2, Type: cfg.NodeTypeBasic},
			{ID: 3, Type: cfg.NodeTypeBasic},
		},
	}
	entry := &cfg.CFGNode{ID: 0, Type: cfg.NodeTypeEntry, Successors: []*cfg.CFGNode{node}}
	graph := &cfg.ControlFlowGraph{
		Entry: entry,
		Nodes: []*cfg.CFGNode{entry, node, node.Successors[0], node.Successors[1]},
	}
	res := NewDefaultEngine().Analyze(graph)
	for _, d := range res.OpaquePredicateDetails {
		if d.NodeID == 1 {
			t.Fatalf("value-less constants must not yield a directional verdict, got %+v", d)
		}
	}
}

func TestCheckConstantConditionImmediatePredConst(t *testing.T) {
	// Predecessor stores a constant 0 into v0, then if-eqz v0 → always-true.
	pred := &cfg.CFGNode{
		ID:   0,
		Type: cfg.NodeTypeBasic,
		Instructions: []cfg.InstructionRef{
			{Index: 0, Opcode: "const/4", Raw: "const/4 v0, 0x0"},
		},
	}
	condNode := &cfg.CFGNode{
		ID:   1,
		Type: cfg.NodeTypeCondition,
		Condition: &cfg.ConditionInfo{
			Op:        cfg.CondEqZero,
			Register1: "v0",
		},
		Predecessors: []*cfg.CFGNode{pred},
		Successors: []*cfg.CFGNode{
			{ID: 2, Type: cfg.NodeTypeBasic},
			{ID: 3, Type: cfg.NodeTypeBasic},
		},
	}
	pred.Successors = []*cfg.CFGNode{condNode}

	graph := &cfg.ControlFlowGraph{
		Entry: pred,
		Nodes: []*cfg.CFGNode{pred, condNode, condNode.Successors[0], condNode.Successors[1]},
	}
	res := NewDefaultEngine().Analyze(graph)
	if res.OpaquePredicatesFound == 0 {
		t.Fatal("const v0=0 + if-eqz must be flagged opaque")
	}

	// Find the corresponding finding and verify its truth value.
	found := false
	for _, info := range res.OpaquePredicateDetails {
		if info.AlwaysTrue {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an always-true finding, got %+v", res.OpaquePredicateDetails)
	}
}

func TestCheckConstantConditionImmediatePredNonZero(t *testing.T) {
	// Predecessor stores non-zero, then if-nez → always-true; if-eqz → always-false.
	pred := &cfg.CFGNode{
		ID: 0, Type: cfg.NodeTypeBasic,
		Instructions: []cfg.InstructionRef{
			{Index: 0, Opcode: "const/16", Raw: "const/16 v0, 0x42"},
		},
	}
	condNode := &cfg.CFGNode{
		ID: 1, Type: cfg.NodeTypeCondition,
		Condition:    &cfg.ConditionInfo{Op: cfg.CondNeZero, Register1: "v0"},
		Predecessors: []*cfg.CFGNode{pred},
		Successors: []*cfg.CFGNode{
			{ID: 2, Type: cfg.NodeTypeBasic},
			{ID: 3, Type: cfg.NodeTypeBasic},
		},
	}
	pred.Successors = []*cfg.CFGNode{condNode}
	graph := &cfg.ControlFlowGraph{Entry: pred, Nodes: []*cfg.CFGNode{pred, condNode, condNode.Successors[0], condNode.Successors[1]}}

	res := NewDefaultEngine().Analyze(graph)
	if res.OpaquePredicatesFound == 0 {
		t.Fatal("if-nez on non-zero const must be opaque")
	}
}

func TestExtractStringConstValue(t *testing.T) {
	e := NewDefaultEngine()
	cases := map[string]string{
		`const-string v0, "hello"`:               "hello",
		`const-string/jumbo v0, "Hello World"`:   "Hello World",
		`malformed without quotes`:               "",
		`const-string v0, "first" then "second"`: `first" then "second`,
	}
	for raw, want := range cases {
		if got := e.extractStringConstValue(raw); got != want {
			t.Errorf("extractStringConstValue(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestExtractMethodRef(t *testing.T) {
	e := NewDefaultEngine()
	in := `invoke-static {v0}, Lcom/example/Decrypt;->decode(Ljava/lang/String;)Ljava/lang/String;`
	got := e.extractMethodRef(in)
	if got == "" {
		t.Errorf("expected non-empty method ref, got %q", got)
	}
	if got[0] != 'L' {
		t.Errorf("method ref must start with L, got %q", got)
	}

	// No 'L' prefix → empty
	if e.extractMethodRef("nothing") != "" {
		t.Error("expected empty result for a no-L raw line")
	}
}

func TestStringEncryptionDetectionEndToEnd(t *testing.T) {
	// One basic block carrying:
	//   const-string v0, "<base64 of a hidden endpoint>"
	//   invoke-static {v0}, Lcom/x/Decrypt;->go(Ljava/lang/String;)Ljava/lang/String;
	//
	// The payload is an endpoint rather than a nonsense token on purpose: the
	// engine only reports a recovery whose plaintext looks like something a
	// program would actually hide, because a brute-force search finds
	// "plausible" text in almost any literal otherwise.
	const hidden = "https://c2.example.net/collect"
	encrypted := base64.StdEncoding.EncodeToString([]byte(hidden))
	node := &cfg.CFGNode{
		ID:   1,
		Type: cfg.NodeTypeBasic,
		Instructions: []cfg.InstructionRef{
			{Index: 0, Opcode: "const-string", Raw: `const-string v0, "` + encrypted + `"`},
			{Index: 1, Opcode: "invoke-static", Raw: `invoke-static {v0}, Lcom/x/Decrypt;->go(Ljava/lang/String;)Ljava/lang/String;`},
			{Index: 2, Opcode: "move-result-object", Raw: `move-result-object v1`},
		},
	}
	graph := &cfg.ControlFlowGraph{
		Entry: node,
		Nodes: []*cfg.CFGNode{node},
	}
	res := NewDefaultEngine().Analyze(graph)
	if len(res.RecoveredStrings) == 0 {
		t.Fatal("expected at least one recovered string")
	}
	if res.RecoveredStrings[0].EncryptedForm != encrypted {
		t.Errorf("EncryptedForm wrong: %q", res.RecoveredStrings[0].EncryptedForm)
	}
	if res.RecoveredStrings[0].DecryptorRef == "" {
		t.Error("DecryptorRef should be populated")
	}
	if got := res.RecoveredStrings[0].DecryptedForm; got != hidden {
		t.Errorf("DecryptedForm = %q, want %q", got, hidden)
	}
}

// TestStringEncryptionSurvivesArgumentSetup covers the shape that the previous
// implementation missed entirely: a decryptor that takes a key or index, so
// the invoke is not immediately adjacent to the const-string. Requiring
// adjacency lost most real call sites.
func TestStringEncryptionSurvivesArgumentSetup(t *testing.T) {
	const hidden = "https://api.example.com/v1/report"
	encrypted := base64.StdEncoding.EncodeToString([]byte(hidden))
	node := &cfg.CFGNode{
		ID:   1,
		Type: cfg.NodeTypeBasic,
		Instructions: []cfg.InstructionRef{
			{Index: 0, Opcode: "const-string", Raw: `const-string v0, "` + encrypted + `"`},
			{Index: 1, Opcode: "const/4", Raw: `const/4 v1, 0x3`},
			{Index: 2, Opcode: "invoke-static", Raw: `invoke-static {v0, v1}, Lcom/x/D;->a(Ljava/lang/String;I)Ljava/lang/String;`},
			{Index: 3, Opcode: "move-result-object", Raw: `move-result-object v2`},
		},
	}
	graph := &cfg.ControlFlowGraph{Entry: node, Nodes: []*cfg.CFGNode{node}}
	res := NewDefaultEngine().Analyze(graph)
	if len(res.RecoveredStrings) == 0 {
		t.Fatal("non-adjacent decryptor call site was not detected")
	}
	if got := res.RecoveredStrings[0].DecryptedForm; got != hidden {
		t.Errorf("DecryptedForm = %q, want %q", got, hidden)
	}
	if res.RecoveredStrings[0].DecryptorRef == "" {
		t.Error("DecryptorRef should point at the invoke two instructions later")
	}
}

// TestStringEncryptionAtBlockEnd covers the off-by-one that skipped the last
// two instructions of every basic block — the most common placement for a
// const-string / invoke pair.
func TestStringEncryptionAtBlockEnd(t *testing.T) {
	const hidden = "https://c2.example.org/beacon"
	encrypted := base64.StdEncoding.EncodeToString([]byte(hidden))
	node := &cfg.CFGNode{
		ID:   1,
		Type: cfg.NodeTypeBasic,
		Instructions: []cfg.InstructionRef{
			{Index: 0, Opcode: "nop", Raw: `nop`},
			{Index: 1, Opcode: "const-string", Raw: `const-string v0, "` + encrypted + `"`},
			{Index: 2, Opcode: "invoke-static", Raw: `invoke-static {v0}, Lcom/x/D;->a(Ljava/lang/String;)Ljava/lang/String;`},
		},
	}
	graph := &cfg.ControlFlowGraph{Entry: node, Nodes: []*cfg.CFGNode{node}}
	res := NewDefaultEngine().Analyze(graph)
	if len(res.RecoveredStrings) == 0 {
		t.Fatal("const-string at end of block was skipped")
	}
}

// TestNoRecoveryFromOrdinaryIdentifiers is the precision guard. Ordinary
// program identifiers must never be reported as decrypted: XOR key 0x20 turns
// "IconCompat" into "iCONcOMPAT", which passes every letter-frequency test
// because that scoring folds case. On a real APK this single class of false
// positive produced thousands of bogus recoveries.
func TestNoRecoveryFromOrdinaryIdentifiers(t *testing.T) {
	for _, ident := range []string{
		"IconCompat", "ProfileInstaller", "TypefaceCompat",
		"androidx.core.graphics", "onCreateViewHolder", "SupportMenuInflater",
	} {
		if plain, transform := tryDecryptString(ident); plain != "" {
			t.Errorf("%q was falsely decrypted to %q via %s", ident, plain, transform)
		}
	}
}

// TestLooksEncryptedHints exercises the high-entropy heuristic threshold.
func TestLooksEncryptedHints(t *testing.T) {
	e := NewDefaultEngine()
	if e.looksEncrypted("short") {
		t.Error("very short string should not be flagged")
	}
	if !e.looksEncrypted("abcdefghABCDEFGH12345678+/==") {
		t.Error("base64-shaped string should be flagged")
	}
}

// caseDigit returns the const-instruction-tail rendering of a small index.
func caseDigit(i int) string {
	switch i {
	case 0:
		return "0x0"
	case 1:
		return "0x1"
	case 2:
		return "0x2"
	case 3:
		return "0x3"
	case 4:
		return "0x4"
	case 5:
		return "0x5"
	default:
		return "0x99"
	}
}
