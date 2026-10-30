package deobfuscation

import (
	"testing"

	"mega-analyzer/pkg/internal/cfg"
)

func TestAnalyze_PopulatesIdentity(t *testing.T) {
	g := buildSimpleTestGraph()
	g.MethodName = "doWork"
	g.ClassName = "Lcom/example/Foo;"
	res := NewDefaultEngine().Analyze(g)
	if res.MethodName != "doWork" {
		t.Errorf("MethodName = %q, want doWork", res.MethodName)
	}
	if res.ClassName != "Lcom/example/Foo;" {
		t.Errorf("ClassName = %q", res.ClassName)
	}
}

func TestIsObfuscated(t *testing.T) {
	clean := &DeobfuscationResult{}
	if clean.IsObfuscated() {
		t.Error("empty result should not be flagged obfuscated")
	}
	if !(&DeobfuscationResult{OpaquePredicatesFound: 1}).IsObfuscated() {
		t.Error("opaque predicate should count as obfuscation")
	}
	if !(&DeobfuscationResult{DeadNodesFound: 2}).IsObfuscated() {
		t.Error("dead nodes should count as obfuscation")
	}
	if !(&DeobfuscationResult{RecoveredStrings: []RecoveredString{{}}}).IsObfuscated() {
		t.Error("recovered strings should count as obfuscation")
	}
}

func TestConfidence_Monotonic(t *testing.T) {
	e := NewDefaultEngine()
	low := e.scoreConfidence(&DeobfuscationResult{OpaquePredicatesFound: 1})
	high := e.scoreConfidence(&DeobfuscationResult{
		CFFFDetected:          true,
		CFFConfidence:         0.9,
		OpaquePredicatesFound: 3,
		DeadNodesFound:        2,
		RecoveredStrings:      []RecoveredString{{}, {}},
	})
	if !(low > 0 && low < high) {
		t.Errorf("expected 0 < low(%v) < high(%v)", low, high)
	}
	if high > 1.0 {
		t.Errorf("confidence must be clamped to 1.0, got %v", high)
	}
}

func TestClamp01(t *testing.T) {
	if clamp01(-0.5) != 0 || clamp01(1.5) != 1 || clamp01(0.3) != 0.3 {
		t.Error("clamp01 failed")
	}
}

// TestCFFConfidence_FullDispatcher confirms a well-formed dispatcher scores
// higher than a bare, loop-less one.
func TestCFFConfidence_Scoring(t *testing.T) {
	const stateReg = "v0"
	build := func(loopDepth int, withAssigns bool) *cfg.ControlFlowGraph {
		cases := make([]*cfg.CFGNode, 6)
		for i := range cases {
			node := &cfg.CFGNode{ID: 2 + i, Type: cfg.NodeTypeBasic, RPONumber: 10 + i}
			if withAssigns {
				node.Instructions = []cfg.InstructionRef{
					{Index: 0, Opcode: "const/4", Raw: "const/4 " + stateReg + ", " + caseDigit((i+1)%6)},
				}
			}
			cases[i] = node
		}
		dispatcher := &cfg.CFGNode{
			ID: 1, Type: cfg.NodeTypeSwitch, LoopDepth: loopDepth, RPONumber: 5,
			SwitchInfo: &cfg.SwitchInfo{Type: cfg.SwitchPacked, Register: stateReg},
		}
		for i, c := range cases {
			dispatcher.SwitchInfo.Targets = append(dispatcher.SwitchInfo.Targets, cfg.SwitchTarget{Key: i, TargetID: c.ID})
			c.Predecessors = append(c.Predecessors, dispatcher)
		}
		dispatcher.Predecessors = append(dispatcher.Predecessors, cases...)
		entry := &cfg.CFGNode{ID: 0, Type: cfg.NodeTypeEntry, Successors: []*cfg.CFGNode{dispatcher}}
		nodes := append([]*cfg.CFGNode{entry, dispatcher}, cases...)
		return &cfg.ControlFlowGraph{Entry: entry, Nodes: nodes}
	}

	strong := NewDefaultEngine().Analyze(build(1, true))
	weak := NewDefaultEngine().Analyze(build(0, false))
	if !strong.CFFFDetected {
		t.Fatal("strong dispatcher should be detected")
	}
	if strong.CFFConfidence <= weak.CFFConfidence {
		t.Errorf("strong confidence (%v) should exceed weak (%v)", strong.CFFConfidence, weak.CFFConfidence)
	}
	if strong.Confidence <= 0 {
		t.Error("overall confidence should be positive for a detected CFF")
	}
}

// TestCFF_HexNextState verifies the robust literal parser handles hex
// next-state constants in CFF edge recovery.
func TestCFF_HexNextStateEdges(t *testing.T) {
	const stateReg = "v0"
	cases := make([]*cfg.CFGNode, 6)
	for i := range cases {
		cases[i] = &cfg.CFGNode{
			ID: 2 + i, Type: cfg.NodeTypeBasic, RPONumber: 10 + i,
			Instructions: []cfg.InstructionRef{
				// Use a two-digit hex value to exercise real hex parsing.
				{Index: 0, Opcode: "const/16", Raw: "const/16 " + stateReg + ", 0x0" + caseDigit((i + 1) % 6)[2:]},
			},
		}
	}
	dispatcher := &cfg.CFGNode{
		ID: 1, Type: cfg.NodeTypeSwitch, LoopDepth: 1, RPONumber: 5,
		SwitchInfo: &cfg.SwitchInfo{Type: cfg.SwitchPacked, Register: stateReg},
	}
	for i, c := range cases {
		dispatcher.SwitchInfo.Targets = append(dispatcher.SwitchInfo.Targets, cfg.SwitchTarget{Key: i, TargetID: c.ID})
		c.Predecessors = append(c.Predecessors, dispatcher)
	}
	dispatcher.Predecessors = append(dispatcher.Predecessors, cases...)
	entry := &cfg.CFGNode{ID: 0, Type: cfg.NodeTypeEntry, Successors: []*cfg.CFGNode{dispatcher}}
	nodes := append([]*cfg.CFGNode{entry, dispatcher}, cases...)
	g := &cfg.ControlFlowGraph{Entry: entry, Nodes: nodes}

	res := NewDefaultEngine().Analyze(g)
	if !res.CFFFDetected {
		t.Fatal("expected CFF detection")
	}
	if len(res.CFFRecoveredEdges) == 0 {
		t.Error("expected recovered edges from hex next-state constants")
	}
}
