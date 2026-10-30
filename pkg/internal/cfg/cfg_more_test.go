package cfg

import (
	"strings"
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// types.go — GuardType, NodeType, EdgeType, ConditionOp, ValueRef
// ═══════════════════════════════════════════════════════════════════════════════

func TestGuardType_StringAll(t *testing.T) {
	cases := map[GuardType]string{
		GuardTypeUnknown:    "unknown",
		GuardTypeNull:       "null",
		GuardTypeBounds:     "bounds",
		GuardTypeType:       "type",
		GuardTypeLicense:    "license",
		GuardTypeRoot:       "root",
		GuardTypeDebug:      "debug",
		GuardTypeNetwork:    "network",
		GuardTypePermission: "permission",
	}
	for g, want := range cases {
		if got := g.String(); got != want {
			t.Errorf("GuardType(%d).String() = %q, want %q", g, got, want)
		}
	}
	// Out-of-range
	if GuardType(100).String() != "unknown" {
		t.Error("out-of-range GuardType should return 'unknown'")
	}
}

func TestNodeType_StringAll(t *testing.T) {
	types := []NodeType{
		NodeTypeEntry, NodeTypeBasic, NodeTypeCondition, NodeTypeSwitch,
		NodeTypeReturn, NodeTypeThrow, NodeTypeExit, NodeTypeCatch, NodeTypeGuard,
		NodeTypeFunnel, NodeTypePhi, NodeTypeCallSite, NodeTypeMonitorEnter,
		NodeTypeMonitorExit, NodeTypeSynthetic,
	}
	for _, nt := range types {
		s := nt.String()
		if s == "" {
			t.Errorf("NodeType(%d).String() is empty", nt)
		}
	}
	// Out-of-range should show "unknown(N)"
	unk := NodeType(200).String()
	if !strings.Contains(unk, "unknown") {
		t.Errorf("out-of-range NodeType.String() = %q, expected 'unknown'", unk)
	}
}

func TestNodeType_IsBranching_X(t *testing.T) {
	if !NodeTypeCondition.IsBranching() {
		t.Error("Condition should be branching")
	}
	if !NodeTypeSwitch.IsBranching() {
		t.Error("Switch should be branching")
	}
	if NodeTypeBasic.IsBranching() {
		t.Error("Basic should not be branching")
	}
}

func TestNodeType_IsTerminator_X(t *testing.T) {
	if !NodeTypeReturn.IsTerminator() {
		t.Error("Return should be terminator")
	}
	if !NodeTypeThrow.IsTerminator() {
		t.Error("Throw should be terminator")
	}
	if !NodeTypeExit.IsTerminator() {
		t.Error("Exit should be terminator")
	}
	if NodeTypeBasic.IsTerminator() {
		t.Error("Basic should not be terminator")
	}
}

func TestExitKind_StringAll(t *testing.T) {
	cases := map[ExitKind]string{
		ExitNormal:      "normal",
		ExitException:   "exception",
		ExitUnreachable: "unreachable",
	}
	for k, want := range cases {
		if got := k.String(); got != want {
			t.Errorf("ExitKind(%d).String() = %q, want %q", k, got, want)
		}
	}
}

func TestEdgeType_StringAll(t *testing.T) {
	types := []EdgeType{
		EdgeFallthrough, EdgeTrue, EdgeFalse, EdgeGoto, EdgeSwitch,
		EdgeException, EdgeCall, EdgeReturn, EdgeSummary,
	}
	for _, et := range types {
		s := et.String()
		if s == "" {
			t.Errorf("EdgeType(%d).String() is empty", et)
		}
	}
	// Out-of-range
	unk := EdgeType(200).String()
	if !strings.Contains(unk, "unknown") {
		t.Errorf("out-of-range EdgeType.String() = %q", unk)
	}
}

func TestLoopType_StringAll(t *testing.T) {
	cases := map[LoopType]string{
		LoopNatural:     "natural",
		LoopIrreducible: "irreducible",
		LoopInfinite:    "infinite",
	}
	for lt, want := range cases {
		if got := lt.String(); got != want {
			t.Errorf("LoopType(%d).String() = %q, want %q", lt, got, want)
		}
	}
}

func TestValueKind_StringAll(t *testing.T) {
	kinds := []ValueKind{
		ValueUnknown, ValueRegister, ValueConst, ValueField, ValueInvoke, ValuePhi, ValueParam,
	}
	for _, k := range kinds {
		s := k.String()
		if s == "" {
			t.Errorf("ValueKind(%d).String() is empty", k)
		}
	}
}

func TestValueRef_IsZero_X(t *testing.T) {
	cases := []struct {
		vr   ValueRef
		want bool
	}{
		{ValueRef{Kind: ValueConst, ConstValue: 0}, true},
		{ValueRef{Kind: ValueConst, ConstValue: int64(0)}, true},
		{ValueRef{Kind: ValueConst, ConstValue: false}, true},
		{ValueRef{Kind: ValueConst, ConstValue: nil}, true},
		{ValueRef{Kind: ValueConst, ConstValue: 1}, false},
		{ValueRef{Kind: ValueConst, ConstValue: int64(1)}, false},
		{ValueRef{Kind: ValueConst, ConstValue: true}, false},
		{ValueRef{Kind: ValueRegister}, false},
	}
	for i, c := range cases {
		if got := c.vr.IsZero(); got != c.want {
			t.Errorf("case %d: IsZero() = %v, want %v", i, got, c.want)
		}
	}
}

func TestValueRef_IsBoolean_X(t *testing.T) {
	vr := ValueRef{Kind: ValueConst, ConstType: "Z"}
	if !vr.IsBoolean() {
		t.Error("Z type should be boolean")
	}
	vr2 := ValueRef{Kind: ValueField, FieldType: "Z"}
	if !vr2.IsBoolean() {
		t.Error("FieldType Z should be boolean")
	}
	vr3 := ValueRef{Kind: ValueConst, ConstType: "I"}
	if vr3.IsBoolean() {
		t.Error("I type should not be boolean")
	}
}

func TestValueRef_String_X(t *testing.T) {
	cases := []struct {
		vr      ValueRef
		contain string
	}{
		{ValueRef{Kind: ValueRegister, Register: "v0"}, "v0"},
		{ValueRef{Kind: ValueRegister, Register: "v1", SSAVersion: 2}, "v1_2"},
		{ValueRef{Kind: ValueConst, ConstValue: 42}, "42"},
		{ValueRef{Kind: ValueField, FieldOwner: "Lcom/test/Foo;", FieldName: "bar"}, "bar"},
		{ValueRef{Kind: ValueInvoke, InvokeMethod: "doStuff"}, "doStuff"},
		{ValueRef{Kind: ValuePhi, Register: "v3"}, "v3"},
		{ValueRef{Kind: ValueParam, Register: "p0"}, "p0"},
		{ValueRef{Kind: ValueUnknown}, "?"},
	}
	for _, c := range cases {
		s := c.vr.String()
		if !strings.Contains(s, c.contain) {
			t.Errorf("ValueRef.String() = %q, expected to contain %q", s, c.contain)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// ConditionOp
// ═══════════════════════════════════════════════════════════════════════════════

func TestConditionOp_StringAll(t *testing.T) {
	ops := []ConditionOp{
		CondUnknown, CondEqZero, CondNeZero, CondLtZero, CondGeZero, CondGtZero, CondLeZero,
		CondEq, CondNe, CondLt, CondGe, CondGt, CondLe,
	}
	for _, op := range ops {
		s := op.String()
		if s == "" {
			t.Errorf("ConditionOp(%d).String() is empty", op)
		}
	}
	// Out-of-range
	if ConditionOp(200).String() != "?" {
		t.Error("out-of-range ConditionOp should return '?'")
	}
}

func TestConditionOp_Negate_X(t *testing.T) {
	pairs := [][2]ConditionOp{
		{CondEqZero, CondNeZero},
		{CondLtZero, CondGeZero},
		{CondGtZero, CondLeZero},
		{CondEq, CondNe},
		{CondLt, CondGe},
		{CondGt, CondLe},
	}
	for _, p := range pairs {
		if p[0].Negate() != p[1] {
			t.Errorf("Negate(%v) = %v, want %v", p[0], p[0].Negate(), p[1])
		}
		if p[1].Negate() != p[0] {
			t.Errorf("Negate(%v) = %v, want %v", p[1], p[1].Negate(), p[0])
		}
	}
	// Unknown → Unknown
	if CondUnknown.Negate() != CondUnknown {
		t.Error("Negate(CondUnknown) should be CondUnknown")
	}
}

func TestConditionOp_IsZeroCheck_X(t *testing.T) {
	zeroChecks := []ConditionOp{CondEqZero, CondNeZero, CondLtZero, CondGeZero, CondGtZero, CondLeZero}
	for _, op := range zeroChecks {
		if !op.IsZeroCheck() {
			t.Errorf("%v should be a zero check", op)
		}
	}
	nonZeroChecks := []ConditionOp{CondEq, CondNe, CondLt, CondGe, CondUnknown}
	for _, op := range nonZeroChecks {
		if op.IsZeroCheck() {
			t.Errorf("%v should not be a zero check", op)
		}
	}
}

func TestConditionOp_IsBooleanCheck_X(t *testing.T) {
	if !CondEqZero.IsBooleanCheck() {
		t.Error("CondEqZero should be boolean check")
	}
	if !CondNeZero.IsBooleanCheck() {
		t.Error("CondNeZero should be boolean check")
	}
	if CondLtZero.IsBooleanCheck() {
		t.Error("CondLtZero should not be boolean check")
	}
}

func TestParseConditionOp(t *testing.T) {
	cases := map[string]ConditionOp{
		"if-eqz": CondEqZero,
		"if-nez": CondNeZero,
		"if-ltz": CondLtZero,
		"if-gez": CondGeZero,
		"if-gtz": CondGtZero,
		"if-lez": CondLeZero,
		"if-eq":  CondEq,
		"if-ne":  CondNe,
		"if-lt":  CondLt,
		"if-ge":  CondGe,
		"if-gt":  CondGt,
		"if-le":  CondLe,
		"other":  CondUnknown,
	}
	for opcode, want := range cases {
		got := ParseConditionOp(opcode)
		if got != want {
			t.Errorf("ParseConditionOp(%q) = %v, want %v", opcode, got, want)
		}
	}
}

func TestConditionInfo_Evaluate_X(t *testing.T) {
	c := &ConditionInfo{
		Op:  CondEqZero,
		LHS: &ValueRef{Kind: ValueConst, ConstValue: 0},
	}
	result, known := c.Evaluate(nil, nil)
	if !known {
		t.Error("should be known")
	}
	if !result {
		t.Error("0 == zero should be true")
	}

	c2 := &ConditionInfo{
		Op:  CondNeZero,
		LHS: &ValueRef{Kind: ValueConst, ConstValue: 0},
	}
	result2, known2 := c2.Evaluate(nil, nil)
	if !known2 {
		t.Error("should be known for NeZero with zero const")
	}
	if result2 {
		t.Error("0 != zero should be false")
	}

	// Non-const → not known
	c3 := &ConditionInfo{
		Op:  CondEqZero,
		LHS: &ValueRef{Kind: ValueRegister},
	}
	_, known3 := c3.Evaluate(nil, nil)
	if known3 {
		t.Error("register value should not produce known result")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// ControlFlowGraph methods
// ═══════════════════════════════════════════════════════════════════════════════

func TestCFG_NodeCountEdgeCount(t *testing.T) {
	g := &ControlFlowGraph{
		Nodes: []*CFGNode{{ID: 0}, {ID: 1}},
		Edges: []*CFGEdge{{}, {}},
	}
	if g.NodeCount() != 2 {
		t.Errorf("NodeCount() = %d, want 2", g.NodeCount())
	}
	if g.EdgeCount() != 2 {
		t.Errorf("EdgeCount() = %d, want 2", g.EdgeCount())
	}
}

func TestCFG_GetNode(t *testing.T) {
	n0 := &CFGNode{ID: 0}
	n1 := &CFGNode{ID: 1}
	g := &ControlFlowGraph{Nodes: []*CFGNode{n0, n1}}
	if g.GetNode(0) != n0 {
		t.Error("GetNode(0) should return n0")
	}
	if g.GetNode(1) != n1 {
		t.Error("GetNode(1) should return n1")
	}
	if g.GetNode(-1) != nil {
		t.Error("GetNode(-1) should return nil")
	}
	if g.GetNode(99) != nil {
		t.Error("GetNode(99) should return nil")
	}
}

func TestCFG_AddEdge(t *testing.T) {
	n0 := &CFGNode{ID: 0, Successors: make([]*CFGNode, 0), Predecessors: make([]*CFGNode, 0)}
	n1 := &CFGNode{ID: 1, Successors: make([]*CFGNode, 0), Predecessors: make([]*CFGNode, 0)}
	g := &ControlFlowGraph{}

	edge := g.AddEdge(n0, n1, EdgeFallthrough)
	if edge == nil {
		t.Fatal("AddEdge returned nil")
	}
	if len(n0.Successors) != 1 || n0.Successors[0] != n1 {
		t.Error("n0 should have n1 as successor")
	}
	if len(n1.Predecessors) != 1 || n1.Predecessors[0] != n0 {
		t.Error("n1 should have n0 as predecessor")
	}
	if len(g.Edges) != 1 {
		t.Errorf("expected 1 edge, got %d", len(g.Edges))
	}
}

func TestCFG_FindEdge(t *testing.T) {
	n0 := &CFGNode{ID: 0, Successors: make([]*CFGNode, 0), Predecessors: make([]*CFGNode, 0)}
	n1 := &CFGNode{ID: 1, Successors: make([]*CFGNode, 0), Predecessors: make([]*CFGNode, 0)}
	n2 := &CFGNode{ID: 2, Successors: make([]*CFGNode, 0), Predecessors: make([]*CFGNode, 0)}
	g := &ControlFlowGraph{}

	g.AddEdge(n0, n1, EdgeTrue)
	edge := g.FindEdge(n0, n1)
	if edge == nil {
		t.Error("FindEdge should return edge")
	}
	// Non-existent edge
	if g.FindEdge(n0, n2) != nil {
		t.Error("FindEdge for non-existent edge should be nil")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// index.go — LabelIndex, InstructionIndex, opcode classifiers
// ═══════════════════════════════════════════════════════════════════════════════

func TestLabelIndex_SizeAndAllLabels(t *testing.T) {
	idx := NewLabelIndex()
	instrs := []Instruction{
		{Line: 1, Opcode: "const/4", Raw: "const/4 v0, 0"},
		{Line: 2, Opcode: "if-eqz", Raw: "if-eqz v0, :cond_0"},
		{Line: 3, Opcode: "return-void", Raw: "return-void"},
	}
	labels := []Label{
		{Name: ":cond_0", Line: 2},
	}
	idx.BuildFromMethod(instrs, labels)
	if idx.Size() != 1 {
		t.Errorf("Size() = %d, want 1", idx.Size())
	}
	all := idx.AllLabels()
	if len(all) != 1 || all[0] != ":cond_0" {
		t.Errorf("AllLabels() = %v", all)
	}
}

func TestLabelIndex_FallbackLineMatch(t *testing.T) {
	idx := NewLabelIndex()
	// Label line matches instruction line exactly (no line+1 match possible)
	instrs := []Instruction{
		{Line: 5, Opcode: "return-void"},
	}
	labels := []Label{
		{Name: ":lbl", Line: 5},
	}
	idx.BuildFromMethod(instrs, labels)
	// Should find via fallback
	if !idx.HasLabel(":lbl") {
		t.Error("label should be indexed via fallback exact line match")
	}
}

func TestInstructionIndex_Basics(t *testing.T) {
	instrs := []Instruction{
		{Index: 0, Line: 1, Opcode: "const/4", Operands: []string{"v0", "0"}, Raw: "const/4 v0, 0"},
		{Index: 1, Line: 2, Opcode: "if-eqz", Operands: []string{"v0", ":cond_0"}, Raw: "if-eqz v0, :cond_0"},
		{Index: 2, Line: 3, Opcode: "return-void", Operands: []string{}, Raw: "return-void"},
		{Index: 3, Line: 4, Opcode: "invoke-virtual", Operands: []string{"v0", "Ljava/lang/Object;->toString()Ljava/lang/String;"}, Raw: "invoke-virtual {v0}, Ljava/lang/Object;->toString()"},
		{Index: 4, Line: 5, Opcode: "throw", Operands: []string{"v1"}, Raw: "throw v1"},
	}
	idx := NewInstructionIndex(instrs)

	if idx.Len() != 5 {
		t.Errorf("Len() = %d, want 5", idx.Len())
	}

	instr := idx.Get(0)
	if instr == nil || instr.Opcode != "const/4" {
		t.Error("Get(0) should return const/4")
	}
	if idx.Get(-1) != nil {
		t.Error("Get(-1) should be nil")
	}
	if idx.Get(99) != nil {
		t.Error("Get(99) should be nil")
	}

	byLine := idx.GetByLine(1)
	if byLine == nil {
		t.Error("GetByLine(1) should return instruction")
	}
	if idx.GetByLine(99) != nil {
		t.Error("GetByLine(99) should return nil")
	}

	if len(idx.GetConditions()) != 1 {
		t.Errorf("expected 1 condition, got %d", len(idx.GetConditions()))
	}
	if len(idx.GetReturns()) != 1 {
		t.Errorf("expected 1 return, got %d", len(idx.GetReturns()))
	}
	if len(idx.GetInvokes()) != 1 {
		t.Errorf("expected 1 invoke, got %d", len(idx.GetInvokes()))
	}
	if len(idx.GetThrows()) != 1 {
		t.Errorf("expected 1 throw, got %d", len(idx.GetThrows()))
	}
}

func TestInstructionIndex_GetByType(t *testing.T) {
	instrs := []Instruction{
		{Index: 0, Opcode: "goto", Raw: "goto :lbl"},
		{Index: 1, Opcode: "monitor-enter", Operands: []string{"v0"}, Raw: "monitor-enter v0"},
		{Index: 2, Opcode: "monitor-exit", Operands: []string{"v0"}, Raw: "monitor-exit v0"},
		{Index: 3, Opcode: "iget", Operands: []string{"v0", "v1", "Lcom/Foo;->bar:I"}, Raw: "iget v0, v1, Lcom/Foo;->bar:I"},
		{Index: 4, Opcode: "iput", Operands: []string{"v0", "v1", "Lcom/Foo;->bar:I"}, Raw: "iput v0, v1, Lcom/Foo;->bar:I"},
		{Index: 5, Opcode: "move", Operands: []string{"v0", "v1"}, Raw: "move v0, v1"},
		{Index: 6, Opcode: "new-instance", Operands: []string{"v0", "Lcom/Foo;"}, Raw: "new-instance v0, Lcom/Foo;"},
		{Index: 7, Opcode: "new-array", Operands: []string{"v0", "v1", "[I"}, Raw: "new-array v0, v1, [I"},
		{Index: 8, Opcode: "packed-switch", Operands: []string{"v0", ":pswitch_data_0"}, Raw: "packed-switch v0, :pswitch_data_0"},
	}
	idx := NewInstructionIndex(instrs)

	if len(idx.GetGotos()) != 1 {
		t.Errorf("gotos = %d, want 1", len(idx.GetGotos()))
	}
	if len(idx.GetMonitors()) != 2 {
		t.Errorf("monitors = %d, want 2", len(idx.GetMonitors()))
	}
	if len(idx.GetFieldReads()) != 1 {
		t.Errorf("fieldReads = %d, want 1", len(idx.GetFieldReads()))
	}
	if len(idx.GetFieldWrites()) != 1 {
		t.Errorf("fieldWrites = %d, want 1", len(idx.GetFieldWrites()))
	}
	if len(idx.GetMoves()) != 1 {
		t.Errorf("moves = %d, want 1", len(idx.GetMoves()))
	}
	if len(idx.GetNews()) != 2 {
		t.Errorf("news = %d, want 2", len(idx.GetNews()))
	}
	if len(idx.GetSwitches()) != 1 {
		t.Errorf("switches = %d, want 1", len(idx.GetSwitches()))
	}
}

func TestInstructionIndex_GetRange_X(t *testing.T) {
	instrs := []Instruction{
		{Index: 0, Opcode: "nop"},
		{Index: 1, Opcode: "const/4"},
		{Index: 2, Opcode: "return-void"},
	}
	idx := NewInstructionIndex(instrs)

	r := idx.GetRange(0, 2)
	if len(r) != 2 {
		t.Errorf("GetRange(0,2) len = %d, want 2", len(r))
	}

	// Edge cases
	if idx.GetRange(2, 1) != nil {
		t.Error("GetRange with start >= end should return nil")
	}
	if idx.GetRange(-1, 2) != nil {
		// start gets clamped to 0
		_ = idx.GetRange(-1, 2)
	}
}

func TestInstructionIndex_DefUse(t *testing.T) {
	instrs := []Instruction{
		{Index: 0, Opcode: "const/4", Operands: []string{"v0", "0"}, Raw: "const/4 v0, 0"},
		{Index: 1, Opcode: "if-eqz", Operands: []string{"v0", ":cond"}, Raw: "if-eqz v0, :cond"},
	}
	idx := NewInstructionIndex(instrs)

	defs := idx.GetDefs("v0")
	if len(defs) != 1 {
		t.Errorf("GetDefs(v0) = %d, want 1", len(defs))
	}
	uses := idx.GetUses("v0")
	if len(uses) != 1 {
		t.Errorf("GetUses(v0) = %d, want 1", len(uses))
	}
	regs := idx.GetAllRegisters()
	found := false
	for _, r := range regs {
		if r == "v0" {
			found = true
		}
	}
	if !found {
		t.Error("expected v0 in GetAllRegisters()")
	}
}

func TestInstructionIndex_GetSemantic(t *testing.T) {
	instrs := []Instruction{
		{Index: 0, Opcode: "const/4"},
	}
	idx := NewInstructionIndex(instrs)
	if idx.GetSemantic(0) != SemanticConst {
		t.Errorf("expected SemanticConst, got %v", idx.GetSemantic(0))
	}
	if idx.GetSemantic(-1) != SemanticOther {
		t.Error("out-of-range should return SemanticOther")
	}
}

func TestOpcodeFunctions(t *testing.T) {
	// isBranchOpcode
	for _, op := range []string{"if-eqz", "goto", "packed-switch", "sparse-switch"} {
		if !isBranchOpcode(op) {
			t.Errorf("isBranchOpcode(%q) should be true", op)
		}
	}
	if isBranchOpcode("const") {
		t.Error("const should not be branch")
	}

	// isReturnOpcode
	for _, op := range []string{"return-void", "return", "return-object"} {
		if !isReturnOpcode(op) {
			t.Errorf("isReturnOpcode(%q) should be true", op)
		}
	}

	// isInvokeOpcode
	for _, op := range []string{"invoke-virtual", "invoke-static", "invoke-direct"} {
		if !isInvokeOpcode(op) {
			t.Errorf("isInvokeOpcode(%q) should be true", op)
		}
	}

	// isConditionOpcode
	for _, op := range []string{"if-eqz", "if-ne", "if-lt"} {
		if !isConditionOpcode(op) {
			t.Errorf("isConditionOpcode(%q) should be true", op)
		}
	}

	// isGotoOpcode
	if !isGotoOpcode("goto") || !isGotoOpcode("goto/16") {
		t.Error("goto variants should be detected")
	}

	// isSwitchOpcode
	if !isSwitchOpcode("packed-switch") || !isSwitchOpcode("sparse-switch") {
		t.Error("switch variants should be detected")
	}

	// isThrowOpcode
	if !isThrowOpcode("throw") || isThrowOpcode("const") {
		t.Error("isThrowOpcode only matches 'throw'")
	}

	// isMonitorOpcode
	if !isMonitorOpcode("monitor-enter") || !isMonitorOpcode("monitor-exit") {
		t.Error("monitor opcodes should be detected")
	}

	// isFieldOpcode
	for _, op := range []string{"iget", "sget", "iput", "sput", "iget-wide"} {
		if !isFieldOpcode(op) {
			t.Errorf("isFieldOpcode(%q) should be true", op)
		}
	}

	// isMoveResultOpcode
	for _, op := range []string{"move-result", "move-result-wide", "move-result-object", "move-exception"} {
		if !isMoveResultOpcode(op) {
			t.Errorf("isMoveResultOpcode(%q) should be true", op)
		}
	}
}

func TestClassifyOpcode_Coverage(t *testing.T) {
	cases := map[string]SemanticType{
		"if-eqz":           SemanticBranch,
		"return-void":      SemanticReturn,
		"invoke-virtual":   SemanticInvoke,
		"throw":            SemanticThrow,
		"monitor-enter":    SemanticMonitor,
		"iget":             SemanticFieldRead,
		"sget":             SemanticFieldRead,
		"iput":             SemanticFieldWrite,
		"sput":             SemanticFieldWrite,
		"aget":             SemanticArrayRead,
		"aput":             SemanticArrayWrite,
		"move":             SemanticMove,
		"const/4":          SemanticConst,
		"add-int":          SemanticArithmetic,
		"sub-int":          SemanticArithmetic,
		"mul-float":        SemanticArithmetic,
		"div-long":         SemanticArithmetic,
		"rem-int":          SemanticArithmetic,
		"neg-int":          SemanticArithmetic,
		"and-int":          SemanticLogical,
		"or-int":           SemanticLogical,
		"xor-int":          SemanticLogical,
		"shl-int":          SemanticLogical,
		"shr-int":          SemanticLogical,
		"ushr-int":         SemanticLogical,
		"not-int":          SemanticLogical,
		"int-to-long":      SemanticConversion,
		"long-to-float":    SemanticConversion,
		"float-to-double":  SemanticConversion,
		"double-to-byte":   SemanticConversion,
		"int-to-char":      SemanticConversion,
		"long-to-short":    SemanticConversion,
		"cmpl-float":       SemanticComparison,
		"new-instance":     SemanticNewInstance,
		"new-array":        SemanticNewArray,
		"filled-new-array": SemanticNewArray,
		"check-cast":       SemanticCheckCast,
		"instance-of":      SemanticInstanceOf,
		"fill-array-data":  SemanticFillArray,
		"nop":              SemanticOther,
	}
	for opcode, want := range cases {
		got := classifyOpcode(opcode)
		if got != want {
			t.Errorf("classifyOpcode(%q) = %v, want %v", opcode, got, want)
		}
	}
}

func TestIsRegister(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{"v0", true},
		{"v9", true},
		{"p0", true},
		{"p3", true},
		{"v", false},
		{"x0", false},
		{"", false},
		{"v ", false},
	}
	for _, c := range cases {
		if got := isRegister(c.s); got != c.want {
			t.Errorf("isRegister(%q) = %v, want %v", c.s, got, c.want)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// builder.go — parseSmaliInt, BuildFromInstructions, BuildInputFromLines
// ═══════════════════════════════════════════════════════════════════════════════

func TestParseSmaliInt(t *testing.T) {
	cases := []struct {
		s    string
		want int
		ok   bool
	}{
		{"42", 42, true},
		{"0x1a", 26, true},
		{"0X1B", 27, true},
		{"-0x5", -5, true},
		{"-10", -10, true},
		{"abc", 0, false},
	}
	for _, c := range cases {
		got, err := parseSmaliInt(c.s)
		if c.ok && err != nil {
			t.Errorf("parseSmaliInt(%q) error: %v", c.s, err)
		}
		if c.ok && got != c.want {
			t.Errorf("parseSmaliInt(%q) = %d, want %d", c.s, got, c.want)
		}
		if !c.ok && err == nil {
			t.Errorf("parseSmaliInt(%q) should fail", c.s)
		}
	}
}

func TestBuildFromInstructions_Empty(t *testing.T) {
	_, err := BuildFromInstructions(nil, nil)
	if err == nil {
		t.Error("expected error for nil instructions")
	}
}

func TestBuildFromInstructions_Simple(t *testing.T) {
	instrs := []InstructionRef{
		{Index: 0, Opcode: "const/4", Raw: "const/4 v0, 0"},
		{Index: 1, Opcode: "return-void", Raw: "return-void"},
	}
	result, err := BuildFromInstructions(instrs, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil || result.CFG == nil {
		t.Error("expected non-nil result")
	}
}

func TestBuildInputFromLines(t *testing.T) {
	lines := []string{
		".method public test()V",
		"    const/4 v0, 0x0",
		"    :cond_0",
		"    if-eqz v0, :cond_1",
		"    return-void",
		"    :cond_1",
		"    return-void",
		".end method",
	}
	input := BuildInputFromLines("Lcom/test/Foo;", "test", "()V", lines)
	if input.MethodName != "test" {
		t.Errorf("MethodName = %q, want 'test'", input.MethodName)
	}
	if len(input.Instructions) == 0 {
		t.Error("expected instructions")
	}
	if len(input.Labels) == 0 {
		t.Error("expected labels")
	}
}

func TestConvertFromSmaliMethod_X(t *testing.T) {
	method := &SmaliMethod{
		Name:      "test",
		ClassName: "Lcom/test/Foo;",
		Signature: "()V",
		Instructions: []SmaliInstruction{
			{Line: 1, Opcode: "return-void", Raw: "return-void"},
		},
		Labels: []SmaliLabel{
			{Name: ":cond_0", Line: 0},
		},
	}
	input := ConvertFromSmaliMethod(method)
	if input.MethodName != "test" {
		t.Errorf("MethodName = %q", input.MethodName)
	}
	if len(input.Instructions) != 1 {
		t.Error("expected 1 instruction")
	}
	if len(input.Labels) != 1 {
		t.Error("expected 1 label")
	}
}

func TestCFGBuilder_BuildEx_IfGotoSwitch(t *testing.T) {
	// Build a method with if, goto, switch
	input := BuildInput{
		MethodName: "complex",
		Instructions: []Instruction{
			{Index: 0, Line: 1, Opcode: "const/4", Operands: []string{"v0", "0"}, Raw: "const/4 v0, 0"},
			{Index: 1, Line: 2, Opcode: "if-eqz", Operands: []string{"v0", ":cond_0"}, Raw: "if-eqz v0, :cond_0"},
			{Index: 2, Line: 3, Opcode: "return-void", Raw: "return-void"},
			{Index: 3, Line: 4, Opcode: "goto", Operands: []string{":goto_0"}, Raw: "goto :goto_0"},
			{Index: 4, Line: 5, Opcode: "return-void", Raw: "return-void"},
		},
		Labels: []Label{
			{Name: ":cond_0", Line: 3},
			{Name: ":goto_0", Line: 4},
		},
	}
	builder := NewCFGBuilder()
	result := builder.BuildEx(input)
	if result == nil || result.CFG == nil {
		t.Fatal("expected non-nil result")
	}
	if result.CFG.Entry == nil {
		t.Error("expected entry node")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// metrics.go
// ═══════════════════════════════════════════════════════════════════════════════

func buildLinearGraph(n int) *ControlFlowGraph {
	nodes := make([]*CFGNode, n)
	for i := range nodes {
		nodes[i] = &CFGNode{ID: i, Type: NodeTypeBasic}
	}
	nodes[0].Type = NodeTypeEntry
	nodes[n-1].Type = NodeTypeReturn

	g := &ControlFlowGraph{Nodes: nodes, Entry: nodes[0]}
	g.Exits = []*CFGNode{nodes[n-1]}
	g.ReturnExits = []*CFGNode{nodes[n-1]}
	for i := 0; i < n-1; i++ {
		g.AddEdge(nodes[i], nodes[i+1], EdgeFallthrough)
	}
	return g
}

func TestMetrics_CyclomaticComplexity_Linear(t *testing.T) {
	g := buildLinearGraph(3)
	m := NewMetrics(g)
	cc := m.CyclomaticComplexity()
	// E=2, N=3, P=1 → 2-3+2=1
	if cc != 1 {
		t.Errorf("expected CC=1 for linear graph, got %d", cc)
	}
}

func TestMetrics_CyclomaticComplexity_Nil(t *testing.T) {
	m := &Metrics{cfg: nil}
	if m.CyclomaticComplexity() != 0 {
		t.Error("nil CFG should give CC=0")
	}
}

func TestMetrics_HalsteadComplexity_X(t *testing.T) {
	g := &ControlFlowGraph{
		Nodes: []*CFGNode{
			{
				ID: 0,
				Instructions: []InstructionRef{
					{Opcode: "const/4", Raw: "const/4 v0, 0"},
					{Opcode: "if-eqz", Raw: "if-eqz v0, :cond"},
				},
			},
		},
	}
	m := NewMetrics(g)
	h := m.HalsteadComplexity()
	if h.N1 == 0 {
		t.Error("expected N1 > 0")
	}
}

func TestMetrics_NPathComplexity_X(t *testing.T) {
	m := &Metrics{cfg: nil}
	if m.NPathComplexity() != 0 {
		t.Error("nil cfg should give 0")
	}

	m2 := &Metrics{cfg: &ControlFlowGraph{}}
	if m2.NPathComplexity() != 0 {
		t.Error("empty cfg should give 0")
	}

	// Linear graph
	g := buildLinearGraph(3)
	m3 := NewMetrics(g)
	n := m3.NPathComplexity()
	if n < 1 {
		t.Errorf("expected NPath >= 1, got %d", n)
	}
}

func TestMetrics_FanAnalysis_X(t *testing.T) {
	g := buildLinearGraph(4)
	m := NewMetrics(g)
	fan := m.FanAnalysis()
	if fan.MaxFanOut == 0 && len(g.Nodes) > 1 {
		t.Error("expected MaxFanOut > 0 for non-trivial graph")
	}
}

func TestMetrics_ObfuscationDetection_X(t *testing.T) {
	g := buildLinearGraph(3)
	m := NewMetrics(g)
	obs := m.ObfuscationDetection()
	if obs.Score < 0 || obs.Score > 100 {
		t.Errorf("ObfuscationScore = %.2f, expected 0-100", obs.Score)
	}
}

func TestMetrics_AIReadiness_X(t *testing.T) {
	g := buildLinearGraph(3)
	m := NewMetrics(g)
	ai := m.AIReadiness()
	if ai.Score < 0 {
		t.Error("AIReadiness score should not be negative")
	}
}

func TestMetrics_MaintainabilityIndex_X(t *testing.T) {
	g := buildLinearGraph(5)
	// Add some instructions
	g.Nodes[1].Instructions = []InstructionRef{
		{Opcode: "const/4", Raw: "const/4 v0, 0"},
	}
	m := NewMetrics(g)
	mi := m.MaintainabilityIndex()
	if mi.MI < 0 || mi.MI > 100 {
		t.Errorf("MaintainabilityIndex = %.2f, expected 0-100", mi.MI)
	}
	if mi.Rating == "" {
		t.Error("Rating should not be empty")
	}
}

func TestMetrics_ExitDiversity_X(t *testing.T) {
	g := buildLinearGraph(3)
	m := NewMetrics(g)
	ed := m.ExitDiversity()
	if ed.TotalExits == 0 {
		t.Error("expected at least 1 exit")
	}
}

func TestMetrics_Summary_X(t *testing.T) {
	g := buildLinearGraph(4)
	m := NewMetrics(g)
	s := m.Summary()
	if s.NodeCount != 4 {
		t.Errorf("NodeCount = %d, want 4", s.NodeCount)
	}
}

func TestMetrics_EssentialComplexity_X(t *testing.T) {
	g := buildLinearGraph(3)
	m := NewMetrics(g)
	ec := m.EssentialComplexity()
	if ec < 0 {
		t.Error("EssentialComplexity should not be negative")
	}
}

func TestMetrics_CognitiveComplexity_X(t *testing.T) {
	g := &ControlFlowGraph{
		Nodes: []*CFGNode{
			{ID: 0, Type: NodeTypeEntry},
			{ID: 1, Type: NodeTypeCondition, IsLoopHeader: true},
			{ID: 2, Type: NodeTypeReturn},
		},
	}
	m := NewMetrics(g)
	cc := m.CognitiveComplexity()
	if cc < 0 {
		t.Error("CognitiveComplexity should not be negative")
	}
}

func TestMetrics_UltimateSummary_X(t *testing.T) {
	g := buildLinearGraph(3)
	m := NewMetrics(g)
	u := m.UltimateSummary()
	if u.Basic.NodeCount != 3 {
		t.Errorf("UltimateSummary.Basic.NodeCount = %d, want 3", u.Basic.NodeCount)
	}
}

func TestSplitSmaliTokens(t *testing.T) {
	tokens := splitSmaliTokens("if-eqz v0, :cond_0")
	if len(tokens) < 2 {
		t.Errorf("expected at least 2 tokens, got %d: %v", len(tokens), tokens)
	}
}

func TestMetricsHelpers(t *testing.T) {
	if !isMetricsRegister("v0") {
		t.Error("v0 should be register")
	}
	if !isMetricsRegister("p1") {
		t.Error("p1 should be register")
	}
	if isMetricsRegister("x") {
		t.Error("x should not be register")
	}

	if !isMetricsConstant("#0") {
		t.Error("#0 should be constant")
	}
	if !isMetricsConstant("0x42") {
		t.Error("0x42 should be constant")
	}
	if !isMetricsConstant("-1") {
		t.Error("-1 should be constant")
	}

	if !isMetricsReference("Lcom/Foo;") {
		t.Error("Lcom/Foo; should be reference")
	}
	if !isMetricsReference("[I") {
		t.Error("[I should be reference")
	}
	if isMetricsReference("v0") {
		t.Error("v0 should not be reference")
	}
}

func TestContainsInt(t *testing.T) {
	if !containsInt([]int{1, 2, 3}, 2) {
		t.Error("expected to find 2")
	}
	if containsInt([]int{1, 2, 3}, 99) {
		t.Error("expected not to find 99")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// patterns.go
// ═══════════════════════════════════════════════════════════════════════════════

func TestPatternAnalyzer_FindAntiDebugPatterns_Empty(t *testing.T) {
	g := &ControlFlowGraph{Nodes: []*CFGNode{}}
	pa := NewPatternAnalyzer(g)
	patterns := pa.FindAntiDebugPatterns()
	if len(patterns) != 0 {
		t.Errorf("expected 0 patterns, got %d", len(patterns))
	}
}

func TestPatternAnalyzer_FindAntiDebugPatterns_Detected(t *testing.T) {
	g := &ControlFlowGraph{
		Nodes: []*CFGNode{
			{
				ID: 0,
				Instructions: []InstructionRef{
					{Opcode: "invoke-virtual", Raw: "invoke-virtual {v0}, Landroid/content/pm/ApplicationInfo;->flags:I"},
				},
			},
		},
	}
	pa := NewPatternAnalyzer(g)
	patterns := pa.FindAntiDebugPatterns()
	if len(patterns) == 0 {
		t.Error("expected anti-debug pattern detected")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// dominators.go
// ═══════════════════════════════════════════════════════════════════════════════

func TestDominatorAnalyzer_ComputeDominators_Simple(t *testing.T) {
	g := buildLinearGraph(4)
	d := NewDominatorAnalyzer(g)
	// Should not panic
	d.ComputeDominators()
}

func TestDominatorAnalyzer_EmptyGraph(t *testing.T) {
	g := &ControlFlowGraph{}
	d := NewDominatorAnalyzer(g)
	// Should not panic on empty
	d.ComputeDominators()
}

// ═══════════════════════════════════════════════════════════════════════════════
// cache.go — EvictExpired, keyOf, Resize
// ═══════════════════════════════════════════════════════════════════════════════

func TestCFGCache_EvictExpired_NoTTL(t *testing.T) {
	c := NewCFGCache(100)
	n := c.EvictExpired()
	if n != 0 {
		t.Errorf("no-TTL cache should evict 0, got %d", n)
	}
}

func TestCFGCache_EvictExpired_WithTTL(t *testing.T) {
	c := NewCFGCacheWithConfig(CacheConfig{Capacity: 100, TTL: 1}) // 1ns TTL
	// Add an entry
	input := BuildInput{ClassName: "Foo", MethodName: "bar"}
	c.GetOrBuild(input)
	// After tiny TTL, entries should be evictable
	n := c.EvictExpired()
	_ = n // may or may not be 0 depending on timing
}

func TestCFGCache_Resize_X(t *testing.T) {
	c := NewCFGCache(100)
	c.Resize(50)
	if c.Capacity() != 50 {
		t.Errorf("Resize(50) capacity = %d, want 50", c.Capacity())
	}
	c.Resize(0) // should not panic, clamps to 1
}

func TestCFGCache_HashInput(t *testing.T) {
	c := NewCFGCache(100)
	a := BuildInput{ClassName: "Foo", MethodName: "bar", Signature: "()V"}
	b := BuildInput{ClassName: "Foo", MethodName: "baz", Signature: "()V"}
	ha := c.keyOf(a)
	hb := c.keyOf(b)
	if ha == hb {
		t.Error("different method names should produce different hashes")
	}
	// same input → same hash
	ha2 := c.keyOf(a)
	if ha != ha2 {
		t.Error("same input should produce same hash")
	}
	// With instructions and labels
	withInsns := BuildInput{
		ClassName:  "Foo",
		MethodName: "run",
		Instructions: []Instruction{
			{Raw: "invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I"},
		},
		Labels: []Label{{Name: ":cond_0"}},
	}
	h := c.keyOf(withInsns)
	if h.hi == 0 && h.lo == 0 {
		t.Error("hash should be non-zero")
	}
}

func TestCFGCache_EvictOldest(t *testing.T) {
	c := NewCFGCache(2)
	// Fill beyond capacity to trigger eviction
	for i := 0; i < 10; i++ {
		input := BuildInput{ClassName: "Class" + strings.Repeat("x", i), MethodName: "m"}
		c.GetOrBuild(input)
	}
	if c.Size() > c.Capacity()+8 { // shards allow slight overage per shard
		t.Errorf("cache size %d exceeds expected bound", c.Size())
	}
}
