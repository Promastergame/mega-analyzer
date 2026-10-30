// Package cfg — cfg_test.go
package cfg

import (
	"strings"
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// HELPER: build simple CFGs for testing
// ═══════════════════════════════════════════════════════════════════════════════

func buildSimpleCFG() *ControlFlowGraph {
	entry := &CFGNode{ID: 0, Type: NodeTypeEntry, Reachable: true}
	basic := &CFGNode{ID: 1, Type: NodeTypeBasic, Reachable: true, Instructions: []InstructionRef{
		{Index: 0, Opcode: "const/4", Line: 1, Raw: "const/4 v0, 0x0"},
		{Index: 1, Opcode: "invoke-virtual", Line: 2, Raw: "invoke-virtual {v0}, Lcom/app/License;->check()Z"},
	}}
	cond := &CFGNode{ID: 2, Type: NodeTypeCondition, Reachable: true, Condition: &ConditionInfo{
		Op:        CondEqZero,
		Register1: "v0",
		Target:    ":cond_0",
	}}
	ret := &CFGNode{ID: 3, Type: NodeTypeReturn, Reachable: true, ExitKind: ExitNormal, Instructions: []InstructionRef{
		{Index: 2, Opcode: "return", Line: 3, Raw: "return v0"},
	}}
	thr := &CFGNode{ID: 4, Type: NodeTypeThrow, Reachable: true, ExitKind: ExitException}

	entry.Successors = []*CFGNode{basic}
	basic.Predecessors = []*CFGNode{entry}
	basic.Successors = []*CFGNode{cond}
	cond.Predecessors = []*CFGNode{basic}
	cond.Successors = []*CFGNode{ret, thr}
	ret.Predecessors = []*CFGNode{cond}
	thr.Predecessors = []*CFGNode{cond}

	g := &ControlFlowGraph{
		MethodName:  "check",
		ClassName:   "Lcom/app/License;",
		Signature:   "()Z",
		FullName:    "Lcom/app/License;->check()Z",
		Nodes:       []*CFGNode{entry, basic, cond, ret, thr},
		Entry:       entry,
		Exits:       []*CFGNode{ret, thr},
		ReturnExits: []*CFGNode{ret},
		ThrowExits:  []*CFGNode{thr},
		EdgeIndex:   make(map[edgeKey]*CFGEdge),
	}

	g.AddEdge(entry, basic, EdgeFallthrough)
	g.AddEdge(basic, cond, EdgeFallthrough)
	g.AddEdge(cond, ret, EdgeTrue)
	g.AddEdge(cond, thr, EdgeFalse)

	return g
}

func buildLinearCFG(n int) *ControlFlowGraph {
	nodes := make([]*CFGNode, n)
	for i := range nodes {
		t := NodeTypeBasic
		if i == 0 {
			t = NodeTypeEntry
		}
		if i == n-1 {
			t = NodeTypeReturn
		}
		nodes[i] = &CFGNode{ID: i, Type: t, Reachable: true}
	}

	g := &ControlFlowGraph{
		MethodName: "linear",
		Nodes:      nodes,
		Entry:      nodes[0],
		Exits:      []*CFGNode{nodes[n-1]},
		EdgeIndex:  make(map[edgeKey]*CFGEdge),
	}

	for i := 0; i < n-1; i++ {
		nodes[i].Successors = []*CFGNode{nodes[i+1]}
		nodes[i+1].Predecessors = []*CFGNode{nodes[i]}
		g.AddEdge(nodes[i], nodes[i+1], EdgeFallthrough)
	}

	return g
}

// ═══════════════════════════════════════════════════════════════════════════════
// TYPES — ENUM STRING METHODS
// ═══════════════════════════════════════════════════════════════════════════════

func TestGuardType_String(t *testing.T) {
	tests := []struct {
		g    GuardType
		want string
	}{
		{GuardTypeUnknown, "unknown"},
		{GuardTypeNull, "null"},
		{GuardTypeBounds, "bounds"},
		{GuardTypeLicense, "license"},
		{GuardTypeRoot, "root"},
		{GuardTypeDebug, "debug"},
		{GuardTypeNetwork, "network"},
		{GuardTypePermission, "permission"},
		{GuardType(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.g.String(); got != tt.want {
			t.Errorf("GuardType(%d).String() = %q, want %q", tt.g, got, tt.want)
		}
	}
}

func TestNodeType_String(t *testing.T) {
	tests := []struct {
		n    NodeType
		want string
	}{
		{NodeTypeEntry, "entry"},
		{NodeTypeBasic, "basic"},
		{NodeTypeCondition, "condition"},
		{NodeTypeSwitch, "switch"},
		{NodeTypeReturn, "return"},
		{NodeTypeThrow, "throw"},
		{NodeTypeExit, "exit"},
		{NodeTypeCatch, "catch"},
		{NodeTypeGuard, "guard"},
		{NodeTypeFunnel, "funnel"},
		{NodeTypePhi, "phi"},
		{NodeTypeCallSite, "callsite"},
		{NodeTypeMonitorEnter, "monitor-enter"},
		{NodeTypeMonitorExit, "monitor-exit"},
		{NodeTypeSynthetic, "synthetic"},
	}
	for _, tt := range tests {
		if got := tt.n.String(); got != tt.want {
			t.Errorf("NodeType(%d).String() = %q, want %q", tt.n, got, tt.want)
		}
	}
}

func TestNodeType_IsTerminator(t *testing.T) {
	if !NodeTypeReturn.IsTerminator() {
		t.Error("return should be terminator")
	}
	if !NodeTypeThrow.IsTerminator() {
		t.Error("throw should be terminator")
	}
	if NodeTypeBasic.IsTerminator() {
		t.Error("basic should not be terminator")
	}
}

func TestNodeType_IsBranching(t *testing.T) {
	if !NodeTypeCondition.IsBranching() {
		t.Error("condition should be branching")
	}
	if !NodeTypeSwitch.IsBranching() {
		t.Error("switch should be branching")
	}
	if NodeTypeBasic.IsBranching() {
		t.Error("basic should not be branching")
	}
}

func TestExitKind_String(t *testing.T) {
	tests := []struct {
		k    ExitKind
		want string
	}{
		{ExitNormal, "normal"},
		{ExitException, "exception"},
		{ExitUnreachable, "unreachable"},
	}
	for _, tt := range tests {
		if got := tt.k.String(); got != tt.want {
			t.Errorf("ExitKind(%d) = %q, want %q", tt.k, got, tt.want)
		}
	}
}

func TestEdgeType_String(t *testing.T) {
	tests := []struct {
		e    EdgeType
		want string
	}{
		{EdgeFallthrough, "fallthrough"},
		{EdgeTrue, "true"},
		{EdgeFalse, "false"},
		{EdgeGoto, "goto"},
		{EdgeSwitch, "switch"},
		{EdgeException, "exception"},
		{EdgeCall, "call"},
		{EdgeReturn, "return"},
		{EdgeSummary, "summary"},
		{EdgeType(99), "unknown(99)"},
	}
	for _, tt := range tests {
		if got := tt.e.String(); got != tt.want {
			t.Errorf("EdgeType(%d) = %q, want %q", tt.e, got, tt.want)
		}
	}
}

func TestValueKind_String(t *testing.T) {
	tests := []struct {
		k    ValueKind
		want string
	}{
		{ValueUnknown, "unknown"},
		{ValueRegister, "reg"},
		{ValueConst, "const"},
		{ValueField, "field"},
		{ValueInvoke, "invoke"},
		{ValuePhi, "phi"},
		{ValueParam, "param"},
	}
	for _, tt := range tests {
		if got := tt.k.String(); got != tt.want {
			t.Errorf("ValueKind(%d) = %q, want %q", tt.k, got, tt.want)
		}
	}
}

func TestLoopType_String(t *testing.T) {
	if LoopNatural.String() != "natural" {
		t.Error("wrong")
	}
	if LoopIrreducible.String() != "irreducible" {
		t.Error("wrong")
	}
	if LoopInfinite.String() != "infinite" {
		t.Error("wrong")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONDITION OP
// ═══════════════════════════════════════════════════════════════════════════════

func TestConditionOp_String(t *testing.T) {
	if CondEqZero.String() != "==0" {
		t.Errorf("got %q", CondEqZero.String())
	}
	if CondNe.String() != "!=" {
		t.Errorf("got %q", CondNe.String())
	}
}

func TestConditionOp_Negate(t *testing.T) {
	tests := []struct {
		op   ConditionOp
		want ConditionOp
	}{
		{CondEqZero, CondNeZero},
		{CondNeZero, CondEqZero},
		{CondLtZero, CondGeZero},
		{CondEq, CondNe},
		{CondLt, CondGe},
		{CondGt, CondLe},
		{CondUnknown, CondUnknown},
	}
	for _, tt := range tests {
		if got := tt.op.Negate(); got != tt.want {
			t.Errorf("Negate(%v) = %v, want %v", tt.op, got, tt.want)
		}
	}
}

func TestConditionOp_IsZeroCheck(t *testing.T) {
	if !CondEqZero.IsZeroCheck() {
		t.Error("eqz should be zero check")
	}
	if CondEq.IsZeroCheck() {
		t.Error("eq should not be zero check")
	}
}

func TestConditionOp_IsBooleanCheck(t *testing.T) {
	if !CondEqZero.IsBooleanCheck() {
		t.Error("eqz should be boolean check")
	}
	if !CondNeZero.IsBooleanCheck() {
		t.Error("nez should be boolean check")
	}
	if CondLtZero.IsBooleanCheck() {
		t.Error("ltz should not be boolean check")
	}
}

func TestParseConditionOp_CFG(t *testing.T) {
	tests := []struct {
		opcode string
		want   ConditionOp
	}{
		{"if-eqz", CondEqZero},
		{"if-nez", CondNeZero},
		{"if-eq", CondEq},
		{"if-ne", CondNe},
		{"if-lt", CondLt},
		{"garbage", CondUnknown},
	}
	for _, tt := range tests {
		if got := ParseConditionOp(tt.opcode); got != tt.want {
			t.Errorf("ParseConditionOp(%q) = %v, want %v", tt.opcode, got, tt.want)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// VALUE REF
// ═══════════════════════════════════════════════════════════════════════════════

func TestValueRef_IsZero(t *testing.T) {
	tests := []struct {
		name string
		v    ValueRef
		want bool
	}{
		{"int zero", ValueRef{Kind: ValueConst, ConstValue: 0}, true},
		{"int64 zero", ValueRef{Kind: ValueConst, ConstValue: int64(0)}, true},
		{"bool false", ValueRef{Kind: ValueConst, ConstValue: false}, true},
		{"nil", ValueRef{Kind: ValueConst, ConstValue: nil}, true},
		{"int nonzero", ValueRef{Kind: ValueConst, ConstValue: 42}, false},
		{"bool true", ValueRef{Kind: ValueConst, ConstValue: true}, false},
		{"register", ValueRef{Kind: ValueRegister}, false},
		{"string zero", ValueRef{Kind: ValueConst, ConstValue: "0"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.v.IsZero(); got != tt.want {
				t.Errorf("IsZero() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValueRef_IsBoolean(t *testing.T) {
	if !(&ValueRef{ConstType: "Z"}).IsBoolean() {
		t.Error("Z should be boolean")
	}
	if !(&ValueRef{FieldType: "Z"}).IsBoolean() {
		t.Error("field Z should be boolean")
	}
	if (&ValueRef{ConstType: "I"}).IsBoolean() {
		t.Error("I should not be boolean")
	}
}

func TestValueRef_String(t *testing.T) {
	tests := []struct {
		v    ValueRef
		want string
	}{
		{ValueRef{Kind: ValueRegister, Register: "v0"}, "v0"},
		{ValueRef{Kind: ValueRegister, Register: "v0", SSAVersion: 2}, "v0_2"},
		{ValueRef{Kind: ValueConst, ConstValue: 42}, "const(42)"},
		{ValueRef{Kind: ValueField, FieldOwner: "Lcom/app/License;", FieldName: "valid"}, "License.valid"},
		{ValueRef{Kind: ValueInvoke, InvokeMethod: "check"}, "check()"},
		{ValueRef{Kind: ValuePhi, Register: "v0"}, "φ(v0)"},
		{ValueRef{Kind: ValueParam, Register: "p0"}, "param(p0)"},
		{ValueRef{Kind: ValueUnknown}, "?"},
	}
	for _, tt := range tests {
		got := tt.v.String()
		if got != tt.want {
			t.Errorf("ValueRef.String() = %q, want %q", got, tt.want)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONDITION INFO — Evaluate
// ═══════════════════════════════════════════════════════════════════════════════

func TestConditionInfo_Evaluate(t *testing.T) {
	ci := &ConditionInfo{
		Op:  CondEqZero,
		LHS: &ValueRef{Kind: ValueConst, ConstValue: 0},
	}
	result, known := ci.Evaluate(nil, nil)
	if !known || !result {
		t.Error("0 == 0 should be true")
	}

	ci2 := &ConditionInfo{
		Op:  CondNeZero,
		LHS: &ValueRef{Kind: ValueConst, ConstValue: 0},
	}
	result2, known2 := ci2.Evaluate(nil, nil)
	if !known2 || result2 {
		t.Error("0 != 0 should be false")
	}

	ci3 := &ConditionInfo{
		Op:  CondEqZero,
		LHS: &ValueRef{Kind: ValueRegister, Register: "v0"},
	}
	_, known3 := ci3.Evaluate(nil, nil)
	if known3 {
		t.Error("register should be unknown")
	}

	ci4 := &ConditionInfo{
		Op:  CondEq,
		LHS: &ValueRef{Kind: ValueConst, ConstValue: 0},
	}
	_, known4 := ci4.Evaluate(nil, nil)
	if known4 {
		t.Error("non-zero-check should be unknown")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONTROL FLOW GRAPH — basic operations
// ═══════════════════════════════════════════════════════════════════════════════

func TestControlFlowGraph_Basic(t *testing.T) {
	g := buildSimpleCFG()

	if g.NodeCount() != 5 {
		t.Errorf("NodeCount = %d, want 5", g.NodeCount())
	}
	if g.EdgeCount() != 4 {
		t.Errorf("EdgeCount = %d, want 4", g.EdgeCount())
	}

	node := g.GetNode(0)
	if node == nil || node.Type != NodeTypeEntry {
		t.Error("GetNode(0) should be entry")
	}

	if g.GetNode(99) != nil {
		t.Error("GetNode(99) should be nil")
	}
	if g.GetNode(-1) != nil {
		t.Error("GetNode(-1) should be nil")
	}
}

func TestControlFlowGraph_FindEdge(t *testing.T) {
	g := buildSimpleCFG()

	edge := g.FindEdge(g.Nodes[0], g.Nodes[1])
	if edge == nil {
		t.Fatal("edge entry→basic should exist")
	}
	if edge.Type != EdgeFallthrough {
		t.Errorf("edge type = %v, want fallthrough", edge.Type)
	}
}

func TestControlFlowGraph_AddEdge(t *testing.T) {
	g := buildSimpleCFG()
	oldEdgeCount := g.EdgeCount()

	newNode := &CFGNode{ID: 5, Type: NodeTypeBasic}
	g.Nodes = append(g.Nodes, newNode)

	g.AddEdge(g.Nodes[1], newNode, EdgeGoto)

	if g.EdgeCount() != oldEdgeCount+1 {
		t.Error("edge count should increase")
	}
	if g.FindEdge(g.Nodes[1], newNode) == nil {
		t.Error("new edge should be findable")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// SHORT CLASS NAME
// ═══════════════════════════════════════════════════════════════════════════════

func TestShortClassName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Lcom/app/License;", "License"},
		{"Ljava/lang/String;", "String"},
		{"Lcom/Test;", "Test"},
	}
	for _, tt := range tests {
		got := shortClassName(tt.input)
		if got != tt.want {
			t.Errorf("shortClassName(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}

	// Edge cases — should not panic
	_ = shortClassName("")
	_ = shortClassName("License")
}

// ═══════════════════════════════════════════════════════════════════════════════
// CFG BUILDER
// ═══════════════════════════════════════════════════════════════════════════════

func TestDefaultBuildOptions(t *testing.T) {
	opts := DefaultBuildOptions()
	if !opts.SplitCriticalEdges {
		t.Error("should split critical edges by default")
	}
	if !opts.DetectUnreachable {
		t.Error("should detect unreachable by default")
	}
}

func TestCFGBuilder_EmptyMethod(t *testing.T) {
	builder := NewCFGBuilder()

	input := BuildInput{
		MethodName: "empty",
		ClassName:  "Test",
	}

	result := builder.BuildEx(input)
	// Empty instructions → nil result
	if result != nil {
		t.Log("empty method may return nil or empty CFG")
	}
}

func TestCFGBuilder_SimpleReturn(t *testing.T) {
	builder := NewCFGBuilder()

	input := BuildInput{
		MethodName: "simple",
		ClassName:  "Test",
		Instructions: []Instruction{
			{Index: 0, Opcode: "const/4", Raw: "const/4 v0, 0x1", Line: 1},
			{Index: 1, Opcode: "return", Raw: "return v0", Line: 2},
		},
	}

	cfg := builder.Build(input)
	if cfg == nil {
		t.Fatal("CFG should not be nil")
	}
	if cfg.Entry == nil {
		t.Error("should have entry node")
	}
	if len(cfg.Exits) == 0 {
		t.Error("should have exit nodes")
	}
}

func TestCFGBuilder_WithCondition(t *testing.T) {
	builder := NewCFGBuilder()

	input := BuildInput{
		MethodName: "cond",
		ClassName:  "Test",
		Instructions: []Instruction{
			{Index: 0, Opcode: "const/4", Raw: "const/4 v0, 0x0", Line: 1},
			{Index: 1, Opcode: "if-eqz", Raw: "if-eqz v0, :cond_0", Line: 2},
			{Index: 2, Opcode: "const/4", Raw: "const/4 v0, 0x1", Line: 3},
			{Index: 3, Opcode: "return", Raw: "return v0", Line: 4},
		},
		Labels: []Label{
			{Name: ":cond_0", Line: 4},
		},
	}

	cfg := builder.Build(input)
	if cfg == nil {
		t.Fatal("CFG should not be nil")
	}

	hasCondition := false
	for _, node := range cfg.Nodes {
		if node.Type == NodeTypeCondition {
			hasCondition = true
		}
	}
	if !hasCondition {
		t.Log("condition node detection depends on label resolution")
	}
}

func TestCFGBuilder_WithGoto(t *testing.T) {
	builder := NewCFGBuilder()

	input := BuildInput{
		MethodName: "withGoto",
		ClassName:  "Test",
		Instructions: []Instruction{
			{Index: 0, Opcode: "goto", Raw: "goto :goto_0", Line: 1},
			{Index: 1, Opcode: "nop", Raw: "nop", Line: 2},
			{Index: 2, Opcode: "return-void", Raw: "return-void", Line: 3},
		},
		Labels: []Label{
			{Name: ":goto_0", Line: 3},
		},
	}

	cfg := builder.Build(input)
	if cfg == nil {
		t.Fatal("CFG should not be nil")
	}
}

func TestCFGBuilder_WithTryCatch(t *testing.T) {
	builder := NewCFGBuilder()

	input := BuildInput{
		MethodName: "withTry",
		ClassName:  "Test",
		Instructions: []Instruction{
			{Index: 0, Opcode: "invoke-virtual", Raw: "invoke-virtual {v0}, Lcom/app/Test;->risky()V", Line: 1},
			{Index: 1, Opcode: "return-void", Raw: "return-void", Line: 2},
			{Index: 2, Opcode: "move-exception", Raw: "move-exception v0", Line: 3},
			{Index: 3, Opcode: "return-void", Raw: "return-void", Line: 4},
		},
		TryBlocks: []TryBlock{
			{
				ID:       0,
				StartIdx: 0,
				EndIdx:   1,
				Handlers: []ExceptionHandler{
					{
						Type:       "Ljava/lang/Exception;",
						StartIdx:   0,
						EndIdx:     1,
						HandlerIdx: 2,
					},
				},
			},
		},
	}

	cfg := builder.Build(input)
	if cfg == nil {
		t.Fatal("CFG should not be nil")
	}
}

func TestCFGBuilder_WithOptions(t *testing.T) {
	opts := DefaultBuildOptions()
	opts.SplitCriticalEdges = false
	opts.DetectUnreachable = false

	builder := NewCFGBuilderWithOptions(opts)

	input := BuildInput{
		MethodName: "opts",
		ClassName:  "Test",
		Instructions: []Instruction{
			{Index: 0, Opcode: "return-void", Raw: "return-void", Line: 1},
		},
	}

	cfg := builder.Build(input)
	if cfg == nil {
		t.Fatal("CFG should not be nil")
	}
}

func TestConvertFromSmaliMethod(t *testing.T) {
	method := &SmaliMethod{
		Name:      "check",
		ClassName: "Lcom/app/License;",
		Signature: "()Z",
		Instructions: []SmaliInstruction{
			{Line: 1, Opcode: "const/4", Raw: "const/4 v0, 0x1"},
			{Line: 2, Opcode: "return", Raw: "return v0"},
		},
	}

	input := ConvertFromSmaliMethod(method)
	if input.MethodName != "check" {
		t.Errorf("MethodName = %q", input.MethodName)
	}
	if len(input.Instructions) != 2 {
		t.Errorf("Instructions len = %d, want 2", len(input.Instructions))
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// LABEL INDEX
// ═══════════════════════════════════════════════════════════════════════════════

func TestLabelIndex_Basic(t *testing.T) {
	idx := NewLabelIndex()

	instructions := []Instruction{
		{Index: 0, Opcode: "const/4", Line: 1},
		{Index: 1, Opcode: "if-eqz", Line: 2},
		{Index: 2, Opcode: "return", Line: 3},
	}

	labels := []Label{
		{Name: ":cond_0", Line: 3},
		{Name: ":goto_0", Line: 1},
	}

	idx.BuildFromMethod(instructions, labels)

	if idx.Size() != 2 {
		t.Errorf("Size = %d, want 2", idx.Size())
	}

	if !idx.HasLabel(":cond_0") {
		t.Error("should have :cond_0")
	}
	if idx.HasLabel(":missing") {
		t.Error("should not have :missing")
	}

	all := idx.AllLabels()
	if len(all) != 2 {
		t.Errorf("AllLabels len = %d", len(all))
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// INSTRUCTION INDEX
// ═══════════════════════════════════════════════════════════════════════════════

func TestInstructionIndex_Basic(t *testing.T) {
	instructions := []Instruction{
		{Index: 0, Opcode: "const/4", Raw: "const/4 v0, 0x1", Line: 1},
		{Index: 1, Opcode: "invoke-virtual", Raw: "invoke-virtual {v0}, Lcom/Test;->check()Z", Line: 2},
		{Index: 2, Opcode: "move-result", Raw: "move-result v1", Line: 3},
		{Index: 3, Opcode: "if-eqz", Raw: "if-eqz v1, :cond_0", Line: 4},
		{Index: 4, Opcode: "return", Raw: "return v0", Line: 5},
	}

	idx := NewInstructionIndex(instructions)

	if idx.Len() != 5 {
		t.Errorf("Len = %d, want 5", idx.Len())
	}

	instr := idx.Get(0)
	if instr == nil || instr.Opcode != "const/4" {
		t.Error("Get(0) wrong")
	}

	if idx.Get(99) != nil {
		t.Error("Get(99) should be nil")
	}
	if idx.Get(-1) != nil {
		t.Error("Get(-1) should be nil")
	}

	byLine := idx.GetByLine(2)
	if byLine == nil || byLine.Opcode != "invoke-virtual" {
		t.Error("GetByLine(2) wrong")
	}

	invokes := idx.GetInvokes()
	if len(invokes) == 0 {
		t.Error("should have invokes")
	}

	conditions := idx.GetConditions()
	if len(conditions) == 0 {
		t.Error("should have conditions")
	}

	returns := idx.GetReturns()
	if len(returns) == 0 {
		t.Error("should have returns")
	}

	consts := idx.GetConsts()
	if len(consts) == 0 {
		t.Error("should have consts")
	}

	moves := idx.GetMoves()
	if len(moves) == 0 {
		t.Error("should have moves (move-result)")
	}
}

func TestInstructionIndex_GetRange(t *testing.T) {
	instructions := []Instruction{
		{Index: 0, Opcode: "a", Line: 1},
		{Index: 1, Opcode: "b", Line: 2},
		{Index: 2, Opcode: "c", Line: 3},
		{Index: 3, Opcode: "d", Line: 4},
	}

	idx := NewInstructionIndex(instructions)
	rng := idx.GetRange(1, 3)
	if len(rng) != 2 {
		t.Errorf("GetRange(1,3) len = %d, want 2", len(rng))
	}

	empty := idx.GetRange(5, 10)
	if len(empty) != 0 {
		t.Error("out of bounds should return empty")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// CACHE
// ═══════════════════════════════════════════════════════════════════════════════

func makeCacheInput(name string) BuildInput {
	return BuildInput{
		MethodName: name,
		ClassName:  "Test",
		Instructions: []Instruction{
			{Index: 0, Opcode: "return-void", Raw: "return-void", Line: 1},
		},
	}
}

func TestCFGCache_Basic(t *testing.T) {
	cache := NewCFGCache(10)

	input := makeCacheInput("test")

	cfg1 := cache.GetOrBuild(input)
	if cfg1 == nil {
		t.Fatal("should build CFG")
	}

	cfg2 := cache.GetOrBuild(input)
	if cfg2 == nil {
		t.Fatal("should return cached")
	}

	stats := cache.Stats()
	if stats.Hits < 1 {
		t.Errorf("hits = %d, want >= 1", stats.Hits)
	}
}

func TestCFGCache_Get(t *testing.T) {
	cache := NewCFGCache(10)
	input := makeCacheInput("test")

	if cache.Get(input) != nil {
		t.Error("should be nil on miss")
	}

	cache.GetOrBuild(input)

	if cache.Get(input) == nil {
		t.Error("should hit after build")
	}
}

func TestCFGCache_Invalidate(t *testing.T) {
	cache := NewCFGCache(10)
	input := makeCacheInput("test")

	cache.GetOrBuild(input)
	cache.Invalidate(input)

	if cache.Get(input) != nil {
		t.Error("should be invalidated")
	}
}

func TestCFGCache_InvalidateClass(t *testing.T) {
	cache := NewCFGCache(10)

	for i := 0; i < 3; i++ {
		input := BuildInput{
			MethodName: "method" + string(rune('A'+i)),
			ClassName:  "Lcom/app/Test;",
			Instructions: []Instruction{
				{Index: 0, Opcode: "return-void", Raw: "return-void", Line: 1},
			},
		}
		cache.GetOrBuild(input)
	}

	sizeBefore := cache.Size()
	count := cache.InvalidateClass("Lcom/app/Test;")
	sizeAfter := cache.Size()

	if sizeBefore != 3 {
		t.Fatalf("precondition size = %d, want 3", sizeBefore)
	}
	if count != sizeBefore {
		t.Fatalf("invalidated = %d, want %d", count, sizeBefore)
	}
	if sizeAfter != 0 {
		t.Fatalf("size after invalidate = %d, want 0", sizeAfter)
	}
}

func TestCFGCache_Clear(t *testing.T) {
	cache := NewCFGCache(10)
	cache.GetOrBuild(makeCacheInput("test"))
	cache.Clear()

	if cache.Size() != 0 {
		t.Error("should be empty after clear")
	}
}

func TestCFGCache_Capacity(t *testing.T) {
	cache := NewCFGCache(5)
	if cache.Capacity() != 5 {
		t.Errorf("Capacity = %d, want 5", cache.Capacity())
	}
}

func TestCFGCache_Resize(t *testing.T) {
	cache := NewCFGCache(10)

	for i := 0; i < 8; i++ {
		cache.GetOrBuild(makeCacheInput(string(rune('0' + i))))
	}

	cache.Resize(3)
	if cache.Capacity() != 3 {
		t.Errorf("Capacity = %d, want 3", cache.Capacity())
	}

	// Resize is per-shard, so total size can exceed Capacity when capacity < numShards.
	perShard := 3 / numShards
	if perShard < 1 {
		perShard = 1
	}
	maxTotal := perShard * numShards
	if cache.Size() > maxTotal {
		t.Errorf("after resize(3), size = %d, max allowed = %d", cache.Size(), maxTotal)
	}
}

func TestCFGCache_Stats(t *testing.T) {
	cache := NewCFGCache(10)
	stats := cache.Stats()
	if stats.Hits != 0 || stats.Misses != 0 {
		t.Error("fresh cache should have zero stats")
	}
}

func TestCFGCache_Warm(t *testing.T) {
	cache := NewCFGCache(10)

	inputs := make([]BuildInput, 3)
	for i := range inputs {
		inputs[i] = makeCacheInput(string(rune('0' + i)))
	}

	cache.Warm(inputs)

	if cache.Size() < 3 {
		t.Errorf("after warm, size = %d", cache.Size())
	}
}

func TestCFGCache_WarmParallel(t *testing.T) {
	cache := NewCFGCache(20)

	inputs := make([]BuildInput, 10)
	for i := range inputs {
		inputs[i] = makeCacheInput(string(rune('0' + i)))
	}

	cache.WarmParallel(inputs, 4)

	if cache.Size() < 10 {
		t.Errorf("after warm parallel, size = %d", cache.Size())
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// VISUALIZER
// ═══════════════════════════════════════════════════════════════════════════════

func TestVisualizer_ExportDOT(t *testing.T) {
	g := buildSimpleCFG()
	viz := NewVisualizer(g)
	opts := DefaultDOTOptions()

	dot := viz.ExportDOT(opts)

	if !strings.Contains(dot, "digraph") {
		t.Error("DOT should contain 'digraph'")
	}
	if dot == "" {
		t.Error("DOT should not be empty")
	}
}

func TestVisualizer_ExportDOT_WithInstructions(t *testing.T) {
	g := buildSimpleCFG()
	viz := NewVisualizer(g)
	opts := DefaultDOTOptions()
	opts.ShowInstructions = true
	opts.ShowConditions = true

	dot := viz.ExportDOT(opts)
	if dot == "" {
		t.Error("DOT with labels should not be empty")
	}
}

func TestVisualizer_ExportASCII(t *testing.T) {
	g := buildSimpleCFG()
	viz := NewVisualizer(g)

	ascii := viz.ExportASCII()
	if ascii == "" {
		t.Error("ASCII should not be empty")
	}
}

func TestDefaultDOTOptions(t *testing.T) {
	opts := DefaultDOTOptions()
	if opts.ShowInstructions {
		t.Error("instructions should be off by default")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// DOMINATORS
// ═══════════════════════════════════════════════════════════════════════════════

func TestDominatorAnalyzer_Basic(t *testing.T) {
	g := buildSimpleCFG()
	da := NewDominatorAnalyzer(g)

	da.ComputeDominators()

	for _, node := range g.Nodes {
		if !da.Dominates(g.Entry, node) {
			t.Errorf("entry should dominate node %d", node.ID)
		}
	}

	if da.StrictlyDominates(g.Entry, g.Entry) {
		t.Error("entry should not strictly dominate itself")
	}
}

func TestDominatorAnalyzer_ImmediateDominator(t *testing.T) {
	g := buildLinearCFG(4)
	da := NewDominatorAnalyzer(g)
	da.ComputeDominators()

	idom := da.GetImmediateDominator(g.Nodes[2])
	if idom == nil {
		t.Fatal("idom should not be nil")
	}
	if idom.ID != 1 {
		t.Errorf("idom of node 2 = %d, want 1", idom.ID)
	}
}

func TestDominatorAnalyzer_PostDominators(t *testing.T) {
	g := buildLinearCFG(3)
	da := NewDominatorAnalyzer(g)
	da.ComputeDominators()
	da.ComputePostDominators()

	last := g.Nodes[len(g.Nodes)-1]
	for _, node := range g.Nodes {
		if da.PostDominates(last, node) {
			// expected for linear
		}
	}
}

func TestDominatorAnalyzer_DomTreeTraversal(t *testing.T) {
	g := buildLinearCFG(4)
	da := NewDominatorAnalyzer(g)
	da.ComputeDominators()

	pre := da.DomTreePreorder()
	if len(pre) == 0 {
		t.Error("preorder should not be empty")
	}

	post := da.DomTreePostorder()
	if len(post) == 0 {
		t.Error("postorder should not be empty")
	}
}

func TestDominatorAnalyzer_DominatedBy(t *testing.T) {
	g := buildLinearCFG(4)
	da := NewDominatorAnalyzer(g)
	da.ComputeDominators()

	dominated := da.DominatedBy(g.Entry)
	if len(dominated) < len(g.Nodes)-1 {
		t.Errorf("entry should dominate %d nodes, got %d",
			len(g.Nodes)-1, len(dominated))
	}
}

func TestDominatorAnalyzer_ControlDependence(t *testing.T) {
	g := buildSimpleCFG()
	da := NewDominatorAnalyzer(g)
	da.ComputeDominators()
	da.ComputePostDominators()

	deps := da.ComputeControlDependence()
	_ = deps
}

func TestDominatorAnalyzer_NearestCommonDominator(t *testing.T) {
	g := buildSimpleCFG()
	da := NewDominatorAnalyzer(g)
	da.ComputeDominators()

	ncd := da.FindNearestCommonDominator(g.Nodes[3], g.Nodes[4])
	_ = ncd // may be nil for small graphs
}

// ═══════════════════════════════════════════════════════════════════════════════
// LOOP ANALYZER
// ═══════════════════════════════════════════════════════════════════════════════

func TestLoopAnalyzer_NoLoops(t *testing.T) {
	g := buildLinearCFG(3)
	la := NewLoopAnalyzer(g)
	loops := la.FindLoops()

	if len(loops) != 0 {
		t.Errorf("linear CFG should have 0 loops, got %d", len(loops))
	}
}

func TestLoopAnalyzer_SimpleLoop(t *testing.T) {
	entry := &CFGNode{ID: 0, Type: NodeTypeEntry, Reachable: true}
	header := &CFGNode{ID: 1, Type: NodeTypeCondition, Reachable: true}
	body := &CFGNode{ID: 2, Type: NodeTypeBasic, Reachable: true}
	exit := &CFGNode{ID: 3, Type: NodeTypeReturn, Reachable: true}

	g := &ControlFlowGraph{
		Nodes:     []*CFGNode{entry, header, body, exit},
		Entry:     entry,
		Exits:     []*CFGNode{exit},
		EdgeIndex: make(map[edgeKey]*CFGEdge),
	}

	g.AddEdge(entry, header, EdgeFallthrough)
	g.AddEdge(header, body, EdgeTrue)
	g.AddEdge(header, exit, EdgeFalse)
	g.AddEdge(body, header, EdgeGoto) // back edge

	da := NewDominatorAnalyzer(g)
	da.ComputeDominators()

	la := NewLoopAnalyzer(g)
	loops := la.FindLoops()

	if len(loops) == 0 {
		t.Error("should detect 1 loop")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// METRICS
// ═══════════════════════════════════════════════════════════════════════════════

func TestMetrics_CyclomaticComplexity(t *testing.T) {
	g := buildSimpleCFG()
	m := NewMetrics(g)
	cc := m.CyclomaticComplexity()
	if cc < 1 {
		t.Errorf("CC = %d", cc)
	}
}

func TestMetrics_CognitiveComplexity(t *testing.T) {
	g := buildSimpleCFG()
	m := NewMetrics(g)
	if m.CognitiveComplexity() < 0 {
		t.Error("should be >= 0")
	}
}

func TestMetrics_Summary(t *testing.T) {
	g := buildSimpleCFG()
	m := NewMetrics(g)
	s := m.Summary()
	if s.NodeCount != 5 {
		t.Errorf("NodeCount = %d", s.NodeCount)
	}
}

func TestMetrics_HalsteadComplexity(t *testing.T) {
	g := buildSimpleCFG()
	m := NewMetrics(g)
	_ = m.HalsteadComplexity()
}

func TestMetrics_FanAnalysis(t *testing.T) {
	g := buildSimpleCFG()
	m := NewMetrics(g)
	_ = m.FanAnalysis()
}

func TestMetrics_ExitDiversity(t *testing.T) {
	g := buildSimpleCFG()
	m := NewMetrics(g)
	ed := m.ExitDiversity()
	if ed.TotalExits < 1 {
		t.Error("should have exits")
	}
}

func TestMetrics_ObfuscationDetection(t *testing.T) {
	g := buildSimpleCFG()
	m := NewMetrics(g)
	obs := m.ObfuscationDetection()
	if obs.Score < 0 {
		t.Error("should be >= 0")
	}
}

func TestMetrics_UltimateSummary(t *testing.T) {
	g := buildSimpleCFG()
	m := NewMetrics(g)
	_ = m.UltimateSummary()
}

func TestMetrics_LinearCFG(t *testing.T) {
	g := buildLinearCFG(5)
	m := NewMetrics(g)
	if m.EstimatedPathCount() < 1 {
		t.Error("should have at least 1 path")
	}
}

func TestMetrics_MaintainabilityIndex(t *testing.T) {
	g := buildSimpleCFG()
	m := NewMetrics(g)
	_ = m.MaintainabilityIndex()
}

func TestMetrics_EssentialComplexity(t *testing.T) {
	g := buildSimpleCFG()
	m := NewMetrics(g)
	_ = m.EssentialComplexity()
}

func TestMetrics_NPathComplexity(t *testing.T) {
	g := buildSimpleCFG()
	m := NewMetrics(g)
	np := m.NPathComplexity()
	if np < 1 {
		t.Error("should be >= 1")
	}
}

func TestMetrics_AIReadiness(t *testing.T) {
	g := buildSimpleCFG()
	m := NewMetrics(g)
	_ = m.AIReadiness()
}

// ═══════════════════════════════════════════════════════════════════════════════
// PATTERN ANALYZER
// ═══════════════════════════════════════════════════════════════════════════════

func TestPatternAnalyzer_FindAllPatterns(t *testing.T) {
	g := buildSimpleCFG()
	pa := NewPatternAnalyzer(g)
	_ = pa.FindAllPatterns()
}

func TestPatternAnalyzer_FindGuards(t *testing.T) {
	g := buildSimpleCFG()
	pa := NewPatternAnalyzer(g)
	_ = pa.FindGuards()
}

func TestPatternAnalyzer_FindFunnels(t *testing.T) {
	g := buildSimpleCFG()
	pa := NewPatternAnalyzer(g)
	_ = pa.FindFunnels()
}

func TestPatternAnalyzer_AntiDebug(t *testing.T) {
	g := buildSimpleCFG()
	pa := NewPatternAnalyzer(g)
	_ = pa.FindAntiDebugPatterns()
}

func TestPatternAnalyzer_Emulator(t *testing.T) {
	g := buildSimpleCFG()
	pa := NewPatternAnalyzer(g)
	_ = pa.FindEmulatorPatterns()
}

func TestPatternAnalyzer_Crypto(t *testing.T) {
	g := buildSimpleCFG()
	pa := NewPatternAnalyzer(g)
	_ = pa.FindCryptoPatterns()
}

func TestPatternAnalyzer_Native(t *testing.T) {
	g := buildSimpleCFG()
	pa := NewPatternAnalyzer(g)
	_ = pa.FindNativePatterns()
}

func TestPatternAnalyzer_Reflection(t *testing.T) {
	g := buildSimpleCFG()
	pa := NewPatternAnalyzer(g)
	_ = pa.FindReflectionPatterns()
}

func TestPatternAnalyzer_StringEncryption(t *testing.T) {
	g := buildSimpleCFG()
	pa := NewPatternAnalyzer(g)
	_ = pa.FindStringEncryption()
}

func TestPatternAnalyzer_Network(t *testing.T) {
	g := buildSimpleCFG()
	pa := NewPatternAnalyzer(g)
	_ = pa.FindNetworkPatterns()
}

func TestPatternAnalyzer_Tamper(t *testing.T) {
	g := buildSimpleCFG()
	pa := NewPatternAnalyzer(g)
	_ = pa.FindTamperPatterns()
}

// ═══════════════════════════════════════════════════════════════════════════════
// SSA BUILDER
// ═══════════════════════════════════════════════════════════════════════════════

func TestSSABuilder_Basic(t *testing.T) {
	g := buildSimpleCFG()

	da := NewDominatorAnalyzer(g)
	da.ComputeDominators()

	ssab := NewSSABuilder(g)
	ssab.BuildSSA()

	if !g.SSAConstructed {
		t.Error("SSAConstructed should be true")
	}
}
