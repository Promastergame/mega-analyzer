package cfg

import (
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/dexir"
)

// ═══════════════════════════════════════════════════════════════════════════════
// parseSmaliOpcode — all major branches
// ═══════════════════════════════════════════════════════════════════════════════

func TestParseSmaliOpcode_InvokeVirtual(t *testing.T) {
	op, operands := parseSmaliOpcode("invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z")
	if op != "invoke-virtual" {
		t.Errorf("opcode = %q, want 'invoke-virtual'", op)
	}
	if len(operands) < 2 {
		t.Errorf("expected ≥2 operands (regs + method), got %d: %v", len(operands), operands)
	}
	// Should contain method ref
	found := false
	for _, o := range operands {
		if strings.Contains(o, "equals") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected method ref in operands: %v", operands)
	}
}

func TestParseSmaliOpcode_InvokeStatic(t *testing.T) {
	op, operands := parseSmaliOpcode("invoke-static {v0}, Lcom/example/Util;->check(I)Z")
	if op != "invoke-static" {
		t.Errorf("opcode = %q, want 'invoke-static'", op)
	}
	_ = operands
}

func TestParseSmaliOpcode_InvokeNoRegs(t *testing.T) {
	// invoke with empty {} braces
	op, operands := parseSmaliOpcode("invoke-static {}, Lcom/example/Util;->noArgs()V")
	if op != "invoke-static" {
		t.Errorf("opcode = %q, want 'invoke-static'", op)
	}
	_ = operands
}

func TestParseSmaliOpcode_InvokeNoSpace(t *testing.T) {
	// Edge case: invoke- without space (shouldn't crash)
	op, _ := parseSmaliOpcode("invoke-virtual")
	if op != "invoke-virtual" {
		t.Errorf("got %q", op)
	}
}

func TestParseSmaliOpcode_ConstString(t *testing.T) {
	op, operands := parseSmaliOpcode(`const-string v0, "hello world"`)
	if op != "const-string" {
		t.Errorf("opcode = %q, want 'const-string'", op)
	}
	if len(operands) < 2 {
		t.Errorf("expected 2 operands, got %d: %v", len(operands), operands)
	}
	if operands[0] != "v0" {
		t.Errorf("operands[0] = %q, want 'v0'", operands[0])
	}
	if !strings.Contains(operands[1], "hello world") {
		t.Errorf("operands[1] = %q, want contains 'hello world'", operands[1])
	}
}

func TestParseSmaliOpcode_ConstStringJumbo(t *testing.T) {
	op, operands := parseSmaliOpcode(`const-string/jumbo v1, "jumbo string"`)
	if op != "const-string/jumbo" {
		t.Errorf("opcode = %q, want 'const-string/jumbo'", op)
	}
	if len(operands) < 2 {
		t.Errorf("expected 2 operands, got %d: %v", len(operands), operands)
	}
}

func TestParseSmaliOpcode_ConstStringNoComma(t *testing.T) {
	// const-string without a comma — fallback to Fields
	op, _ := parseSmaliOpcode("const-string v0")
	if op != "const-string" {
		t.Errorf("opcode = %q, want 'const-string'", op)
	}
}

func TestParseSmaliOpcode_General_IfEqz(t *testing.T) {
	op, operands := parseSmaliOpcode("if-eqz v0, :cond_0")
	if op != "if-eqz" {
		t.Errorf("opcode = %q, want 'if-eqz'", op)
	}
	if len(operands) != 2 {
		t.Errorf("expected 2 operands, got %d: %v", len(operands), operands)
	}
	if operands[0] != "v0" {
		t.Errorf("operands[0] = %q, want 'v0'", operands[0])
	}
	if operands[1] != ":cond_0" {
		t.Errorf("operands[1] = %q, want ':cond_0'", operands[1])
	}
}

func TestParseSmaliOpcode_General_Const4(t *testing.T) {
	op, operands := parseSmaliOpcode("const/4 v0, 0x0")
	if op != "const/4" {
		t.Errorf("opcode = %q, want 'const/4'", op)
	}
	if len(operands) != 2 {
		t.Errorf("expected 2 operands, got %d: %v", len(operands), operands)
	}
}

func TestParseSmaliOpcode_NoSpace(t *testing.T) {
	// opcode without space — returns opcode, nil operands
	op, operands := parseSmaliOpcode("return-void")
	if op != "return-void" {
		t.Errorf("opcode = %q, want 'return-void'", op)
	}
	if len(operands) != 0 {
		t.Errorf("expected no operands for return-void, got %v", operands)
	}
}

func TestParseSmaliOpcode_General_Move(t *testing.T) {
	op, operands := parseSmaliOpcode("move v0, v1")
	if op != "move" {
		t.Errorf("opcode = %q, want 'move'", op)
	}
	if len(operands) != 2 {
		t.Errorf("expected 2 operands, got %d: %v", len(operands), operands)
	}
}

func TestParseSmaliOpcode_IGetWide(t *testing.T) {
	op, operands := parseSmaliOpcode("iget-wide v0, v1, Lcom/Foo;->bar:J")
	if op != "iget-wide" {
		t.Errorf("opcode = %q", op)
	}
	if len(operands) != 3 {
		t.Errorf("expected 3 operands, got %d: %v", len(operands), operands)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// hasSuccessor
// ═══════════════════════════════════════════════════════════════════════════════

func TestHasSuccessor_True(t *testing.T) {
	target := &CFGNode{ID: 1}
	node := &CFGNode{
		ID:         0,
		Successors: []*CFGNode{target},
	}
	if !hasSuccessor(node, target) {
		t.Error("hasSuccessor should be true when target is in successors")
	}
}

func TestHasSuccessor_False(t *testing.T) {
	target := &CFGNode{ID: 1}
	other := &CFGNode{ID: 2}
	node := &CFGNode{
		ID:         0,
		Successors: []*CFGNode{other},
	}
	if hasSuccessor(node, target) {
		t.Error("hasSuccessor should be false when target is not in successors")
	}
}

func TestHasSuccessor_NilNode(t *testing.T) {
	target := &CFGNode{ID: 1}
	if hasSuccessor(nil, target) {
		t.Error("hasSuccessor(nil, ...) should be false")
	}
}

func TestHasSuccessor_NilTarget(t *testing.T) {
	node := &CFGNode{ID: 0, Successors: []*CFGNode{{ID: 1}}}
	if hasSuccessor(node, nil) {
		t.Error("hasSuccessor(..., nil) should be false")
	}
}

func TestHasSuccessor_EmptySuccessors(t *testing.T) {
	target := &CFGNode{ID: 1}
	node := &CFGNode{ID: 0, Successors: nil}
	if hasSuccessor(node, target) {
		t.Error("hasSuccessor with empty successors should be false")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// analyzeInstruction (DFGAnalyzer)
// ═══════════════════════════════════════════════════════════════════════════════

func buildAnalyzedGraph(instrs []Instruction) *DFGAnalyzer {
	ptrs := make([]*Instruction, len(instrs))
	for i := range instrs {
		ptrs[i] = &instrs[i]
	}
	cfg := &ControlFlowGraph{
		Method: &MethodInfo{Instructions: ptrs},
	}
	d := NewDFGAnalyzer(cfg)
	d.Analyze()
	return d
}

func TestAnalyzeInstruction_ConstString(t *testing.T) {
	instrs := []Instruction{
		{Index: 0, Opcode: "const-string", Raw: `const-string v0, "premium"`},
	}
	d := buildAnalyzedGraph(instrs)
	instr := d.cfg.Method.Instructions[0]
	if len(instr.DefRegs) != 1 || instr.DefRegs[0] != "v0" {
		t.Errorf("DefRegs = %v, want [v0]", instr.DefRegs)
	}
	if instr.ConstVal == nil || *instr.ConstVal != "premium" {
		t.Errorf("ConstVal = %v, want 'premium'", instr.ConstVal)
	}
}

func TestAnalyzeInstruction_Const4(t *testing.T) {
	instrs := []Instruction{
		{Index: 0, Opcode: "const/4", Raw: "const/4 v0, 0x1"},
	}
	d := buildAnalyzedGraph(instrs)
	instr := d.cfg.Method.Instructions[0]
	if len(instr.DefRegs) != 1 || instr.DefRegs[0] != "v0" {
		t.Errorf("DefRegs = %v, want [v0]", instr.DefRegs)
	}
	if instr.ConstVal == nil {
		t.Error("expected ConstVal to be set")
	}
}

func TestAnalyzeInstruction_ConstClass(t *testing.T) {
	instrs := []Instruction{
		{Index: 0, Opcode: "const-class", Raw: "const-class v0, Lcom/example/Foo;"},
	}
	d := buildAnalyzedGraph(instrs)
	instr := d.cfg.Method.Instructions[0]
	if len(instr.DefRegs) != 1 {
		t.Errorf("DefRegs = %v, want 1 reg", instr.DefRegs)
	}
}

func TestAnalyzeInstruction_MoveResult(t *testing.T) {
	instrs := []Instruction{
		{Index: 0, Opcode: "invoke-virtual", Raw: "invoke-virtual {v0}, Lcom/Foo;->isPremium()Z"},
		{Index: 1, Opcode: "move-result", Raw: "move-result v1"},
	}
	d := buildAnalyzedGraph(instrs)
	moveResult := d.cfg.Method.Instructions[1]
	if len(moveResult.DefRegs) != 1 || moveResult.DefRegs[0] != "v1" {
		t.Errorf("move-result DefRegs = %v, want [v1]", moveResult.DefRegs)
	}
	// InvokeRef should be propagated from the preceding invoke
	if moveResult.InvokeRef == "" {
		t.Error("expected InvokeRef to be propagated from invoke-virtual")
	}
}

func TestAnalyzeInstruction_Move(t *testing.T) {
	instrs := []Instruction{
		{Index: 0, Opcode: "move", Raw: "move v2, v0"},
	}
	d := buildAnalyzedGraph(instrs)
	instr := d.cfg.Method.Instructions[0]
	if len(instr.DefRegs) != 1 || instr.DefRegs[0] != "v2" {
		t.Errorf("DefRegs = %v, want [v2]", instr.DefRegs)
	}
	if instr.MoveSrc != "v0" {
		t.Errorf("MoveSrc = %q, want 'v0'", instr.MoveSrc)
	}
}

func TestAnalyzeInstruction_InvokeVirtual(t *testing.T) {
	instrs := []Instruction{
		{Index: 0, Opcode: "invoke-virtual", Raw: "invoke-virtual {v0, v1}, Lcom/Foo;->doSomething(I)V"},
	}
	d := buildAnalyzedGraph(instrs)
	instr := d.cfg.Method.Instructions[0]
	if len(instr.UseRegs) == 0 {
		t.Error("expected UseRegs from invoke-virtual")
	}
	if instr.InvokeRef == "" {
		t.Error("expected InvokeRef from invoke-virtual")
	}
}

func TestAnalyzeInstruction_IGet(t *testing.T) {
	instrs := []Instruction{
		{Index: 0, Opcode: "iget", Raw: "iget v0, v1, Lcom/Foo;->bar:I"},
	}
	d := buildAnalyzedGraph(instrs)
	instr := d.cfg.Method.Instructions[0]
	if len(instr.DefRegs) != 1 || instr.DefRegs[0] != "v0" {
		t.Errorf("DefRegs = %v, want [v0]", instr.DefRegs)
	}
	if instr.FieldRef == "" {
		t.Error("expected FieldRef from iget")
	}
}

func TestAnalyzeInstruction_SGet(t *testing.T) {
	// sget uses 3-part comma split: "sget dest, obj, field"
	// For sget the instruction has no object register, but the raw still
	// needs 3 comma-separated parts for the handler to fire.
	// The handler is: iget/sget with parts >= 3
	instrs := []Instruction{
		{Index: 0, Opcode: "sget", Raw: "sget v0, v1, Lcom/Foo;->INSTANCE:I"},
	}
	d := buildAnalyzedGraph(instrs)
	instr := d.cfg.Method.Instructions[0]
	if len(instr.DefRegs) != 1 {
		t.Errorf("DefRegs = %v, want 1 reg", instr.DefRegs)
	}
	if instr.FieldRef == "" {
		t.Error("expected FieldRef from sget")
	}
}

func TestAnalyzeInstruction_IPut(t *testing.T) {
	instrs := []Instruction{
		{Index: 0, Opcode: "iput", Raw: "iput v0, v1, Lcom/Foo;->bar:I"},
	}
	d := buildAnalyzedGraph(instrs)
	instr := d.cfg.Method.Instructions[0]
	if len(instr.UseRegs) < 2 {
		t.Errorf("UseRegs = %v, want 2 regs for iput", instr.UseRegs)
	}
	if instr.FieldRef == "" {
		t.Error("expected FieldRef from iput")
	}
}

func TestAnalyzeInstruction_SPut(t *testing.T) {
	instrs := []Instruction{
		{Index: 0, Opcode: "sput", Raw: "sput v0, v1, Lcom/Foo;->count:I"},
	}
	d := buildAnalyzedGraph(instrs)
	instr := d.cfg.Method.Instructions[0]
	if instr.FieldRef == "" {
		t.Error("expected FieldRef from sput")
	}
}

func TestAnalyzeInstruction_IfEqz(t *testing.T) {
	instrs := []Instruction{
		{Index: 0, Opcode: "if-eqz", Raw: "if-eqz v0, :cond_0"},
	}
	d := buildAnalyzedGraph(instrs)
	instr := d.cfg.Method.Instructions[0]
	if len(instr.UseRegs) == 0 {
		t.Error("expected UseRegs from if-eqz")
	}
}

func TestAnalyzeInstruction_IfEq_TwoRegs(t *testing.T) {
	instrs := []Instruction{
		{Index: 0, Opcode: "if-eq", Raw: "if-eq v0, v1, :cond_0"},
	}
	d := buildAnalyzedGraph(instrs)
	instr := d.cfg.Method.Instructions[0]
	if len(instr.UseRegs) < 2 {
		t.Errorf("UseRegs = %v, want 2 regs for if-eq", instr.UseRegs)
	}
}

func TestAnalyzeInstruction_Return(t *testing.T) {
	instrs := []Instruction{
		{Index: 0, Opcode: "return", Raw: "return v0"},
	}
	d := buildAnalyzedGraph(instrs)
	instr := d.cfg.Method.Instructions[0]
	if len(instr.UseRegs) != 1 {
		t.Errorf("UseRegs = %v, want 1 reg for return", instr.UseRegs)
	}
}

func TestAnalyzeInstruction_ReturnVoid(t *testing.T) {
	instrs := []Instruction{
		{Index: 0, Opcode: "return-void", Raw: "return-void"},
	}
	d := buildAnalyzedGraph(instrs)
	instr := d.cfg.Method.Instructions[0]
	// return-void should NOT add UseRegs
	if len(instr.UseRegs) != 0 {
		t.Errorf("UseRegs = %v, want empty for return-void", instr.UseRegs)
	}
}

func TestAnalyzeInstruction_Aget(t *testing.T) {
	instrs := []Instruction{
		{Index: 0, Opcode: "aget", Raw: "aget v0, v1, v2"},
	}
	d := buildAnalyzedGraph(instrs)
	instr := d.cfg.Method.Instructions[0]
	if len(instr.DefRegs) != 1 {
		t.Errorf("DefRegs = %v, want [v0]", instr.DefRegs)
	}
	if len(instr.UseRegs) < 2 {
		t.Errorf("UseRegs = %v, want 2 regs for aget", instr.UseRegs)
	}
}

func TestAnalyzeInstruction_Aput(t *testing.T) {
	instrs := []Instruction{
		{Index: 0, Opcode: "aput", Raw: "aput v0, v1, v2"},
	}
	d := buildAnalyzedGraph(instrs)
	instr := d.cfg.Method.Instructions[0]
	if len(instr.UseRegs) < 3 {
		t.Errorf("UseRegs = %v, want 3 regs for aput", instr.UseRegs)
	}
}

func TestAnalyzeInstruction_AddInt_ThreeOps(t *testing.T) {
	instrs := []Instruction{
		{Index: 0, Opcode: "add-int", Raw: "add-int v0, v1, v2"},
	}
	d := buildAnalyzedGraph(instrs)
	instr := d.cfg.Method.Instructions[0]
	if len(instr.DefRegs) != 1 {
		t.Errorf("DefRegs = %v, want [v0]", instr.DefRegs)
	}
	if len(instr.UseRegs) < 2 {
		t.Errorf("UseRegs = %v, want 2 regs", instr.UseRegs)
	}
}

func TestAnalyzeInstruction_AddInt_TwoOps(t *testing.T) {
	// 2-operand form: add-int/2addr v0, v1
	instrs := []Instruction{
		{Index: 0, Opcode: "add-int", Raw: "add-int v0, v1"},
	}
	d := buildAnalyzedGraph(instrs)
	instr := d.cfg.Method.Instructions[0]
	if len(instr.DefRegs) != 1 {
		t.Errorf("DefRegs = %v, want [v0]", instr.DefRegs)
	}
}

func TestAnalyzeInstruction_NewInstance(t *testing.T) {
	instrs := []Instruction{
		{Index: 0, Opcode: "new-instance", Raw: "new-instance v0, Lcom/Foo;"},
	}
	d := buildAnalyzedGraph(instrs)
	instr := d.cfg.Method.Instructions[0]
	if len(instr.DefRegs) != 1 || instr.DefRegs[0] != "v0" {
		t.Errorf("DefRegs = %v, want [v0]", instr.DefRegs)
	}
}

func TestAnalyzeInstruction_InstanceOf(t *testing.T) {
	instrs := []Instruction{
		{Index: 0, Opcode: "instance-of", Raw: "instance-of v0, v1, Lcom/Foo;"},
	}
	d := buildAnalyzedGraph(instrs)
	instr := d.cfg.Method.Instructions[0]
	if len(instr.DefRegs) != 1 {
		t.Errorf("DefRegs = %v, want 1 reg", instr.DefRegs)
	}
}

func TestAnalyzeInstruction_CheckCast(t *testing.T) {
	instrs := []Instruction{
		{Index: 0, Opcode: "check-cast", Raw: "check-cast v0, Lcom/Foo;"},
	}
	d := buildAnalyzedGraph(instrs)
	instr := d.cfg.Method.Instructions[0]
	if len(instr.DefRegs) != 1 {
		t.Errorf("DefRegs = %v, want 1 reg", instr.DefRegs)
	}
	if len(instr.UseRegs) != 1 {
		t.Errorf("UseRegs = %v, want 1 reg (same as DefReg)", instr.UseRegs)
	}
}

func TestAnalyzeInstruction_NilCFG(t *testing.T) {
	d := &DFGAnalyzer{cfg: nil}
	// Should not panic
	d.Analyze()
}

func TestAnalyzeInstruction_NilMethod(t *testing.T) {
	d := &DFGAnalyzer{cfg: &ControlFlowGraph{Method: nil}}
	// Should not panic
	d.Analyze()
}

// ═══════════════════════════════════════════════════════════════════════════════
// DFGAnalyzer — Trace and FindLicenseChecks
// ═══════════════════════════════════════════════════════════════════════════════

func TestDFGAnalyzer_GetDFG_NoChecks(t *testing.T) {
	// Plain return-void — no license checks
	instrs := []Instruction{
		{Index: 0, Opcode: "return-void", Raw: "return-void"},
	}
	d := buildAnalyzedGraph(instrs)
	// Build CFG nodes so Trace can find blocks
	node := &CFGNode{ID: 0, StartIdx: 0, EndIdx: 0, Instructions: []InstructionRef{{Index: 0}}}
	d.cfg.Nodes = []*CFGNode{node}

	result := d.GetDFG(5)
	if result != nil {
		t.Errorf("expected nil DFG for plain return-void, got: %+v", result)
	}
}

func TestDFGAnalyzer_FindLicenseChecks_NilCFG(t *testing.T) {
	d := &DFGAnalyzer{cfg: nil}
	checks := d.FindLicenseChecks(3)
	if len(checks) != 0 {
		t.Errorf("expected 0 checks for nil CFG, got %d", len(checks))
	}
}

func TestDFGAnalyzer_Trace_ZeroDepth(t *testing.T) {
	d := &DFGAnalyzer{cfg: &ControlFlowGraph{}}
	startInstr := &Instruction{Index: 0}
	result := d.Trace("v0", startInstr, 0)
	if result != nil {
		t.Error("expected nil trace with depth=0")
	}
}

func TestDFGAnalyzer_Trace_NilCFG(t *testing.T) {
	d := &DFGAnalyzer{cfg: nil}
	startInstr := &Instruction{Index: 0}
	result := d.Trace("v0", startInstr, 5)
	if result != nil {
		t.Error("expected nil trace with nil CFG")
	}
}

func TestDFGAnalyzer_Trace_NilInstr(t *testing.T) {
	d := &DFGAnalyzer{cfg: &ControlFlowGraph{}}
	result := d.Trace("v0", nil, 5)
	if result != nil {
		t.Error("expected nil trace with nil startInstr")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// BuildFromInstructions with options
// ═══════════════════════════════════════════════════════════════════════════════

func TestBuildFromInstructions_WithOptions(t *testing.T) {
	opts := BuildOptions{
		SplitCriticalEdges: false,
		DetectUnreachable:  true,
		ComputeRPO:         false,
		ComputeMetrics:     false,
	}
	instrs := []InstructionRef{
		{Index: 0, Opcode: "const/4", Raw: "const/4 v0, 0"},
		{Index: 1, Opcode: "return-void", Raw: "return-void"},
	}
	result, err := BuildFromInstructions(instrs, &opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil || result.CFG == nil {
		t.Error("expected non-nil result")
	}
}

func TestBuildFromInstructions_WithIfGoto(t *testing.T) {
	instrs := []InstructionRef{
		{Index: 0, Line: 1, Opcode: "const/4", Raw: "const/4 v0, 0x0"},
		{Index: 1, Line: 2, Opcode: "if-eqz", Raw: "if-eqz v0, :cond_0"},
		{Index: 2, Line: 3, Opcode: "return-void", Raw: "return-void"},
		{Index: 3, Line: 4, Opcode: "return-void", Raw: "return-void"},
	}
	result, err := BuildFromInstructions(instrs, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.CFG.NodeCount() < 2 {
		t.Errorf("expected ≥2 nodes for if-branch, got %d", result.CFG.NodeCount())
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// CFGBuilder with TryBlocks and exception handling
// ═══════════════════════════════════════════════════════════════════════════════

func TestCFGBuilder_WithTryBlock(t *testing.T) {
	input := BuildInput{
		MethodName: "tryTest",
		Instructions: []Instruction{
			{Index: 0, Line: 1, Opcode: "const/4", Operands: []string{"v0", "0"}, Raw: "const/4 v0, 0"},
			{Index: 1, Line: 2, Opcode: "invoke-virtual", Operands: []string{"v0", "Lcom/Foo;->bar()V"}, Raw: "invoke-virtual {v0}, Lcom/Foo;->bar()V"},
			{Index: 2, Line: 3, Opcode: "return-void", Raw: "return-void"},
			{Index: 3, Line: 4, Opcode: "move-exception", Operands: []string{"v1"}, Raw: "move-exception v1"},
			{Index: 4, Line: 5, Opcode: "return-void", Raw: "return-void"},
		},
		Labels: []Label{
			{Name: ":catch_0", Line: 4},
		},
		TryBlocks: []TryBlock{
			{
				StartIdx: 0,
				EndIdx:   1,
				Handlers: []ExceptionHandler{
					{Type: "Ljava/lang/Exception;", HandlerIdx: 3},
				},
			},
		},
	}
	builder := NewCFGBuilder()
	result := builder.BuildEx(input)
	if result == nil || result.CFG == nil {
		t.Fatal("expected non-nil result")
	}
	// Should have exception edges
	if result.Stats.ExceptionEdges == 0 {
		t.Error("expected at least 1 exception edge for try block")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// BuildStats validation
// ═══════════════════════════════════════════════════════════════════════════════

func TestBuildStats_BasicMetrics(t *testing.T) {
	input := BuildInput{
		MethodName: "metricsTest",
		Instructions: []Instruction{
			{Index: 0, Line: 1, Opcode: "const/4", Operands: []string{"v0", "0"}, Raw: "const/4 v0, 0"},
			{Index: 1, Line: 2, Opcode: "const/4", Operands: []string{"v1", "1"}, Raw: "const/4 v1, 1"},
			{Index: 2, Line: 3, Opcode: "return-void", Raw: "return-void"},
		},
	}
	builder := NewCFGBuilder()
	result := builder.BuildEx(input)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Stats.TotalInstructions != 3 {
		t.Errorf("TotalInstructions = %d, want 3", result.Stats.TotalInstructions)
	}
	if result.Stats.BasicBlocks < 1 {
		t.Errorf("BasicBlocks = %d, want ≥1", result.Stats.BasicBlocks)
	}
	if result.Stats.MaxBlockSize < 1 {
		t.Errorf("MaxBlockSize = %d, want ≥1", result.Stats.MaxBlockSize)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// removeSuccessor / removePredecessor (internal helpers)
// ═══════════════════════════════════════════════════════════════════════════════

func TestRemoveSuccessor_Found(t *testing.T) {
	n1 := &CFGNode{ID: 1}
	n2 := &CFGNode{ID: 2}
	node := &CFGNode{ID: 0, Successors: []*CFGNode{n1, n2}}
	removeSuccessor(node, n1)
	if len(node.Successors) != 1 || node.Successors[0] != n2 {
		t.Errorf("after removeSuccessor: %v", node.Successors)
	}
}

func TestRemoveSuccessor_NotFound(t *testing.T) {
	n1 := &CFGNode{ID: 1}
	n2 := &CFGNode{ID: 2}
	node := &CFGNode{ID: 0, Successors: []*CFGNode{n1}}
	removeSuccessor(node, n2) // should not panic or remove n1
	if len(node.Successors) != 1 {
		t.Errorf("unexpected modification: %v", node.Successors)
	}
}

func TestRemovePredecessor_Found(t *testing.T) {
	n1 := &CFGNode{ID: 1}
	n2 := &CFGNode{ID: 2}
	node := &CFGNode{ID: 0, Predecessors: []*CFGNode{n1, n2}}
	removePredecessor(node, n1)
	if len(node.Predecessors) != 1 || node.Predecessors[0] != n2 {
		t.Errorf("after removePredecessor: %v", node.Predecessors)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// isLicenseRelated
// ═══════════════════════════════════════════════════════════════════════════════

func TestIsLicenseRelated(t *testing.T) {
	trueKws := []string{"premium", "license", "licensed", "ispro",
		"checklicense", "haspurchased", "isvalid", "verify", "mlicensed", "unlocked"}
	for _, kw := range trueKws {
		if !isLicenseRelated(kw) {
			t.Errorf("isLicenseRelated(%q) = false, want true", kw)
		}
	}
	// lowercase containing keyword — the function does case-sensitive contains
	if !isLicenseRelated("checklicense") {
		t.Error("isLicenseRelated('checklicense') should be true (contains 'checklicense')")
	}
	// Unrelated
	if isLicenseRelated("hello") {
		t.Error("isLicenseRelated('hello') = true, want false")
	}
	if isLicenseRelated("") {
		t.Error("isLicenseRelated('') = true, want false")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// registerName (typed replacement of the removed extractRegister helper)
// ═══════════════════════════════════════════════════════════════════════════════

func TestRegisterName(t *testing.T) {
	cases := []struct {
		r    int32
		want string
	}{
		{0, "v0"},
		{15, "v15"},
		{dexir.NoRegister, ""},
		{-2, "p0"}, // unresolved p-sentinel encoding -(N+2)
		{-4, "p2"},
	}
	for _, c := range cases {
		got := registerName(c.r)
		if got != c.want {
			t.Errorf("registerName(%d) = %q, want %q", c.r, got, c.want)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Condition.String
// ═══════════════════════════════════════════════════════════════════════════════

func TestConditionString_AllCases(t *testing.T) {
	cases := []struct {
		cond Condition
		want string
	}{
		{Condition{Opcode: "if-eqz", Register: "v0"}, "v0 == false"},
		{Condition{Opcode: "if-nez", Register: "v0"}, "v0 != false"},
		{Condition{Opcode: "if-eq", Register: "v0", TargetReg: "v1"}, "v0 == v1"},
		{Condition{Opcode: "if-ne", Register: "v0", TargetReg: "v1"}, "v0 != v1"},
		{Condition{Opcode: "if-lt", Register: "v0", TargetReg: "v1"}, "v0 < v1"},
		{Condition{Opcode: "if-ge", Register: "v0", TargetReg: "v1"}, "v0 >= v1"},
		{Condition{Opcode: "if-gtz", Register: "v2"}, "if-gtz v2"}, // default
	}
	for _, c := range cases {
		got := c.cond.String()
		if got != c.want {
			t.Errorf("Condition{%q}.String() = %q, want %q", c.cond.Opcode, got, c.want)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// DFGAnalyzer.parseCondition (internal)
// ═══════════════════════════════════════════════════════════════════════════════

func TestDFGAnalyzer_ParseCondition(t *testing.T) {
	instrs := []Instruction{
		{Index: 0, Opcode: "const/4", Raw: "const/4 v0, 0x1"},
		{Index: 1, Opcode: "if-eqz", Raw: "if-eqz v0, :cond_0", UseRegs: []string{"v0"}},
	}
	d := buildAnalyzedGraph(instrs)
	node := &CFGNode{ID: 0, StartIdx: 0, EndIdx: 1}
	d.cfg.Nodes = []*CFGNode{node}

	cond := d.parseCondition(d.cfg.Method.Instructions[1])
	if cond.Opcode != "if-eqz" {
		t.Errorf("Opcode = %q, want 'if-eqz'", cond.Opcode)
	}
	if cond.Register != "v0" {
		t.Errorf("Register = %q, want 'v0'", cond.Register)
	}
	if !strings.Contains(cond.TargetLabel, "cond_0") {
		t.Errorf("TargetLabel = %q, want ':cond_0'", cond.TargetLabel)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// BuildInputFromLines — all branch paths
// ═══════════════════════════════════════════════════════════════════════════════

func TestBuildInputFromLines_SkipsDirectives(t *testing.T) {
	lines := []string{
		".method public test()V",
		".locals 2",
		"    const/4 v0, 0x0",
		".end method",
	}
	input := BuildInputFromLines("Lcom/Foo;", "test", "()V", lines)
	if len(input.Instructions) != 1 {
		t.Errorf("expected 1 instruction (directives skipped), got %d", len(input.Instructions))
	}
	if input.Instructions[0].Opcode != "const/4" {
		t.Errorf("instruction opcode = %q, want 'const/4'", input.Instructions[0].Opcode)
	}
}

func TestBuildInputFromLines_Labels(t *testing.T) {
	lines := []string{
		"    const/4 v0, 0x0",
		"    :cond_0",
		"    return-void",
	}
	input := BuildInputFromLines("Lcom/Foo;", "test", "()V", lines)
	if len(input.Labels) != 1 {
		t.Errorf("expected 1 label, got %d: %v", len(input.Labels), input.Labels)
	}
	if input.Labels[0].Name != ":cond_0" {
		t.Errorf("label name = %q, want ':cond_0'", input.Labels[0].Name)
	}
}

func TestBuildInputFromLines_EmptyLines(t *testing.T) {
	lines := []string{"", "  ", ""}
	input := BuildInputFromLines("Lcom/Foo;", "test", "()V", lines)
	if len(input.Instructions) != 0 {
		t.Errorf("expected 0 instructions for empty lines, got %d", len(input.Instructions))
	}
}

func TestBuildInputFromLines_InvokeInstruction(t *testing.T) {
	lines := []string{
		`    invoke-virtual {v0}, Lcom/Foo;->bar()V`,
	}
	input := BuildInputFromLines("Lcom/Foo;", "test", "()V", lines)
	if len(input.Instructions) != 1 {
		t.Fatalf("expected 1 instruction, got %d", len(input.Instructions))
	}
	if input.Instructions[0].Opcode != "invoke-virtual" {
		t.Errorf("opcode = %q, want 'invoke-virtual'", input.Instructions[0].Opcode)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// DefaultBuildOptions / NewCFGBuilderWithOptions
// ═══════════════════════════════════════════════════════════════════════════════

func TestDefaultBuildOptions_More2(t *testing.T) {
	opts := DefaultBuildOptions()
	if !opts.SplitCriticalEdges {
		t.Error("SplitCriticalEdges should be true by default")
	}
	if !opts.DetectUnreachable {
		t.Error("DetectUnreachable should be true by default")
	}
	if !opts.ComputeRPO {
		t.Error("ComputeRPO should be true by default")
	}
	if !opts.ComputeMetrics {
		t.Error("ComputeMetrics should be true by default")
	}
}

func TestNewCFGBuilderWithOptions_More2(t *testing.T) {
	opts := BuildOptions{ComputeRPO: false}
	b := NewCFGBuilderWithOptions(opts)
	if b == nil {
		t.Fatal("expected non-nil builder")
	}
	if b.opts.ComputeRPO {
		t.Error("ComputeRPO should be false per our options")
	}
}

func TestCFGBuilder_Build_ReturnsNilOnEmpty(t *testing.T) {
	b := NewCFGBuilder()
	result := b.Build(BuildInput{Instructions: nil})
	if result != nil {
		t.Error("Build with no instructions should return nil")
	}
}
