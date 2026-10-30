package cfg

import (
	"strings"
	"testing"
)

// ─── LabelIndex.GetLabels ─────────────────────────────────────────────────────

func TestLabelIndex_GetLabels_Empty(t *testing.T) {
	idx := NewLabelIndex()
	labels := idx.GetLabels(0)
	if labels != nil {
		t.Errorf("expected nil for unmapped index, got %v", labels)
	}
}

func TestLabelIndex_GetLabels_WithLabel(t *testing.T) {
	idx := NewLabelIndex()
	instrs := []Instruction{
		{Line: 1, Opcode: "const/4"},
		{Line: 2, Opcode: "return-void"},
	}
	lbls := []Label{
		{Name: ":cond_0", Line: 0},
	}
	idx.BuildFromMethod(instrs, lbls)
	result := idx.GetLabels(0)
	_ = result // just ensure no panic
}

// ─── InstructionIndex.GetByType / GetBranches ─────────────────────────────────

func TestInstructionIndex_GetByType_Empty(t *testing.T) {
	idx := NewInstructionIndex(nil)
	branches := idx.GetByType(SemanticBranch)
	if branches == nil {
		t.Error("GetByType should return non-nil slice")
	}
	if len(branches) != 0 {
		t.Errorf("expected 0 branches, got %d", len(branches))
	}
}

func TestInstructionIndex_GetByType_Unknown(t *testing.T) {
	idx := NewInstructionIndex(nil)
	result := idx.GetByType(SemanticOther)
	if result != nil {
		t.Error("unknown semantic type should return nil")
	}
}

func TestInstructionIndex_GetBranches_Empty(t *testing.T) {
	idx := NewInstructionIndex(nil)
	b := idx.GetBranches()
	if b == nil {
		t.Error("GetBranches should not return nil on empty index")
	}
}

func TestInstructionIndex_GetBranches_WithGoto(t *testing.T) {
	instrs := []Instruction{
		{Line: 1, Opcode: "const/4"},
		{Line: 2, Opcode: "goto"},
		{Line: 3, Opcode: "return-void"},
	}
	idx := NewInstructionIndex(instrs)
	branches := idx.GetBranches()
	if len(branches) == 0 {
		t.Error("expected at least one branch for goto instruction")
	}
}

func TestInstructionIndex_GetReturns_WithReturn(t *testing.T) {
	instrs := []Instruction{
		{Line: 1, Opcode: "const/4"},
		{Line: 2, Opcode: "return-void"},
	}
	idx := NewInstructionIndex(instrs)
	returns := idx.GetReturns()
	if len(returns) == 0 {
		t.Error("expected at least one return")
	}
}

func TestInstructionIndex_GetByType_Return(t *testing.T) {
	instrs := []Instruction{
		{Line: 1, Opcode: "return-void"},
	}
	idx := NewInstructionIndex(instrs)
	result := idx.GetByType(SemanticReturn)
	if len(result) == 0 {
		t.Error("expected at least one return in GetByType")
	}
}

// ─── DominatorAnalyzer.GetImmediatePostDominator ─────────────────────────────

func TestGetImmediatePostDominator_Nil(t *testing.T) {
	da := NewDominatorAnalyzer(nil)
	result := da.GetImmediatePostDominator(nil)
	if result != nil {
		t.Error("nil node should return nil post-dominator")
	}
}

func TestGetImmediatePostDominator_NoPostDom(t *testing.T) {
	node := &CFGNode{ID: 1}
	da := NewDominatorAnalyzer(nil)
	result := da.GetImmediatePostDominator(node)
	if result != nil {
		t.Error("node with no post-dom should return nil")
	}
}

func TestGetImmediatePostDominator_WithPostDom(t *testing.T) {
	postDom := &CFGNode{ID: 2}
	node := &CFGNode{ID: 1, ImmediatePostDom: postDom}
	da := NewDominatorAnalyzer(nil)
	result := da.GetImmediatePostDominator(node)
	if result != postDom {
		t.Error("expected the set post-dominator to be returned")
	}
}

// ─── LoopAnalyzer getters on empty analyzer ───────────────────────────────────

func TestLoopAnalyzer_GetLoops_Empty(t *testing.T) {
	la := NewLoopAnalyzer(nil)
	loops := la.GetLoops()
	if loops == nil {
		t.Error("GetLoops should not return nil")
	}
	if len(loops) != 0 {
		t.Errorf("fresh analyzer should have 0 loops, got %d", len(loops))
	}
}

func TestLoopAnalyzer_GetRootLoops_Empty(t *testing.T) {
	la := NewLoopAnalyzer(nil)
	roots := la.GetRootLoops()
	if len(roots) != 0 {
		t.Errorf("expected 0 root loops, got %d", len(roots))
	}
}

func TestLoopAnalyzer_GetInfiniteLoops_Empty(t *testing.T) {
	la := NewLoopAnalyzer(nil)
	infinite := la.GetInfiniteLoops()
	if len(infinite) != 0 {
		t.Errorf("expected 0 infinite loops, got %d", len(infinite))
	}
}

func TestLoopAnalyzer_GetLoopsByType_Empty(t *testing.T) {
	la := NewLoopAnalyzer(nil)
	result := la.GetLoopsByType(LoopClassPreTest)
	if len(result) != 0 {
		t.Errorf("expected 0 loops by type, got %d", len(result))
	}
}

func TestLoopAnalyzer_GetProtectedLoops_Empty(t *testing.T) {
	la := NewLoopAnalyzer(nil)
	result := la.GetProtectedLoops()
	if len(result) != 0 {
		t.Errorf("expected 0 protected loops, got %d", len(result))
	}
}

func TestLoopAnalyzer_GetLoopForNode_Nil(t *testing.T) {
	la := NewLoopAnalyzer(nil)
	result := la.GetLoopForNode(nil)
	if result != nil {
		t.Error("nil node should return nil loop")
	}
}

func TestLoopAnalyzer_GetAllLoopsForNode_Nil(t *testing.T) {
	la := NewLoopAnalyzer(nil)
	result := la.GetAllLoopsForNode(nil)
	if result != nil {
		t.Error("nil node should return nil")
	}
}

func TestLoopAnalyzer_GetLoopForNode_NotFound(t *testing.T) {
	la := NewLoopAnalyzer(nil)
	node := &CFGNode{ID: 99}
	result := la.GetLoopForNode(node)
	if result != nil {
		t.Error("node not in any loop should return nil")
	}
}

// ─── LoopAnalyzer getters with actual loops ───────────────────────────────────

func TestLoopAnalyzer_GetLoops_WithLoops(t *testing.T) {
	la := NewLoopAnalyzer(nil)
	header := &CFGNode{ID: 0}
	loop := &Loop{
		ID:             1,
		Header:         header,
		Type:           LoopNatural,
		Classification: LoopClassPreTest,
		TripCount:      -1,
	}
	la.loops = append(la.loops, loop)
	la.nodeToLoop[header.ID] = loop

	if loops := la.GetLoops(); len(loops) != 1 {
		t.Errorf("expected 1 loop, got %d", len(loops))
	}
	if result := la.GetLoopForNode(header); result != loop {
		t.Error("GetLoopForNode should return the loop")
	}
}

func TestLoopAnalyzer_GetRootLoops_WithParent(t *testing.T) {
	la := NewLoopAnalyzer(nil)
	header := &CFGNode{ID: 0}
	parent := &Loop{ID: 1, Header: header, TripCount: -1}
	child := &Loop{ID: 2, Header: header, Parent: parent, TripCount: -1}
	la.loops = append(la.loops, parent, child)

	roots := la.GetRootLoops()
	if len(roots) != 1 {
		t.Errorf("expected 1 root loop, got %d", len(roots))
	}
	if roots[0] != parent {
		t.Error("expected parent to be root")
	}
}

func TestLoopAnalyzer_GetInfiniteLoops_WithInfinite(t *testing.T) {
	la := NewLoopAnalyzer(nil)
	header := &CFGNode{ID: 0}
	loop := &Loop{ID: 1, Header: header, IsInfinite: true, TripCount: -1}
	la.loops = append(la.loops, loop)

	infinite := la.GetInfiniteLoops()
	if len(infinite) != 1 {
		t.Errorf("expected 1 infinite loop, got %d", len(infinite))
	}
}

func TestLoopAnalyzer_GetProtectedLoops_WithLicense(t *testing.T) {
	la := NewLoopAnalyzer(nil)
	header := &CFGNode{ID: 0}
	loop := &Loop{
		ID:        1,
		Header:    header,
		TripCount: -1,
		Guards: []*LoopGuardInfo{
			{Type: GuardTypeLicense},
		},
	}
	la.loops = append(la.loops, loop)

	protected := la.GetProtectedLoops()
	if len(protected) != 1 {
		t.Errorf("expected 1 protected loop, got %d", len(protected))
	}
}

// ─── Loop.String() ────────────────────────────────────────────────────────────

func TestLoop_String_Natural(t *testing.T) {
	header := &CFGNode{ID: 3}
	loop := &Loop{
		ID:             1,
		Header:         header,
		Type:           LoopNatural,
		Classification: LoopClassPreTest,
		TripCount:      10,
		Depth:          1,
	}
	s := loop.String()
	if !strings.Contains(s, "Natural") {
		t.Errorf("expected 'Natural' in loop string, got %q", s)
	}
	if !strings.Contains(s, "while-loop") {
		t.Errorf("expected 'while-loop' in loop string, got %q", s)
	}
}

func TestLoop_String_WithIndVarsAndGuards(t *testing.T) {
	header := &CFGNode{ID: 0}
	loop := &Loop{
		ID:            2,
		Header:        header,
		Type:          LoopNatural,
		TripCount:     -1,
		InductionVars: []*InductionVar{{Register: "v0", Type: InductionLinear}},
		Guards:        []*LoopGuardInfo{{Type: GuardTypeRoot}},
		HasBreak:      true,
	}
	s := loop.String()
	if !strings.Contains(s, "IndVars=1") {
		t.Errorf("expected IndVars in string, got %q", s)
	}
	if !strings.Contains(s, "Guards=1") {
		t.Errorf("expected Guards in string, got %q", s)
	}
	if !strings.Contains(s, "HasBreak") {
		t.Errorf("expected HasBreak in string, got %q", s)
	}
}

// ─── InductionVar.String() ────────────────────────────────────────────────────

func TestInductionVar_String_Linear(t *testing.T) {
	iv := &InductionVar{Register: "v1", Type: InductionLinear, InitValue: 0, StepValue: 1, Bound: 10}
	s := iv.String()
	if !strings.Contains(s, "linear") {
		t.Errorf("expected 'linear' in string, got %q", s)
	}
	if !strings.Contains(s, "v1") {
		t.Errorf("expected register 'v1' in string, got %q", s)
	}
}

func TestInductionVar_String_Affine(t *testing.T) {
	iv := &InductionVar{Register: "v2", Type: InductionAffine}
	s := iv.String()
	if !strings.Contains(s, "affine") {
		t.Errorf("expected 'affine' in string, got %q", s)
	}
}

// ─── LoopGuardInfo.String() ───────────────────────────────────────────────────

func TestLoopGuardInfo_String_License(t *testing.T) {
	g := &LoopGuardInfo{Type: GuardTypeLicense}
	s := g.String()
	if !strings.Contains(s, "license") {
		t.Errorf("expected 'license' in guard string, got %q", s)
	}
}

func TestLoopGuardInfo_String_WithMethodRef(t *testing.T) {
	g := &LoopGuardInfo{Type: GuardTypeRoot, MethodRef: "Lcom/example/Check;->isRooted()Z"}
	s := g.String()
	if !strings.Contains(s, "isRooted") {
		t.Errorf("expected method ref in guard string, got %q", s)
	}
}

func TestLoopGuardInfo_String_NullCheck(t *testing.T) {
	g := &LoopGuardInfo{Type: GuardTypeNull}
	s := g.String()
	if !strings.Contains(s, "null-check") {
		t.Errorf("expected 'null-check' in guard string, got %q", s)
	}
}

// ─── LoopClassification.String() ─────────────────────────────────────────────

func TestLoopClassification_String_PostTest(t *testing.T) {
	lc := LoopClassPostTest
	s := lc.String()
	if s != "post-test" {
		t.Errorf("expected 'post-test', got %q", s)
	}
}

func TestLoopClassification_String_Counted(t *testing.T) {
	lc := LoopClassCounted
	s := lc.String()
	if s != "counted" {
		t.Errorf("expected 'counted', got %q", s)
	}
}

func TestLoopClassification_String_PreTest(t *testing.T) {
	lc := LoopClassPreTest
	s := lc.String()
	if s != "pre-test" {
		t.Errorf("expected 'pre-test', got %q", s)
	}
}
