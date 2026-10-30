package cfg

import (
	"fmt"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// LOOP ANALYSIS — Natural Loops, Induction Variables, Trip Count, Guards
// ═══════════════════════════════════════════════════════════════════════════════

type Loop struct {
	ID        int
	Header    *CFGNode
	Nodes     []*CFGNode
	BackEdges []*CFGEdge
	Type      LoopType
	Depth     int

	// Hierarchy
	Parent   *Loop
	Children []*Loop

	// Structure
	ExitNodes []*CFGNode
	ExitEdges []*CFGEdge
	Latches   []*CFGNode

	// Guards
	PreHeader *CFGNode
	Guards    []*LoopGuardInfo

	// Analysis results
	IsInfinite    bool
	HasBreak      bool
	TripCount     int // -1 = unknown, 0 = never, >0 = estimated count
	LoopInvariant []*LoopValueRef

	// Classification
	Classification LoopClassification

	// Induction variables
	InductionVars []*InductionVar

	// Metrics
	Metrics LoopMetrics
}

// LoopClassification describes the loop shape
type LoopClassification int

const (
	LoopClassUnknown LoopClassification = iota
	LoopClassPreTest
	LoopClassPostTest
	LoopClassCounted
	LoopClassInfinite
	LoopClassIterator
	LoopClassForEach
)

// InductionVar represents a variable that changes predictably each iteration
type InductionVar struct {
	Register  string
	Type      InductionType
	InitValue int
	StepValue int
	Bound     int
	BoundOp   ConditionOp
	DefIdx    int
	UseIdx    int
}

// InductionType describes how the variable changes
type InductionType int

const (
	InductionLinear InductionType = iota
	InductionAffine
	InductionUnknown
)

// LoopMetrics contains computed statistics about a loop
type LoopMetrics struct {
	BodySize       int
	NumBlocks      int
	NestingDepth   int
	BranchDensity  float64
	HasInvoke      bool
	HasFieldAccess bool
	HasArrayAccess bool
	HasException   bool
}

// LoopGuardInfo describes a condition that guards loop entry
type LoopGuardInfo struct {
	Type      GuardType
	Node      *CFGNode
	Condition *ConditionInfo
	Inverted  bool
	MethodRef string
}

// LoopValueRef represents a reference to a value (register at a specific point)
type LoopValueRef struct {
	Register string
	DefIndex int
	Node     *CFGNode
}

// ───────────────────────────────────────────────────────────────────────────────

type LoopAnalyzer struct {
	cfg    *ControlFlowGraph
	dom    *DominatorAnalyzer
	loops  []*Loop
	loopID int

	nodeToLoop map[int]*Loop
}

func NewLoopAnalyzer(cfg *ControlFlowGraph) *LoopAnalyzer {
	return &LoopAnalyzer{
		cfg:        cfg,
		loops:      make([]*Loop, 0),
		nodeToLoop: make(map[int]*Loop),
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// FIND LOOPS
// ═══════════════════════════════════════════════════════════════════════════════

func (l *LoopAnalyzer) FindLoops() []*Loop {
	if l.cfg == nil || len(l.cfg.Nodes) == 0 {
		return nil
	}

	if !l.cfg.DominatorTree {
		l.dom = NewDominatorAnalyzer(l.cfg)
		l.dom.ComputeDominators()
	} else {
		l.dom = NewDominatorAnalyzer(l.cfg)
	}

	backEdges := l.findBackEdges()

	headerToBackEdges := make(map[int][]*CFGEdge)
	for _, edge := range backEdges {
		headerToBackEdges[edge.To.ID] = append(headerToBackEdges[edge.To.ID], edge)
	}

	for headerID, edges := range headerToBackEdges {
		header := l.cfg.GetNode(headerID)
		if header == nil {
			continue
		}
		loop := l.buildLoop(header, edges)
		l.loops = append(l.loops, loop)
	}

	l.detectIrreducible()
	l.buildLoopHierarchy()
	l.findLoopGuards()
	l.detectInductionVariables()
	l.classifyLoops()
	l.computeLoopMetrics()
	l.buildNodeToLoopMap()
	l.markNodes()

	l.cfg.Loops = l.loops
	l.cfg.LoopsAnalyzed = true

	return l.loops
}

func (l *LoopAnalyzer) findBackEdges() []*CFGEdge {
	var backEdges []*CFGEdge
	for _, edge := range l.cfg.Edges {
		if l.dom.Dominates(edge.To, edge.From) {
			backEdges = append(backEdges, edge)
		}
	}
	return backEdges
}

func (l *LoopAnalyzer) buildLoop(header *CFGNode, backEdges []*CFGEdge) *Loop {
	l.loopID++

	loop := &Loop{
		ID:        l.loopID,
		Header:    header,
		BackEdges: backEdges,
		Nodes:     []*CFGNode{header},
		Type:      LoopNatural,
		TripCount: -1,
		Children:  make([]*Loop, 0),
		Latches:   make([]*CFGNode, 0),
	}

	for _, edge := range backEdges {
		loop.Latches = append(loop.Latches, edge.From)
	}

	inLoop := make(map[int]bool, len(l.cfg.Nodes)/2)
	inLoop[header.ID] = true

	var stack []*CFGNode
	for _, latch := range loop.Latches {
		if !inLoop[latch.ID] {
			stack = append(stack, latch)
		}
	}

	for len(stack) > 0 {
		node := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		if inLoop[node.ID] {
			continue
		}
		inLoop[node.ID] = true
		loop.Nodes = append(loop.Nodes, node)

		for _, pred := range node.Predecessors {
			if !inLoop[pred.ID] {
				stack = append(stack, pred)
			}
		}
	}

	loop.ExitNodes, loop.ExitEdges = l.findLoopExits(loop, inLoop)
	loop.IsInfinite = len(loop.ExitNodes) == 0
	if loop.IsInfinite {
		loop.Type = LoopInfinite
	}

	loop.PreHeader = l.findPreHeader(loop)

	for _, node := range loop.Nodes {
		if len(node.Instructions) > 0 {
			lastOp := node.Instructions[len(node.Instructions)-1].Opcode
			if isLoopGotoOpcode(lastOp) {
				for _, succ := range node.Successors {
					if !inLoop[succ.ID] {
						loop.HasBreak = true
						break
					}
				}
			}
		}
		if loop.HasBreak {
			break
		}
	}

	return loop
}

func (l *LoopAnalyzer) findLoopExits(loop *Loop, inLoop map[int]bool) ([]*CFGNode, []*CFGEdge) {
	var exitNodes []*CFGNode
	var exitEdges []*CFGEdge
	seen := make(map[int]bool)

	for _, node := range loop.Nodes {
		for _, succ := range node.Successors {
			if !inLoop[succ.ID] && !seen[succ.ID] {
				exitNodes = append(exitNodes, succ)
				seen[succ.ID] = true

				if edge := l.cfg.FindEdge(node, succ); edge != nil {
					exitEdges = append(exitEdges, edge)
				}
			}
		}
	}

	return exitNodes, exitEdges
}

func (l *LoopAnalyzer) findPreHeader(loop *Loop) *CFGNode {
	var preHeader *CFGNode

	for _, pred := range loop.Header.Predecessors {
		isLatch := false
		for _, latch := range loop.Latches {
			if pred == latch {
				isLatch = true
				break
			}
		}

		if !isLatch {
			if preHeader != nil {
				return nil
			}
			preHeader = pred
		}
	}

	return preHeader
}

// ═══════════════════════════════════════════════════════════════════════════════
// IRREDUCIBLE DETECTION
// ═══════════════════════════════════════════════════════════════════════════════

func (l *LoopAnalyzer) detectIrreducible() {
	for _, loop := range l.loops {
		entries := l.findLoopEntries(loop)
		if len(entries) > 1 {
			loop.Type = LoopIrreducible
		}
	}
}

func (l *LoopAnalyzer) findLoopEntries(loop *Loop) []*CFGNode {
	inLoop := make(map[int]bool, len(loop.Nodes))
	for _, node := range loop.Nodes {
		inLoop[node.ID] = true
	}

	var entries []*CFGNode
	seen := make(map[int]bool)

	for _, node := range loop.Nodes {
		for _, pred := range node.Predecessors {
			if !inLoop[pred.ID] && !seen[node.ID] {
				entries = append(entries, node)
				seen[node.ID] = true
			}
		}
	}

	return entries
}

// ═══════════════════════════════════════════════════════════════════════════════
// INDUCTION VARIABLE DETECTION
// ═══════════════════════════════════════════════════════════════════════════════

func (l *LoopAnalyzer) detectInductionVariables() {
	for _, loop := range l.loops {
		loop.InductionVars = l.findInductionVars(loop)

		if loop.TripCount == -1 && len(loop.InductionVars) > 0 {
			loop.TripCount = l.estimateTripCount(loop)
		}
	}
}

func (l *LoopAnalyzer) findInductionVars(loop *Loop) []*InductionVar {
	var ivs []*InductionVar

	inLoop := make(map[int]bool, len(loop.Nodes))
	for _, node := range loop.Nodes {
		inLoop[node.ID] = true
	}

	for _, node := range loop.Nodes {
		for _, instrRef := range node.Instructions {
			instr := l.getInstruction(instrRef.Index)
			if instr == nil {
				continue
			}

			iv := l.checkInductionPattern(instr, instrRef.Index, loop)
			if iv != nil {
				ivs = append(ivs, iv)
			}
		}
	}

	return ivs
}

func (l *LoopAnalyzer) checkInductionPattern(instr *Instruction, idx int, loop *Loop) *InductionVar {
	opcode := instr.Opcode

	if (strings.HasPrefix(opcode, "add-int/lit") || strings.HasPrefix(opcode, "add-int/2addr")) &&
		len(instr.Operands) >= 2 {

		destReg := instr.Operands[0]

		var srcReg string
		var step int

		if strings.HasPrefix(opcode, "add-int/2addr") && len(instr.Operands) >= 2 {
			_ = destReg
			return nil
		}

		if len(instr.Operands) >= 3 {
			srcReg = instr.Operands[1]
			if v, err := parseLoopSmaliInt(instr.Operands[2]); err == nil {
				step = v
			} else {
				return nil
			}
		}

		if destReg == srcReg && step != 0 {
			iv := &InductionVar{
				Register:  destReg,
				Type:      InductionLinear,
				StepValue: step,
				DefIdx:    idx,
			}

			iv.InitValue = l.findInitValue(destReg, loop)
			l.findBound(iv, loop)

			return iv
		}
	}

	if strings.HasPrefix(opcode, "sub-int/lit") && len(instr.Operands) >= 3 {
		destReg := instr.Operands[0]
		srcReg := instr.Operands[1]

		if destReg == srcReg {
			if v, err := parseLoopSmaliInt(instr.Operands[2]); err == nil && v != 0 {
				iv := &InductionVar{
					Register:  destReg,
					Type:      InductionLinear,
					StepValue: -v,
					DefIdx:    idx,
				}
				iv.InitValue = l.findInitValue(destReg, loop)
				l.findBound(iv, loop)
				return iv
			}
		}
	}

	return nil
}

func (l *LoopAnalyzer) findInitValue(register string, loop *Loop) int {
	if loop.PreHeader != nil {
		for _, ref := range loop.PreHeader.Instructions {
			instr := l.getInstruction(ref.Index)
			if instr == nil {
				continue
			}

			if strings.HasPrefix(instr.Opcode, "const") && len(instr.Operands) >= 2 {
				if instr.Operands[0] == register {
					if v, err := parseLoopSmaliInt(instr.Operands[1]); err == nil {
						return v
					}
				}
			}
		}
	}

	return 0
}

func (l *LoopAnalyzer) findBound(iv *InductionVar, loop *Loop) {
	if loop.Header.Condition == nil {
		return
	}

	cond := loop.Header.Condition

	if cond.Register1 == iv.Register || cond.Register2 == iv.Register {
		iv.BoundOp = cond.Op
		iv.UseIdx = loop.Header.Instructions[len(loop.Header.Instructions)-1].Index

		otherReg := cond.Register2
		if cond.Register2 == iv.Register {
			otherReg = cond.Register1
		}

		if otherReg != "" {
			for _, node := range l.cfg.Nodes {
				for _, ref := range node.Instructions {
					instr := l.getInstruction(ref.Index)
					if instr == nil {
						continue
					}
					if strings.HasPrefix(instr.Opcode, "const") && len(instr.Operands) >= 2 {
						if instr.Operands[0] == otherReg {
							if v, err := parseLoopSmaliInt(instr.Operands[1]); err == nil {
								iv.Bound = v
								return
							}
						}
					}
				}
			}
		}
	}
}

func (l *LoopAnalyzer) estimateTripCount(loop *Loop) int {
	for _, iv := range loop.InductionVars {
		if iv.StepValue == 0 || iv.BoundOp == CondUnknown {
			continue
		}

		switch iv.BoundOp {
		case CondLtZero, CondLt:
			if iv.StepValue > 0 && iv.Bound > iv.InitValue {
				return (iv.Bound - iv.InitValue + iv.StepValue - 1) / iv.StepValue
			}
		case CondLeZero, CondLe:
			if iv.StepValue > 0 && iv.Bound >= iv.InitValue {
				return (iv.Bound-iv.InitValue)/iv.StepValue + 1
			}
		case CondGtZero, CondGt:
			if iv.StepValue < 0 && iv.Bound < iv.InitValue {
				return (iv.InitValue - iv.Bound - iv.StepValue - 1) / (-iv.StepValue)
			}
		case CondGeZero, CondGe:
			if iv.StepValue < 0 && iv.Bound <= iv.InitValue {
				return (iv.InitValue-iv.Bound)/(-iv.StepValue) + 1
			}
		case CondNe, CondNeZero:
			if iv.StepValue > 0 && iv.Bound > iv.InitValue {
				diff := iv.Bound - iv.InitValue
				if diff%iv.StepValue == 0 {
					return diff / iv.StepValue
				}
			} else if iv.StepValue < 0 && iv.Bound < iv.InitValue {
				diff := iv.InitValue - iv.Bound
				step := -iv.StepValue
				if diff%step == 0 {
					return diff / step
				}
			}
		}
	}
	return -1
}

// ═══════════════════════════════════════════════════════════════════════════════
// LOOP HIERARCHY
// ═══════════════════════════════════════════════════════════════════════════════

func (l *LoopAnalyzer) buildLoopHierarchy() {
	loopNodes := make([]map[int]bool, len(l.loops))
	for i, loop := range l.loops {
		loopNodes[i] = make(map[int]bool, len(loop.Nodes))
		for _, node := range loop.Nodes {
			loopNodes[i][node.ID] = true
		}
	}

	for i, innerLoop := range l.loops {
		var bestParent *Loop
		bestSize := int(^uint(0) >> 1)

		for j, outerLoop := range l.loops {
			if i == j {
				continue
			}

			if loopNodes[j][innerLoop.Header.ID] {
				if len(outerLoop.Nodes) < bestSize {
					bestParent = outerLoop
					bestSize = len(outerLoop.Nodes)
				}
			}
		}

		if bestParent != nil {
			innerLoop.Parent = bestParent
			bestParent.Children = append(bestParent.Children, innerLoop)
		}
	}

	for _, loop := range l.loops {
		depth := 0
		p := loop.Parent
		for p != nil {
			depth++
			p = p.Parent
		}
		loop.Depth = depth
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// LOOP GUARDS
// ═══════════════════════════════════════════════════════════════════════════════

func (l *LoopAnalyzer) findLoopGuards() {
	for _, loop := range l.loops {
		loop.Guards = l.findGuardsForLoop(loop)
	}
}

func (l *LoopAnalyzer) findGuardsForLoop(loop *Loop) []*LoopGuardInfo {
	var guards []*LoopGuardInfo

	if loop.PreHeader != nil {
		guards = append(guards, l.extractGuards(loop.PreHeader)...)
	}

	if loop.Header.Condition != nil {
		if g := l.analyzeGuardCondition(loop.Header, loop.Header.Condition); g != nil {
			guards = append(guards, g)
		}
	}

	if l.dom != nil {
		idom := l.dom.GetImmediateDominator(loop.Header)
		visited := make(map[int]bool)
		depth := 0

		for idom != nil && depth < 5 && !visited[idom.ID] {
			visited[idom.ID] = true
			guards = append(guards, l.extractGuards(idom)...)
			idom = l.dom.GetImmediateDominator(idom)
			depth++
		}
	}

	return guards
}

func (l *LoopAnalyzer) extractGuards(node *CFGNode) []*LoopGuardInfo {
	var guards []*LoopGuardInfo

	for _, ref := range node.Instructions {
		instr := l.getInstruction(ref.Index)
		if instr == nil {
			continue
		}

		if strings.HasPrefix(instr.Opcode, "invoke") {
			if g := l.checkInvokeGuard(node, instr); g != nil {
				guards = append(guards, g)
			}
		}

		if instr.Opcode == "instance-of" {
			guards = append(guards, &LoopGuardInfo{
				Type: GuardTypeType,
				Node: node,
			})
		}
	}

	if node.Condition != nil {
		if g := l.analyzeGuardCondition(node, node.Condition); g != nil {
			guards = append(guards, g)
		}
	}

	return guards
}

func (l *LoopAnalyzer) checkInvokeGuard(node *CFGNode, instr *Instruction) *LoopGuardInfo {
	if len(instr.Operands) == 0 {
		return nil
	}

	methodRef := instr.Operands[len(instr.Operands)-1]
	methodLower := strings.ToLower(methodRef)

	guard := &LoopGuardInfo{
		Node:      node,
		MethodRef: methodRef,
	}

	licensePatterns := []string{
		"islicensed", "checklicense", "verifylicense",
		"getlicensestate", "checkpurchase", "ispurchased",
		"issubscribed", "validatepurchase", "billing",
		"iab", "inappbilling", "play/billing",
	}
	for _, pattern := range licensePatterns {
		if strings.Contains(methodLower, pattern) {
			guard.Type = GuardTypeLicense
			return guard
		}
	}

	rootPatterns := []string{
		"isrooted", "isdevicerooted", "checkroot",
		"detectroot", "rootbeer", "rootdetect",
		"checksu", "checksuperuser", "rooted",
	}
	for _, pattern := range rootPatterns {
		if strings.Contains(methodLower, pattern) {
			guard.Type = GuardTypeRoot
			return guard
		}
	}

	debugPatterns := []string{
		"isdebuggable", "isdebugging", "debugger",
		"checkdebug", "detectdebug", "istampered",
		"checksignature", "verifysignature", "integrity",
		"safetynet", "attestation",
	}
	for _, pattern := range debugPatterns {
		if strings.Contains(methodLower, pattern) {
			guard.Type = GuardTypeDebug
			return guard
		}
	}

	networkPatterns := []string{
		"isnetworkavailable", "isconnected", "hasnetwork",
		"checkconnectivity", "getactivenetwork",
	}
	for _, pattern := range networkPatterns {
		if strings.Contains(methodLower, pattern) {
			guard.Type = GuardTypeNetwork
			return guard
		}
	}

	permissionPatterns := []string{
		"checkpermission", "haspermission", "requestpermission",
		"checkselfpermission",
	}
	for _, pattern := range permissionPatterns {
		if strings.Contains(methodLower, pattern) {
			guard.Type = GuardTypePermission
			return guard
		}
	}

	return nil
}

func (l *LoopAnalyzer) analyzeGuardCondition(node *CFGNode, cond *ConditionInfo) *LoopGuardInfo {
	if cond.Op == CondEqZero || cond.Op == CondNeZero {
		return &LoopGuardInfo{
			Type:      GuardTypeNull,
			Node:      node,
			Condition: cond,
			Inverted:  cond.Op == CondEqZero,
		}
	}

	return nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// LOOP CLASSIFICATION
// ═══════════════════════════════════════════════════════════════════════════════

func (l *LoopAnalyzer) classifyLoops() {
	for _, loop := range l.loops {
		loop.Classification = l.classifyLoop(loop)
	}
}

func (l *LoopAnalyzer) classifyLoop(loop *Loop) LoopClassification {
	if loop.IsInfinite {
		return LoopClassInfinite
	}

	if l.isIteratorLoop(loop) {
		return LoopClassIterator
	}

	if l.isForEachLoop(loop) {
		return LoopClassForEach
	}

	if len(loop.InductionVars) > 0 {
		for _, iv := range loop.InductionVars {
			if iv.Type == InductionLinear && iv.BoundOp != CondUnknown {
				return LoopClassCounted
			}
		}
	}

	headerHasCondition := loop.Header.Condition != nil

	latchHasCondition := false
	for _, latch := range loop.Latches {
		if latch.Condition != nil {
			latchHasCondition = true
			break
		}
	}

	if headerHasCondition && !latchHasCondition {
		return LoopClassPreTest
	}

	if latchHasCondition && !headerHasCondition {
		return LoopClassPostTest
	}

	if headerHasCondition && len(loop.Header.Instructions) <= 2 {
		return LoopClassPreTest
	}

	return LoopClassUnknown
}

func (l *LoopAnalyzer) isIteratorLoop(loop *Loop) bool {
	hasHasNext := false
	hasNext := false

	for _, node := range loop.Nodes {
		for _, ref := range node.Instructions {
			instr := l.getInstruction(ref.Index)
			if instr == nil {
				continue
			}

			if strings.HasPrefix(instr.Opcode, "invoke") {
				for _, op := range instr.Operands {
					if strings.Contains(op, "Iterator;->hasNext") {
						hasHasNext = true
					}
					if strings.Contains(op, "Iterator;->next") {
						hasNext = true
					}
				}
			}
		}
	}

	return hasHasNext && hasNext
}

func (l *LoopAnalyzer) isForEachLoop(loop *Loop) bool {
	for _, node := range loop.Nodes {
		for _, ref := range node.Instructions {
			instr := l.getInstruction(ref.Index)
			if instr == nil {
				continue
			}

			if strings.HasPrefix(instr.Opcode, "invoke") {
				for _, op := range instr.Operands {
					if strings.Contains(op, "->forEach(") {
						return true
					}
				}
			}
		}
	}

	return false
}

// ═══════════════════════════════════════════════════════════════════════════════
// LOOP METRICS
// ═══════════════════════════════════════════════════════════════════════════════

func (l *LoopAnalyzer) computeLoopMetrics() {
	for _, loop := range l.loops {
		loop.Metrics = l.computeMetricsForLoop(loop)
	}
}

func (l *LoopAnalyzer) computeMetricsForLoop(loop *Loop) LoopMetrics {
	metrics := LoopMetrics{
		NumBlocks:    len(loop.Nodes),
		NestingDepth: loop.Depth,
	}

	branchCount := 0

	for _, node := range loop.Nodes {
		metrics.BodySize += len(node.Instructions)

		for _, ref := range node.Instructions {
			instr := l.getInstruction(ref.Index)
			if instr == nil {
				continue
			}

			opcode := instr.Opcode

			if isLoopBranchOpcode(opcode) {
				branchCount++
			}

			if strings.HasPrefix(opcode, "invoke") {
				metrics.HasInvoke = true
			}

			if strings.HasPrefix(opcode, "iget") || strings.HasPrefix(opcode, "iput") ||
				strings.HasPrefix(opcode, "sget") || strings.HasPrefix(opcode, "sput") {
				metrics.HasFieldAccess = true
			}

			if strings.HasPrefix(opcode, "aget") || strings.HasPrefix(opcode, "aput") ||
				opcode == "array-length" {
				metrics.HasArrayAccess = true
			}

			if opcode == "throw" || strings.HasPrefix(opcode, "div-") ||
				strings.HasPrefix(opcode, "rem-") {
				metrics.HasException = true
			}
		}
	}

	if metrics.BodySize > 0 {
		metrics.BranchDensity = float64(branchCount) / float64(metrics.BodySize)
	}

	return metrics
}

// ═══════════════════════════════════════════════════════════════════════════════
// NODE TO LOOP MAPPING
// ═══════════════════════════════════════════════════════════════════════════════

func (l *LoopAnalyzer) buildNodeToLoopMap() {
	for _, loop := range l.loops {
		for _, node := range loop.Nodes {
			existing := l.nodeToLoop[node.ID]
			if existing == nil || len(loop.Nodes) < len(existing.Nodes) {
				l.nodeToLoop[node.ID] = loop
			}
		}
	}
}

func (l *LoopAnalyzer) GetLoopForNode(node *CFGNode) *Loop {
	if node == nil {
		return nil
	}
	return l.nodeToLoop[node.ID]
}

func (l *LoopAnalyzer) GetAllLoopsForNode(node *CFGNode) []*Loop {
	if node == nil {
		return nil
	}

	var result []*Loop
	innermost := l.nodeToLoop[node.ID]

	if innermost == nil {
		return nil
	}

	for loop := innermost; loop != nil; loop = loop.Parent {
		result = append(result, loop)
	}

	return result
}

// ═══════════════════════════════════════════════════════════════════════════════
// MARK NODES
// ═══════════════════════════════════════════════════════════════════════════════

func (l *LoopAnalyzer) markNodes() {
	for _, loop := range l.loops {
		if loop.Header != nil {
			loop.Header.LoopHeader = loop.Header
			loop.Header.IsLoopHeader = true
			loop.Header.LoopType = loop.Type
			loop.Header.LoopDepth = loop.Depth + 1
		}

		for _, node := range loop.Nodes {
			if node.LoopDepth < loop.Depth+1 {
				node.LoopDepth = loop.Depth + 1
			}
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// LOOP-INVARIANT DETECTION
// ═══════════════════════════════════════════════════════════════════════════════

func (l *LoopAnalyzer) FindLoopInvariants(loop *Loop) []*LoopValueRef {
	var invariants []*LoopValueRef

	inLoop := make(map[int]bool, len(loop.Nodes))
	for _, node := range loop.Nodes {
		inLoop[node.ID] = true
	}

	definedInLoop := make(map[string]bool)

	for _, node := range loop.Nodes {
		for _, ref := range node.Instructions {
			instr := l.getInstruction(ref.Index)
			if instr == nil || len(instr.Operands) == 0 {
				continue
			}

			if isLoopDefiningOpcode(instr.Opcode) {
				definedInLoop[instr.Operands[0]] = true
			}
		}
	}

	seen := make(map[string]bool)

	for _, node := range loop.Nodes {
		for _, ref := range node.Instructions {
			instr := l.getInstruction(ref.Index)
			if instr == nil {
				continue
			}

			startIdx := 0
			if isLoopDefiningOpcode(instr.Opcode) {
				startIdx = 1
			}

			for i := startIdx; i < len(instr.Operands); i++ {
				reg := instr.Operands[i]
				if !isLoopRegister(reg) {
					continue
				}

				if !definedInLoop[reg] && !seen[reg] {
					seen[reg] = true
					invariants = append(invariants, &LoopValueRef{
						Register: reg,
						Node:     node,
					})
				}
			}
		}
	}

	loop.LoopInvariant = invariants
	return invariants
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

func (l *LoopAnalyzer) getInstruction(index int) *Instruction {
	if l.cfg == nil || l.cfg.Method == nil {
		return nil
	}
	if index < 0 || index >= len(l.cfg.Method.Instructions) {
		return nil
	}
	return l.cfg.Method.Instructions[index]
}

func isLoopGotoOpcode(opcode string) bool {
	return opcode == "goto" || opcode == "goto/16" || opcode == "goto/32"
}

func isLoopBranchOpcode(opcode string) bool {
	if isLoopGotoOpcode(opcode) {
		return true
	}
	if strings.HasPrefix(opcode, "if-") {
		return true
	}
	if strings.HasPrefix(opcode, "packed-switch") || strings.HasPrefix(opcode, "sparse-switch") {
		return true
	}
	return false
}

func isLoopDefiningOpcode(opcode string) bool {
	defOpcodes := []string{
		"const", "move", "new-", "iget", "sget", "aget",
		"add-", "sub-", "mul-", "div-", "rem-", "and-", "or-", "xor-",
		"shl-", "shr-", "ushr-", "neg-", "not-",
		"int-to-", "long-to-", "float-to-", "double-to-",
		"invoke-", "check-cast", "instance-of", "array-length",
		"filled-new-array", "cmpl-", "cmpg-", "cmp-",
	}

	for _, prefix := range defOpcodes {
		if strings.HasPrefix(opcode, prefix) {
			return true
		}
	}
	return false
}

func isLoopRegister(s string) bool {
	if len(s) < 2 {
		return false
	}
	return (s[0] == 'v' || s[0] == 'p') && s[1] >= '0' && s[1] <= '9'
}

func parseLoopSmaliInt(s string) (int, error) {
	s = strings.TrimSpace(s)

	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "-0x") {
		negative := strings.HasPrefix(s, "-")
		hexStr := s
		if negative {
			hexStr = s[1:]
		}
		hexStr = strings.TrimPrefix(hexStr, "0x")

		var val int64
		_, err := fmt.Sscanf(hexStr, "%x", &val)
		if err != nil {
			return 0, err
		}
		if negative {
			return int(-val), nil
		}
		return int(val), nil
	}

	var val int
	_, err := fmt.Sscanf(s, "%d", &val)
	return val, err
}

// ═══════════════════════════════════════════════════════════════════════════════
// LOOP QUERY METHODS
// ═══════════════════════════════════════════════════════════════════════════════

func (l *LoopAnalyzer) GetLoops() []*Loop {
	return l.loops
}

func (l *LoopAnalyzer) GetRootLoops() []*Loop {
	var roots []*Loop
	for _, loop := range l.loops {
		if loop.Parent == nil {
			roots = append(roots, loop)
		}
	}
	return roots
}

func (l *LoopAnalyzer) GetInfiniteLoops() []*Loop {
	var infinite []*Loop
	for _, loop := range l.loops {
		if loop.IsInfinite {
			infinite = append(infinite, loop)
		}
	}
	return infinite
}

func (l *LoopAnalyzer) GetLoopsByType(class LoopClassification) []*Loop {
	var result []*Loop
	for _, loop := range l.loops {
		if loop.Classification == class {
			result = append(result, loop)
		}
	}
	return result
}

func (l *LoopAnalyzer) GetProtectedLoops() []*Loop {
	var result []*Loop
	for _, loop := range l.loops {
		for _, guard := range loop.Guards {
			if guard.Type == GuardTypeLicense ||
				guard.Type == GuardTypeRoot ||
				guard.Type == GuardTypeDebug {
				result = append(result, loop)
				break
			}
		}
	}
	return result
}

// ═══════════════════════════════════════════════════════════════════════════════
// LOOP STRING REPRESENTATION
// ═══════════════════════════════════════════════════════════════════════════════

func (loop *Loop) String() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Loop#%d [Header: BB%d, ", loop.ID, loop.Header.ID))

	switch loop.Type {
	case LoopNatural:
		sb.WriteString("Natural")
	case LoopIrreducible:
		sb.WriteString("Irreducible")
	case LoopInfinite:
		sb.WriteString("Infinite")
	default:
		sb.WriteString("Unknown")
	}

	sb.WriteString(", ")
	switch loop.Classification {
	case LoopClassPreTest:
		sb.WriteString("while-loop")
	case LoopClassPostTest:
		sb.WriteString("do-while")
	case LoopClassCounted:
		sb.WriteString("for-loop")
	case LoopClassInfinite:
		sb.WriteString("infinite")
	case LoopClassIterator:
		sb.WriteString("iterator")
	case LoopClassForEach:
		sb.WriteString("forEach")
	default:
		sb.WriteString("unclassified")
	}

	sb.WriteString(fmt.Sprintf(", Depth=%d, Nodes=%d", loop.Depth, len(loop.Nodes)))

	if loop.TripCount >= 0 {
		sb.WriteString(fmt.Sprintf(", TripCount=%d", loop.TripCount))
	}

	if len(loop.InductionVars) > 0 {
		sb.WriteString(fmt.Sprintf(", IndVars=%d", len(loop.InductionVars)))
	}

	if len(loop.Guards) > 0 {
		sb.WriteString(fmt.Sprintf(", Guards=%d", len(loop.Guards)))
	}

	if loop.HasBreak {
		sb.WriteString(", HasBreak")
	}

	sb.WriteString("]")

	return sb.String()
}

func (iv *InductionVar) String() string {
	typeStr := "unknown"
	switch iv.Type {
	case InductionLinear:
		typeStr = "linear"
	case InductionAffine:
		typeStr = "affine"
	}

	return fmt.Sprintf("IndVar{%s: %s, init=%d, step=%d, bound=%d}",
		iv.Register, typeStr, iv.InitValue, iv.StepValue, iv.Bound)
}

func (g *LoopGuardInfo) String() string {
	typeStr := "unknown"
	switch g.Type {
	case GuardTypeNull:
		typeStr = "null-check"
	case GuardTypeBounds:
		typeStr = "bounds-check"
	case GuardTypeType:
		typeStr = "type-check"
	case GuardTypeLicense:
		typeStr = "license"
	case GuardTypeRoot:
		typeStr = "root-detect"
	case GuardTypeDebug:
		typeStr = "debug-detect"
	case GuardTypeNetwork:
		typeStr = "network"
	case GuardTypePermission:
		typeStr = "permission"
	}

	if g.MethodRef != "" {
		return fmt.Sprintf("Guard{%s: %s}", typeStr, g.MethodRef)
	}
	return fmt.Sprintf("Guard{%s}", typeStr)
}

func (lc LoopClassification) String() string {
	switch lc {
	case LoopClassPreTest:
		return "pre-test"
	case LoopClassPostTest:
		return "post-test"
	case LoopClassCounted:
		return "counted"
	case LoopClassInfinite:
		return "infinite"
	case LoopClassIterator:
		return "iterator"
	case LoopClassForEach:
		return "forEach"
	default:
		return "unknown"
	}
}
