package cfg

import (
	"fmt"
	"strconv"
	"strings"

	"mega-analyzer/pkg/internal/dexir"
)

// ═══════════════════════════════════════════════════════════════════════════════
// CFG BUILDER — Advanced Multi-Phase Construction Engine
// ═══════════════════════════════════════════════════════════════════════════════
//
// Phases:
//   1. Pre-scan switch payloads (packed/sparse)
//   2. Find leaders (basic block boundaries)
//   3. Create basic blocks
//   4. Create edges (branch, goto, switch, fallthrough)
//   5. Handle exception edges (try/catch)
//   6. Classify nodes (condition, return, throw, switch, catch)
//   7. Detect unreachable blocks
//   8. Split critical edges
//   9. Compute RPO numbering
//  10. Finalize + compute block metrics
// ═══════════════════════════════════════════════════════════════════════════════

// BuildOptions controls optional analysis phases
type BuildOptions struct {
	SplitCriticalEdges bool // insert synthetic blocks on critical edges
	DetectUnreachable  bool // mark unreachable blocks
	ComputeRPO         bool // compute reverse post-order numbering
	ComputeMetrics     bool // compute per-block metrics
}

// DefaultBuildOptions returns production defaults
func DefaultBuildOptions() BuildOptions {
	return BuildOptions{
		SplitCriticalEdges: true,
		DetectUnreachable:  true,
		ComputeRPO:         true,
		ComputeMetrics:     true,
	}
}

// BuildResult contains the CFG plus build statistics
type BuildResult struct {
	CFG   *ControlFlowGraph
	Stats BuildStats
}

// BuildStats tracks what the builder did
type BuildStats struct {
	TotalInstructions  int
	BasicBlocks        int
	Edges              int
	UnreachableBlocks  int
	CriticalEdgesSplit int
	SwitchPayloads     int
	ExceptionEdges     int
	MaxBlockSize       int
	AvgBlockSize       float64
}

// SwitchPayload holds parsed switch data
type SwitchPayload struct {
	Type       SwitchType // SwitchPacked or SwitchSparse
	DataLabel  string     // label pointing to payload data
	FirstKey   int        // first key (packed only)
	Targets    []string   // target labels
	Keys       []int      // keys (sparse only)
	InstrIndex int        // index of the switch instruction
}

// ───────────────────────────────────────────────────────────────────────────────

type CFGBuilder struct {
	// Input
	instructions []Instruction
	labels       []Label
	tryBlocks    []TryBlock

	// Indexes
	labelIndex  *LabelIndex
	instrIndex  *InstructionIndex
	offsetToIdx map[uint32]int // DEX-origin offset → instruction index

	// Build state
	leaders        map[int]bool
	nodeByIdx      map[int]*CFGNode
	switchPayloads map[string]*SwitchPayload // data label → payload
	nextNodeID     int

	// Options
	opts BuildOptions

	// Output
	cfg   *ControlFlowGraph
	stats BuildStats
}

func NewCFGBuilder() *CFGBuilder {
	return &CFGBuilder{
		opts: DefaultBuildOptions(),
	}
}

func NewCFGBuilderWithOptions(opts BuildOptions) *CFGBuilder {
	return &CFGBuilder{
		opts: opts,
	}
}

// reset clears all internal state so the builder can be reused safely
func (b *CFGBuilder) reset() {
	b.instructions = nil
	b.labels = nil
	b.tryBlocks = nil
	b.labelIndex = nil
	b.instrIndex = nil
	b.offsetToIdx = nil
	b.leaders = nil
	b.nodeByIdx = nil
	b.switchPayloads = nil
	b.nextNodeID = 0
	b.cfg = nil
	b.stats = BuildStats{}
}

// ═══════════════════════════════════════════════════════════════════════════════
// PUBLIC API
// ═══════════════════════════════════════════════════════════════════════════════

type BuildInput struct {
	MethodName   string
	ClassName    string
	Signature    string
	Instructions []Instruction
	Labels       []Label
	TryBlocks    []TryBlock

	// labelResolution carries pre-resolved label → instruction index
	// mappings produced by BuildFromMethod (typed-IR entry). When set,
	// BuildEx wires the label index from it directly instead of
	// re-deriving associations from line numbers.
	labelResolution map[string]int
}

// Build constructs a CFG (backward compatible)
func (b *CFGBuilder) Build(input BuildInput) *ControlFlowGraph {
	result := b.BuildEx(input)
	if result == nil {
		return nil
	}
	return result.CFG
}

// BuildFromInstructions — удобная обёртка для построения CFG из инструкций
func BuildFromInstructions(instructions []InstructionRef, opts *BuildOptions) (*BuildResult, error) {
	if len(instructions) == 0 {
		return nil, fmt.Errorf("no instructions provided")
	}

	// Конвертируем InstructionRef → Instruction
	ins := make([]Instruction, len(instructions))
	for i, ref := range instructions {
		ins[i] = Instruction{
			Index:  i,
			Line:   ref.Line,
			Opcode: ref.Opcode,
			Raw:    ref.Raw,
		}
	}

	input := BuildInput{
		MethodName:   "anonymous",
		Instructions: ins,
	}

	builder := NewCFGBuilder()
	if opts != nil {
		builder.opts = *opts
	}

	result := builder.BuildEx(input)
	if result == nil {
		return nil, fmt.Errorf("failed to build CFG")
	}

	return result, nil
}

// BuildEx constructs a CFG with full statistics
func (b *CFGBuilder) BuildEx(input BuildInput) *BuildResult {
	if len(input.Instructions) == 0 {
		return nil
	}

	// Reset state for reuse safety
	b.reset()

	// Store input. Legacy inputs may lack the typed IR pointer; the
	// boundary shim reconstructs it once here so every phase below can
	// rely on typed operand access exclusively.
	ensureLegacyIR(input.Instructions)
	b.instructions = input.Instructions
	b.labels = input.Labels
	b.tryBlocks = input.TryBlocks
	b.leaders = make(map[int]bool, len(input.Instructions)/4)
	b.nodeByIdx = make(map[int]*CFGNode, len(input.Instructions)/4)
	b.switchPayloads = make(map[string]*SwitchPayload)
	b.stats.TotalInstructions = len(input.Instructions)

	// Build indexes — O(N)
	b.labelIndex = NewLabelIndex()
	if input.labelResolution != nil {
		// Typed-IR input: associations were resolved during conversion
		// (labels carry body-relative lines for text IR, offsets for
		// DEX IR — neither can be re-derived from line numbers here).
		for name, idx := range input.labelResolution {
			b.labelIndex.SetLabel(name, idx)
		}
	} else {
		b.labelIndex.BuildFromMethod(input.Instructions, input.Labels)
	}
	b.instrIndex = NewInstructionIndex(input.Instructions)

	// DEX-origin IR carries absolute code-unit offsets; index them so
	// label-less branch/payload targets can still resolve.
	b.offsetToIdx = make(map[uint32]int, len(input.Instructions))
	for i := range input.Instructions {
		if ir := input.Instructions[i].IR; ir != nil && ir.Size > 0 {
			if _, exists := b.offsetToIdx[ir.Offset]; !exists {
				b.offsetToIdx[ir.Offset] = i
			}
		}
	}

	// Initialize CFG.
	//
	// FullName is derived here. Nothing in the tree ever assigned it, so every
	// consumer that identified a method by it — GNN findings, cache keys —
	// silently used the empty string.
	b.cfg = &ControlFlowGraph{
		MethodName: input.MethodName,
		ClassName:  input.ClassName,
		Signature:  input.Signature,
		FullName:   buildFullName(input.ClassName, input.MethodName, input.Signature),
		Nodes:      make([]*CFGNode, 0, len(input.Instructions)/3),
		Edges:      make([]*CFGEdge, 0, len(input.Instructions)/2),
		LabelIndex: b.labelIndex,
		NodeByIdx:  make(map[int]*CFGNode),
		TryBlocks:  input.TryBlocks,

		// ✅ ДОБАВИТЬ: Заполняем Method для доступа к инструкциям
		Method: &MethodInfo{
			Instructions: convertToInstructionPointers(input.Instructions),
		},
	} // ← ОДНА закрывающая скобка (конец ControlFlowGraph)

	// ── Phase 1: Pre-scan switch payloads ──
	b.prescanSwitchPayloads()

	// ── Phase 2: Find leaders ──
	b.findLeaders()

	// ── Phase 3: Create basic blocks ──
	b.createBasicBlocks()

	// ── Phase 4: Create edges ──
	b.createEdges()

	// ── Phase 5: Handle exceptions ──
	b.handleExceptions()

	// ── Phase 6: Classify nodes ──
	b.classifyNodes()

	// ── Phase 7: Detect unreachable blocks ──
	if b.opts.DetectUnreachable {
		b.detectUnreachable()
	}

	// ── Phase 8: Split critical edges ──
	if b.opts.SplitCriticalEdges {
		b.splitCriticalEdges()
	}

	// ── Phase 9: Compute RPO ──
	if b.opts.ComputeRPO {
		b.computeRPO()
	}

	// ── Loop Analysis ──
	NewLoopAnalyzer(b.cfg).FindLoops()

	// ── Phase 10: Finalize ──
	b.finalize()

	// ── Compute metrics ──
	if b.opts.ComputeMetrics {
		b.computeBlockMetrics()
	}

	b.stats.BasicBlocks = len(b.cfg.Nodes)
	b.stats.Edges = len(b.cfg.Edges)

	return &BuildResult{
		CFG:   b.cfg,
		Stats: b.stats,
	}
}

// ✅ ДОБАВИТЬ: Helper для конвертации []Instruction в []*Instruction
func convertToInstructionPointers(instructions []Instruction) []*Instruction {
	result := make([]*Instruction, len(instructions))
	for i := range instructions {
		result[i] = &instructions[i]
	}
	return result
}

// ═══════════════════════════════════════════════════════════════════════════════
// PHASE 1: PRE-SCAN SWITCH PAYLOADS
// ═══════════════════════════════════════════════════════════════════════════════
//
// In Smali, switch instructions reference a data label:
//   packed-switch v0, :pswitch_data_0
//
// The payload is defined separately:
//   :pswitch_data_0
//   .packed-switch 0x0
//       :pswitch_0
//       :pswitch_1
//   .end packed-switch
//
// We pre-scan to collect all payloads before building the CFG.
// ═══════════════════════════════════════════════════════════════════════════════

func (b *CFGBuilder) prescanSwitchPayloads() {
	for i := range b.instructions {
		ir := b.instructions[i].IR
		if ir == nil {
			continue
		}
		// Two shapes carry a table: a payload pseudo-instruction (DEX
		// origin, and the label-addressed form) and a switch /
		// fill-array-data instruction whose table the smali boundary
		// attached directly. Only the first used to be counted, so a
		// text-origin scan reported zero switch payloads even though its
		// switches did resolve.
		if ir.Op == dexir.OpPackedSwitchPayload || ir.Op == dexir.OpSparseSwitchPayload {
			payload := b.payloadFromIR(i, ir)
			for _, label := range b.labelIndex.GetLabels(i) {
				payload.DataLabel = label
				b.switchPayloads[label] = payload
			}
			b.stats.SwitchPayloads++
			continue
		}
		if ir.Payload != nil &&
			(ir.Op == dexir.OpPackedSwitch || ir.Op == dexir.OpSparseSwitch || ir.Op == dexir.OpFillArrayData) {
			b.stats.SwitchPayloads++
		}
	}
}

// payloadFromIR converts a typed switch payload table into the
// builder's SwitchPayload representation. Target label names are
// rendered with their leading colon, matching the label index keys.
func (b *CFGBuilder) payloadFromIR(instrIdx int, ir *dexir.Instruction) *SwitchPayload {
	payload := &SwitchPayload{
		InstrIndex: instrIdx,
		Targets:    make([]string, 0, 8),
		Keys:       make([]int, 0, 8),
	}

	switch ir.Op {
	case dexir.OpPackedSwitchPayload, dexir.OpPackedSwitch:
		payload.Type = SwitchPacked
		if ir.Payload != nil {
			payload.FirstKey = int(ir.Payload.FirstKey)
		}
	case dexir.OpSparseSwitchPayload, dexir.OpSparseSwitch:
		payload.Type = SwitchSparse
	}

	if ir.Payload == nil {
		return payload
	}
	// Keys are a property of the TABLE, not of the instruction that refers
	// to it: the smali boundary attaches payloads to their switch
	// instruction, while DEX-origin input carries them on a payload
	// pseudo-instruction. Keying off ir.Op dropped every sparse key for
	// text-origin input and collapsed all case keys to 0.
	sparse := ir.Payload.Kind == dexir.PayloadSparseSwitch
	for i := range ir.Payload.Targets {
		if i < len(ir.Payload.TargetLabels) && ir.Payload.TargetLabels[i] != "" {
			payload.Targets = append(payload.Targets, ":"+ir.Payload.TargetLabels[i])
		}
		if sparse && i < len(ir.Payload.Keys) {
			payload.Keys = append(payload.Keys, int(ir.Payload.Keys[i]))
		}
	}
	return payload
}

// ═══════════════════════════════════════════════════════════════════════════════
// PHASE 2: FIND LEADERS
// ═══════════════════════════════════════════════════════════════════════════════

func (b *CFGBuilder) findLeaders() {
	// Rule 1: First instruction is always a leader
	b.leaders[0] = true

	for i, instr := range b.instructions {
		// Rule 2: Target of any branch is a leader
		if target, ok := b.getBranchTarget(instr); ok {
			if targetIdx, found := b.labelIndex.GetInstructionIndex(target); found {
				b.leaders[targetIdx] = true
			}
		}

		// Rule 3: Instruction after branch is a leader
		if isBranchOpcode(instr.Opcode) && i+1 < len(b.instructions) {
			b.leaders[i+1] = true
		}

		// Rule 4: Instruction after return/throw is a leader
		if (isReturnOpcode(instr.Opcode) || isThrowOpcode(instr.Opcode)) &&
			i+1 < len(b.instructions) {
			b.leaders[i+1] = true
		}

		// Rule 5: Switch targets from pre-scanned payloads
		if isSwitchOpcode(instr.Opcode) {
			for _, target := range b.getSwitchTargets(i) {
				if targetIdx, found := b.labelIndex.GetInstructionIndex(target); found {
					b.leaders[targetIdx] = true
				}
			}
		}

		// Rule 6: Monitor-enter/exit create boundaries
		if isMonitorOpcode(instr.Opcode) {
			if i+1 < len(b.instructions) {
				b.leaders[i+1] = true
			}
		}
	}

	// Rule 7: Exception handlers are leaders
	for _, tryBlock := range b.tryBlocks {
		for _, handler := range tryBlock.Handlers {
			b.leaders[handler.HandlerIdx] = true
		}
	}

	// Rule 8: Try-block start is a leader
	for _, tryBlock := range b.tryBlocks {
		b.leaders[tryBlock.StartIdx] = true
		if tryBlock.EndIdx+1 < len(b.instructions) {
			b.leaders[tryBlock.EndIdx+1] = true
		}
	}
}

// getBranchTarget returns the branch target label of a goto/if-*
// instruction from its typed IR (BranchLabel).
func (b *CFGBuilder) getBranchTarget(instr Instruction) (string, bool) {
	if !isBranchOpcode(instr.Opcode) || instr.IR == nil {
		return "", false
	}
	if isConditionOpcode(instr.Opcode) || isGotoOpcode(instr.Opcode) {
		if instr.IR.BranchLabel != "" {
			return ":" + instr.IR.BranchLabel, true
		}
	}
	return "", false
}

// switchPayloadFor returns the payload table attached to a switch
// instruction: first via the pre-scanned data-label registry, then via
// the table the adapter paired directly onto the instruction.
func (b *CFGBuilder) switchPayloadFor(instr Instruction) *SwitchPayload {
	ir := instr.IR
	if ir == nil {
		return nil
	}
	if ir.BranchLabel != "" {
		if p, ok := b.switchPayloads[":"+ir.BranchLabel]; ok {
			return p
		}
	}
	if ir.Payload != nil && (ir.Payload.Kind == dexir.PayloadPackedSwitch || ir.Payload.Kind == dexir.PayloadSparseSwitch) {
		return b.payloadFromIR(-1, ir)
	}
	return nil
}

// getSwitchTargets resolves the case-target labels of a switch
// instruction from its typed payload table. Labels come first
// (text-origin IR and label-decorated DEX IR); bare DEX payloads fall
// back to absolute target offsets via the offset index.
func (b *CFGBuilder) getSwitchTargets(switchIdx int) []string {
	instr := b.instructions[switchIdx]
	if instr.IR == nil {
		return nil
	}

	if payload := b.switchPayloadFor(instr); payload != nil && len(payload.Targets) > 0 {
		return payload.Targets
	}

	// Offset fallback for DEX-origin payloads without labels.
	ir := instr.IR
	if ir.Payload != nil {
		var targets []string
		for i := range ir.Payload.Targets {
			abs := ir.PayloadTargetAbs(i)
			if idx, ok := b.offsetToIdx[uint32(abs)]; ok {
				name := fmt.Sprintf(":__off_%x", abs)
				targets = append(targets, name)
				b.labelIndex.SetLabel(name, idx)
			}
		}
		return targets
	}
	return nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// PHASE 3: CREATE BASIC BLOCKS
// ═══════════════════════════════════════════════════════════════════════════════

func (b *CFGBuilder) createBasicBlocks() {
	var currentNode *CFGNode

	for i, instr := range b.instructions {
		if b.leaders[i] || currentNode == nil {
			if currentNode != nil {
				b.cfg.Nodes = append(b.cfg.Nodes, currentNode)
			}

			currentNode = &CFGNode{
				ID:           b.nextNodeID,
				Type:         NodeTypeBasic,
				StartIdx:     i,
				LineStart:    instr.Line,
				Instructions: make([]InstructionRef, 0, 8),
				Successors:   make([]*CFGNode, 0, 2),
				Predecessors: make([]*CFGNode, 0, 2),
			}

			b.nodeByIdx[i] = currentNode
			b.nextNodeID++
		}

		currentNode.Instructions = append(currentNode.Instructions, InstructionRef{
			Index:  i,
			Opcode: instr.Opcode,
			Line:   instr.Line,
			Raw:    instr.Raw,
			IR:     instr.IR,
		})
		currentNode.EndIdx = i
		currentNode.LineEnd = instr.Line

		b.cfg.NodeByIdx[i] = currentNode
	}

	if currentNode != nil {
		b.cfg.Nodes = append(b.cfg.Nodes, currentNode)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// PHASE 4: CREATE EDGES
// ═══════════════════════════════════════════════════════════════════════════════

func (b *CFGBuilder) createEdges() {
	for _, node := range b.cfg.Nodes {
		if len(node.Instructions) == 0 {
			continue
		}

		lastRef := node.Instructions[len(node.Instructions)-1]
		lastInstr := b.instructions[lastRef.Index]

		switch {
		case isConditionOpcode(lastInstr.Opcode):
			b.handleConditionEdges(node, lastInstr)

		case isGotoOpcode(lastInstr.Opcode):
			b.handleGotoEdge(node, lastInstr)

		case isSwitchOpcode(lastInstr.Opcode):
			b.handleSwitchEdges(node, lastInstr, lastRef.Index)

		case isReturnOpcode(lastInstr.Opcode):
			node.Type = NodeTypeReturn
			node.ExitKind = ExitNormal

		case isThrowOpcode(lastInstr.Opcode):
			node.Type = NodeTypeThrow
			node.ExitKind = ExitException

		default:
			b.handleFallthroughEdge(node)
		}
	}
}

func (b *CFGBuilder) handleConditionEdges(node *CFGNode, instr Instruction) {
	node.Type = NodeTypeCondition
	node.Condition = b.parseCondition(instr)

	// True branch → target
	if node.Condition != nil && node.Condition.Target != "" {
		if targetIdx, ok := b.labelIndex.GetInstructionIndex(node.Condition.Target); ok {
			if targetNode := b.cfg.NodeByIdx[targetIdx]; targetNode != nil {
				edge := b.cfg.AddEdge(node, targetNode, EdgeTrue)
				edge.Predicate = &EdgePredicate{Condition: node.Condition, Expected: true}
				edge.Label = node.Condition.Target
			}
		}
	}

	// False branch → fallthrough
	nextIdx := node.EndIdx + 1
	if nextNode := b.cfg.NodeByIdx[nextIdx]; nextNode != nil {
		edge := b.cfg.AddEdge(node, nextNode, EdgeFalse)
		if node.Condition != nil {
			edge.Predicate = &EdgePredicate{Condition: node.Condition, Expected: false}
		}
	}
}

func (b *CFGBuilder) parseCondition(instr Instruction) *ConditionInfo {
	cond := &ConditionInfo{
		Op: ParseConditionOp(instr.Opcode),
	}

	ir := instr.IR
	if ir == nil {
		return cond
	}

	// Typed register operands: if-XXz has one, if-XX has two.
	if cond.Op.IsZeroCheck() && len(ir.Srcs) >= 1 {
		cond.Register1 = registerName(ir.Srcs[0])
	}
	if !cond.Op.IsZeroCheck() && len(ir.Srcs) >= 2 {
		cond.Register1 = registerName(ir.Srcs[0])
		cond.Register2 = registerName(ir.Srcs[1])
	}

	if ir.BranchLabel != "" {
		cond.Target = ":" + ir.BranchLabel
	}

	if idx, ok := b.labelIndex.GetInstructionIndex(cond.Target); ok {
		cond.TargetIdx = idx
	}

	return cond
}

func (b *CFGBuilder) handleGotoEdge(node *CFGNode, instr Instruction) {
	if instr.IR == nil || instr.IR.BranchLabel == "" {
		return
	}

	target := ":" + instr.IR.BranchLabel
	if targetIdx, ok := b.labelIndex.GetInstructionIndex(target); ok {
		if targetNode := b.cfg.NodeByIdx[targetIdx]; targetNode != nil {
			edge := b.cfg.AddEdge(node, targetNode, EdgeGoto)
			edge.Label = target
		}
	}
}

func (b *CFGBuilder) handleSwitchEdges(node *CFGNode, instr Instruction, instrIdx int) {
	node.Type = NodeTypeSwitch

	switchType := SwitchPacked
	if instr.IR != nil && instr.IR.Op == dexir.OpSparseSwitch {
		switchType = SwitchSparse
	}

	node.SwitchInfo = &SwitchInfo{
		Type:    switchType,
		Targets: make([]SwitchTarget, 0, 8),
	}

	// Get register
	if instr.IR != nil && len(instr.IR.Srcs) > 0 {
		node.SwitchInfo.Register = registerName(instr.IR.Srcs[0])
	}

	// Resolve targets from pre-scanned payloads
	targets := b.getSwitchTargets(instrIdx)
	payload := b.switchPayloadFor(instr)

	for i, target := range targets {
		if targetIdx, ok := b.labelIndex.GetInstructionIndex(target); ok {
			if targetNode := b.cfg.NodeByIdx[targetIdx]; targetNode != nil {
				edge := b.cfg.AddEdge(node, targetNode, EdgeSwitch)
				edge.Label = target

				// ✅ ИСПРАВЛЕНО: используем TargetID вместо NodeID
				st := SwitchTarget{
					Key:      0,
					Label:    target,
					TargetID: targetNode.ID, // ✅ правильное поле!
				}

				if payload != nil {
					if switchType == SwitchPacked {
						st.Key = payload.FirstKey + i
					} else if i < len(payload.Keys) {
						st.Key = payload.Keys[i]
					}
				}

				node.SwitchInfo.Targets = append(node.SwitchInfo.Targets, st)
			}
		}
	}

	// Default case: fallthrough
	b.handleFallthroughEdge(node)
}

func (b *CFGBuilder) handleFallthroughEdge(node *CFGNode) {
	nextIdx := node.EndIdx + 1
	if nextNode := b.cfg.NodeByIdx[nextIdx]; nextNode != nil {
		b.cfg.AddEdge(node, nextNode, EdgeFallthrough)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// PHASE 5: HANDLE EXCEPTIONS
// ═══════════════════════════════════════════════════════════════════════════════

func (b *CFGBuilder) handleExceptions() {
	// Pre-compute set of nodes per try-block to avoid O(N²)
	for _, tryBlock := range b.tryBlocks {
		// Collect unique source nodes in this try range
		sourceNodes := make(map[int]*CFGNode)
		for idx := tryBlock.StartIdx; idx <= tryBlock.EndIdx; idx++ {
			if node := b.cfg.NodeByIdx[idx]; node != nil {
				sourceNodes[node.ID] = node
			}
		}

		for _, handler := range tryBlock.Handlers {
			handlerNode := b.cfg.NodeByIdx[handler.HandlerIdx]
			if handlerNode == nil {
				continue
			}

			handlerNode.Type = NodeTypeCatch
			handlerCopy := handler
			handlerNode.ExceptionHandler = &handlerCopy
			b.cfg.Handlers = append(b.cfg.Handlers, handlerNode)

			// Add exception edges from each unique node in try block
			for _, sourceNode := range sourceNodes {
				if !hasSuccessor(sourceNode, handlerNode) {
					edge := b.cfg.AddEdge(sourceNode, handlerNode, EdgeException)
					edge.Label = handler.Type
					b.stats.ExceptionEdges++
				}
			}
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// PHASE 6: CLASSIFY NODES
// ═══════════════════════════════════════════════════════════════════════════════

func (b *CFGBuilder) classifyNodes() {
	for _, node := range b.cfg.Nodes {
		if node.Type != NodeTypeBasic {
			continue
		}

		if len(node.Successors) == 0 {
			node.Type = NodeTypeExit
			node.ExitKind = ExitNormal
		}

		// Detect monitor blocks
		if len(node.Instructions) > 0 {
			switch node.Instructions[0].Opcode {
			case "monitor-enter":
				node.Type = NodeTypeMonitorEnter
			case "monitor-exit":
				node.Type = NodeTypeMonitorExit
			}
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// PHASE 7: DETECT UNREACHABLE BLOCKS
// ═══════════════════════════════════════════════════════════════════════════════

func (b *CFGBuilder) detectUnreachable() {
	if b.cfg.Entry == nil && len(b.cfg.Nodes) > 0 {
		b.cfg.Entry = b.cfg.Nodes[0]
	}
	if b.cfg.Entry == nil {
		return
	}

	// BFS from entry
	reachable := make(map[int]bool, len(b.cfg.Nodes))
	queue := []*CFGNode{b.cfg.Entry}
	reachable[b.cfg.Entry.ID] = true

	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]

		for _, succ := range node.Successors {
			if !reachable[succ.ID] {
				reachable[succ.ID] = true
				queue = append(queue, succ)
			}
		}
	}

	// Also consider exception handler entry points as reachable
	for _, handler := range b.cfg.Handlers {
		if !reachable[handler.ID] {
			reachable[handler.ID] = true
			// BFS from handler
			hQueue := []*CFGNode{handler}
			for len(hQueue) > 0 {
				node := hQueue[0]
				hQueue = hQueue[1:]
				for _, succ := range node.Successors {
					if !reachable[succ.ID] {
						reachable[succ.ID] = true
						hQueue = append(hQueue, succ)
					}
				}
			}
		}
	}

	// Mark unreachable
	for _, node := range b.cfg.Nodes {
		if !reachable[node.ID] {
			node.IsUnreachable = true
			b.stats.UnreachableBlocks++
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// PHASE 8: SPLIT CRITICAL EDGES
// ═══════════════════════════════════════════════════════════════════════════════
//
// A critical edge is src→dst where src has >1 successor and dst has >1 predecessor.
// We insert a synthetic empty block on the edge to enable clean SSA construction
// and phi-node insertion.
// ═══════════════════════════════════════════════════════════════════════════════

func (b *CFGBuilder) splitCriticalEdges() {
	// Collect critical edges first (don't modify during iteration)
	var criticalEdges []*CFGEdge

	for _, edge := range b.cfg.Edges {
		if edge.Type == EdgeException {
			continue // never split exception edges
		}
		if len(edge.From.Successors) > 1 && len(edge.To.Predecessors) > 1 {
			criticalEdges = append(criticalEdges, edge)
		}
	}

	for _, edge := range criticalEdges {
		b.splitEdge(edge)
		b.stats.CriticalEdgesSplit++
	}
}

func (b *CFGBuilder) splitEdge(edge *CFGEdge) {
	src := edge.From
	dst := edge.To

	// Create synthetic block
	synth := &CFGNode{
		ID:           b.nextNodeID,
		Type:         NodeTypeSynthetic,
		IsSynthetic:  true,
		StartIdx:     src.EndIdx,
		EndIdx:       src.EndIdx,
		LineStart:    src.LineEnd,
		LineEnd:      src.LineEnd,
		Instructions: make([]InstructionRef, 0),
		Successors:   make([]*CFGNode, 0, 1),
		Predecessors: make([]*CFGNode, 0, 1),
	}
	b.nextNodeID++

	// Rewire: src → synth → dst
	// Remove dst from src.Successors
	removeSuccessor(src, dst)
	removePredecessor(dst, src)

	// src → synth
	src.Successors = append(src.Successors, synth)
	synth.Predecessors = append(synth.Predecessors, src)

	// synth → dst
	synth.Successors = append(synth.Successors, dst)
	dst.Predecessors = append(dst.Predecessors, synth)

	// Update edge
	edge.To = synth
	edge.IsCriticalSplit = true

	// New edge synth → dst
	newEdge := &CFGEdge{
		From:  synth,
		To:    dst,
		Type:  EdgeFallthrough,
		Label: fmt.Sprintf("split_%d", synth.ID),
	}
	b.cfg.Edges = append(b.cfg.Edges, newEdge)
	b.cfg.Nodes = append(b.cfg.Nodes, synth)
}

func removeSuccessor(node, target *CFGNode) {
	for i, s := range node.Successors {
		if s == target {
			node.Successors = append(node.Successors[:i], node.Successors[i+1:]...)
			return
		}
	}
}

func removePredecessor(node, target *CFGNode) {
	for i, p := range node.Predecessors {
		if p == target {
			node.Predecessors = append(node.Predecessors[:i], node.Predecessors[i+1:]...)
			return
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// PHASE 9: COMPUTE REVERSE POST-ORDER
// ═══════════════════════════════════════════════════════════════════════════════
//
// RPO is essential for efficient dataflow analysis. Nodes are numbered such that
// every predecessor (except back-edges) has a lower RPO number.
// ═══════════════════════════════════════════════════════════════════════════════

func (b *CFGBuilder) computeRPO() {
	if b.cfg.Entry == nil {
		return
	}

	visited := make(map[int]bool, len(b.cfg.Nodes))
	order := make([]*CFGNode, 0, len(b.cfg.Nodes))

	// Iterative post-order DFS (no recursion → no stack overflow)
	type frame struct {
		node *CFGNode
		idx  int // current successor index
	}

	stack := []frame{{node: b.cfg.Entry}}
	visited[b.cfg.Entry.ID] = true

	for len(stack) > 0 {
		top := &stack[len(stack)-1]

		if top.idx < len(top.node.Successors) {
			succ := top.node.Successors[top.idx]
			top.idx++

			if !visited[succ.ID] {
				visited[succ.ID] = true
				stack = append(stack, frame{node: succ})
			}
		} else {
			order = append(order, top.node)
			stack = stack[:len(stack)-1]
		}
	}

	// Reverse for RPO
	for i, j := 0, len(order)-1; i < j; i, j = i+1, j-1 {
		order[i], order[j] = order[j], order[i]
	}

	// Assign RPO numbers
	b.cfg.RPOOrder = order
	for i, node := range order {
		node.RPONumber = i
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// PHASE 10: FINALIZE
// ═══════════════════════════════════════════════════════════════════════════════

func (b *CFGBuilder) finalize() {
	// Set entry
	if len(b.cfg.Nodes) > 0 {
		b.cfg.Entry = b.cfg.Nodes[0]
		if b.cfg.Entry.Type == NodeTypeBasic {
			b.cfg.Entry.Type = NodeTypeEntry
		}
	}

	// Collect exits by kind
	for _, node := range b.cfg.Nodes {
		switch node.Type {
		case NodeTypeReturn:
			b.cfg.Exits = append(b.cfg.Exits, node)
			b.cfg.ReturnExits = append(b.cfg.ReturnExits, node)
		case NodeTypeThrow:
			b.cfg.Exits = append(b.cfg.Exits, node)
			b.cfg.ThrowExits = append(b.cfg.ThrowExits, node)
		case NodeTypeExit:
			b.cfg.Exits = append(b.cfg.Exits, node)
		}
	}

	// Sync nodeByIdx map
	b.cfg.NodeByIdx = b.nodeByIdx
}

// computeBlockMetrics gathers per-block statistics
func (b *CFGBuilder) computeBlockMetrics() {
	totalSize := 0
	for _, node := range b.cfg.Nodes {
		size := len(node.Instructions)
		totalSize += size
		if size > b.stats.MaxBlockSize {
			b.stats.MaxBlockSize = size
		}

		// Classify instructions within block
		for _, ref := range node.Instructions {
			if isInvokeOpcode(ref.Opcode) {
				node.HasInvoke = true
			}
			if isFieldOpcode(ref.Opcode) {
				node.HasFieldAccess = true
			}
		}
	}

	if len(b.cfg.Nodes) > 0 {
		b.stats.AvgBlockSize = float64(totalSize) / float64(len(b.cfg.Nodes))
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPER: BUILD FROM SMALI METHOD
// ═══════════════════════════════════════════════════════════════════════════════

type SmaliMethod struct {
	Name         string
	ClassName    string
	Signature    string
	Instructions []SmaliInstruction
	Labels       []SmaliLabel
	TryBlocks    []TryBlock
}

type SmaliInstruction struct {
	Line     int
	Opcode   string
	Operands []string
	Raw      string
}

type SmaliLabel struct {
	Name string
	Line int
}

func ConvertFromSmaliMethod(method *SmaliMethod) BuildInput {
	instructions := make([]Instruction, len(method.Instructions))
	for i, instr := range method.Instructions {
		instructions[i] = Instruction{
			Index:    i,
			Line:     instr.Line,
			Opcode:   instr.Opcode,
			Operands: instr.Operands,
			Raw:      instr.Raw,
		}
	}

	labels := make([]Label, len(method.Labels))
	for i, label := range method.Labels {
		labels[i] = Label{
			Name: label.Name,
			Line: label.Line,
		}
	}

	return BuildInput{
		MethodName:   method.Name,
		ClassName:    method.ClassName,
		Signature:    method.Signature,
		Instructions: instructions,
		Labels:       labels,
		TryBlocks:    method.TryBlocks,
	}
}

// buildFullName renders a human-readable method identity for reports.
//
// Signature here is the caller-supplied descriptor tail (parameters followed
// by return type); it is appended verbatim rather than re-wrapped in parens,
// because callers pass it in more than one shape and inventing a smali
// descriptor from a partial one would produce something that looks canonical
// but is not.
func buildFullName(className, methodName, signature string) string {
	if className == "" && methodName == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(className) + len(methodName) + len(signature) + 2)
	b.WriteString(className)
	if className != "" && methodName != "" {
		b.WriteString("->")
	}
	b.WriteString(methodName)
	b.WriteString(signature)
	return b.String()
}

// BuildInputFromLines retains executable instructions, typed payloads and
// exception ranges. Labels bind to instruction positions, not adjacent source
// lines, so comments, debug directives and consecutive labels are harmless.
func BuildInputFromLines(className, methodName, signature string, lines []string) BuildInput {
	return buildSmaliInput(className, methodName, signature, lines)
}

// parseSmaliOpcode извлекает opcode и operands из строки smali инструкции
func parseSmaliOpcode(line string) (string, []string) {
	line = stripSmaliComment(line)
	space := strings.IndexAny(line, " \t\r\n")
	if space < 0 {
		return line, nil
	}
	opcode, rest := line[:space], strings.TrimSpace(line[space+1:])
	if strings.HasPrefix(opcode, "invoke-") || strings.HasPrefix(opcode, "filled-new-array") {
		if strings.HasPrefix(rest, "{") {
			if end := strings.IndexByte(rest, '}'); end >= 0 {
				operands := smaliRegisterList(rest[1:end])
				tail := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(rest[end+1:]), ","))
				return opcode, append(operands, splitSmaliOperands(tail)...)
			}
		}
	}
	return opcode, splitSmaliOperands(rest)
}

func hasSuccessor(node, target *CFGNode) bool {
	if node == nil || target == nil {
		return false
	}
	for _, succ := range node.Successors {
		if succ == target {
			return true
		}
	}
	return false
}

func parseSmaliInt(s string) (int, error) {
	s = strings.TrimSpace(s)
	neg := false
	if strings.HasPrefix(s, "-") {
		neg = true
		s = s[1:]
	}
	var v int64
	var err error
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		v, err = strconv.ParseInt(s[2:], 16, 64)
	} else {
		v, err = strconv.ParseInt(s, 10, 64)
	}
	if neg {
		v = -v
	}
	return int(v), err
}
