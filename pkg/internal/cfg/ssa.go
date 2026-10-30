package cfg

import (
	"fmt"

	"mega-analyzer/pkg/internal/dexir"
)

// ═══════════════════════════════════════════════════════════════════════════════
// SSA - Static Single Assignment Form
// ═══════════════════════════════════════════════════════════════════════════════

type PhiNode struct {
	Register string                 // original register (v0)
	Version  int                    // SSA version
	Operands map[*CFGNode]*ValueRef // predecessor → value
	Result   *ValueRef              // resulting SSA value

	Node *CFGNode // where this phi is
}

func (p *PhiNode) String() string {
	return fmt.Sprintf("%s_%d = φ(...)", p.Register, p.Version)
}

// ═══════════════════════════════════════════════════════════════════════════════
// SSA BUILDER
// ═══════════════════════════════════════════════════════════════════════════════

type SSABuilder struct {
	cfg *ControlFlowGraph

	// Версионирование
	currentVersion map[string]int        // register → current version
	versionStack   map[string][]int      // register → stack of versions
	definitions    map[string][]*CFGNode // register → nodes that define it

	// Phi nodes
	phiPlaced map[*CFGNode]map[string]bool // node → registers with phi
}

func NewSSABuilder(cfg *ControlFlowGraph) *SSABuilder {
	return &SSABuilder{
		cfg:            cfg,
		currentVersion: make(map[string]int),
		versionStack:   make(map[string][]int),
		definitions:    make(map[string][]*CFGNode),
		phiPlaced:      make(map[*CFGNode]map[string]bool),
	}
}

// BuildSSA строит SSA форму
func (b *SSABuilder) BuildSSA() {
	if b.cfg == nil || !b.cfg.DominatorTree {
		return
	}

	// 1. Найти все определения
	b.findDefinitions()

	// 2. Вставить phi-nodes используя Dominance Frontier
	b.insertPhiNodes()

	// 3. Переименовать переменные
	b.renameVariables(b.cfg.Entry)

	b.cfg.SSAConstructed = true
}

// ═══════════════════════════════════════════════════════════════════════════════
// STEP 1: FIND DEFINITIONS
// ═══════════════════════════════════════════════════════════════════════════════

func (b *SSABuilder) findDefinitions() {
	for _, node := range b.cfg.Nodes {
		node.Definitions = make(map[string]*ValueRef)

		for _, instr := range node.Instructions {
			// Ищем определения регистров
			defs := b.extractDefinitions(instr)
			for _, reg := range defs {
				b.definitions[reg] = append(b.definitions[reg], node)

				// Создаём ValueRef для определения
				node.Definitions[reg] = &ValueRef{
					Kind:         b.inferValueKind(instr),
					Register:     reg,
					DefinedAt:    node,
					DefinedInstr: instr.Index,
				}
			}
		}
	}
}

// extractDefinitions returns the registers defined by an instruction,
// read from the typed IR destination operand. The opcode gate mirrors
// the historical definition classes (const/move/move-result/gets/
// agets/new-*); arithmetic and other writers are intentionally not
// SSA-tracked to preserve phi placement.
func (b *SSABuilder) extractDefinitions(instr InstructionRef) []string {
	ir := b.irOf(instr)
	if ir == nil || ir.Dst == dexir.NoRegister {
		return nil
	}

	switch {
	case isConstOp(ir.Op),
		isMoveOp(ir.Op),
		ir.Op == dexir.OpMoveResult || ir.Op == dexir.OpMoveResultWide || ir.Op == dexir.OpMoveResultObject,
		isFieldGetOp(ir.Op),
		isArrayGetOp(ir.Op),
		ir.Op == dexir.OpNewInstance || ir.Op == dexir.OpNewArray:
		if reg := registerName(ir.Dst); reg != "" {
			return []string{reg}
		}
	}

	return nil
}

func (b *SSABuilder) irOf(instr InstructionRef) *dexir.Instruction {
	if b.cfg == nil || b.cfg.Method == nil {
		return nil
	}
	if instr.Index < 0 || instr.Index >= len(b.cfg.Method.Instructions) {
		return nil
	}
	mi := b.cfg.Method.Instructions[instr.Index]
	if mi == nil {
		return nil
	}
	return mi.IR
}

// isConstOp reports const-* opcodes (including const-string/class).
func isConstOp(op dexir.Opcode) bool {
	return (op >= dexir.OpConst4 && op <= dexir.OpConstClass)
}

// isMoveOp reports the move family (excluding move-result/move-exception).
func isMoveOp(op dexir.Opcode) bool {
	return op >= dexir.OpMove && op <= dexir.OpMoveObject16
}

// isFieldGetOp reports iget*/sget* opcodes.
func isFieldGetOp(op dexir.Opcode) bool {
	return (op >= dexir.OpIget && op <= dexir.OpIget+6) ||
		(op >= dexir.OpSget && op <= dexir.OpSget+6)
}

// isArrayGetOp reports aget* opcodes.
func isArrayGetOp(op dexir.Opcode) bool {
	return op >= dexir.OpAget && op <= dexir.OpAget+6
}

func (b *SSABuilder) inferValueKind(instr InstructionRef) ValueKind {
	ir := b.irOf(instr)
	if ir == nil {
		return ValueRegister
	}
	switch {
	case isConstOp(ir.Op):
		return ValueConst
	case isFieldGetOp(ir.Op):
		return ValueField
	case ir.Op == dexir.OpMoveResult || ir.Op == dexir.OpMoveResultObject:
		return ValueInvoke
	default:
		return ValueRegister
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// STEP 2: INSERT PHI NODES (using Dominance Frontier)
// ═══════════════════════════════════════════════════════════════════════════════

func (b *SSABuilder) insertPhiNodes() {
	for reg, defNodes := range b.definitions {
		// Worklist algorithm
		worklist := make([]*CFGNode, len(defNodes))
		copy(worklist, defNodes)

		inWorklist := make(map[int]bool)
		for _, node := range defNodes {
			inWorklist[node.ID] = true
		}

		for len(worklist) > 0 {
			node := worklist[0]
			worklist = worklist[1:]

			// Для каждого node в DF
			for _, dfNode := range node.DominanceFrontier {
				// Вставить phi если ещё нет
				if !b.hasPhiFor(dfNode, reg) {
					b.insertPhi(dfNode, reg)

					// Добавить в worklist
					if !inWorklist[dfNode.ID] {
						worklist = append(worklist, dfNode)
						inWorklist[dfNode.ID] = true
					}
				}
			}
		}
	}
}

func (b *SSABuilder) hasPhiFor(node *CFGNode, reg string) bool {
	if b.phiPlaced[node] == nil {
		return false
	}
	return b.phiPlaced[node][reg]
}

func (b *SSABuilder) insertPhi(node *CFGNode, reg string) {
	phi := &PhiNode{
		Register: reg,
		Operands: make(map[*CFGNode]*ValueRef),
		Node:     node,
	}

	node.PhiNodes = append(node.PhiNodes, phi)

	if b.phiPlaced[node] == nil {
		b.phiPlaced[node] = make(map[string]bool)
	}
	b.phiPlaced[node][reg] = true
}

// ═══════════════════════════════════════════════════════════════════════════════
// STEP 3: RENAME VARIABLES
// ═══════════════════════════════════════════════════════════════════════════════

func (b *SSABuilder) renameVariables(node *CFGNode) {
	if node == nil {
		return
	}

	// Сохраняем состояние стека для отката
	savedStacks := make(map[string]int)
	for reg := range b.versionStack {
		if len(b.versionStack[reg]) > 0 {
			savedStacks[reg] = len(b.versionStack[reg])
		}
	}

	// 1. Rename phi node results
	for _, phi := range node.PhiNodes {
		version := b.newVersion(phi.Register)
		phi.Version = version
		phi.Result = &ValueRef{
			Kind:       ValuePhi,
			Register:   phi.Register,
			SSAVersion: version,
			DefinedAt:  node,
		}
	}

	// 2. Rename uses and definitions in instructions
	for _, instr := range node.Instructions {
		// Rename uses. Typed IR exposes the full source set; the reads
		// are observed but do not consume versions, matching the
		// historical rename semantics (uses were never extracted).
		uses := b.extractUses(instr)
		for _, reg := range uses {
			currentVer := b.getCurrentVersion(reg)
			// Update ValueRef in node.Definitions or wherever used
			_ = currentVer // Use for renaming
		}

		// Rename definitions
		defs := b.extractDefinitions(instr)
		for _, reg := range defs {
			version := b.newVersion(reg)
			if node.Definitions[reg] != nil {
				node.Definitions[reg].SSAVersion = version
			}
		}
	}

	// 3. Fill phi operands in successors
	for _, succ := range node.Successors {
		for _, phi := range succ.PhiNodes {
			currentVer := b.getCurrentVersion(phi.Register)
			phi.Operands[node] = &ValueRef{
				Kind:       ValueRegister,
				Register:   phi.Register,
				SSAVersion: currentVer,
			}
		}
	}

	// 4. Recurse in dominator tree order
	for _, child := range node.DomTreeChildren {
		b.renameVariables(child)
	}

	// 5. Pop stacks
	for reg, savedLen := range savedStacks {
		if len(b.versionStack[reg]) > savedLen {
			b.versionStack[reg] = b.versionStack[reg][:savedLen]
		}
	}
}

func (b *SSABuilder) newVersion(reg string) int {
	b.currentVersion[reg]++
	version := b.currentVersion[reg]
	b.versionStack[reg] = append(b.versionStack[reg], version)
	return version
}

func (b *SSABuilder) getCurrentVersion(reg string) int {
	if len(b.versionStack[reg]) == 0 {
		return 0
	}
	return b.versionStack[reg][len(b.versionStack[reg])-1]
}

// extractUses returns the registers read by an instruction, straight
// from the typed IR source operands.
func (b *SSABuilder) extractUses(instr InstructionRef) []string {
	ir := b.irOf(instr)
	if ir == nil {
		return nil
	}
	uses := make([]string, 0, len(ir.Srcs))
	for _, r := range ir.Srcs {
		if reg := registerName(r); reg != "" {
			uses = append(uses, reg)
		}
	}
	return uses
}

// ═══════════════════════════════════════════════════════════════════════════════
// SSA QUERIES
// ═══════════════════════════════════════════════════════════════════════════════

// GetReachingDefinition returns the SSA value that reaches this point
func (b *SSABuilder) GetReachingDefinition(node *CFGNode, reg string) *ValueRef {
	// Check phi nodes first
	for _, phi := range node.PhiNodes {
		if phi.Register == reg {
			return phi.Result
		}
	}

	// Check local definitions
	if def, ok := node.Definitions[reg]; ok {
		return def
	}

	// Check dominator
	if node.ImmediateDom != nil {
		return b.GetReachingDefinition(node.ImmediateDom, reg)
	}

	return nil
}

// TraceValue traces a value back to its origin
func (b *SSABuilder) TraceValue(value *ValueRef, maxDepth int) []*ValueRef {
	if value == nil || maxDepth <= 0 {
		return nil
	}

	chain := []*ValueRef{value}

	if value.Kind == ValuePhi {
		// Phi - trace all operands
		node := value.DefinedAt
		for _, phi := range node.PhiNodes {
			if phi.Result == value {
				for _, operand := range phi.Operands {
					sub := b.TraceValue(operand, maxDepth-1)
					chain = append(chain, sub...)
				}
				break
			}
		}
	} else if value.DefinedAt != nil {
		// Non-phi - trace source
		// ... depends on instruction type
	}

	return chain
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
