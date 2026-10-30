package apkloader

import (
	"fmt"
	"sort"
)

// ═══════════════════════════════════════════════════════════════════════════════
// LIMITED SYMBOLIC EXECUTION
// ═══════════════════════════════════════════════════════════════════════════════
//
// Performs intra-procedural symbolic execution with bounded depth.
// Tracks symbolic values through execution paths and explores multiple paths
// with pruning to avoid exponential explosion.
//
// Key features:
// - Intra-procedural analysis (single method only)
// - Execution depth limiting (max 10 steps per path)
// - State management for symbolic values
// - Path exploration with pruning
// - Limited constraint solving
// - Fallback to concrete execution

// SymbolicValue represents a value that may be symbolic or concrete.
type SymbolicValue struct {
	IsSymbolic bool        // true if symbolic, false if concrete
	Concrete   interface{} // concrete value (int64, string, bool, etc.)
	Symbolic   string      // symbolic expression (e.g., "v1 + 5", "v2 & 0xFF")
	Confidence int         // 0-100, confidence in this value
	Source     string      // where this value came from
}

// ExecutionState represents the state of symbolic execution at a point.
type ExecutionState struct {
	BlockID           int                       // current basic block ID
	InsnIndex         int                       // current instruction index within block
	Registers         map[int16]*SymbolicValue  // register values
	Memory            map[string]*SymbolicValue // field/array values
	Constraints       []Constraint              // accumulated constraints
	Depth             int                       // execution depth (number of steps)
	PathID            int                       // unique path identifier
	IsTerminated      bool                      // true if path has terminated
	TerminationReason string                    // why path terminated
}

// Constraint represents a constraint on symbolic values.
type Constraint struct {
	Type       string // "eq", "ne", "lt", "le", "gt", "ge", "range"
	Variable   string // symbolic variable name
	Value      interface{}
	Confidence int
}

// ExecutionPath represents a single execution path through the method.
type ExecutionPath struct {
	State        *ExecutionState
	Instructions []MIRInsn        // instructions executed on this path
	Branches     []BranchDecision // branch decisions made
}

// BranchDecision represents a decision made at a branch point.
type BranchDecision struct {
	InsnIndex int    // index of branch instruction
	Condition string // condition expression
	Taken     bool   // which branch was taken
	Reason    string // why this branch was taken
}

// SymbolicExecutionResult contains the results of symbolic execution.
type SymbolicExecutionResult struct {
	Paths               []*ExecutionPath
	SymbolicValues      map[int16]*SymbolicValue // final symbolic values for registers
	ConstraintsSolved   []Constraint
	ConstraintsUnsolved []Constraint
	ExecutionDepth      int
	PathCount           int
	PrunedPaths         int
	FallbackUsed        bool
	Trace               []string
}

// SymbolicExecutor performs symbolic execution on a method.
type SymbolicExecutor struct {
	cfg           *CFG
	ssa           *SSAForm
	maxDepth      int // maximum execution depth per path
	maxPaths      int // maximum number of paths to explore
	currentPathID int
	paths         []*ExecutionPath
	trace         []string
	prunedPaths   int
	fallbackUsed  bool
}

// NewSymbolicExecutor creates a new symbolic executor.
func NewSymbolicExecutor(cfg *CFG, ssa *SSAForm) *SymbolicExecutor {
	return &SymbolicExecutor{
		cfg:           cfg,
		ssa:           ssa,
		maxDepth:      10,  // limit execution depth to 10 steps
		maxPaths:      100, // limit to 100 paths
		currentPathID: 0,
		paths:         make([]*ExecutionPath, 0),
		trace:         make([]string, 0),
		prunedPaths:   0,
		fallbackUsed:  false,
	}
}

// Execute performs symbolic execution on the method.
func (se *SymbolicExecutor) Execute() *SymbolicExecutionResult {
	se.trace = append(se.trace, "Starting symbolic execution")

	// Initialize entry state
	initialState := &ExecutionState{
		BlockID:      se.cfg.Entry.ID,
		InsnIndex:    0,
		Registers:    make(map[int16]*SymbolicValue),
		Memory:       make(map[string]*SymbolicValue),
		Constraints:  make([]Constraint, 0),
		Depth:        0,
		PathID:       se.currentPathID,
		IsTerminated: false,
	}
	se.currentPathID++

	// Initialize registers with symbolic values
	se.initializeSymbolicRegisters(initialState)

	// Explore paths starting from entry
	se.explorePath(initialState)

	se.trace = append(se.trace, fmt.Sprintf("Symbolic execution complete: %d paths explored, %d pruned", len(se.paths), se.prunedPaths))

	// Collect results
	result := se.collectResults()
	return result
}

// initializeSymbolicRegisters initializes all registers with symbolic values.
func (se *SymbolicExecutor) initializeSymbolicRegisters(state *ExecutionState) {
	// Initialize all registers as symbolic
	for i := int16(0); i < int16(se.ssa.OriginalRegCount); i++ {
		state.Registers[i] = &SymbolicValue{
			IsSymbolic: true,
			Symbolic:   fmt.Sprintf("v%d", i),
			Confidence: 50,
			Source:     "parameter",
		}
	}
	se.trace = append(se.trace, fmt.Sprintf("Initialized %d symbolic registers", se.ssa.OriginalRegCount))
}

// explorePath explores a single execution path.
func (se *SymbolicExecutor) explorePath(state *ExecutionState) {
	// Check depth limit
	if state.Depth >= se.maxDepth {
		se.trace = append(se.trace, fmt.Sprintf("Path %d: depth limit reached (%d)", state.PathID, state.Depth))
		se.prunedPaths++
		return
	}

	// Check path count limit
	if len(se.paths) >= se.maxPaths {
		se.trace = append(se.trace, fmt.Sprintf("Path %d: path count limit reached", state.PathID))
		se.prunedPaths++
		return
	}

	// Get current block
	block := se.getBlockByID(state.BlockID)
	if block == nil || se.cfg == nil {
		state.IsTerminated = true
		state.TerminationReason = "block not found"
		se.paths = append(se.paths, &ExecutionPath{
			State:        state,
			Instructions: make([]MIRInsn, 0),
			Branches:     make([]BranchDecision, 0),
		})
		return
	}

	// Execute instructions in block
	path := &ExecutionPath{
		State:        state,
		Instructions: make([]MIRInsn, 0),
		Branches:     make([]BranchDecision, 0),
	}

	for i := 0; i < len(block.Insns); i++ {
		insn := block.Insns[i]
		path.Instructions = append(path.Instructions, insn)

		// Execute instruction
		se.executeInstruction(state, &insn)
		state.Depth++

		// Check if instruction is a branch
		if se.isBranchInstruction(&insn) {
			// Evaluate branch condition
			taken, reason := se.evaluateBranch(state, &insn)

			decision := BranchDecision{
				InsnIndex: i,
				Condition: se.getBranchCondition(&insn),
				Taken:     taken,
				Reason:    reason,
			}
			path.Branches = append(path.Branches, decision)

			// Explore both branches if condition is symbolic
			if se.isSymbolicCondition(state, &insn) {
				// Create two new states for both branches
				trueBranch := se.cloneState(state)
				falseBranch := se.cloneState(state)

				// Set next block for true branch
				if taken && len(block.Succs) > 0 {
					trueBranch.BlockID = block.Succs[0].ID
				}

				// Set next block for false branch
				if !taken && len(block.Succs) > 1 {
					falseBranch.BlockID = block.Succs[1].ID
				} else if !taken && len(block.Succs) > 0 {
					falseBranch.BlockID = block.Succs[0].ID
				}

				trueBranch.PathID = se.currentPathID
				se.currentPathID++
				falseBranch.PathID = se.currentPathID
				se.currentPathID++

				se.trace = append(se.trace, fmt.Sprintf("Path %d: branching at instruction %d", state.PathID, i))

				// Recursively explore both branches
				se.explorePath(trueBranch)
				se.explorePath(falseBranch)

				return // Don't continue on current path
			}

			// If condition is concrete, continue on taken branch
			if len(block.Succs) > 0 {
				state.BlockID = block.Succs[0].ID
				se.explorePath(state)
				return
			}
		}
	}

	// If we reach here, block execution completed
	// Move to next block (fallthrough)
	if len(block.Succs) > 0 {
		state.BlockID = block.Succs[0].ID
		se.explorePath(state)
	} else {
		// No successors - path terminated
		state.IsTerminated = true
		state.TerminationReason = "no successors"
		se.paths = append(se.paths, path)
	}
}

// executeInstruction executes a single instruction symbolically.
func (se *SymbolicExecutor) executeInstruction(state *ExecutionState, insn *MIRInsn) {
	switch insn.Kind {
	case MIR_CONST:
		// Constant assignment
		state.Registers[insn.Dst] = &SymbolicValue{
			IsSymbolic: false,
			Concrete:   insn.Imm,
			Confidence: 100,
			Source:     "literal",
		}
		se.trace = append(se.trace, fmt.Sprintf("Path %d: v%d = %d (const)", state.PathID, insn.Dst, insn.Imm))

	case MIR_MOVE:
		// Register move
		if src, ok := state.Registers[insn.Src1]; ok {
			state.Registers[insn.Dst] = &SymbolicValue{
				IsSymbolic: src.IsSymbolic,
				Concrete:   src.Concrete,
				Symbolic:   src.Symbolic,
				Confidence: src.Confidence,
				Source:     "move",
			}
			se.trace = append(se.trace, fmt.Sprintf("Path %d: v%d = v%d", state.PathID, insn.Dst, insn.Src1))
		}

	case MIR_ADD, MIR_SUB, MIR_RSUB, MIR_MUL, MIR_DIV, MIR_REM:
		// Arithmetic operations
		se.executeArithmetic(state, insn)

	case MIR_AND, MIR_OR, MIR_XOR:
		// Logical operations
		se.executeLogical(state, insn)

	case MIR_NOT, MIR_NEG:
		// Logical NOT / Arithmetic NEG
		if src, ok := state.Registers[insn.Src1]; ok {
			if !src.IsSymbolic {
				if v, ok := src.Concrete.(int64); ok {
					var res int64
					if insn.Kind == MIR_NOT {
						res = ^v
					} else {
						res = -v
					}
					state.Registers[insn.Dst] = &SymbolicValue{
						IsSymbolic: false,
						Concrete:   res,
						Confidence: 100,
						Source:     "unary",
					}
				}
			} else {
				op := "~"
				if insn.Kind == MIR_NEG {
					op = "-"
				}
				state.Registers[insn.Dst] = &SymbolicValue{
					IsSymbolic: true,
					Symbolic:   fmt.Sprintf("%s(%s)", op, src.Symbolic),
					Confidence: src.Confidence,
					Source:     "unary",
				}
			}
		}

	case MIR_ARRAY_PUT:
		// Array write: Src1 = array, Src2 = index, Src3 = value
		valReg := insn.Src3
		if valReg < 0 {
			valReg = insn.Src1
		}
		arrKey := fmt.Sprintf("array_%d_%d", insn.Src1, insn.Src2)
		if val, ok := state.Registers[valReg]; ok {
			state.Memory[arrKey] = val
		}

	case MIR_FIELD_GET:
		// Field read
		fieldKey := fmt.Sprintf("field_%d", insn.RefIdx)
		if val, ok := state.Memory[fieldKey]; ok {
			state.Registers[insn.Dst] = val
		} else {
			// Unknown field - create symbolic value
			state.Registers[insn.Dst] = &SymbolicValue{
				IsSymbolic: true,
				Symbolic:   fmt.Sprintf("field_%d", insn.RefIdx),
				Confidence: 30,
				Source:     "field_read",
			}
		}

	case MIR_FIELD_PUT:
		// Field write
		fieldKey := fmt.Sprintf("field_%d", insn.RefIdx)
		if val, ok := state.Registers[insn.Src1]; ok {
			state.Memory[fieldKey] = val
		}

	case MIR_IF:
		// Branch instruction - handled separately
		break

	default:
		// Unknown instruction - mark as symbolic
		if insn.Dst >= 0 {
			state.Registers[insn.Dst] = &SymbolicValue{
				IsSymbolic: true,
				Symbolic:   fmt.Sprintf("unknown_%d", insn.Kind),
				Confidence: 20,
				Source:     "unknown",
			}
		}
	}
}

// executeArithmetic executes arithmetic operations.
func (se *SymbolicExecutor) executeArithmetic(state *ExecutionState, insn *MIRInsn) {
	src1, ok1 := state.Registers[insn.Src1]
	src2, ok2 := state.Registers[insn.Src2]

	if !ok1 || !ok2 {
		return
	}

	// If both are concrete, compute concrete result
	if !src1.IsSymbolic && !src2.IsSymbolic {
		v1, isInt1 := src1.Concrete.(int64)
		v2, isInt2 := src2.Concrete.(int64)

		if isInt1 && isInt2 {
			var result int64
			switch insn.Kind {
			case MIR_ADD:
				result = v1 + v2
			case MIR_SUB:
				result = v1 - v2
			case MIR_RSUB:
				result = v2 - v1
			case MIR_MUL:
				result = v1 * v2
			case MIR_DIV:
				if v2 != 0 {
					result = v1 / v2
				} else {
					return // Division by zero
				}
			case MIR_REM:
				if v2 != 0 {
					result = v1 % v2
				} else {
					return // Division by zero
				}
			}

			state.Registers[insn.Dst] = &SymbolicValue{
				IsSymbolic: false,
				Concrete:   result,
				Confidence: 100,
				Source:     "arithmetic",
			}
			se.trace = append(se.trace, fmt.Sprintf("Path %d: v%d = %d (arithmetic)", state.PathID, insn.Dst, result))
			return
		}
	}

	// Otherwise, create symbolic expression
	opName := se.getOpName(insn.Kind)
	state.Registers[insn.Dst] = &SymbolicValue{
		IsSymbolic: true,
		Symbolic:   fmt.Sprintf("(%s %s %s)", src1.Symbolic, opName, src2.Symbolic),
		Confidence: (src1.Confidence + src2.Confidence) / 2,
		Source:     "arithmetic",
	}
}

// executeLogical executes logical operations.
func (se *SymbolicExecutor) executeLogical(state *ExecutionState, insn *MIRInsn) {
	src1, ok1 := state.Registers[insn.Src1]
	src2, ok2 := state.Registers[insn.Src2]

	if !ok1 || !ok2 {
		return
	}

	// If both are concrete, compute concrete result
	if !src1.IsSymbolic && !src2.IsSymbolic {
		v1, isInt1 := src1.Concrete.(int64)
		v2, isInt2 := src2.Concrete.(int64)

		if isInt1 && isInt2 {
			var result int64
			switch insn.Kind {
			case MIR_AND:
				result = v1 & v2
			case MIR_OR:
				result = v1 | v2
			case MIR_XOR:
				result = v1 ^ v2
			}

			state.Registers[insn.Dst] = &SymbolicValue{
				IsSymbolic: false,
				Concrete:   result,
				Confidence: 100,
				Source:     "logical",
			}
			return
		}
	}

	// Otherwise, create symbolic expression
	opName := se.getOpName(insn.Kind)
	state.Registers[insn.Dst] = &SymbolicValue{
		IsSymbolic: true,
		Symbolic:   fmt.Sprintf("(%s %s %s)", src1.Symbolic, opName, src2.Symbolic),
		Confidence: (src1.Confidence + src2.Confidence) / 2,
		Source:     "logical",
	}
}

// isBranchInstruction checks if an instruction is a branch.
func (se *SymbolicExecutor) isBranchInstruction(insn *MIRInsn) bool {
	return insn.Kind == MIR_IF
}

// evaluateBranch evaluates a branch condition.
func (se *SymbolicExecutor) evaluateBranch(state *ExecutionState, insn *MIRInsn) (bool, string) {
	src, ok := state.Registers[insn.Src1]
	if !ok {
		return true, "register not found"
	}

	// If concrete, evaluate directly
	if !src.IsSymbolic {
		if v, ok := src.Concrete.(int64); ok {
			taken := v != 0
			return taken, fmt.Sprintf("concrete: %d != 0 = %v", v, taken)
		}
	}

	// If symbolic, we can't determine - assume both branches possible
	return true, "symbolic condition"
}

// isSymbolicCondition checks if a branch condition is symbolic.
func (se *SymbolicExecutor) isSymbolicCondition(state *ExecutionState, insn *MIRInsn) bool {
	src, ok := state.Registers[insn.Src1]
	if !ok {
		return true
	}
	return src.IsSymbolic
}

// getBranchCondition returns the branch condition as a string.
func (se *SymbolicExecutor) getBranchCondition(insn *MIRInsn) string {
	switch insn.Cond {
	case CondEQ:
		return "== 0"
	case CondNE:
		return "!= 0"
	case CondLT:
		return "< 0"
	case CondLE:
		return "<= 0"
	case CondGT:
		return "> 0"
	case CondGE:
		return ">= 0"
	case CondEQZ:
		return "== 0"
	case CondNEZ:
		return "!= 0"
	case CondLTZ:
		return "< 0"
	case CondLEZ:
		return "<= 0"
	case CondGTZ:
		return "> 0"
	case CondGEZ:
		return ">= 0"
	default:
		return "unknown"
	}
}

// getOpName returns the name of an operation.
func (se *SymbolicExecutor) getOpName(kind MIROpKind) string {
	switch kind {
	case MIR_ADD:
		return "+"
	case MIR_SUB:
		return "-"
	case MIR_MUL:
		return "*"
	case MIR_DIV:
		return "/"
	case MIR_REM:
		return "%"
	case MIR_AND:
		return "&"
	case MIR_OR:
		return "|"
	case MIR_XOR:
		return "^"
	case MIR_NOT:
		return "~"
	default:
		return "?"
	}
}

// cloneState creates a deep copy of an execution state.
func (se *SymbolicExecutor) cloneState(state *ExecutionState) *ExecutionState {
	newState := &ExecutionState{
		BlockID:           state.BlockID,
		InsnIndex:         state.InsnIndex,
		Registers:         make(map[int16]*SymbolicValue),
		Memory:            make(map[string]*SymbolicValue),
		Constraints:       make([]Constraint, len(state.Constraints)),
		Depth:             state.Depth,
		PathID:            state.PathID,
		IsTerminated:      state.IsTerminated,
		TerminationReason: state.TerminationReason,
	}

	// Copy registers
	for reg, val := range state.Registers {
		newVal := *val
		newState.Registers[reg] = &newVal
	}

	// Copy memory
	for key, val := range state.Memory {
		newVal := *val
		newState.Memory[key] = &newVal
	}

	// Copy constraints
	copy(newState.Constraints, state.Constraints)

	return newState
}

// getBlockByID returns a block by its ID.
func (se *SymbolicExecutor) getBlockByID(id int) *BasicBlock {
	if se.cfg == nil || se.cfg.Blocks == nil {
		return nil
	}
	for _, block := range se.cfg.Blocks {
		if block.ID == id {
			return block
		}
	}
	return nil
}

// collectResults collects the results of symbolic execution.
func (se *SymbolicExecutor) collectResults() *SymbolicExecutionResult {
	// Collect final symbolic values from all paths
	finalValues := make(map[int16]*SymbolicValue)

	for _, path := range se.paths {
		for reg, val := range path.State.Registers {
			if _, ok := finalValues[reg]; !ok {
				finalValues[reg] = val
			}
		}
	}

	// Collect constraints
	solvedConstraints := make([]Constraint, 0)
	unsolvedConstraints := make([]Constraint, 0)

	for _, path := range se.paths {
		for _, constraint := range path.State.Constraints {
			// Try to solve constraint
			if se.canSolveConstraint(&constraint) {
				solvedConstraints = append(solvedConstraints, constraint)
			} else {
				unsolvedConstraints = append(unsolvedConstraints, constraint)
			}
		}
	}

	// Find maximum execution depth
	maxDepth := 0
	for _, path := range se.paths {
		if path.State.Depth > maxDepth {
			maxDepth = path.State.Depth
		}
	}

	return &SymbolicExecutionResult{
		Paths:               se.paths,
		SymbolicValues:      finalValues,
		ConstraintsSolved:   solvedConstraints,
		ConstraintsUnsolved: unsolvedConstraints,
		ExecutionDepth:      maxDepth,
		PathCount:           len(se.paths),
		PrunedPaths:         se.prunedPaths,
		FallbackUsed:        se.fallbackUsed,
		Trace:               se.trace,
	}
}

// canSolveConstraint checks if a constraint can be solved.
func (se *SymbolicExecutor) canSolveConstraint(constraint *Constraint) bool {
	// Simple constraint solving: only solve concrete constraints
	switch constraint.Type {
	case "eq", "ne", "lt", "le", "gt", "ge":
		// Can solve if value is concrete
		_, isInt := constraint.Value.(int64)
		return isInt
	case "range":
		// Can solve if range is concrete
		return true
	default:
		return false
	}
}

// GetSymbolicValue returns the symbolic value for a register.
func (se *SymbolicExecutor) GetSymbolicValue(reg int16) *SymbolicValue {
	if len(se.paths) == 0 {
		return nil
	}

	// Return value from first path
	if val, ok := se.paths[0].State.Registers[reg]; ok {
		return val
	}
	return nil
}

// GetPathCount returns the number of paths explored.
func (se *SymbolicExecutor) GetPathCount() int {
	return len(se.paths)
}

// GetPrunedPathCount returns the number of paths pruned.
func (se *SymbolicExecutor) GetPrunedPathCount() int {
	return se.prunedPaths
}

// GetTrace returns the execution trace.
func (se *SymbolicExecutor) GetTrace() []string {
	return se.trace
}

// SetMaxDepth sets the maximum execution depth.
func (se *SymbolicExecutor) SetMaxDepth(depth int) {
	se.maxDepth = depth
}

// SetMaxPaths sets the maximum number of paths.
func (se *SymbolicExecutor) SetMaxPaths(paths int) {
	se.maxPaths = paths
}

// PerformSymbolicExecution performs symbolic execution on a method.
func PerformSymbolicExecution(cfg *CFG, ssa *SSAForm) *SymbolicExecutionResult {
	executor := NewSymbolicExecutor(cfg, ssa)
	return executor.Execute()
}

// PerformSymbolicExecutionWithLimits performs symbolic execution with custom limits.
func PerformSymbolicExecutionWithLimits(cfg *CFG, ssa *SSAForm, maxDepth, maxPaths int) *SymbolicExecutionResult {
	executor := NewSymbolicExecutor(cfg, ssa)
	executor.SetMaxDepth(maxDepth)
	executor.SetMaxPaths(maxPaths)
	return executor.Execute()
}

// SortPathsByDepth sorts paths by execution depth.
func (result *SymbolicExecutionResult) SortPathsByDepth() {
	sort.Slice(result.Paths, func(i, j int) bool {
		return result.Paths[i].State.Depth < result.Paths[j].State.Depth
	})
}

// SortPathsByConstraintCount sorts paths by constraint count.
func (result *SymbolicExecutionResult) SortPathsByConstraintCount() {
	sort.Slice(result.Paths, func(i, j int) bool {
		return len(result.Paths[i].State.Constraints) < len(result.Paths[j].State.Constraints)
	})
}

// GetPathsWithConstraints returns paths that have constraints.
func (result *SymbolicExecutionResult) GetPathsWithConstraints() []*ExecutionPath {
	paths := make([]*ExecutionPath, 0)
	for _, path := range result.Paths {
		if len(path.State.Constraints) > 0 {
			paths = append(paths, path)
		}
	}
	return paths
}

// GetPathsTerminated returns paths that have terminated.
func (result *SymbolicExecutionResult) GetPathsTerminated() []*ExecutionPath {
	paths := make([]*ExecutionPath, 0)
	for _, path := range result.Paths {
		if path.State.IsTerminated {
			paths = append(paths, path)
		}
	}
	return paths
}
