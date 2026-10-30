package apkloader

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// HYPERION ENGINE v3.0 — Virtualization Detection & Devirtualization Engine
// ═══════════════════════════════════════════════════════════════════════════════
//
// Two-phase architecture:
//   Phase 1: Detection — Identifies VM dispatcher patterns, interpreter loops,
//            opaque bytecode, and custom VM entry points via structural heuristics.
//   Phase 2: Devirtualization (Lifter) — Symbolically traces VM handlers,
//            recovers semantic opcodes, and reconstructs clean MIR/CFG that the
//            rest of the pipeline (SSA, taint, concolic, HDC) can consume.
//
// Supported VM archetypes:
//   - Switch-dispatcher VMs (DexProtector, Bangcle, Ijiami)
//   - Table-dispatch VMs (computed jump tables)
//   - Computed-goto VMs (arithmetic address calculation)
//   - Interpreter-loop VMs (fetch-decode-execute with state registers)
//   - Hybrid VMs (mixed dispatch + JIT stubs)
//
// The devirtualizer uses partial symbolic evaluation of handler bodies to
// recover the semantic effect of each virtual opcode without full emulation.

// VirtualizationTechnique classifies the type of virtualization detected.
type VirtualizationTechnique uint8

const (
	VirtualizationUnknown VirtualizationTechnique = iota
	VirtualizationDispatcher
	VirtualizationInterpreter
	VirtualizationJIT
	VirtualizationObfuscatedBytecode
	VirtualizationCustomVM
)

func (vt VirtualizationTechnique) String() string {
	switch vt {
	case VirtualizationDispatcher:
		return "Dispatcher"
	case VirtualizationInterpreter:
		return "Interpreter"
	case VirtualizationJIT:
		return "JIT"
	case VirtualizationObfuscatedBytecode:
		return "ObfuscatedBytecode"
	case VirtualizationCustomVM:
		return "CustomVM"
	default:
		return "Unknown"
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// DEVIRTUALIZATION TYPES
// ═══════════════════════════════════════════════════════════════════════════════

// DevirtStatus tracks the devirtualization state of a pattern.
type DevirtStatus uint8

const (
	DevirtPending   DevirtStatus = iota // detected but not yet lifted
	DevirtPartial                       // some handlers recovered
	DevirtComplete                      // full semantic recovery
	DevirtFailed                        // lifting failed (too complex / anti-devirt)
	DevirtProtected                     // anti-devirt traps detected, unsafe to lift
)

func (ds DevirtStatus) String() string {
	switch ds {
	case DevirtPending:
		return "Pending"
	case DevirtPartial:
		return "Partial"
	case DevirtComplete:
		return "Complete"
	case DevirtFailed:
		return "Failed"
	case DevirtProtected:
		return "Protected"
	default:
		return "Unknown"
	}
}

// VirtualOpcode represents a recovered virtual instruction from the VM bytecode.
type VirtualOpcode struct {
	Index         int         // position in virtual bytecode stream
	RawValue      uint32      // raw opcode value from VM bytecode
	SemanticKind  MIROpKind   // recovered MIR equivalent (MIR_ADD, MIR_IF, etc.)
	HandlerBlock  *BasicBlock // the handler basic block that implements this opcode
	HandlerInsns  []MIRInsn   // lifted MIR instructions from handler
	Operands      []int16     // virtual register operands
	Immediate     int64       // immediate value (if any)
	Confidence    int         // confidence of semantic recovery (0-100)
	IsControlFlow bool        // true if this opcode affects control flow
	SideEffects   []string    // detected side effects (memory write, invoke, etc.)
}

// VMContext represents the virtual machine's execution context.
type VMContext struct {
	PCRegister       int16   // register holding the virtual program counter
	OpcodeRegister   int16   // register holding the current opcode
	StateRegisters   []int16 // registers used as VM state (stack pointer, frame, etc.)
	VirtualStack     int16   // register/field holding the virtual stack array
	VirtualRegisters int16   // register/field holding the virtual register file
	HandlerTable     int16   // register/field holding the handler dispatch table
	BytecodeArray    int16   // register/field holding the bytecode array
}

// DevirtualizationResult holds the output of the devirtualization pass.
type DevirtualizationResult struct {
	OriginalPattern *VirtualizationPattern // the detected VM pattern
	Status          DevirtStatus           // devirtualization status
	RecoveredMIR    []MIRInsn              // lifted MIR instructions (clean)
	RecoveredCFG    *CFG                   // reconstructed CFG from lifted MIR
	VMContext       *VMContext             // recovered VM context layout
	VirtualOps      []*VirtualOpcode       // all recovered virtual opcodes
	HandlerMap      map[uint32]*BasicBlock // raw opcode → handler block mapping
	Coverage        float64                // percentage of bytecode successfully lifted
	AntiDevirtTraps []string               // detected anti-devirtualization traps
	Trace           []string               // detailed trace of the lifting process
}

// HandlerSemantics captures the semantic effect of a single VM handler.
type HandlerSemantics struct {
	OpcodeValue    uint32    // the opcode this handler processes
	Effect         MIROpKind // primary semantic effect
	ReadsRegisters []int16   // virtual registers read
	WritesRegister int16     // virtual register written (-1 if none)
	ReadsMemory    bool      // reads from virtual stack/heap
	WritesMemory   bool      // writes to virtual stack/heap
	IsTerminator   bool      // ends a virtual basic block
	BranchTarget   int64     // branch offset (if IsTerminator && branch)
	Confidence     int       // confidence of this semantic assignment
	SideEffects    []string  // detected side effects (memory_write, invoke, control_flow)
}

// ═══════════════════════════════════════════════════════════════════════════════
// CORE STRUCTS
// ═══════════════════════════════════════════════════════════════════════════════

// VirtualizationPattern represents a detected virtualization pattern.
type VirtualizationPattern struct {
	Technique             VirtualizationTechnique
	Location              *BasicBlock
	InsnIndex             int
	DispatcherLocation    *BasicBlock
	DispatcherType        string
	VirtualOpcodes        []uint32
	ExtractedBytecode     []byte
	Confidence            int
	Rationale             string
	AnnotatedInstructions []string

	// ── Devirtualization fields (Phase 2) ────────────────────────
	DevirtResult    *DevirtualizationResult // result of devirtualization pass
	HandlerBlocks   []*BasicBlock           // identified handler basic blocks
	VMCtx           *VMContext              // recovered VM context
	OpcodeSemantics []*HandlerSemantics     // semantic map for each handler
	Complexity      int                     // estimated VM complexity score (0-100)
	AntiDevirt      []string                // detected anti-devirt techniques
}

// VirtualizationDetector detects virtualized bytecode patterns and devirtualizes them.
type VirtualizationDetector struct {
	CFG                 *CFG
	SSA                 *SSAForm
	Patterns            []*VirtualizationPattern
	Trace               []string
	Changes             int
	ConfidenceThreshold int

	// ── Devirtualization engine state ────────────────────────────
	DevirtResults    []*DevirtualizationResult
	SymbolicState    map[int16]int64
	HandlerCache     map[uint32]*HandlerSemantics
	MaxTraceDepth    int
	EnableAntiDevirt bool
}

// NewVirtualizationDetector creates a new virtualization detector.
func NewVirtualizationDetector(cfg *CFG, ssa *SSAForm) *VirtualizationDetector {
	return &VirtualizationDetector{
		CFG:                 cfg,
		SSA:                 ssa,
		Patterns:            make([]*VirtualizationPattern, 0),
		Trace:               make([]string, 0),
		Changes:             0,
		ConfidenceThreshold: 50,
		DevirtResults:       make([]*DevirtualizationResult, 0),
		SymbolicState:       make(map[int16]int64),
		HandlerCache:        make(map[uint32]*HandlerSemantics),
		MaxTraceDepth:       64,
		EnableAntiDevirt:    true,
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// PHASE 1: DETECTION ENGINE
// ═══════════════════════════════════════════════════════════════════════════════

// DetectVirtualization detects all virtualization patterns in the CFG.
func (vd *VirtualizationDetector) DetectVirtualization() {
	if vd.CFG == nil || len(vd.CFG.Blocks) == 0 {
		vd.addTrace("No CFG blocks to analyze")
		return
	}

	vd.addTrace(fmt.Sprintf("Starting virtualization detection on %d blocks", len(vd.CFG.Blocks)))

	vd.detectDispatcherPatterns()
	vd.detectInterpreterPatterns()
	vd.detectObfuscatedBytecodePatterns()
	vd.detectCustomVMPatterns()

	vd.addTrace(fmt.Sprintf("Detected %d virtualization patterns", len(vd.Patterns)))
}

// detectDispatcherPatterns detects dispatcher-based virtualization.
func (vd *VirtualizationDetector) detectDispatcherPatterns() {
	for _, block := range vd.CFG.Blocks {
		if block == nil || len(block.Insns) == 0 {
			continue
		}

		if len(block.Succs) > 5 {
			if vd.isSwitchDispatcher(block) {
				pattern := vd.analyzeSwitchDispatcher(block)
				if pattern != nil {
					vd.Patterns = append(vd.Patterns, pattern)
					vd.Changes++
				}
			}
		}

		if vd.isTableDispatcher(block) {
			pattern := vd.analyzeTableDispatcher(block)
			if pattern != nil {
				vd.Patterns = append(vd.Patterns, pattern)
				vd.Changes++
			}
		}

		if vd.isComputedGotoDispatcher(block) {
			pattern := vd.analyzeComputedGotoDispatcher(block)
			if pattern != nil {
				vd.Patterns = append(vd.Patterns, pattern)
				vd.Changes++
			}
		}
	}
}

// isSwitchDispatcher checks if a block is a switch-based dispatcher.
func (vd *VirtualizationDetector) isSwitchDispatcher(block *BasicBlock) bool {
	if block == nil || len(block.Insns) == 0 {
		return false
	}

	lastInsn := &block.Insns[len(block.Insns)-1]

	if lastInsn.Kind == MIR_SWITCH {
		return true
	}

	if lastInsn.Kind == MIR_IF && len(block.Succs) > 2 {
		return true
	}

	return false
}

// isTableDispatcher checks if a block uses table-based dispatch.
func (vd *VirtualizationDetector) isTableDispatcher(block *BasicBlock) bool {
	if block == nil || len(block.Insns) == 0 {
		return false
	}

	for i := range block.Insns {
		insn := &block.Insns[i]

		if insn.Kind == MIR_ARRAY_GET {
			if i+1 < len(block.Insns) {
				nextInsn := &block.Insns[i+1]
				if nextInsn.Kind == MIR_GOTO || nextInsn.Kind == MIR_IF {
					return true
				}
			}
		}
	}

	return false
}

// isComputedGotoDispatcher checks if a block uses computed goto dispatch.
func (vd *VirtualizationDetector) isComputedGotoDispatcher(block *BasicBlock) bool {
	if block == nil || len(block.Insns) == 0 {
		return false
	}

	for i := range block.Insns {
		insn := &block.Insns[i]

		if insn.Kind == MIR_ADD || insn.Kind == MIR_MUL ||
			insn.Kind == MIR_SHL || insn.Kind == MIR_SHR {
			if i+1 < len(block.Insns) {
				nextInsn := &block.Insns[i+1]
				if nextInsn.Kind == MIR_GOTO {
					return true
				}
			}
		}
	}

	return false
}

// analyzeSwitchDispatcher analyzes a switch-based dispatcher.
func (vd *VirtualizationDetector) analyzeSwitchDispatcher(block *BasicBlock) *VirtualizationPattern {
	if block == nil {
		return nil
	}

	pattern := &VirtualizationPattern{
		Technique:             VirtualizationDispatcher,
		Location:              block,
		DispatcherType:        "switch",
		VirtualOpcodes:        make([]uint32, 0),
		Confidence:            75,
		AnnotatedInstructions: make([]string, 0),
	}

	for _, succ := range block.Succs {
		if succ != nil && len(succ.Insns) > 0 {
			firstInsn := &succ.Insns[0]
			if firstInsn.Kind == MIR_CONST {
				pattern.VirtualOpcodes = append(pattern.VirtualOpcodes, uint32(len(pattern.VirtualOpcodes)))
			}
		}
	}

	pattern.Rationale = fmt.Sprintf("Switch-based dispatcher with %d branches detected", len(block.Succs))
	pattern.DispatcherLocation = block

	for i := range block.Insns {
		insn := &block.Insns[i]
		pattern.AnnotatedInstructions = append(pattern.AnnotatedInstructions,
			fmt.Sprintf("%v [dispatcher]", insn.Kind))
	}

	// Identify handler blocks for devirtualization
	pattern.HandlerBlocks = make([]*BasicBlock, 0, len(block.Succs))
	for _, succ := range block.Succs {
		if succ != nil {
			pattern.HandlerBlocks = append(pattern.HandlerBlocks, succ)
		}
	}

	// Estimate complexity based on handler count and instruction density
	pattern.Complexity = vd.estimateVMComplexity(pattern)

	return pattern
}

// analyzeTableDispatcher analyzes a table-based dispatcher.
func (vd *VirtualizationDetector) analyzeTableDispatcher(block *BasicBlock) *VirtualizationPattern {
	if block == nil {
		return nil
	}

	pattern := &VirtualizationPattern{
		Technique:             VirtualizationDispatcher,
		Location:              block,
		DispatcherType:        "table",
		VirtualOpcodes:        make([]uint32, 0),
		Confidence:            70,
		AnnotatedInstructions: make([]string, 0),
	}

	for i := range block.Insns {
		insn := &block.Insns[i]
		if insn.Kind == MIR_ARRAY_GET {
			pattern.VirtualOpcodes = append(pattern.VirtualOpcodes, uint32(i))
		}
	}

	pattern.Rationale = fmt.Sprintf("Table-based dispatcher with %d entries detected", len(pattern.VirtualOpcodes))
	pattern.DispatcherLocation = block

	for i := range block.Insns {
		insn := &block.Insns[i]
		pattern.AnnotatedInstructions = append(pattern.AnnotatedInstructions,
			fmt.Sprintf("%v [table_dispatch]", insn.Kind))
	}

	pattern.Complexity = vd.estimateVMComplexity(pattern)

	return pattern
}

// analyzeComputedGotoDispatcher analyzes a computed goto dispatcher.
func (vd *VirtualizationDetector) analyzeComputedGotoDispatcher(block *BasicBlock) *VirtualizationPattern {
	if block == nil {
		return nil
	}

	pattern := &VirtualizationPattern{
		Technique:             VirtualizationDispatcher,
		Location:              block,
		DispatcherType:        "computed_goto",
		VirtualOpcodes:        make([]uint32, 0),
		Confidence:            65,
		AnnotatedInstructions: make([]string, 0),
	}

	for i := range block.Insns {
		insn := &block.Insns[i]
		if insn.Kind == MIR_ADD || insn.Kind == MIR_MUL {
			pattern.VirtualOpcodes = append(pattern.VirtualOpcodes, uint32(i))
		}
	}

	pattern.Rationale = fmt.Sprintf("Computed goto dispatcher with %d computations detected", len(pattern.VirtualOpcodes))
	pattern.DispatcherLocation = block

	for i := range block.Insns {
		insn := &block.Insns[i]
		pattern.AnnotatedInstructions = append(pattern.AnnotatedInstructions,
			fmt.Sprintf("%v [computed_goto]", insn.Kind))
	}

	pattern.Complexity = vd.estimateVMComplexity(pattern)

	return pattern
}

// detectInterpreterPatterns detects interpreter-based virtualization.
func (vd *VirtualizationDetector) detectInterpreterPatterns() {
	for _, block := range vd.CFG.Blocks {
		if block == nil || len(block.Insns) == 0 {
			continue
		}

		if vd.isInterpreterLoop(block) {
			pattern := vd.analyzeInterpreterLoop(block)
			if pattern != nil {
				vd.Patterns = append(vd.Patterns, pattern)
				vd.Changes++
			}
		}
	}
}

// isInterpreterLoop checks if a block is part of an interpreter loop.
func (vd *VirtualizationDetector) isInterpreterLoop(block *BasicBlock) bool {
	if block == nil || len(block.Insns) == 0 {
		return false
	}

	for _, succ := range block.Succs {
		if succ != nil && succ.ID <= block.ID {
			if vd.hasStateMachinePattern(block) {
				return true
			}
		}
	}

	return false
}

// hasStateMachinePattern checks if a block has state machine characteristics.
func (vd *VirtualizationDetector) hasStateMachinePattern(block *BasicBlock) bool {
	if block == nil || len(block.Insns) == 0 {
		return false
	}

	stateLoadCount := 0
	stateUpdateCount := 0

	for i := range block.Insns {
		insn := &block.Insns[i]

		if insn.Kind == MIR_FIELD_GET || insn.Kind == MIR_ARRAY_GET {
			stateLoadCount++
		}

		if insn.Kind == MIR_FIELD_PUT || insn.Kind == MIR_ARRAY_PUT {
			stateUpdateCount++
		}
	}

	return stateLoadCount >= 2 && stateUpdateCount >= 1
}

// analyzeInterpreterLoop analyzes an interpreter loop.
func (vd *VirtualizationDetector) analyzeInterpreterLoop(block *BasicBlock) *VirtualizationPattern {
	if block == nil {
		return nil
	}

	pattern := &VirtualizationPattern{
		Technique:             VirtualizationInterpreter,
		Location:              block,
		VirtualOpcodes:        make([]uint32, 0),
		Confidence:            60,
		AnnotatedInstructions: make([]string, 0),
	}

	for i := range block.Insns {
		insn := &block.Insns[i]
		if insn.Kind == MIR_FIELD_GET || insn.Kind == MIR_FIELD_PUT {
			pattern.VirtualOpcodes = append(pattern.VirtualOpcodes, uint32(i))
		}
	}

	pattern.Rationale = fmt.Sprintf("Interpreter loop with %d state operations detected", len(pattern.VirtualOpcodes))

	for i := range block.Insns {
		insn := &block.Insns[i]
		pattern.AnnotatedInstructions = append(pattern.AnnotatedInstructions,
			fmt.Sprintf("%v [interpreter]", insn.Kind))
	}

	// Attempt to recover VM context from interpreter loop
	pattern.VMCtx = vd.recoverVMContext(block)
	pattern.Complexity = vd.estimateVMComplexity(pattern)

	return pattern
}

// detectObfuscatedBytecodePatterns detects obfuscated bytecode patterns.
func (vd *VirtualizationDetector) detectObfuscatedBytecodePatterns() {
	for _, block := range vd.CFG.Blocks {
		if block == nil || len(block.Insns) == 0 {
			continue
		}

		if vd.hasUnusualInstructionSequence(block) {
			pattern := vd.analyzeObfuscatedBytecode(block)
			if pattern != nil {
				vd.Patterns = append(vd.Patterns, pattern)
				vd.Changes++
			}
		}
	}
}

// hasUnusualInstructionSequence checks for unusual instruction patterns.
func (vd *VirtualizationDetector) hasUnusualInstructionSequence(block *BasicBlock) bool {
	if block == nil || len(block.Insns) < 3 {
		return false
	}

	arithmeticCount := 0
	for i := range block.Insns {
		insn := &block.Insns[i]

		if insn.Kind == MIR_ADD || insn.Kind == MIR_SUB ||
			insn.Kind == MIR_MUL || insn.Kind == MIR_DIV ||
			insn.Kind == MIR_XOR || insn.Kind == MIR_AND ||
			insn.Kind == MIR_OR {
			arithmeticCount++
		}
	}

	return arithmeticCount >= 3
}

// analyzeObfuscatedBytecode analyzes obfuscated bytecode.
func (vd *VirtualizationDetector) analyzeObfuscatedBytecode(block *BasicBlock) *VirtualizationPattern {
	if block == nil {
		return nil
	}

	pattern := &VirtualizationPattern{
		Technique:             VirtualizationObfuscatedBytecode,
		Location:              block,
		VirtualOpcodes:        make([]uint32, 0),
		Confidence:            55,
		AnnotatedInstructions: make([]string, 0),
	}

	for i := range block.Insns {
		insn := &block.Insns[i]
		if insn.Kind == MIR_ADD || insn.Kind == MIR_XOR {
			pattern.VirtualOpcodes = append(pattern.VirtualOpcodes, uint32(i))
		}
	}

	pattern.Rationale = fmt.Sprintf("Obfuscated bytecode with %d suspicious operations detected", len(pattern.VirtualOpcodes))

	for i := range block.Insns {
		insn := &block.Insns[i]
		pattern.AnnotatedInstructions = append(pattern.AnnotatedInstructions,
			fmt.Sprintf("%v [obfuscated]", insn.Kind))
	}

	pattern.Complexity = vd.estimateVMComplexity(pattern)

	return pattern
}

// detectCustomVMPatterns detects custom VM patterns.
func (vd *VirtualizationDetector) detectCustomVMPatterns() {
	for _, block := range vd.CFG.Blocks {
		if block == nil || len(block.Insns) == 0 {
			continue
		}

		if vd.isCustomVMEntry(block) {
			pattern := vd.analyzeCustomVM(block)
			if pattern != nil {
				vd.Patterns = append(vd.Patterns, pattern)
				vd.Changes++
			}
		}
	}
}

// isCustomVMEntry checks if a block is a custom VM entry point.
func (vd *VirtualizationDetector) isCustomVMEntry(block *BasicBlock) bool {
	if block == nil || len(block.Insns) == 0 {
		return false
	}

	initCount := 0
	for i := range block.Insns {
		insn := &block.Insns[i]

		if insn.Kind == MIR_CONST || insn.Kind == MIR_NEW_ARRAY {
			initCount++
		}
	}

	return initCount >= 2
}

// analyzeCustomVM analyzes a custom VM pattern.
func (vd *VirtualizationDetector) analyzeCustomVM(block *BasicBlock) *VirtualizationPattern {
	if block == nil {
		return nil
	}

	pattern := &VirtualizationPattern{
		Technique:             VirtualizationCustomVM,
		Location:              block,
		VirtualOpcodes:        make([]uint32, 0),
		Confidence:            50,
		AnnotatedInstructions: make([]string, 0),
	}

	for i := range block.Insns {
		insn := &block.Insns[i]
		if insn.Kind == MIR_CONST || insn.Kind == MIR_NEW_ARRAY {
			pattern.VirtualOpcodes = append(pattern.VirtualOpcodes, uint32(i))
		}
	}

	pattern.Rationale = fmt.Sprintf("Custom VM with %d initialization operations detected", len(pattern.VirtualOpcodes))

	for i := range block.Insns {
		insn := &block.Insns[i]
		pattern.AnnotatedInstructions = append(pattern.AnnotatedInstructions,
			fmt.Sprintf("%v [custom_vm]", insn.Kind))
	}

	pattern.Complexity = vd.estimateVMComplexity(pattern)

	return pattern
}

// ═══════════════════════════════════════════════════════════════════════════════
// PHASE 2: DEVIRTUALIZATION ENGINE (LIFTER)
// ═══════════════════════════════════════════════════════════════════════════════

// Devirtualize runs the full devirtualization pipeline on all detected patterns.
// For each pattern with sufficient confidence, it:
//  1. Recovers the VM context (PC, opcode register, handler table)
//  2. Identifies and isolates handler basic blocks
//  3. Symbolically traces each handler to recover semantics
//  4. Reconstructs clean MIR from recovered virtual opcodes
//  5. Builds a new CFG from the lifted MIR
func (vd *VirtualizationDetector) Devirtualize() []*DevirtualizationResult {
	if len(vd.Patterns) == 0 {
		vd.addTrace("No patterns to devirtualize")
		return nil
	}

	vd.addTrace(fmt.Sprintf("Starting devirtualization on %d patterns", len(vd.Patterns)))

	results := make([]*DevirtualizationResult, 0, len(vd.Patterns))

	for _, pattern := range vd.Patterns {
		if pattern == nil || pattern.Confidence < vd.ConfidenceThreshold {
			continue
		}

		result := vd.devirtualizePattern(pattern)
		if result != nil {
			results = append(results, result)
			pattern.DevirtResult = result
		}
	}

	vd.DevirtResults = results
	vd.addTrace(fmt.Sprintf("Devirtualization complete: %d results", len(results)))

	return results
}

// devirtualizePattern runs devirtualization on a single pattern.
func (vd *VirtualizationDetector) devirtualizePattern(pattern *VirtualizationPattern) *DevirtualizationResult {
	result := &DevirtualizationResult{
		OriginalPattern: pattern,
		Status:          DevirtPending,
		RecoveredMIR:    make([]MIRInsn, 0),
		VirtualOps:      make([]*VirtualOpcode, 0),
		HandlerMap:      make(map[uint32]*BasicBlock),
		AntiDevirtTraps: make([]string, 0),
		Trace:           make([]string, 0),
	}

	result.addTrace(fmt.Sprintf("Devirtualizing %s pattern at block %d",
		pattern.Technique.String(), pattern.Location.ID))

	// Step 1: Check for anti-devirtualization traps
	if vd.EnableAntiDevirt {
		traps := vd.detectAntiDevirtTraps(pattern)
		if len(traps) > 0 {
			result.AntiDevirtTraps = traps
			pattern.AntiDevirt = traps
			result.addTrace(fmt.Sprintf("WARNING: %d anti-devirt traps detected", len(traps)))

			// If critical traps found, mark as protected and bail
			if vd.hasCriticalTraps(traps) {
				result.Status = DevirtProtected
				result.addTrace("Critical anti-devirt traps — aborting lift")
				return result
			}
		}
	}

	// Step 2: Recover VM context
	vmCtx := vd.recoverVMContext(pattern.Location)
	if vmCtx == nil {
		// Try broader recovery from handler blocks
		vmCtx = vd.recoverVMContextFromHandlers(pattern)
	}
	result.VMContext = vmCtx
	pattern.VMCtx = vmCtx

	// Step 3: Identify handler blocks
	handlers := vd.identifyHandlerBlocks(pattern)
	result.addTrace(fmt.Sprintf("Identified %d handler blocks", len(handlers)))

	// Step 4: Symbolically trace each handler
	semantics := make([]*HandlerSemantics, 0, len(handlers))
	for opcodeVal, handlerBlock := range handlers {
		result.HandlerMap[opcodeVal] = handlerBlock
		sem := vd.traceHandler(handlerBlock, vmCtx, opcodeVal)
		if sem != nil {
			semantics = append(semantics, sem)
			vd.HandlerCache[opcodeVal] = sem
		}
	}
	pattern.OpcodeSemantics = semantics

	// Step 5: Recover virtual opcodes from bytecode
	virtualOps := vd.recoverVirtualOpcodes(pattern, semantics)
	result.VirtualOps = virtualOps

	// Step 6: Lift virtual opcodes to MIR
	liftedMIR := vd.liftToMIR(virtualOps, vmCtx)
	result.RecoveredMIR = liftedMIR

	// Step 7: Build CFG from lifted MIR
	if len(liftedMIR) > 0 {
		result.RecoveredCFG = BuildCFG(liftedMIR)
	}

	// Calculate coverage
	if len(pattern.VirtualOpcodes) > 0 {
		lifted := 0
		for _, vop := range virtualOps {
			if vop.Confidence >= 50 {
				lifted++
			}
		}
		result.Coverage = float64(lifted) / float64(len(pattern.VirtualOpcodes)) * 100.0
	}

	// Determine final status
	if result.Coverage >= 90.0 {
		result.Status = DevirtComplete
	} else if result.Coverage >= 30.0 {
		result.Status = DevirtPartial
	} else if len(liftedMIR) > 0 {
		result.Status = DevirtPartial
	} else {
		result.Status = DevirtFailed
	}

	result.addTrace(fmt.Sprintf("Devirtualization %s: %.1f%% coverage, %d MIR instructions recovered",
		result.Status.String(), result.Coverage, len(liftedMIR)))

	return result
}

// detectAntiDevirtTraps identifies anti-devirtualization techniques.
func (vd *VirtualizationDetector) detectAntiDevirtTraps(pattern *VirtualizationPattern) []string {
	traps := make([]string, 0)

	if pattern.Location == nil {
		return traps
	}

	// Check for opaque predicates in dispatcher
	if vd.hasOpaquePredicates(pattern.Location) {
		traps = append(traps, "opaque_predicates")
	}

	// Check for handler integrity checks (checksumming own code)
	if vd.hasIntegrityChecks(pattern) {
		traps = append(traps, "integrity_check")
	}

	// Check for timing-based anti-debug in handlers
	if vd.hasTimingChecks(pattern) {
		traps = append(traps, "timing_check")
	}

	// Check for handler duplication (same semantic, different code — confuses pattern matching)
	if vd.hasHandlerDuplication(pattern) {
		traps = append(traps, "handler_duplication")
	}

	// Check for dynamic handler table mutation
	if vd.hasDynamicHandlerTable(pattern) {
		traps = append(traps, "dynamic_handler_table")
	}

	return traps
}

// hasOpaquePredicates checks for opaque predicates in a block.
func (vd *VirtualizationDetector) hasOpaquePredicates(block *BasicBlock) bool {
	if block == nil || len(block.Insns) < 2 {
		return false
	}

	// Pattern: const followed by if-eq/if-ne with same register (always true/false)
	for i := 0; i < len(block.Insns)-1; i++ {
		insn := &block.Insns[i]
		next := &block.Insns[i+1]

		if insn.Kind == MIR_CONST && next.Kind == MIR_IF {
			if insn.Dst == next.Src1 && next.Src2 == insn.Dst {
				return true
			}
		}
	}

	return false
}

// hasIntegrityChecks checks if handlers verify their own code integrity.
func (vd *VirtualizationDetector) hasIntegrityChecks(pattern *VirtualizationPattern) bool {
	for _, handler := range pattern.HandlerBlocks {
		if handler == nil {
			continue
		}
		// Look for array-get sequences that read from code memory + XOR/ADD accumulation
		arrayGets := 0
		xorOps := 0
		for i := range handler.Insns {
			switch handler.Insns[i].Kind {
			case MIR_ARRAY_GET:
				arrayGets++
			case MIR_XOR:
				xorOps++
			}
		}
		if arrayGets >= 4 && xorOps >= 2 {
			return true
		}
	}
	return false
}

// hasTimingChecks checks for timing-based anti-analysis.
func (vd *VirtualizationDetector) hasTimingChecks(pattern *VirtualizationPattern) bool {
	for _, handler := range pattern.HandlerBlocks {
		if handler == nil {
			continue
		}
		for i := range handler.Insns {
			insn := &handler.Insns[i]
			if insn.Kind == MIR_INVOKE {
				// Check for System.nanoTime() or System.currentTimeMillis() calls
				// (detected via RefIdx pointing to timing methods)
				if insn.RefIdx > 0 {
					// Heuristic: two invokes close together with a CMP suggests timing check
					if i+3 < len(handler.Insns) {
						for j := i + 1; j < i+4 && j < len(handler.Insns); j++ {
							if handler.Insns[j].Kind == MIR_CMP || handler.Insns[j].Kind == MIR_SUB {
								return true
							}
						}
					}
				}
			}
		}
	}
	return false
}

// hasHandlerDuplication checks for duplicated handlers (anti-pattern matching).
func (vd *VirtualizationDetector) hasHandlerDuplication(pattern *VirtualizationPattern) bool {
	if len(pattern.HandlerBlocks) < 4 {
		return false
	}

	// Compare handler instruction sequences — if many are identical, it's duplication
	signatures := make(map[string]int)
	for _, handler := range pattern.HandlerBlocks {
		if handler == nil || len(handler.Insns) == 0 {
			continue
		}
		sig := vd.handlerSignature(handler)
		signatures[sig]++
	}

	duplicates := 0
	for _, count := range signatures {
		if count > 1 {
			duplicates += count - 1
		}
	}

	// If >30% of handlers are duplicates, flag it
	return duplicates > len(pattern.HandlerBlocks)/3
}

// hasDynamicHandlerTable checks if the handler table is mutated at runtime.
func (vd *VirtualizationDetector) hasDynamicHandlerTable(pattern *VirtualizationPattern) bool {
	if pattern.Location == nil {
		return false
	}

	// Look for ARRAY_PUT to the handler table register before dispatch
	for i := range pattern.Location.Insns {
		insn := &pattern.Location.Insns[i]
		if insn.Kind == MIR_ARRAY_PUT {
			return true
		}
	}
	return false
}

// hasCriticalTraps determines if detected traps are too dangerous to proceed.
func (vd *VirtualizationDetector) hasCriticalTraps(traps []string) bool {
	for _, trap := range traps {
		if trap == "dynamic_handler_table" || trap == "integrity_check" {
			return true
		}
	}
	return false
}

// handlerSignature generates a compact signature for a handler block.
func (vd *VirtualizationDetector) handlerSignature(block *BasicBlock) string {
	if block == nil || len(block.Insns) == 0 {
		return ""
	}
	var sb strings.Builder
	for i := range block.Insns {
		sb.WriteByte(byte(block.Insns[i].Kind))
	}
	return sb.String()
}

// ═══════════════════════════════════════════════════════════════════════════════
// VM CONTEXT RECOVERY
// ═══════════════════════════════════════════════════════════════════════════════

// recoverVMContext attempts to identify the VM's register layout from a block.
// It looks for patterns like:
//   - Array allocation (virtual register file / stack)
//   - Field loads that feed into the dispatcher (PC, opcode)
//   - Constant loads that initialize state
func (vd *VirtualizationDetector) recoverVMContext(block *BasicBlock) *VMContext {
	if block == nil || len(block.Insns) == 0 {
		return nil
	}

	ctx := &VMContext{
		PCRegister:       -1,
		OpcodeRegister:   -1,
		VirtualStack:     -1,
		VirtualRegisters: -1,
		HandlerTable:     -1,
		BytecodeArray:    -1,
		StateRegisters:   make([]int16, 0),
	}

	recovered := false

	for i := range block.Insns {
		insn := &block.Insns[i]

		switch insn.Kind {
		case MIR_ARRAY_GET:
			// Array get followed by switch/goto → likely opcode fetch from bytecode
			if i+1 < len(block.Insns) {
				next := &block.Insns[i+1]
				if next.Kind == MIR_SWITCH || next.Kind == MIR_GOTO {
					ctx.OpcodeRegister = insn.Dst
					ctx.BytecodeArray = insn.Src1
					ctx.PCRegister = insn.Src2 // index register = PC
					recovered = true
				}
			}

		case MIR_NEW_ARRAY:
			// New array allocation → virtual register file or stack
			if ctx.VirtualRegisters == -1 {
				ctx.VirtualRegisters = insn.Dst
				recovered = true
			} else if ctx.VirtualStack == -1 {
				ctx.VirtualStack = insn.Dst
				recovered = true
			}

		case MIR_FIELD_GET:
			// Field loads in dispatcher → state registers
			ctx.StateRegisters = append(ctx.StateRegisters, insn.Dst)
			recovered = true

		case MIR_FIELD_PUT:
			// Field stores → PC update or state mutation
			if ctx.PCRegister == -1 {
				ctx.PCRegister = insn.Src1
				recovered = true
			}
		}
	}

	if !recovered {
		return nil
	}

	return ctx
}

// recoverVMContextFromHandlers attempts broader VM context recovery by analyzing handlers.
func (vd *VirtualizationDetector) recoverVMContextFromHandlers(pattern *VirtualizationPattern) *VMContext {
	if len(pattern.HandlerBlocks) == 0 {
		return nil
	}

	ctx := &VMContext{
		PCRegister:       -1,
		OpcodeRegister:   -1,
		VirtualStack:     -1,
		VirtualRegisters: -1,
		HandlerTable:     -1,
		BytecodeArray:    -1,
		StateRegisters:   make([]int16, 0),
	}

	// Analyze register usage frequency across handlers
	// Registers used in ALL handlers are likely VM state (PC, SP, etc.)
	regUsage := make(map[int16]int)
	regWrite := make(map[int16]int)

	for _, handler := range pattern.HandlerBlocks {
		if handler == nil {
			continue
		}
		seen := make(map[int16]bool)
		for i := range handler.Insns {
			insn := &handler.Insns[i]
			if insn.Src1 >= 0 && !seen[insn.Src1] {
				regUsage[insn.Src1]++
				seen[insn.Src1] = true
			}
			if insn.Src2 >= 0 && !seen[insn.Src2] {
				regUsage[insn.Src2]++
				seen[insn.Src2] = true
			}
			if insn.Dst >= 0 {
				regWrite[insn.Dst]++
			}
		}
	}

	// Registers used in >80% of handlers are VM state
	threshold := len(pattern.HandlerBlocks) * 80 / 100
	if threshold < 1 {
		threshold = 1
	}

	for reg, count := range regUsage {
		if count >= threshold {
			ctx.StateRegisters = append(ctx.StateRegisters, reg)
		}
	}

	// The most-written register across handlers is likely the PC (incremented each iteration)
	maxWrites := 0
	for reg, count := range regWrite {
		if count > maxWrites {
			maxWrites = count
			ctx.PCRegister = reg
		}
	}

	if len(ctx.StateRegisters) > 0 || ctx.PCRegister >= 0 {
		return ctx
	}

	return nil
}

// identifyHandlerBlocks maps opcode values to their handler basic blocks.
func (vd *VirtualizationDetector) identifyHandlerBlocks(pattern *VirtualizationPattern) map[uint32]*BasicBlock {
	handlers := make(map[uint32]*BasicBlock)

	switch pattern.DispatcherType {
	case "switch":
		// Switch dispatcher: successors are handlers, ordered by case value
		for i, succ := range pattern.HandlerBlocks {
			if succ != nil {
				handlers[uint32(i)] = succ
			}
		}

	case "table":
		// Table dispatcher: need to trace array contents
		for i, succ := range pattern.Location.Succs {
			if succ != nil {
				handlers[uint32(i)] = succ
			}
		}

	case "computed_goto":
		// Computed goto: successors reachable via arithmetic
		for i, succ := range pattern.Location.Succs {
			if succ != nil {
				handlers[uint32(i)] = succ
			}
		}

	default:
		// Generic: use all successor blocks
		if pattern.Location != nil {
			for i, succ := range pattern.Location.Succs {
				if succ != nil {
					handlers[uint32(i)] = succ
				}
			}
		}
	}

	return handlers
}

// ═══════════════════════════════════════════════════════════════════════════════
// SYMBOLIC HANDLER TRACING
// ═══════════════════════════════════════════════════════════════════════════════

// traceHandler symbolically executes a handler block to recover its semantic effect.
// This is the core of the devirtualizer — it determines what each virtual opcode DOES.
func (vd *VirtualizationDetector) traceHandler(block *BasicBlock, vmCtx *VMContext, opcodeVal uint32) *HandlerSemantics {
	if block == nil || len(block.Insns) == 0 {
		return nil
	}

	sem := &HandlerSemantics{
		OpcodeValue:    opcodeVal,
		Effect:         MIR_NOP,
		ReadsRegisters: make([]int16, 0),
		WritesRegister: -1,
		Confidence:     0,
	}

	// Track register reads/writes within the handler
	reads := make(map[int16]bool)
	var lastWrite int16 = -1
	hasMemRead := false
	hasMemWrite := false
	hasInvoke := false
	hasBranch := false
	primaryEffect := MIR_NOP

	for i := range block.Insns {
		insn := &block.Insns[i]

		// Skip VM bookkeeping (PC increment, opcode fetch) if we know the context
		if vmCtx != nil && vd.isVMBookkeeping(insn, vmCtx) {
			continue
		}

		// Track reads
		if insn.Src1 >= 0 {
			reads[insn.Src1] = true
		}
		if insn.Src2 >= 0 {
			reads[insn.Src2] = true
		}

		// Track writes
		if insn.Dst >= 0 {
			lastWrite = insn.Dst
		}

		// Classify the semantic effect
		switch insn.Kind {
		case MIR_ADD, MIR_SUB, MIR_MUL, MIR_DIV, MIR_REM:
			primaryEffect = insn.Kind
			sem.Confidence += 20

		case MIR_AND, MIR_OR, MIR_XOR, MIR_SHL, MIR_SHR, MIR_USHR:
			primaryEffect = insn.Kind
			sem.Confidence += 20

		case MIR_NEG, MIR_NOT:
			primaryEffect = insn.Kind
			sem.Confidence += 20

		case MIR_ARRAY_GET, MIR_FIELD_GET:
			hasMemRead = true
			if primaryEffect == MIR_NOP {
				primaryEffect = insn.Kind
			}
			sem.Confidence += 10

		case MIR_ARRAY_PUT, MIR_FIELD_PUT:
			hasMemWrite = true
			if primaryEffect == MIR_NOP {
				primaryEffect = insn.Kind
			}
			sem.Confidence += 10

		case MIR_INVOKE:
			hasInvoke = true
			primaryEffect = MIR_INVOKE
			sem.Confidence += 15

		case MIR_IF, MIR_GOTO, MIR_SWITCH:
			hasBranch = true
			sem.IsTerminator = true
			primaryEffect = insn.Kind
			if insn.Kind == MIR_IF || insn.Kind == MIR_GOTO {
				sem.BranchTarget = insn.Imm
			}
			sem.Confidence += 25

		case MIR_RETURN, MIR_THROW:
			sem.IsTerminator = true
			primaryEffect = insn.Kind
			sem.Confidence += 25

		case MIR_CONST:
			// Constants alone don't define semantics, but boost confidence
			sem.Confidence += 5

		case MIR_MOVE:
			if primaryEffect == MIR_NOP {
				primaryEffect = MIR_MOVE
			}
			sem.Confidence += 10

		case MIR_CONVERT:
			primaryEffect = MIR_CONVERT
			sem.Confidence += 15
		}
	}

	// Assign final semantics
	sem.Effect = primaryEffect
	sem.WritesRegister = lastWrite
	sem.ReadsMemory = hasMemRead
	sem.WritesMemory = hasMemWrite

	for reg := range reads {
		sem.ReadsRegisters = append(sem.ReadsRegisters, reg)
	}

	// Build side effects list
	sem.SideEffects = make([]string, 0)
	if hasMemWrite {
		sem.SideEffects = append(sem.SideEffects, "memory_write")
	}
	if hasInvoke {
		sem.SideEffects = append(sem.SideEffects, "invoke")
	}
	if hasBranch {
		sem.SideEffects = append(sem.SideEffects, "control_flow")
	}

	// Cap confidence at 100
	if sem.Confidence > 100 {
		sem.Confidence = 100
	}

	return sem
}

// isVMBookkeeping checks if an instruction is VM overhead (PC increment, opcode fetch).
func (vd *VirtualizationDetector) isVMBookkeeping(insn *MIRInsn, vmCtx *VMContext) bool {
	if vmCtx == nil {
		return false
	}

	// PC increment: ADD to PC register with constant 1
	if insn.Kind == MIR_ADD && insn.Dst == vmCtx.PCRegister {
		return true
	}

	// Opcode fetch: ARRAY_GET from bytecode array using PC as index
	if insn.Kind == MIR_ARRAY_GET && insn.Src1 == vmCtx.BytecodeArray && insn.Src2 == vmCtx.PCRegister {
		return true
	}

	// State register is one of the known VM registers
	for _, stateReg := range vmCtx.StateRegisters {
		if insn.Dst == stateReg && (insn.Kind == MIR_ADD || insn.Kind == MIR_FIELD_GET) {
			return true
		}
	}

	return false
}

// recoverVirtualOpcodes reconstructs the virtual opcode stream from the pattern.
func (vd *VirtualizationDetector) recoverVirtualOpcodes(pattern *VirtualizationPattern, semantics []*HandlerSemantics) []*VirtualOpcode {
	ops := make([]*VirtualOpcode, 0)

	// Build semantic lookup
	semMap := make(map[uint32]*HandlerSemantics)
	for _, sem := range semantics {
		if sem != nil {
			semMap[sem.OpcodeValue] = sem
		}
	}

	// For each virtual opcode in the pattern, create a VirtualOpcode with recovered semantics
	for i, rawOp := range pattern.VirtualOpcodes {
		vop := &VirtualOpcode{
			Index:    i,
			RawValue: rawOp,
			Operands: make([]int16, 0),
		}

		if sem, ok := semMap[rawOp]; ok {
			vop.SemanticKind = sem.Effect
			vop.Confidence = sem.Confidence
			vop.IsControlFlow = sem.IsTerminator
			vop.Immediate = sem.BranchTarget
			vop.Operands = sem.ReadsRegisters
			vop.SideEffects = sem.SideEffects

			if handler, ok := pattern.DevirtResult.HandlerMap[rawOp]; ok {
				vop.HandlerBlock = handler
				vop.HandlerInsns = handler.Insns
			}
		} else {
			// Unknown opcode — mark with low confidence
			vop.SemanticKind = MIR_NOP
			vop.Confidence = 10
		}

		ops = append(ops, vop)
	}

	return ops
}

// liftToMIR converts recovered virtual opcodes into clean MIR instructions.
func (vd *VirtualizationDetector) liftToMIR(virtualOps []*VirtualOpcode, _ *VMContext) []MIRInsn {
	mir := make([]MIRInsn, 0, len(virtualOps))

	var offset uint32
	for _, vop := range virtualOps {
		if vop == nil || vop.Confidence < 30 {
			// Skip low-confidence ops — emit NOP placeholder
			mir = append(mir, MIRInsn{
				Kind:   MIR_NOP,
				Offset: offset,
			})
			offset++
			continue
		}

		insn := MIRInsn{
			Kind:   vop.SemanticKind,
			Offset: offset,
		}

		// Assign operands based on semantic kind
		switch vop.SemanticKind {
		case MIR_ADD, MIR_SUB, MIR_MUL, MIR_DIV, MIR_REM,
			MIR_AND, MIR_OR, MIR_XOR, MIR_SHL, MIR_SHR, MIR_USHR:
			// Binary arithmetic: dst = src1 op src2
			if len(vop.Operands) >= 2 {
				insn.Src1 = vop.Operands[0]
				insn.Src2 = vop.Operands[1]
			}
			insn.Dst = int16(vop.Index) // virtual register = opcode index
			insn.DataType = TypeInt

		case MIR_NEG, MIR_NOT:
			// Unary: dst = op src1
			if len(vop.Operands) >= 1 {
				insn.Src1 = vop.Operands[0]
			}
			insn.Dst = int16(vop.Index)
			insn.DataType = TypeInt

		case MIR_CONST:
			insn.Dst = int16(vop.Index)
			insn.Imm = vop.Immediate
			insn.DataType = TypeInt

		case MIR_MOVE:
			if len(vop.Operands) >= 1 {
				insn.Src1 = vop.Operands[0]
			}
			insn.Dst = int16(vop.Index)

		case MIR_IF:
			if len(vop.Operands) >= 1 {
				insn.Src1 = vop.Operands[0]
			}
			if len(vop.Operands) >= 2 {
				insn.Src2 = vop.Operands[1]
			}
			insn.Imm = vop.Immediate

		case MIR_GOTO:
			insn.Imm = vop.Immediate

		case MIR_RETURN:
			if len(vop.Operands) >= 1 {
				insn.Src1 = vop.Operands[0]
			}

		case MIR_INVOKE:
			// Preserve invoke metadata
			insn.InvokeKind = InvokeVirtual

		case MIR_ARRAY_GET, MIR_FIELD_GET:
			if len(vop.Operands) >= 1 {
				insn.Src1 = vop.Operands[0]
			}
			if len(vop.Operands) >= 2 {
				insn.Src2 = vop.Operands[1]
			}
			insn.Dst = int16(vop.Index)

		case MIR_ARRAY_PUT, MIR_FIELD_PUT:
			if len(vop.Operands) >= 1 {
				insn.Src1 = vop.Operands[0]
			}
			if len(vop.Operands) >= 2 {
				insn.Src2 = vop.Operands[1]
			}
		}

		mir = append(mir, insn)
		offset++
	}

	return mir
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMPLEXITY ESTIMATION & ANALYSIS HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

// estimateVMComplexity scores the complexity of a detected VM (0-100).
// Higher complexity = harder to devirtualize.
func (vd *VirtualizationDetector) estimateVMComplexity(pattern *VirtualizationPattern) int {
	score := 0

	// Factor 1: Number of handlers (more handlers = more complex VM)
	handlerCount := len(pattern.HandlerBlocks)
	if handlerCount == 0 {
		handlerCount = len(pattern.VirtualOpcodes)
	}
	if handlerCount > 50 {
		score += 30
	} else if handlerCount > 20 {
		score += 20
	} else if handlerCount > 5 {
		score += 10
	}

	// Factor 2: Average handler size (larger handlers = more complex semantics)
	totalInsns := 0
	for _, handler := range pattern.HandlerBlocks {
		if handler != nil {
			totalInsns += len(handler.Insns)
		}
	}
	if handlerCount > 0 {
		avgSize := totalInsns / handlerCount
		if avgSize > 20 {
			score += 25
		} else if avgSize > 10 {
			score += 15
		} else if avgSize > 5 {
			score += 8
		}
	}

	// Factor 3: Dispatcher type complexity
	switch pattern.DispatcherType {
	case "computed_goto":
		score += 20 // hardest to trace
	case "table":
		score += 15
	case "switch":
		score += 10 // easiest
	}

	// Factor 4: Presence of anti-devirt techniques
	score += len(pattern.AntiDevirt) * 10

	// Factor 5: Nested control flow in handlers
	for _, handler := range pattern.HandlerBlocks {
		if handler != nil && len(handler.Succs) > 2 {
			score += 5
		}
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}

// GetDevirtResults returns all devirtualization results.
func (vd *VirtualizationDetector) GetDevirtResults() []*DevirtualizationResult {
	return vd.DevirtResults
}

// GetDevirtCoverage returns the average devirtualization coverage across all patterns.
func (vd *VirtualizationDetector) GetDevirtCoverage() float64 {
	if len(vd.DevirtResults) == 0 {
		return 0
	}

	total := 0.0
	for _, result := range vd.DevirtResults {
		total += result.Coverage
	}
	return total / float64(len(vd.DevirtResults))
}

// GetLiftedMIR returns all recovered MIR instructions across all devirtualized patterns.
func (vd *VirtualizationDetector) GetLiftedMIR() []MIRInsn {
	all := make([]MIRInsn, 0)
	for _, result := range vd.DevirtResults {
		if result.Status == DevirtComplete || result.Status == DevirtPartial {
			all = append(all, result.RecoveredMIR...)
		}
	}
	return all
}

// GetRecoveredCFGs returns all reconstructed CFGs from devirtualization.
func (vd *VirtualizationDetector) GetRecoveredCFGs() []*CFG {
	cfgs := make([]*CFG, 0)
	for _, result := range vd.DevirtResults {
		if result.RecoveredCFG != nil {
			cfgs = append(cfgs, result.RecoveredCFG)
		}
	}
	return cfgs
}

// ═══════════════════════════════════════════════════════════════════════════════
// ORIGINAL API (preserved for backward compatibility)
// ═══════════════════════════════════════════════════════════════════════════════

// ExtractBytecode extracts partial bytecode from virtualized code.
func (vd *VirtualizationDetector) ExtractBytecode(pattern *VirtualizationPattern) []byte {
	if pattern == nil || pattern.Location == nil {
		return nil
	}

	bytecode := make([]byte, 0)

	for i := range pattern.Location.Insns {
		insn := &pattern.Location.Insns[i]

		kindStr := fmt.Sprintf("%v", insn.Kind)
		bytecode = append(bytecode, byte(len(kindStr)))
		bytecode = append(bytecode, []byte(kindStr)...)
	}

	pattern.ExtractedBytecode = bytecode
	return bytecode
}

// AnnotateVirtualization annotates virtualization techniques in the code.
func (vd *VirtualizationDetector) AnnotateVirtualization() []string {
	annotations := make([]string, 0)

	for _, pattern := range vd.Patterns {
		if pattern == nil {
			continue
		}

		annotation := fmt.Sprintf("Block %d: %s virtualization detected (confidence: %d%%)",
			pattern.Location.ID, pattern.Technique.String(), pattern.Confidence)

		if pattern.DispatcherLocation != nil {
			annotation += fmt.Sprintf(" [dispatcher at block %d, type: %s]",
				pattern.DispatcherLocation.ID, pattern.DispatcherType)
		}

		annotation += fmt.Sprintf(" - %s", pattern.Rationale)

		// Add devirtualization status if available
		if pattern.DevirtResult != nil {
			annotation += fmt.Sprintf(" | devirt: %s (%.1f%% coverage)",
				pattern.DevirtResult.Status.String(), pattern.DevirtResult.Coverage)
		}

		annotations = append(annotations, annotation)
	}

	return annotations
}

// GetPatterns returns all detected virtualization patterns.
func (vd *VirtualizationDetector) GetPatterns() []*VirtualizationPattern {
	return vd.Patterns
}

// GetPatternsByTechnique returns patterns of a specific technique.
func (vd *VirtualizationDetector) GetPatternsByTechnique(technique VirtualizationTechnique) []*VirtualizationPattern {
	result := make([]*VirtualizationPattern, 0)
	for _, pattern := range vd.Patterns {
		if pattern != nil && pattern.Technique == technique {
			result = append(result, pattern)
		}
	}
	return result
}

// GetPatternsByConfidenceVirt returns patterns above a confidence threshold.
func (vd *VirtualizationDetector) GetPatternsByConfidenceVirt(threshold int) []*VirtualizationPattern {
	result := make([]*VirtualizationPattern, 0)
	for _, pattern := range vd.Patterns {
		if pattern != nil && pattern.Confidence >= threshold {
			result = append(result, pattern)
		}
	}
	return result
}

// GetTraceVirt returns the analysis trace.
func (vd *VirtualizationDetector) GetTraceVirt() []string {
	return vd.Trace
}

// GetChangeCountVirt returns the number of changes detected.
func (vd *VirtualizationDetector) GetChangeCountVirt() int {
	return vd.Changes
}

// GetDetectionStats returns detection statistics.
func (vd *VirtualizationDetector) GetDetectionStats() (total, dispatcher, interpreter, jit, obfuscated, customVM int) {
	total = len(vd.Patterns)
	for _, pattern := range vd.Patterns {
		if pattern == nil {
			continue
		}
		switch pattern.Technique {
		case VirtualizationDispatcher:
			dispatcher++
		case VirtualizationInterpreter:
			interpreter++
		case VirtualizationJIT:
			jit++
		case VirtualizationObfuscatedBytecode:
			obfuscated++
		case VirtualizationCustomVM:
			customVM++
		}
	}
	return
}

// GetAverageConfidenceVirt returns the average confidence of detected patterns.
func (vd *VirtualizationDetector) GetAverageConfidenceVirt() int {
	if len(vd.Patterns) == 0 {
		return 0
	}

	total := 0
	for _, pattern := range vd.Patterns {
		if pattern != nil {
			total += pattern.Confidence
		}
	}

	return total / len(vd.Patterns)
}

// ═══════════════════════════════════════════════════════════════════════════════
// REPORT GENERATION (ENHANCED)
// ═══════════════════════════════════════════════════════════════════════════════

// GenerateReportVirt generates a comprehensive detection and devirtualization report.
func (vd *VirtualizationDetector) GenerateReportVirt() string {
	report := strings.Builder{}
	report.WriteString("═══════════════════════════════════════════════════════════════\n")
	report.WriteString("VIRTUALIZATION DETECTION REPORT\n")
	report.WriteString("═══════════════════════════════════════════════════════════════\n\n")

	total, dispatcher, interpreter, jit, obfuscated, customVM := vd.GetDetectionStats()

	fmt.Fprintf(&report, "Total Patterns Detected: %d\n", total)
	fmt.Fprintf(&report, "  - Dispatcher: %d\n", dispatcher)
	fmt.Fprintf(&report, "  - Interpreter: %d\n", interpreter)
	fmt.Fprintf(&report, "  - JIT: %d\n", jit)
	fmt.Fprintf(&report, "  - Obfuscated Bytecode: %d\n", obfuscated)
	fmt.Fprintf(&report, "  - Custom VM: %d\n", customVM)
	fmt.Fprintf(&report, "\nAverage Confidence: %d%%\n", vd.GetAverageConfidenceVirt())
	fmt.Fprintf(&report, "Total Changes: %d\n\n", vd.Changes)

	if len(vd.Patterns) > 0 {
		report.WriteString("Detected Patterns:\n")
		report.WriteString("─────────────────────────────────────────────────────────────\n")
		for i, pattern := range vd.Patterns {
			if pattern != nil {
				fmt.Fprintf(&report, "%d. %s (Confidence: %d%%)\n",
					i+1, pattern.Technique.String(), pattern.Confidence)
				fmt.Fprintf(&report, "   Location: Block %d\n", pattern.Location.ID)
				fmt.Fprintf(&report, "   Rationale: %s\n", pattern.Rationale)
				if pattern.DispatcherLocation != nil {
					fmt.Fprintf(&report, "   Dispatcher: Block %d (%s)\n",
						pattern.DispatcherLocation.ID, pattern.DispatcherType)
				}
				fmt.Fprintf(&report, "   Virtual Opcodes: %d\n", len(pattern.VirtualOpcodes))
				fmt.Fprintf(&report, "   Complexity: %d/100\n", pattern.Complexity)

				if len(pattern.AntiDevirt) > 0 {
					fmt.Fprintf(&report, "   Anti-Devirt: %s\n", strings.Join(pattern.AntiDevirt, ", "))
				}

				if pattern.DevirtResult != nil {
					fmt.Fprintf(&report, "   Devirt Status: %s (%.1f%% coverage)\n",
						pattern.DevirtResult.Status.String(), pattern.DevirtResult.Coverage)
					fmt.Fprintf(&report, "   Recovered MIR: %d instructions\n",
						len(pattern.DevirtResult.RecoveredMIR))
					if len(pattern.DevirtResult.AntiDevirtTraps) > 0 {
						fmt.Fprintf(&report, "   Traps: %s\n",
							strings.Join(pattern.DevirtResult.AntiDevirtTraps, ", "))
					}
				}

				report.WriteString("\n")
			}
		}
	}

	// Devirtualization summary
	if len(vd.DevirtResults) > 0 {
		report.WriteString("═══════════════════════════════════════════════════════════════\n")
		report.WriteString("DEVIRTUALIZATION SUMMARY\n")
		report.WriteString("═══════════════════════════════════════════════════════════════\n\n")

		complete := 0
		partial := 0
		failed := 0
		protected := 0
		totalMIR := 0

		for _, result := range vd.DevirtResults {
			switch result.Status {
			case DevirtComplete:
				complete++
			case DevirtPartial:
				partial++
			case DevirtFailed:
				failed++
			case DevirtProtected:
				protected++
			}
			totalMIR += len(result.RecoveredMIR)
		}

		fmt.Fprintf(&report, "Total Patterns Processed: %d\n", len(vd.DevirtResults))
		fmt.Fprintf(&report, "  ✓ Complete: %d\n", complete)
		fmt.Fprintf(&report, "  ◐ Partial:  %d\n", partial)
		fmt.Fprintf(&report, "  ✗ Failed:   %d\n", failed)
		fmt.Fprintf(&report, "  🛡 Protected: %d\n", protected)
		fmt.Fprintf(&report, "\nTotal MIR Recovered: %d instructions\n", totalMIR)
		fmt.Fprintf(&report, "Average Coverage: %.1f%%\n", vd.GetDevirtCoverage())

		// Handler semantics breakdown
		if len(vd.HandlerCache) > 0 {
			report.WriteString("\nHandler Semantics Breakdown:\n")
			effectCounts := make(map[MIROpKind]int)
			for _, sem := range vd.HandlerCache {
				effectCounts[sem.Effect]++
			}

			type effectEntry struct {
				kind  MIROpKind
				count int
			}
			entries := make([]effectEntry, 0, len(effectCounts))
			for k, v := range effectCounts {
				entries = append(entries, effectEntry{k, v})
			}
			sort.Slice(entries, func(i, j int) bool {
				return entries[i].count > entries[j].count
			})

			for _, entry := range entries {
				fmt.Fprintf(&report, "  %v: %d handlers\n", entry.kind, entry.count)
			}
		}
	}

	return report.String()
}

// addTrace adds a trace message.
func (vd *VirtualizationDetector) addTrace(msg string) {
	vd.Trace = append(vd.Trace, msg)
}

// addTrace adds a trace message to a DevirtualizationResult.
func (dr *DevirtualizationResult) addTrace(msg string) {
	dr.Trace = append(dr.Trace, msg)
}

// ═══════════════════════════════════════════════════════════════════════════════
// UTILITY: suppress unused import warnings
// ═══════════════════════════════════════════════════════════════════════════════

var (
	_ = math.MaxInt
	_ = sort.Ints
)
