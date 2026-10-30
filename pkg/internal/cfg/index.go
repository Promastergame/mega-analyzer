package cfg

import (
	"strings"

	"mega-analyzer/pkg/internal/dexir"
)

// ═══════════════════════════════════════════════════════════════════════════════
// LABEL INDEX — Fast label ↔ instruction index mapping
// ═══════════════════════════════════════════════════════════════════════════════

type LabelIndex struct {
	labelToIdx  map[string]int
	idxToLabels map[int][]string
	labelToLine map[string]int
	lineToLabel map[int]string
}

func NewLabelIndex() *LabelIndex {
	return &LabelIndex{
		labelToIdx:  make(map[string]int),
		idxToLabels: make(map[int][]string),
		labelToLine: make(map[string]int),
		lineToLabel: make(map[int]string),
	}
}

func (idx *LabelIndex) BuildFromMethod(instructions []Instruction, labels []Label) {
	lineToIdx := make(map[int]int, len(instructions))
	for i, instr := range instructions {
		lineToIdx[instr.Line] = i
	}

	for _, label := range labels {
		targetLine := label.Line + 1

		if instrIdx, ok := lineToIdx[targetLine]; ok {
			idx.labelToIdx[label.Name] = instrIdx
			idx.idxToLabels[instrIdx] = append(idx.idxToLabels[instrIdx], label.Name)
		} else {
			// Fallback: try exact line match (some parsers use this convention)
			if instrIdx, ok := lineToIdx[label.Line]; ok {
				idx.labelToIdx[label.Name] = instrIdx
				idx.idxToLabels[instrIdx] = append(idx.idxToLabels[instrIdx], label.Name)
			}
		}

		idx.labelToLine[label.Name] = label.Line
		idx.lineToLabel[label.Line] = label.Name
	}
}

func (idx *LabelIndex) GetInstructionIndex(label string) (int, bool) {
	i, ok := idx.labelToIdx[label]
	return i, ok
}

// SetLabel directly associates a label name with an instruction index.
// Later calls with the same name overwrite earlier ones, matching the
// last-wins semantics of BuildFromMethod's line-based resolution.
func (idx *LabelIndex) SetLabel(name string, instrIdx int) {
	idx.labelToIdx[name] = instrIdx
	idx.idxToLabels[instrIdx] = append(idx.idxToLabels[instrIdx], name)
}

func (idx *LabelIndex) GetLabels(instrIdx int) []string {
	return idx.idxToLabels[instrIdx]
}

func (idx *LabelIndex) HasLabel(label string) bool {
	_, ok := idx.labelToIdx[label]
	return ok
}

// Size returns the number of labels indexed
func (idx *LabelIndex) Size() int {
	return len(idx.labelToIdx)
}

// AllLabels returns all known label names
func (idx *LabelIndex) AllLabels() []string {
	result := make([]string, 0, len(idx.labelToIdx))
	for name := range idx.labelToIdx {
		result = append(result, name)
	}
	return result
}

// ═══════════════════════════════════════════════════════════════════════════════
// INSTRUCTION INDEX — Comprehensive instruction classification & lookup
// ═══════════════════════════════════════════════════════════════════════════════

// SemanticType classifies instructions at a higher level
type SemanticType int

const (
	SemanticOther       SemanticType = iota
	SemanticBranch                   // if-*, goto, switch
	SemanticReturn                   // return*
	SemanticInvoke                   // invoke-*
	SemanticFieldRead                // iget, sget
	SemanticFieldWrite               // iput, sput
	SemanticArrayRead                // aget
	SemanticArrayWrite               // aput
	SemanticMonitor                  // monitor-enter/exit
	SemanticThrow                    // throw
	SemanticMove                     // move*
	SemanticConst                    // const*
	SemanticArithmetic               // add, sub, mul, div, rem
	SemanticLogical                  // and, or, xor, shl, shr
	SemanticConversion               // int-to-long, etc
	SemanticComparison               // cmp*
	SemanticNewInstance              // new-instance
	SemanticNewArray                 // new-array
	SemanticCheckCast                // check-cast
	SemanticInstanceOf               // instance-of
	SemanticFillArray                // fill-array-data
)

// Instruction represents a single smali instruction.
//
// IR is the typed dexir representation and the source of truth for
// register operands, branch targets, payloads and references. The
// builder, SSA and DFG phases read IR exclusively; Opcode/Operands/Raw
// remain populated for legacy consumers (pattern matching, metrics,
// reports) and may be empty for DEX-origin input.
type Instruction struct {
	Index    int
	Line     int
	Opcode   string
	Operands []string
	Raw      string

	IR *dexir.Instruction // typed source of truth (always populated by the builder)

	// ═══════════════════════════════════════════════════════════════════════════════
	// DFG (Data Flow Graph) fields - NEW
	// ═══════════════════════════════════════════════════════════════════════════════
	DefRegs   []string // Registers defined by this instruction (written)
	UseRegs   []string // Registers used by this instruction (read)
	ConstVal  *string  // Constant value (for const-string, const/4, etc.)
	InvokeRef string   // Method reference (for invoke-*)
	FieldRef  string   // Field reference (for iget/iput/sget/sput)
	MoveSrc   string   // Source register for move instructions
	// ═══════════════════════════════════════════════════════════════════════════════
}

// Label represents a label in smali
type Label struct {
	Name string
	Line int
}

// InstructionIndex provides fast lookups for instructions
type InstructionIndex struct {
	instructions []Instruction

	// Primary indexes
	byLine   map[int]int      // line → index
	byOpcode map[string][]int // opcode → indices

	// Classified instruction indices
	branches    []int
	returns     []int
	invokes     []int
	conditions  []int
	throws      []int
	gotos       []int
	switches    []int
	monitors    []int
	fieldReads  []int
	fieldWrites []int
	moves       []int
	consts      []int
	news        []int

	// Semantic classification
	semantics []SemanticType

	// Register def-use tracking
	defs map[string][]int // register → instruction indices that define it
	uses map[string][]int // register → instruction indices that use it
}

func NewInstructionIndex(instructions []Instruction) *InstructionIndex {
	idx := &InstructionIndex{
		instructions: instructions,
		byLine:       make(map[int]int, len(instructions)),
		byOpcode:     make(map[string][]int),
		branches:     make([]int, 0),
		returns:      make([]int, 0),
		invokes:      make([]int, 0),
		conditions:   make([]int, 0),
		throws:       make([]int, 0),
		gotos:        make([]int, 0),
		switches:     make([]int, 0),
		monitors:     make([]int, 0),
		fieldReads:   make([]int, 0),
		fieldWrites:  make([]int, 0),
		moves:        make([]int, 0),
		consts:       make([]int, 0),
		news:         make([]int, 0),
		semantics:    make([]SemanticType, len(instructions)),
		defs:         make(map[string][]int),
		uses:         make(map[string][]int),
	}

	for i, instr := range instructions {
		idx.byLine[instr.Line] = i
		idx.byOpcode[instr.Opcode] = append(idx.byOpcode[instr.Opcode], i)

		sem := classifyOpcode(instr.Opcode)
		idx.semantics[i] = sem

		switch sem {
		case SemanticBranch:
			idx.branches = append(idx.branches, i)
			if isConditionOpcode(instr.Opcode) {
				idx.conditions = append(idx.conditions, i)
			}
			if isGotoOpcode(instr.Opcode) {
				idx.gotos = append(idx.gotos, i)
			}
			if isSwitchOpcode(instr.Opcode) {
				idx.switches = append(idx.switches, i)
			}
		case SemanticReturn:
			idx.returns = append(idx.returns, i)
		case SemanticInvoke:
			idx.invokes = append(idx.invokes, i)
		case SemanticThrow:
			idx.throws = append(idx.throws, i)
		case SemanticMonitor:
			idx.monitors = append(idx.monitors, i)
		case SemanticFieldRead:
			idx.fieldReads = append(idx.fieldReads, i)
		case SemanticFieldWrite:
			idx.fieldWrites = append(idx.fieldWrites, i)
		case SemanticMove:
			idx.moves = append(idx.moves, i)
		case SemanticConst:
			idx.consts = append(idx.consts, i)
		case SemanticNewInstance, SemanticNewArray:
			idx.news = append(idx.news, i)
		}

		// Track register defs and uses
		idx.trackRegisters(i, instr)
	}

	return idx
}

// trackRegisters extracts register definitions and uses from an instruction
func (idx *InstructionIndex) trackRegisters(instrIdx int, instr Instruction) {
	if len(instr.Operands) == 0 {
		return
	}

	sem := idx.semantics[instrIdx]

	switch sem {
	case SemanticMove, SemanticConst, SemanticNewInstance, SemanticNewArray,
		SemanticCheckCast, SemanticInstanceOf, SemanticFieldRead,
		SemanticArrayRead, SemanticArithmetic, SemanticLogical,
		SemanticConversion, SemanticComparison:
		// First operand is typically the destination register
		if len(instr.Operands) > 0 && isRegister(instr.Operands[0]) {
			idx.defs[instr.Operands[0]] = append(idx.defs[instr.Operands[0]], instrIdx)
		}
		// Remaining operands are uses
		for j := 1; j < len(instr.Operands); j++ {
			if isRegister(instr.Operands[j]) {
				idx.uses[instr.Operands[j]] = append(idx.uses[instr.Operands[j]], instrIdx)
			}
		}

	case SemanticFieldWrite, SemanticArrayWrite:
		// All register operands are uses
		for _, op := range instr.Operands {
			if isRegister(op) {
				idx.uses[op] = append(idx.uses[op], instrIdx)
			}
		}

	case SemanticInvoke:
		// All register operands are uses; move-result will define the dest
		for _, op := range instr.Operands {
			if isRegister(op) {
				idx.uses[op] = append(idx.uses[op], instrIdx)
			}
		}

	case SemanticBranch:
		// Registers in conditions are uses
		for _, op := range instr.Operands {
			if isRegister(op) {
				idx.uses[op] = append(idx.uses[op], instrIdx)
			}
		}

	case SemanticReturn, SemanticThrow, SemanticMonitor:
		for _, op := range instr.Operands {
			if isRegister(op) {
				idx.uses[op] = append(idx.uses[op], instrIdx)
			}
		}
	}
}

// isRegister checks if a string looks like a Dalvik register
func isRegister(s string) bool {
	if len(s) < 2 {
		return false
	}
	return (s[0] == 'v' || s[0] == 'p') && s[1] >= '0' && s[1] <= '9'
}

// classifyOpcode maps an opcode to its semantic type
func classifyOpcode(opcode string) SemanticType {
	switch {
	case strings.HasPrefix(opcode, "if-") ||
		strings.HasPrefix(opcode, "goto") ||
		strings.HasPrefix(opcode, "packed-switch") ||
		strings.HasPrefix(opcode, "sparse-switch"):
		return SemanticBranch

	case strings.HasPrefix(opcode, "return"):
		return SemanticReturn

	case strings.HasPrefix(opcode, "invoke-"):
		return SemanticInvoke

	case opcode == "throw":
		return SemanticThrow

	case opcode == "monitor-enter" || opcode == "monitor-exit":
		return SemanticMonitor

	case strings.HasPrefix(opcode, "iget") || strings.HasPrefix(opcode, "sget"):
		return SemanticFieldRead

	case strings.HasPrefix(opcode, "iput") || strings.HasPrefix(opcode, "sput"):
		return SemanticFieldWrite

	case strings.HasPrefix(opcode, "aget"):
		return SemanticArrayRead

	case strings.HasPrefix(opcode, "aput"):
		return SemanticArrayWrite

	case strings.HasPrefix(opcode, "move"):
		return SemanticMove

	case strings.HasPrefix(opcode, "const"):
		return SemanticConst

	case strings.HasPrefix(opcode, "add-") || strings.HasPrefix(opcode, "sub-") ||
		strings.HasPrefix(opcode, "mul-") || strings.HasPrefix(opcode, "div-") ||
		strings.HasPrefix(opcode, "rem-") || strings.HasPrefix(opcode, "neg-"):
		return SemanticArithmetic

	case strings.HasPrefix(opcode, "and-") || strings.HasPrefix(opcode, "or-") ||
		strings.HasPrefix(opcode, "xor-") || strings.HasPrefix(opcode, "shl-") ||
		strings.HasPrefix(opcode, "shr-") || strings.HasPrefix(opcode, "ushr-") ||
		strings.HasPrefix(opcode, "not-"):
		return SemanticLogical

	case strings.HasSuffix(opcode, "-to-int") || strings.HasSuffix(opcode, "-to-long") ||
		strings.HasSuffix(opcode, "-to-float") || strings.HasSuffix(opcode, "-to-double") ||
		strings.HasSuffix(opcode, "-to-byte") || strings.HasSuffix(opcode, "-to-char") ||
		strings.HasSuffix(opcode, "-to-short"):
		return SemanticConversion

	case strings.HasPrefix(opcode, "cmp"):
		return SemanticComparison

	case opcode == "new-instance":
		return SemanticNewInstance

	case opcode == "new-array" || strings.HasPrefix(opcode, "filled-new-array"):
		return SemanticNewArray

	case opcode == "check-cast":
		return SemanticCheckCast

	case opcode == "instance-of":
		return SemanticInstanceOf

	case opcode == "fill-array-data":
		return SemanticFillArray

	default:
		return SemanticOther
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// LOOKUPS
// ═══════════════════════════════════════════════════════════════════════════════

func (idx *InstructionIndex) Get(i int) *Instruction {
	if i >= 0 && i < len(idx.instructions) {
		return &idx.instructions[i]
	}
	return nil
}

func (idx *InstructionIndex) Len() int {
	return len(idx.instructions)
}

func (idx *InstructionIndex) GetByLine(line int) *Instruction {
	if i, ok := idx.byLine[line]; ok {
		return &idx.instructions[i]
	}
	return nil
}

func (idx *InstructionIndex) GetSemantic(i int) SemanticType {
	if i >= 0 && i < len(idx.semantics) {
		return idx.semantics[i]
	}
	return SemanticOther
}

// GetByType returns all indices of a given semantic type
func (idx *InstructionIndex) GetByType(sem SemanticType) []int {
	switch sem {
	case SemanticBranch:
		return idx.branches
	case SemanticReturn:
		return idx.returns
	case SemanticInvoke:
		return idx.invokes
	case SemanticThrow:
		return idx.throws
	case SemanticMonitor:
		return idx.monitors
	case SemanticFieldRead:
		return idx.fieldReads
	case SemanticFieldWrite:
		return idx.fieldWrites
	case SemanticMove:
		return idx.moves
	case SemanticConst:
		return idx.consts
	case SemanticNewInstance, SemanticNewArray:
		return idx.news
	default:
		return nil
	}
}

func (idx *InstructionIndex) GetBranches() []int    { return idx.branches }
func (idx *InstructionIndex) GetReturns() []int     { return idx.returns }
func (idx *InstructionIndex) GetConditions() []int  { return idx.conditions }
func (idx *InstructionIndex) GetInvokes() []int     { return idx.invokes }
func (idx *InstructionIndex) GetThrows() []int      { return idx.throws }
func (idx *InstructionIndex) GetGotos() []int       { return idx.gotos }
func (idx *InstructionIndex) GetSwitches() []int    { return idx.switches }
func (idx *InstructionIndex) GetMonitors() []int    { return idx.monitors }
func (idx *InstructionIndex) GetFieldReads() []int  { return idx.fieldReads }
func (idx *InstructionIndex) GetFieldWrites() []int { return idx.fieldWrites }
func (idx *InstructionIndex) GetConsts() []int      { return idx.consts }
func (idx *InstructionIndex) GetMoves() []int       { return idx.moves }
func (idx *InstructionIndex) GetNews() []int        { return idx.news }

// ═══════════════════════════════════════════════════════════════════════════════
// REGISTER DEF-USE QUERIES
// ═══════════════════════════════════════════════════════════════════════════════

// GetDefs returns instruction indices that define the given register
func (idx *InstructionIndex) GetDefs(register string) []int {
	return idx.defs[register]
}

// GetUses returns instruction indices that use the given register
func (idx *InstructionIndex) GetUses(register string) []int {
	return idx.uses[register]
}

// GetAllRegisters returns all registers referenced in the method
func (idx *InstructionIndex) GetAllRegisters() []string {
	seen := make(map[string]bool)
	var regs []string

	for reg := range idx.defs {
		if !seen[reg] {
			seen[reg] = true
			regs = append(regs, reg)
		}
	}
	for reg := range idx.uses {
		if !seen[reg] {
			seen[reg] = true
			regs = append(regs, reg)
		}
	}

	return regs
}

// GetRange returns instructions in [start, end) range
func (idx *InstructionIndex) GetRange(start, end int) []Instruction {
	if start < 0 {
		start = 0
	}
	if end > len(idx.instructions) {
		end = len(idx.instructions)
	}
	if start >= end {
		return nil
	}
	result := make([]Instruction, end-start)
	copy(result, idx.instructions[start:end])
	return result
}

// ═══════════════════════════════════════════════════════════════════════════════
// OPCODE CLASSIFICATION (exported for other packages)
// ═══════════════════════════════════════════════════════════════════════════════

func isBranchOpcode(opcode string) bool {
	return strings.HasPrefix(opcode, "if-") ||
		strings.HasPrefix(opcode, "goto") ||
		strings.HasPrefix(opcode, "packed-switch") ||
		strings.HasPrefix(opcode, "sparse-switch")
}

func isReturnOpcode(opcode string) bool {
	return strings.HasPrefix(opcode, "return")
}

func isInvokeOpcode(opcode string) bool {
	return strings.HasPrefix(opcode, "invoke-")
}

func isConditionOpcode(opcode string) bool {
	return strings.HasPrefix(opcode, "if-")
}

func isGotoOpcode(opcode string) bool {
	return strings.HasPrefix(opcode, "goto")
}

func isSwitchOpcode(opcode string) bool {
	return strings.HasPrefix(opcode, "packed-switch") ||
		strings.HasPrefix(opcode, "sparse-switch")
}

func isThrowOpcode(opcode string) bool {
	return opcode == "throw"
}

func isMonitorOpcode(opcode string) bool {
	return opcode == "monitor-enter" || opcode == "monitor-exit"
}

func isFieldOpcode(opcode string) bool {
	return strings.HasPrefix(opcode, "iget") || strings.HasPrefix(opcode, "sget") ||
		strings.HasPrefix(opcode, "iput") || strings.HasPrefix(opcode, "sput")
}

func isMoveResultOpcode(opcode string) bool {
	return opcode == "move-result" || opcode == "move-result-wide" ||
		opcode == "move-result-object" || opcode == "move-exception"
}
