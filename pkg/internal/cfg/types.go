package cfg

import (
	"fmt"
	"strings"

	"mega-analyzer/pkg/internal/dexir"
)

// ═══════════════════════════════════════════════════════════════════════════════
// GUARD TYPE
// ═══════════════════════════════════════════════════════════════════════════════

// GuardType categorizes the kind of guard
type GuardType int

const (
	GuardTypeUnknown    GuardType = iota
	GuardTypeNull                 // null check
	GuardTypeBounds               // array bounds
	GuardTypeType                 // instanceof check
	GuardTypeLicense              // license/billing check
	GuardTypeRoot                 // root detection
	GuardTypeDebug                // debug/tamper check
	GuardTypeNetwork              // network availability
	GuardTypePermission           // permission check
)

func (g GuardType) String() string {
	names := [...]string{
		"unknown", "null", "bounds", "type", "license",
		"root", "debug", "network", "permission",
	}
	if int(g) < len(names) {
		return names[g]
	}
	return "unknown"
}

// ═══════════════════════════════════════════════════════════════════════════════
// NODE TYPES
// ═══════════════════════════════════════════════════════════════════════════════

type NodeType uint8

const (
	NodeTypeEntry NodeType = iota
	NodeTypeBasic
	NodeTypeCondition
	NodeTypeSwitch
	NodeTypeReturn
	NodeTypeThrow
	NodeTypeExit
	NodeTypeCatch
	NodeTypeGuard
	NodeTypeFunnel
	NodeTypePhi          // SSA phi-node
	NodeTypeCallSite     // ICFG call site
	NodeTypeMonitorEnter // synchronized block start
	NodeTypeMonitorExit  // synchronized block end
	NodeTypeSynthetic    // synthetic block (critical edge split)
)

func (t NodeType) String() string {
	names := [...]string{
		"entry", "basic", "condition", "switch", "return", "throw",
		"exit", "catch", "guard", "funnel", "phi", "callsite",
		"monitor-enter", "monitor-exit", "synthetic",
	}
	if int(t) < len(names) {
		return names[t]
	}
	return fmt.Sprintf("unknown(%d)", t)
}

func (t NodeType) IsTerminator() bool {
	return t == NodeTypeReturn || t == NodeTypeThrow || t == NodeTypeExit
}

func (t NodeType) IsBranching() bool {
	return t == NodeTypeCondition || t == NodeTypeSwitch
}

// ═══════════════════════════════════════════════════════════════════════════════
// EXIT KIND - разделение return/throw
// ═══════════════════════════════════════════════════════════════════════════════

type ExitKind uint8

const (
	ExitNormal      ExitKind = iota // return
	ExitException                   // throw
	ExitUnreachable                 // после infinite loop
)

func (k ExitKind) String() string {
	return [...]string{"normal", "exception", "unreachable"}[k]
}

// ═══════════════════════════════════════════════════════════════════════════════
// EDGE TYPES
// ═══════════════════════════════════════════════════════════════════════════════

type EdgeType uint8

const (
	EdgeFallthrough EdgeType = iota
	EdgeTrue
	EdgeFalse
	EdgeGoto
	EdgeSwitch
	EdgeException
	EdgeCall    // ICFG: caller → callee entry
	EdgeReturn  // ICFG: callee exit → caller
	EdgeSummary // ICFG: caller → caller (через callee)
)

func (t EdgeType) String() string {
	names := [...]string{
		"fallthrough", "true", "false", "goto", "switch",
		"exception", "call", "return", "summary",
	}
	if int(t) < len(names) {
		return names[t]
	}
	return fmt.Sprintf("unknown(%d)", t)
}

// ═══════════════════════════════════════════════════════════════════════════════
// VALUE REFERENCE - для SSA и condition analysis
// ═══════════════════════════════════════════════════════════════════════════════

type ValueKind uint8

const (
	ValueUnknown  ValueKind = iota
	ValueRegister           // v0, p0
	ValueConst              // 0, 1, "string"
	ValueField              // iget-object result
	ValueInvoke             // invoke result (move-result)
	ValuePhi                // SSA phi
	ValueParam              // method parameter
)

func (k ValueKind) String() string {
	return [...]string{"unknown", "reg", "const", "field", "invoke", "phi", "param"}[k]
}

type ValueRef struct {
	Kind ValueKind

	// Register info
	Register   string // v0, p0
	SSAVersion int    // v0_1, v0_2 в SSA

	// Constant info
	ConstValue interface{} // int, string, nil
	ConstType  string      // I, Z, Ljava/lang/String;

	// Field info
	FieldOwner string // Lcom/app/License;
	FieldName  string // isLicensed
	FieldType  string // Z

	// Invoke info
	InvokeTarget string // Lcom/app/License;->check()Z
	InvokeClass  string
	InvokeMethod string

	// Source tracking
	DefinedAt    *CFGNode
	DefinedInstr int // instruction index
}

func (v *ValueRef) IsZero() bool {
	if v.Kind != ValueConst {
		return false
	}
	switch val := v.ConstValue.(type) {
	case int:
		return val == 0
	case int64:
		return val == 0
	case bool:
		return !val
	case nil:
		return true
	}
	return false
}

func (v *ValueRef) IsBoolean() bool {
	return v.ConstType == "Z" || v.FieldType == "Z"
}

func (v *ValueRef) String() string {
	switch v.Kind {
	case ValueRegister:
		if v.SSAVersion > 0 {
			return fmt.Sprintf("%s_%d", v.Register, v.SSAVersion)
		}
		return v.Register
	case ValueConst:
		return fmt.Sprintf("const(%v)", v.ConstValue)
	case ValueField:
		return fmt.Sprintf("%s.%s", shortClassName(v.FieldOwner), v.FieldName)
	case ValueInvoke:
		return fmt.Sprintf("%s()", v.InvokeMethod)
	case ValuePhi:
		return fmt.Sprintf("φ(%s)", v.Register)
	case ValueParam:
		return fmt.Sprintf("param(%s)", v.Register)
	default:
		return "?"
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONDITION OPERATORS
// ═══════════════════════════════════════════════════════════════════════════════

type ConditionOp uint8

const (
	CondUnknown ConditionOp = iota
	CondEqZero              // if-eqz
	CondNeZero              // if-nez
	CondLtZero              // if-ltz
	CondGeZero              // if-gez
	CondGtZero              // if-gtz
	CondLeZero              // if-lez
	CondEq                  // if-eq
	CondNe                  // if-ne
	CondLt                  // if-lt
	CondGe                  // if-ge
	CondGt                  // if-gt
	CondLe                  // if-le
)

func (o ConditionOp) String() string {
	names := [...]string{
		"?", "==0", "!=0", "<0", ">=0", ">0", "<=0",
		"==", "!=", "<", ">=", ">", "<=",
	}
	if int(o) < len(names) {
		return names[o]
	}
	return "?"
}

func (o ConditionOp) Negate() ConditionOp {
	neg := map[ConditionOp]ConditionOp{
		CondEqZero: CondNeZero, CondNeZero: CondEqZero,
		CondLtZero: CondGeZero, CondGeZero: CondLtZero,
		CondGtZero: CondLeZero, CondLeZero: CondGtZero,
		CondEq: CondNe, CondNe: CondEq,
		CondLt: CondGe, CondGe: CondLt,
		CondGt: CondLe, CondLe: CondGt,
	}
	if n, ok := neg[o]; ok {
		return n
	}
	return CondUnknown
}

func (o ConditionOp) IsZeroCheck() bool {
	return o >= CondEqZero && o <= CondLeZero
}

func (o ConditionOp) IsBooleanCheck() bool {
	return o == CondEqZero || o == CondNeZero
}

func ParseConditionOp(opcode string) ConditionOp {
	ops := map[string]ConditionOp{
		"if-eqz": CondEqZero, "if-nez": CondNeZero,
		"if-ltz": CondLtZero, "if-gez": CondGeZero,
		"if-gtz": CondGtZero, "if-lez": CondLeZero,
		"if-eq": CondEq, "if-ne": CondNe,
		"if-lt": CondLt, "if-ge": CondGe,
		"if-gt": CondGt, "if-le": CondLe,
	}
	if op, ok := ops[opcode]; ok {
		return op
	}
	return CondUnknown
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONDITION INFO - расширенный
// ═══════════════════════════════════════════════════════════════════════════════

type ConditionInfo struct {
	Op ConditionOp

	// Value references (не просто строки!)
	LHS *ValueRef // левая часть
	RHS *ValueRef // правая часть (nil для zero-checks)

	// Legacy (для совместимости)
	Register1 string
	Register2 string

	// Target
	Target    string // label name
	TargetIdx int    // instruction index

	// Semantic info
	TruthOnTrueEdge bool // какое значение на true edge
	IsNullCheck     bool
	IsBooleanCheck  bool

	// Inferred meaning
	Meaning ConditionMeaning
}

type ConditionMeaning uint8

const (
	MeaningUnknown ConditionMeaning = iota
	MeaningLicenseCheck
	MeaningPremiumCheck
	MeaningPurchaseCheck
	MeaningTrialCheck
	MeaningRootCheck
	MeaningDebugCheck
	MeaningNullCheck
)

func (c *ConditionInfo) Evaluate(lhs, rhs interface{}) (result bool, known bool) {
	// Попытка статической оценки условия
	if c.Op.IsZeroCheck() {
		if c.LHS != nil && c.LHS.Kind == ValueConst {
			isZero := c.LHS.IsZero()
			switch c.Op {
			case CondEqZero:
				return isZero, true
			case CondNeZero:
				return !isZero, true
			}
		}
	}
	return false, false
}

// ═══════════════════════════════════════════════════════════════════════════════
// EDGE PREDICATE - семантика перехода
// ═══════════════════════════════════════════════════════════════════════════════

type EdgePredicate struct {
	Condition *ConditionInfo
	Expected  bool // true = condition must be true, false = must be false

	// Derived info
	Implies []*ValueConstraint // какие constraints накладывает
}

type ValueConstraint struct {
	Value   *ValueRef
	Op      ConditionOp
	Against *ValueRef
}

// ═══════════════════════════════════════════════════════════════════════════════
// LOOP TYPE
// ═══════════════════════════════════════════════════════════════════════════════

type LoopType uint8

const (
	LoopNatural     LoopType = iota // Single header, reducible
	LoopIrreducible                 // Multiple entries
	LoopInfinite                    // No exits
)

func (t LoopType) String() string {
	return [...]string{"natural", "irreducible", "infinite"}[t]
}

// ═══════════════════════════════════════════════════════════════════════════════
// CFG NODE - полная структура
// ═══════════════════════════════════════════════════════════════════════════════

type CFGNode struct {
	ID   int
	Type NodeType

	// Instruction range (by index!)
	StartIdx  int
	EndIdx    int
	LineStart int
	LineEnd   int

	// Instructions
	Instructions []InstructionRef

	// Graph structure (POINTERS!)
	Successors   []*CFGNode
	Predecessors []*CFGNode

	// Condition (for condition nodes)
	Condition *ConditionInfo

	// Switch info
	SwitchInfo *SwitchInfo

	// Exception handling
	ExceptionHandler *ExceptionHandler
	TryBlockID       int // какому try-block принадлежит

	// ═══════════════════════════════════════════════════════════════════
	// DOMINATORS - вычисляются
	// ═══════════════════════════════════════════════════════════════════
	Dominators        []*CFGNode
	ImmediateDom      *CFGNode
	DominanceFrontier []*CFGNode // DF[n] - хранится в ноде!
	DomTreeChildren   []*CFGNode // дети в dominator tree
	DomTreeDepth      int

	// Post-dominators
	PostDominators   []*CFGNode
	ImmediatePostDom *CFGNode
	PostDomFrontier  []*CFGNode

	// ═══════════════════════════════════════════════════════════════════
	// LOOPS
	// ═══════════════════════════════════════════════════════════════════
	LoopHeader   *CFGNode
	LoopDepth    int
	IsLoopHeader bool
	LoopType     LoopType

	// ═══════════════════════════════════════════════════════════════════
	// PATTERNS
	// ═══════════════════════════════════════════════════════════════════
	IsGuard    bool
	GuardInfo  *GuardInfo
	IsFunnel   bool
	FunnelInfo *FunnelInfo

	// ═══════════════════════════════════════════════════════════════════
	// SSA
	// ═══════════════════════════════════════════════════════════════════
	PhiNodes    []*PhiNode
	Definitions map[string]*ValueRef // register → SSA value

	// ═══════════════════════════════════════════════════════════════════
	// EXIT INFO
	// ═══════════════════════════════════════════════════════════════════
	ExitKind    ExitKind
	ReturnValue *ValueRef // для return nodes

	// ═══════════════════════════════════════════════════════════════════
	// ICFG
	// ═══════════════════════════════════════════════════════════════════
	CallSite *CallSiteInfo

	// ═══════════════════════════════════════════════════════════════════
	// BUILD FLAGS
	// ═══════════════════════════════════════════════════════════════════
	Reachable     bool
	IsUnreachable bool // ← ДОБАВЛЕНО
	CanReachExit  bool
	IsSynthetic   bool // ← ДОБАВЛЕНО (для critical edge split)
	RPONumber     int  // ← ДОБАВЛЕНО (reverse post-order number)

	// Block characteristics
	HasInvoke      bool // ← ДОБАВЛЕНО
	HasFieldAccess bool // ← ДОБАВЛЕНО

	// ═══════════════════════════════════════════════════════════════════
	// ANALYSIS FLAGS
	// ═══════════════════════════════════════════════════════════════════
	Analyzed bool
	Visited  bool
}

type InstructionRef struct {
	Index  int
	Opcode string
	Line   int
	Raw    string
	IR     *dexir.Instruction // typed operands (always populated by the builder)
}

type SwitchInfo struct {
	Type     SwitchType
	Register string
	Targets  []SwitchTarget
	Default  int
}

type SwitchType uint8

const (
	SwitchPacked SwitchType = iota
	SwitchSparse
)

type SwitchTarget struct {
	Key      int
	Label    string
	TargetID int
}

type ExceptionHandler struct {
	Type       string
	StartIdx   int
	EndIdx     int
	HandlerIdx int
}

type GuardInfo struct {
	Condition   *ConditionInfo
	GuardEdge   EdgeType // which edge is the guard
	ActionNode  *CFGNode // return/throw node
	ActionType  NodeType
	Meaning     ConditionMeaning
	Description string

	// Path-sensitive
	DominatesExit bool // condition dominates exit
	ExitPostDoms  bool // exit post-dominates condition
}

type FunnelInfo struct {
	SourceNodes []*CFGNode
	Conditions  []*ConditionInfo
	ReturnValue *ValueRef
	Purpose     string

	// SAT analysis
	RequiresAllTrue  bool // AND-funnel
	RequiresAnyFalse bool // OR-funnel (short-circuit false)
}

type CallSiteInfo struct {
	CallerNode   *CFGNode
	TargetMethod string
	TargetClass  string
	Arguments    []*ValueRef
	ReturnValue  *ValueRef

	// ICFG edges
	CalleeEntry *CFGNode // в другом CFG
	CalleeExits []*CFGNode
}

// ═══════════════════════════════════════════════════════════════════════════════
// CFG EDGE
// ═══════════════════════════════════════════════════════════════════════════════

type CFGEdge struct {
	From  *CFGNode
	To    *CFGNode
	Type  EdgeType
	Label string

	// Predicate (NOT Condition!)
	Predicate *EdgePredicate

	// For exception edges
	ExceptionType string

	// For critical edge splitting
	IsCriticalSplit bool // ← ДОБАВЛЕНО
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONTROL FLOW GRAPH
// ═══════════════════════════════════════════════════════════════════════════════

type ControlFlowGraph struct {
	// Identity
	MethodName string
	ClassName  string
	Signature  string
	FullName   string

	// Graph structure
	Nodes []*CFGNode
	Edges []*CFGEdge

	// Special nodes
	Entry *CFGNode
	Exits []*CFGNode

	// Exits by kind
	ReturnExits []*CFGNode
	ThrowExits  []*CFGNode

	// Indexes
	LabelIndex *LabelIndex
	NodeByIdx  map[int]*CFGNode
	EdgeIndex  map[edgeKey]*CFGEdge

	// Exception handling
	TryBlocks []TryBlock
	Handlers  []*CFGNode

	// Ordering
	RPOOrder []*CFGNode // reverse post-order

	// Analysis state
	DominatorTree       bool
	PostDomTree         bool
	SSAConstructed      bool
	LoopsAnalyzed       bool
	PatternsFound       bool
	ControlDepsComputed bool

	// ═══════════════════════════════════════════════════════════════════════════════
	// DFG: Raw method instructions for data flow analysis
	// ═══════════════════════════════════════════════════════════════════════════════
	Method *MethodInfo
	// ═══════════════════════════════════════════════════════════════════════════════

	// Analysis results
	Loops   []*Loop
	Guards  []*GuardInfo
	Funnels []*FunnelInfo

	// Control dependencies - два формата для совместимости
	ControlDeps         map[int][]*CFGNode  // для ComputeControlDependencies()
	ControlDepsDetailed []ControlDependence // для ComputeControlDependence()
}

// MethodInfo wraps instruction data
type MethodInfo struct {
	Instructions []*Instruction
}

type TryBlock struct {
	ID       int
	StartIdx int
	EndIdx   int
	Handlers []ExceptionHandler
}

type edgeKey struct {
	from, to int
}

// ═══════════════════════════════════════════════════════════════════════════════
// CFG METHODS
// ═══════════════════════════════════════════════════════════════════════════════

func (g *ControlFlowGraph) NodeCount() int { return len(g.Nodes) }
func (g *ControlFlowGraph) EdgeCount() int { return len(g.Edges) }

func (g *ControlFlowGraph) GetNode(id int) *CFGNode {
	if id >= 0 && id < len(g.Nodes) {
		return g.Nodes[id]
	}
	return nil
}

func (g *ControlFlowGraph) FindEdge(from, to *CFGNode) *CFGEdge {
	key := edgeKey{from.ID, to.ID}
	return g.EdgeIndex[key]
}

func (g *ControlFlowGraph) AddEdge(from, to *CFGNode, edgeType EdgeType) *CFGEdge {
	edge := &CFGEdge{
		From: from,
		To:   to,
		Type: edgeType,
	}

	from.Successors = append(from.Successors, to)
	to.Predecessors = append(to.Predecessors, from)

	g.Edges = append(g.Edges, edge)

	if g.EdgeIndex == nil {
		g.EdgeIndex = make(map[edgeKey]*CFGEdge)
	}
	g.EdgeIndex[edgeKey{from.ID, to.ID}] = edge

	return edge
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

func shortClassName(fullName string) string {
	if idx := strings.LastIndex(fullName, "/"); idx >= 0 {
		return strings.TrimSuffix(fullName[idx+1:], ";")
	}
	return strings.Trim(fullName, "L;")
}

// ═══════════════════════════════════════════════════════════════════════════════
// ДОПОЛНИТЕЛЬНЫЕ ТИПЫ (для полноты)
// ═══════════════════════════════════════════════════════════════════════════════

type PhiOperand struct {
	Value  *ValueRef
	Source *CFGNode
}
