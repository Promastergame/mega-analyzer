package types

// ═══════════════════════════════════════════════════════════════════════════════
// GRAPHS
// ═══════════════════════════════════════════════════════════════════════════════

// MethodNode — узел в графе вызовов.
type MethodNode struct {
	SourceLocation
	FullName string   `json:"full_name"`
	Class    string   `json:"class"`
	Method   string   `json:"method"`
	Calls    []string `json:"calls,omitempty"`
	CalledBy []string `json:"called_by,omitempty"`
}

// CallGraph — граф вызовов методов.
type CallGraph struct {
	Nodes map[string]*MethodNode `json:"nodes,omitempty"`
}

func NewCallGraph() *CallGraph {
	return &CallGraph{Nodes: make(map[string]*MethodNode)}
}

func (g *CallGraph) AddNode(fullName string) *MethodNode {
	if g.Nodes == nil {
		g.Nodes = make(map[string]*MethodNode)
	}
	if node, ok := g.Nodes[fullName]; ok {
		return node
	}
	node := &MethodNode{FullName: fullName}
	g.Nodes[fullName] = node
	return node
}

// CFGNodeType — тип узла CFG.
type CFGNodeType uint8

const (
	CFGNodeBasic CFGNodeType = iota
	CFGNodeEntry
	CFGNodeExit
	CFGNodeBranch
	CFGNodeMerge
	CFGNodeLoop
	cfgNodeTypeCount
)

var cfgNodeTypeNames = [cfgNodeTypeCount]string{
	"basic", "entry", "exit", "branch", "merge", "loop",
}

func (t CFGNodeType) String() string {
	if t < cfgNodeTypeCount {
		return cfgNodeTypeNames[t]
	}
	return "unknown"
}

// CFGNode — узел графа потока управления.
type CFGNode struct {
	ID           int           `json:"id"`
	Type         CFGNodeType   `json:"type"`
	LineStart    int           `json:"line_start"`
	LineEnd      int           `json:"line_end"`
	Instructions []Instruction `json:"instructions,omitempty"`
	Successors   []int         `json:"successors,omitempty"`
	Predecessors []int         `json:"predecessors,omitempty"`
	Condition    *Condition    `json:"condition,omitempty"`
}

type CFGEdgeType uint8

const (
	CFGEdgeFallthrough CFGEdgeType = iota
	CFGEdgeBranch
	CFGEdgeBackedge
	CFGEdgeException
)

var cfgEdgeTypeNames = [4]string{"fallthrough", "branch", "backedge", "exception"}

func (t CFGEdgeType) String() string {
	if int(t) < len(cfgEdgeTypeNames) {
		return cfgEdgeTypeNames[t]
	}
	return "unknown"
}

type CFGEdge struct {
	From  int         `json:"from"`
	To    int         `json:"to"`
	Type  CFGEdgeType `json:"type"`
	Label string      `json:"label,omitempty"`
}

type ControlFlowGraph struct {
	Nodes     []CFGNode      `json:"nodes"`
	Edges     []CFGEdge      `json:"edges,omitempty"`
	Labels    map[string]int `json:"labels,omitempty"`
	EntryNode int            `json:"entry_node"`
	ExitNodes []int          `json:"exit_nodes,omitempty"`
}
