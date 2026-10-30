package analysis

import "mega-analyzer/pkg/binzap/ir"

// Node is a CFG node wrapping a basic block.
type Node struct {
	ID    int
	Block *ir.Block
	Succs []int
}

// CFG is a simple control-flow graph over a method's basic blocks.
type CFG struct {
	Nodes []*Node
}

// BuildCFG constructs a CFG from a lowered method.
func BuildCFG(m *ir.Method) *CFG {
	g := &CFG{}
	index := map[*ir.Block]int{}
	for i, b := range m.Blocks {
		index[b] = i
		g.Nodes = append(g.Nodes, &Node{ID: i, Block: b})
	}
	for i, b := range m.Blocks {
		for _, s := range b.Succs {
			if si, ok := index[s]; ok {
				g.Nodes[i].Succs = append(g.Nodes[i].Succs, si)
			}
		}
		if len(b.Succs) == 0 && i+1 < len(m.Blocks) {
			g.Nodes[i].Succs = append(g.Nodes[i].Succs, i+1)
		}
	}
	return g
}

// Reachable returns the set of node IDs reachable from the entry (node 0).
func (g *CFG) Reachable() map[int]bool {
	seen := map[int]bool{}
	if len(g.Nodes) == 0 {
		return seen
	}
	stack := []int{0}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[n] {
			continue
		}
		seen[n] = true
		for _, s := range g.Nodes[n].Succs {
			if !seen[s] {
				stack = append(stack, s)
			}
		}
	}
	return seen
}
