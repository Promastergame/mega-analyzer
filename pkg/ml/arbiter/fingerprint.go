package arbiter

import (
	"sort"
	"strconv"
	"strings"

	"mega-analyzer/pkg/internal/cfg"
	"mega-analyzer/pkg/ml/arbiter/hdc"
)

// wlIterations is the number of Weisfeiler-Leman refinement rounds. 2-3
// rounds is the standard sweet spot for WL graph fingerprints: enough to
// fold in 2-3 hop neighborhood structure without the label alphabet
// exploding (each round's label length grows with the graph, but round
// count stays tiny for basic-block-sized CFGs).
const wlIterations = 3

// opcodeCategory buckets a smali opcode into a small structural alphabet.
// This is the WL-hash's initial node label: coarse enough that renaming
// registers/labels (simple obfuscation) doesn't change it, specific enough
// that swapping e.g. an invoke for a field access does.
func opcodeCategory(opcode string) string {
	switch {
	case strings.HasPrefix(opcode, "invoke"):
		return "call"
	case strings.HasPrefix(opcode, "if") || strings.HasPrefix(opcode, "goto") || strings.HasPrefix(opcode, "switch"):
		return "branch"
	case strings.HasPrefix(opcode, "return"):
		return "return"
	case strings.HasPrefix(opcode, "throw"):
		return "throw"
	case strings.HasPrefix(opcode, "iget") || strings.HasPrefix(opcode, "iput") ||
		strings.HasPrefix(opcode, "sget") || strings.HasPrefix(opcode, "sput"):
		return "field"
	case strings.HasPrefix(opcode, "new-instance") || strings.HasPrefix(opcode, "new-array"):
		return "alloc"
	case strings.HasPrefix(opcode, "const"):
		return "const"
	case strings.HasPrefix(opcode, "move"):
		return "move"
	default:
		return "other"
	}
}

// blockLabel is the initial WL label for a CFG node: the multiset of its
// instructions' opcode categories, counted and sorted for determinism.
func blockLabel(node *cfg.CFGNode) string {
	counts := map[string]int{}
	for _, instr := range node.Instructions {
		counts[opcodeCategory(instr.Opcode)]++
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte(':')
		b.WriteString(strconv.Itoa(counts[k]))
		b.WriteByte(',')
	}
	return b.String()
}

// WLFingerprint computes a Weisfeiler-Leman structural fingerprint of a
// function's control flow graph as a single hdc.Vector: wlIterations rounds
// of "relabel each node as hash(own label + sorted neighbor labels)", then
// bundle every node's final-round label into one hypervector for the whole
// function. Two functions with similar control-flow shape and similar
// per-block instruction-category mix land close in Hamming distance even
// after cosmetic obfuscation (renamed registers/labels/strings), because
// none of that survives into opcodeCategory or the label multiset.
func WLFingerprint(g *cfg.ControlFlowGraph) hdc.Vector {
	if g == nil || len(g.Nodes) == 0 {
		return hdc.Vector{}
	}

	labels := make(map[int]string, len(g.Nodes))
	for _, n := range g.Nodes {
		labels[n.ID] = blockLabel(n)
	}

	for iter := 0; iter < wlIterations; iter++ {
		next := make(map[int]string, len(g.Nodes))
		for _, n := range g.Nodes {
			neighborLabels := make([]string, 0, len(n.Successors)+len(n.Predecessors))
			for _, s := range n.Successors {
				if s != nil {
					neighborLabels = append(neighborLabels, labels[s.ID])
				}
			}
			for _, p := range n.Predecessors {
				if p != nil {
					neighborLabels = append(neighborLabels, labels[p.ID])
				}
			}
			sort.Strings(neighborLabels)
			next[n.ID] = labels[n.ID] + "|" + strings.Join(neighborLabels, ";")
		}
		labels = next
	}

	vecs := make([]hdc.Vector, 0, len(g.Nodes))
	for _, n := range g.Nodes {
		vecs = append(vecs, hdc.Atom("wl:"+labels[n.ID]))
	}
	return hdc.Bundle(vecs...)
}
