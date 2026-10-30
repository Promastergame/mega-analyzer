package apkid

// ahoCorasick is a classic multi-pattern automaton. It lets the engine find
// every literal pattern from every rule in a single O(len(data)) pass, instead
// of running one bytes.Index per pattern per file.
type acNode struct {
	children map[byte]int
	fail     int
	outputs  []int // indices into patterns that terminate at this node
}

type ahoCorasick struct {
	nodes    []acNode
	patterns [][]byte
}

// newAhoCorasick builds an automaton from the given byte patterns. Empty
// patterns are ignored.
func newAhoCorasick(patterns [][]byte) *ahoCorasick {
	ac := &ahoCorasick{patterns: patterns}
	ac.nodes = []acNode{{children: map[byte]int{}}}
	for i, p := range patterns {
		if len(p) == 0 {
			continue
		}
		cur := 0
		for j := 0; j < len(p); j++ {
			b := p[j]
			nxt, ok := ac.nodes[cur].children[b]
			if !ok {
				nxt = len(ac.nodes)
				ac.nodes = append(ac.nodes, acNode{children: map[byte]int{}})
				ac.nodes[cur].children[b] = nxt
			}
			cur = nxt
		}
		ac.nodes[cur].outputs = append(ac.nodes[cur].outputs, i)
	}
	ac.buildFailLinks()
	return ac
}

func (ac *ahoCorasick) buildFailLinks() {
	queue := make([]int, 0, len(ac.nodes))
	for _, c := range ac.nodes[0].children {
		ac.nodes[c].fail = 0
		queue = append(queue, c)
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for b, nxt := range ac.nodes[cur].children {
			queue = append(queue, nxt)
			f := ac.nodes[cur].fail
			for f != 0 {
				if _, ok := ac.nodes[f].children[b]; ok {
					break
				}
				f = ac.nodes[f].fail
			}
			if child, ok := ac.nodes[f].children[b]; ok && child != nxt {
				ac.nodes[nxt].fail = child
			} else {
				ac.nodes[nxt].fail = 0
			}
			// Fail node is shallower (processed earlier), so its outputs are
			// already fully merged.
			ac.nodes[nxt].outputs = append(ac.nodes[nxt].outputs,
				ac.nodes[ac.nodes[nxt].fail].outputs...)
		}
	}
}

// findAll returns, for every pattern that occurs in data, the offset of its
// first occurrence.
func (ac *ahoCorasick) findAll(data []byte) map[int]int {
	hits := map[int]int{}
	if len(ac.nodes) <= 1 {
		return hits
	}
	cur := 0
	for i := 0; i < len(data); i++ {
		b := data[i]
		for cur != 0 {
			if _, ok := ac.nodes[cur].children[b]; ok {
				break
			}
			cur = ac.nodes[cur].fail
		}
		if nxt, ok := ac.nodes[cur].children[b]; ok {
			cur = nxt
		}
		for _, pi := range ac.nodes[cur].outputs {
			if _, seen := hits[pi]; !seen {
				hits[pi] = i - len(ac.patterns[pi]) + 1
			}
		}
	}
	return hits
}
