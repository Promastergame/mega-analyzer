package cfg

// ═══════════════════════════════════════════════════════════════════════════════
// DOMINATOR ANALYSIS — Lengauer-Tarjan with Iterative Path Compression
//                     + Cooper's DF + Control Dependence Graph
// ═══════════════════════════════════════════════════════════════════════════════
//
// Improvements over original:
//   • Iterative compress() — prevents stack overflow on deep CFGs
//   • Control Dependence Graph computation
//   • Binary Lifting for O(log N) LCA queries
//   • Dominator tree iterators (preorder, postorder, BFS)
//   • O(1) dominance depth queries
//   • Proper post-dominator with unified virtual exit
// ═══════════════════════════════════════════════════════════════════════════════

type DominatorAnalyzer struct {
	cfg *ControlFlowGraph

	// Lengauer-Tarjan state
	parent   []*CFGNode
	semi     []int
	vertex   []*CFGNode
	bucket   [][]*CFGNode
	dom      []*CFGNode
	ancestor []*CFGNode
	label    []*CFGNode

	n int

	// Binary lifting for O(log N) LCA
	liftUp  [][]*CFGNode // liftUp[k][v] = 2^k-th ancestor of v
	maxLogN int
}

func NewDominatorAnalyzer(cfg *ControlFlowGraph) *DominatorAnalyzer {
	return &DominatorAnalyzer{cfg: cfg}
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMPUTE DOMINATORS
// ═══════════════════════════════════════════════════════════════════════════════

func (d *DominatorAnalyzer) ComputeDominators() {
	if d.cfg == nil || len(d.cfg.Nodes) == 0 {
		return
	}

	n := len(d.cfg.Nodes)

	d.parent = make([]*CFGNode, n)
	d.semi = make([]int, n)
	d.vertex = make([]*CFGNode, n)
	d.bucket = make([][]*CFGNode, n)
	d.dom = make([]*CFGNode, n)
	d.ancestor = make([]*CFGNode, n)
	d.label = make([]*CFGNode, n)

	for i := range d.semi {
		d.semi[i] = -1
		d.bucket[i] = make([]*CFGNode, 0, 2)
		d.label[i] = d.cfg.Nodes[i]
	}

	d.n = 0

	// Step 1: DFS numbering (iterative to avoid stack overflow)
	d.dfsIterative(d.cfg.Entry)

	// Steps 2-3: Semidominators and implicit dominators
	for i := d.n - 1; i >= 1; i-- {
		w := d.vertex[i]

		for _, v := range w.Predecessors {
			if d.semi[v.ID] < 0 {
				continue
			}
			u := d.eval(v)
			if d.semi[u.ID] < d.semi[w.ID] {
				d.semi[w.ID] = d.semi[u.ID]
			}
		}

		semiVertex := d.vertex[d.semi[w.ID]]
		d.bucket[semiVertex.ID] = append(d.bucket[semiVertex.ID], w)
		d.link(d.parent[w.ID], w)

		parentID := d.parent[w.ID].ID
		for _, v := range d.bucket[parentID] {
			u := d.eval(v)
			if d.semi[u.ID] < d.semi[v.ID] {
				d.dom[v.ID] = u
			} else {
				d.dom[v.ID] = d.parent[w.ID]
			}
		}
		d.bucket[parentID] = d.bucket[parentID][:0]
	}

	// Step 4: Explicit dominators
	for i := 1; i < d.n; i++ {
		w := d.vertex[i]
		if d.dom[w.ID] != d.vertex[d.semi[w.ID]] {
			d.dom[w.ID] = d.dom[d.dom[w.ID].ID]
		}
	}

	d.buildDominatorTree()
	d.computeDominanceFrontierFast()
	d.buildBinaryLifting()

	d.cfg.DominatorTree = true
}

// dfsIterative performs DFS numbering without recursion
func (d *DominatorAnalyzer) dfsIterative(entry *CFGNode) {
	if entry == nil {
		return
	}

	type frame struct {
		node *CFGNode
		idx  int // next successor to visit
	}

	stack := []frame{{node: entry}}
	d.semi[entry.ID] = d.n
	d.vertex[d.n] = entry
	d.n++

	for len(stack) > 0 {
		top := &stack[len(stack)-1]

		if top.idx < len(top.node.Successors) {
			w := top.node.Successors[top.idx]
			top.idx++

			if d.semi[w.ID] == -1 {
				d.parent[w.ID] = top.node
				d.semi[w.ID] = d.n
				d.vertex[d.n] = w
				d.n++
				stack = append(stack, frame{node: w})
			}
		} else {
			stack = stack[:len(stack)-1]
		}
	}
}

func (d *DominatorAnalyzer) link(v, w *CFGNode) {
	d.ancestor[w.ID] = v
}

func (d *DominatorAnalyzer) eval(v *CFGNode) *CFGNode {
	if d.ancestor[v.ID] == nil {
		return v
	}
	d.compressIterative(v)
	return d.label[v.ID]
}

// compressIterative does path compression without recursion
// This prevents stack overflow on deep CFGs (original was recursive)
func (d *DominatorAnalyzer) compressIterative(v *CFGNode) {
	// Collect the path from v to the root of the forest
	var path []*CFGNode
	u := v
	for d.ancestor[u.ID] != nil && d.ancestor[d.ancestor[u.ID].ID] != nil {
		path = append(path, u)
		u = d.ancestor[u.ID]
	}

	// Walk path in reverse, updating labels and compressing
	for i := len(path) - 1; i >= 0; i-- {
		u := path[i]
		anc := d.ancestor[u.ID]

		if d.ancestor[anc.ID] != nil {
			if d.semi[d.label[anc.ID].ID] < d.semi[d.label[u.ID].ID] {
				d.label[u.ID] = d.label[anc.ID]
			}
			d.ancestor[u.ID] = d.ancestor[anc.ID]
		}
	}
}

func (d *DominatorAnalyzer) buildDominatorTree() {
	for _, node := range d.cfg.Nodes {
		node.ImmediateDom = d.dom[node.ID]
		node.DomTreeChildren = nil
		node.DomTreeDepth = 0
	}

	for _, node := range d.cfg.Nodes {
		if node.ImmediateDom != nil {
			node.ImmediateDom.DomTreeChildren = append(
				node.ImmediateDom.DomTreeChildren, node)
		}
	}

	// Compute depths iteratively
	if d.cfg.Entry != nil {
		type item struct {
			node  *CFGNode
			depth int
		}

		stack := []item{{node: d.cfg.Entry, depth: 0}}
		for len(stack) > 0 {
			it := stack[len(stack)-1]
			stack = stack[:len(stack)-1]

			it.node.DomTreeDepth = it.depth
			for _, child := range it.node.DomTreeChildren {
				stack = append(stack, item{node: child, depth: it.depth + 1})
			}
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// DOMINANCE FRONTIER — Cooper's Algorithm O(E)
// ═══════════════════════════════════════════════════════════════════════════════

func (d *DominatorAnalyzer) computeDominanceFrontierFast() {
	for _, node := range d.cfg.Nodes {
		node.DominanceFrontier = nil
	}

	for _, node := range d.cfg.Nodes {
		if len(node.Predecessors) < 2 {
			continue
		}

		for _, pred := range node.Predecessors {
			runner := pred
			for runner != nil && runner != node.ImmediateDom {
				if !containsNode(runner.DominanceFrontier, node) {
					runner.DominanceFrontier = append(runner.DominanceFrontier, node)
				}
				runner = runner.ImmediateDom
			}
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// BINARY LIFTING — O(log N) LCA queries
// ═══════════════════════════════════════════════════════════════════════════════

func (d *DominatorAnalyzer) buildBinaryLifting() {
	n := len(d.cfg.Nodes)
	if n == 0 {
		return
	}

	// Compute max log
	d.maxLogN = 1
	for (1 << d.maxLogN) < n {
		d.maxLogN++
	}
	d.maxLogN++

	// Initialize lifting table
	d.liftUp = make([][]*CFGNode, d.maxLogN)
	for k := 0; k < d.maxLogN; k++ {
		d.liftUp[k] = make([]*CFGNode, n)
	}

	// Level 0: immediate dominator
	for _, node := range d.cfg.Nodes {
		d.liftUp[0][node.ID] = node.ImmediateDom
	}

	// Level k: 2^k-th ancestor
	for k := 1; k < d.maxLogN; k++ {
		for _, node := range d.cfg.Nodes {
			prev := d.liftUp[k-1][node.ID]
			if prev != nil {
				d.liftUp[k][node.ID] = d.liftUp[k-1][prev.ID]
			}
		}
	}
}

// FindNearestCommonDominator finds LCA in O(log N) using binary lifting
func (d *DominatorAnalyzer) FindNearestCommonDominator(a, b *CFGNode) *CFGNode {
	if a == nil || b == nil {
		return nil
	}
	if a == b {
		return a
	}

	// If binary lifting is not available, fall back to naive
	if d.liftUp == nil {
		return d.findNearestCommonDominatorNaive(a, b)
	}

	// Ensure a is deeper
	if a.DomTreeDepth < b.DomTreeDepth {
		a, b = b, a
	}

	// Lift a to same depth as b
	diff := a.DomTreeDepth - b.DomTreeDepth
	for k := 0; k < d.maxLogN && diff > 0; k++ {
		if diff&1 == 1 {
			a = d.liftUp[k][a.ID]
		}
		diff >>= 1
	}

	if a == b {
		return a
	}

	// Lift both until they meet
	for k := d.maxLogN - 1; k >= 0; k-- {
		if k < len(d.liftUp) && a != nil && b != nil {
			if d.liftUp[k][a.ID] != d.liftUp[k][b.ID] {
				a = d.liftUp[k][a.ID]
				b = d.liftUp[k][b.ID]
			}
		}
	}

	if a != nil {
		return a.ImmediateDom
	}
	return nil
}

func (d *DominatorAnalyzer) findNearestCommonDominatorNaive(a, b *CFGNode) *CFGNode {
	aDoms := make(map[int]bool)
	for node := a; node != nil; node = node.ImmediateDom {
		aDoms[node.ID] = true
	}
	for node := b; node != nil; node = node.ImmediateDom {
		if aDoms[node.ID] {
			return node
		}
	}
	return nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// POST-DOMINATORS
// ═══════════════════════════════════════════════════════════════════════════════

func (d *DominatorAnalyzer) ComputePostDominators() {
	if d.cfg == nil || len(d.cfg.Nodes) == 0 {
		return
	}

	// Build reversed CFG with a single unified virtual exit
	reversedCFG := d.buildReversedCFG()

	// Compute dominators on reversed CFG
	reverseDom := NewDominatorAnalyzer(reversedCFG)
	reverseDom.ComputeDominators()

	// Map results back
	for i, node := range d.cfg.Nodes {
		if i < len(reversedCFG.Nodes)-1 { // skip virtual exit
			revNode := reversedCFG.Nodes[i]
			node.ImmediatePostDom = d.mapBackNode(revNode.ImmediateDom, reversedCFG)
			node.PostDomFrontier = d.mapBackNodes(revNode.DominanceFrontier, reversedCFG)
		}
	}

	d.cfg.PostDomTree = true
}

func (d *DominatorAnalyzer) buildReversedCFG() *ControlFlowGraph {
	n := len(d.cfg.Nodes)

	reversed := &ControlFlowGraph{
		Nodes: make([]*CFGNode, n+1), // +1 for single virtual exit
		Edges: make([]*CFGEdge, 0, len(d.cfg.Edges)+len(d.cfg.Exits)),
	}

	// Create reversed nodes
	nodeMap := make(map[int]*CFGNode, n)
	for i, node := range d.cfg.Nodes {
		revNode := &CFGNode{
			ID:           node.ID,
			Type:         node.Type,
			Successors:   make([]*CFGNode, 0, len(node.Predecessors)),
			Predecessors: make([]*CFGNode, 0, len(node.Successors)),
		}
		reversed.Nodes[i] = revNode
		nodeMap[node.ID] = revNode
	}

	// Single virtual exit node
	virtualExit := &CFGNode{
		ID:           n,
		Type:         NodeTypeEntry,
		Successors:   make([]*CFGNode, 0, len(d.cfg.Exits)),
		Predecessors: make([]*CFGNode, 0),
	}
	reversed.Nodes[n] = virtualExit

	// Reverse all edges
	for _, edge := range d.cfg.Edges {
		fromRev := nodeMap[edge.To.ID]
		toRev := nodeMap[edge.From.ID]

		if fromRev != nil && toRev != nil {
			fromRev.Successors = append(fromRev.Successors, toRev)
			toRev.Predecessors = append(toRev.Predecessors, fromRev)
		}
	}

	// Connect all exit nodes to virtual exit (reversed: virtual exit → exit nodes)
	for _, exit := range d.cfg.Exits {
		if revNode := nodeMap[exit.ID]; revNode != nil {
			virtualExit.Successors = append(virtualExit.Successors, revNode)
			revNode.Predecessors = append(revNode.Predecessors, virtualExit)
		}
	}

	reversed.Entry = virtualExit

	return reversed
}

func (d *DominatorAnalyzer) mapBackNode(revNode *CFGNode, _ *ControlFlowGraph) *CFGNode {
	if revNode == nil || revNode.ID >= len(d.cfg.Nodes) {
		return nil
	}
	return d.cfg.Nodes[revNode.ID]
}

func (d *DominatorAnalyzer) mapBackNodes(revNodes []*CFGNode, revCFG *ControlFlowGraph) []*CFGNode {
	result := make([]*CFGNode, 0, len(revNodes))
	for _, rn := range revNodes {
		if mapped := d.mapBackNode(rn, revCFG); mapped != nil {
			result = append(result, mapped)
		}
	}
	return result
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONTROL DEPENDENCE GRAPH
// ═══════════════════════════════════════════════════════════════════════════════
//
// Node B is control-dependent on node A if:
//   1. There exists a path from A to B in CFG
//   2. B post-dominates every node on the path except A
//
// Equivalently: B ∈ PostDominanceFrontier(A)
//
// This is crucial for identifying which conditions guard which code.
// ═══════════════════════════════════════════════════════════════════════════════

// ControlDependence represents a control dependence relation
type ControlDependence struct {
	Controller *CFGNode       // the branching node
	Dependent  *CFGNode       // the dependent node
	Edge       EdgeType       // which branch leads to dependent
	Condition  *ConditionInfo // the branch condition (if any)
}

// ComputeControlDependence computes the CDG (detailed version)
func (d *DominatorAnalyzer) ComputeControlDependence() []ControlDependence {
	// Ensure post-dominators are computed
	if !d.cfg.PostDomTree {
		d.ComputePostDominators()
	}

	var deps []ControlDependence

	// For each node, its post-dominance frontier gives control dependences
	for _, node := range d.cfg.Nodes {
		for _, pdfNode := range node.PostDomFrontier {
			dep := ControlDependence{
				Controller: pdfNode,
				Dependent:  node,
			}

			// Determine which edge
			if edge := d.cfg.FindEdge(pdfNode, node); edge != nil {
				dep.Edge = edge.Type
			}

			if pdfNode.Condition != nil {
				dep.Condition = pdfNode.Condition
			}

			deps = append(deps, dep)
		}
	}

	// ✅ ИСПРАВЛЕНО: Store in correct field
	d.cfg.ControlDepsDetailed = deps

	return deps
}

// GetControllers returns all nodes that control the given node
func (d *DominatorAnalyzer) GetControllers(node *CFGNode) []*CFGNode {
	var controllers []*CFGNode
	seen := make(map[int]bool)

	// ✅ ИСПРАВЛЕНО: используем ControlDepsDetailed
	for _, dep := range d.cfg.ControlDepsDetailed {
		if dep.Dependent == node && !seen[dep.Controller.ID] {
			controllers = append(controllers, dep.Controller)
			seen[dep.Controller.ID] = true
		}
	}

	return controllers
}

// GetDependents returns all nodes controlled by the given node
func (d *DominatorAnalyzer) GetDependents(node *CFGNode) []*CFGNode {
	var dependents []*CFGNode
	seen := make(map[int]bool)

	// ✅ ИСПРАВЛЕНО: используем ControlDepsDetailed
	for _, dep := range d.cfg.ControlDepsDetailed {
		if dep.Controller == node && !seen[dep.Dependent.ID] {
			dependents = append(dependents, dep.Dependent)
			seen[dep.Dependent.ID] = true
		}
	}

	return dependents
}

// ═══════════════════════════════════════════════════════════════════════════════
// DOMINANCE QUERIES
// ═══════════════════════════════════════════════════════════════════════════════

func (d *DominatorAnalyzer) Dominates(a, b *CFGNode) bool {
	if a == b {
		return true
	}
	if a == nil || b == nil {
		return false
	}

	// Use depth to avoid infinite loops and speed up
	if a.DomTreeDepth >= b.DomTreeDepth {
		return false
	}

	dom := b.ImmediateDom
	for dom != nil {
		if dom == a {
			return true
		}
		if dom.DomTreeDepth <= a.DomTreeDepth {
			break
		}
		dom = dom.ImmediateDom
	}
	return false
}

func (d *DominatorAnalyzer) StrictlyDominates(a, b *CFGNode) bool {
	return a != b && d.Dominates(a, b)
}

func (d *DominatorAnalyzer) PostDominates(a, b *CFGNode) bool {
	if a == b {
		return true
	}

	dom := b.ImmediatePostDom
	for dom != nil {
		if dom == a {
			return true
		}
		dom = dom.ImmediatePostDom
	}
	return false
}

// DominatedBy returns all nodes dominated by the given node
func (d *DominatorAnalyzer) DominatedBy(node *CFGNode) []*CFGNode {
	var result []*CFGNode

	// BFS on dominator tree children
	queue := []*CFGNode{node}
	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]
		result = append(result, curr)

		for _, child := range curr.DomTreeChildren {
			queue = append(queue, child)
		}
	}

	return result
}

// ═══════════════════════════════════════════════════════════════════════════════
// TREE ITERATORS
// ═══════════════════════════════════════════════════════════════════════════════

// DomTreePreorder returns nodes in dominator tree preorder
func (d *DominatorAnalyzer) DomTreePreorder() []*CFGNode {
	if d.cfg.Entry == nil {
		return nil
	}

	result := make([]*CFGNode, 0, len(d.cfg.Nodes))
	stack := []*CFGNode{d.cfg.Entry}

	for len(stack) > 0 {
		node := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		result = append(result, node)

		// Push children in reverse for correct order
		for i := len(node.DomTreeChildren) - 1; i >= 0; i-- {
			stack = append(stack, node.DomTreeChildren[i])
		}
	}

	return result
}

// DomTreePostorder returns nodes in dominator tree postorder
func (d *DominatorAnalyzer) DomTreePostorder() []*CFGNode {
	if d.cfg.Entry == nil {
		return nil
	}

	result := make([]*CFGNode, 0, len(d.cfg.Nodes))

	type frame struct {
		node *CFGNode
		idx  int
	}

	stack := []frame{{node: d.cfg.Entry}}

	for len(stack) > 0 {
		top := &stack[len(stack)-1]

		if top.idx < len(top.node.DomTreeChildren) {
			child := top.node.DomTreeChildren[top.idx]
			top.idx++
			stack = append(stack, frame{node: child})
		} else {
			result = append(result, top.node)
			stack = stack[:len(stack)-1]
		}
	}

	return result
}

func containsNode(nodes []*CFGNode, target *CFGNode) bool {
	for _, n := range nodes {
		if n == target {
			return true
		}
	}
	return false
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPER METHODS
// ═══════════════════════════════════════════════════════════════════════════════

// GetImmediateDominator returns the immediate dominator of a node
func (d *DominatorAnalyzer) GetImmediateDominator(node *CFGNode) *CFGNode {
	if node == nil {
		return nil
	}
	return node.ImmediateDom
}

// GetImmediatePostDominator returns the immediate post-dominator of a node
func (d *DominatorAnalyzer) GetImmediatePostDominator(node *CFGNode) *CFGNode {
	if node == nil {
		return nil
	}
	return node.ImmediatePostDom
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONTROL DEPENDENCIES (alternative implementation)
// ═══════════════════════════════════════════════════════════════════════════════

// ComputeControlDependencies computes control dependence edges
// Node B is control-dependent on node A if there exists a path from A to B
// such that B post-dominates all nodes on the path except A.
func (d *DominatorAnalyzer) ComputeControlDependencies() {
	if d.cfg == nil {
		return
	}

	// Ensure post-dominators are computed
	if !d.cfg.PostDomTree {
		d.ComputePostDominators()
	}

	// Initialize map
	if d.cfg.ControlDeps == nil {
		d.cfg.ControlDeps = make(map[int][]*CFGNode)
	}

	// For each node with multiple successors (branch point)
	for _, node := range d.cfg.Nodes {
		if len(node.Successors) <= 1 {
			continue
		}

		// For each successor
		for _, succ := range node.Successors {
			// Walk from succ up the post-dominator tree
			// until we reach a node that post-dominates the branch point
			runner := succ
			for runner != nil && !d.PostDominates(runner, node) {
				// runner is control-dependent on node
				if d.cfg.ControlDeps[runner.ID] == nil {
					d.cfg.ControlDeps[runner.ID] = make([]*CFGNode, 0, 2)
				}

				// Check if already added (avoid duplicates)
				alreadyAdded := false
				for _, existing := range d.cfg.ControlDeps[runner.ID] {
					if existing == node {
						alreadyAdded = true
						break
					}
				}

				if !alreadyAdded {
					d.cfg.ControlDeps[runner.ID] = append(d.cfg.ControlDeps[runner.ID], node)
				}

				runner = runner.ImmediatePostDom
			}
		}
	}

	d.cfg.ControlDepsComputed = true
}

// GetControlledNodes returns all nodes that are control-dependent on the given node
func (d *DominatorAnalyzer) GetControlledNodes(node *CFGNode) []*CFGNode {
	if d.cfg == nil || d.cfg.ControlDeps == nil {
		return nil
	}

	if !d.cfg.ControlDepsComputed {
		d.ComputeControlDependencies()
	}

	var controlled []*CFGNode
	seen := make(map[int]bool)

	for nodeID, controllers := range d.cfg.ControlDeps {
		for _, controller := range controllers {
			if controller == node && !seen[nodeID] {
				controlled = append(controlled, d.cfg.Nodes[nodeID])
				seen[nodeID] = true
			}
		}
	}

	return controlled
}
