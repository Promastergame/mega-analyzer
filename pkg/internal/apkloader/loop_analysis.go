package apkloader

// ═══════════════════════════════════════════════════════════════════════════════
// LOOP ANALYSIS
// ═══════════════════════════════════════════════════════════════════════════════
//
// Identifies and classifies natural loops in the CFG.
// A natural loop is a loop with a single entry point (header) and one or more back edges.

// LoopType classifies the type of loop.
type LoopType uint8

const (
	LoopUnknown     LoopType = iota
	LoopCounted              // for loop with induction variable
	LoopIterator             // for-each loop with iterator
	LoopCondition            // while/do-while loop
	LoopIrreducible          // irreducible loop (multiple entry points)
)

// Loop represents a natural loop in the CFG.
type Loop struct {
	Header         *BasicBlock   // loop header (entry point)
	Blocks         []*BasicBlock // all blocks in the loop
	BackEdges      []*BasicBlock // blocks with back edges to header
	Parent         *Loop         // parent loop (if nested)
	Children       []*Loop       // child loops (if nested)
	Classification LoopType      // loop type classification
	InductionVar   *SSAVariable  // induction variable (for counted loops)
	LoopBound      int64         // loop bound (for counted loops)
	IsIrreducible  bool          // true if loop has multiple entry points
}

// LoopAnalysis contains all loop information for a method.
type LoopAnalysis struct {
	Loops     map[*BasicBlock]*Loop // header → loop mapping
	Hierarchy *Loop                 // root of loop tree (synthetic)
	AllLoops  []*Loop               // all loops in order
}

// AnalyzeLoops performs loop analysis on a CFG.
// Requires: CFG must have computed dominance information (ComputeDominance called)
func AnalyzeLoops(cfg *CFG) *LoopAnalysis {
	analysis := &LoopAnalysis{
		Loops:    make(map[*BasicBlock]*Loop),
		AllLoops: make([]*Loop, 0),
	}

	// Step 1: Detect back edges
	backEdges := analysis.detectBackEdges(cfg)

	// Step 2: Extract natural loops
	analysis.extractNaturalLoops(cfg, backEdges)

	// Step 3: Build loop hierarchy
	analysis.buildLoopHierarchy()

	// Step 4: Classify loops
	analysis.classifyLoops(cfg)

	return analysis
}

// detectBackEdges identifies back edges in the CFG.
// A back edge is an edge from a node to its dominator (or ancestor in dominator tree).
func (la *LoopAnalysis) detectBackEdges(cfg *CFG) map[*BasicBlock][]*BasicBlock {
	backEdges := make(map[*BasicBlock][]*BasicBlock)

	for _, block := range cfg.Blocks {
		for _, succ := range block.Succs {
			// Check if succ dominates block (back edge)
			if la.dominates(succ, block) {
				backEdges[succ] = append(backEdges[succ], block)
			}
		}
	}

	return backEdges
}

// dominates checks if a dominates b.
func (la *LoopAnalysis) dominates(a, b *BasicBlock) bool {
	cur := b
	for cur != nil {
		if cur == a {
			return true
		}
		cur = cur.IDom
	}
	return false
}

// extractNaturalLoops extracts natural loops from back edges.
// For each back edge (tail → header), extract the natural loop.
func (la *LoopAnalysis) extractNaturalLoops(_ *CFG, backEdges map[*BasicBlock][]*BasicBlock) {
	for header, tails := range backEdges {
		// Create loop for this header
		loop := &Loop{
			Header:    header,
			Blocks:    make([]*BasicBlock, 0),
			BackEdges: tails,
		}

		// Add header to loop
		loop.Blocks = append(loop.Blocks, header)

		// Extract loop body using worklist algorithm
		worklist := make([]*BasicBlock, 0)
		inLoop := make(map[*BasicBlock]bool)
		inLoop[header] = true

		// Start with predecessors of header that are in the loop
		for _, tail := range tails {
			if !inLoop[tail] {
				worklist = append(worklist, tail)
				inLoop[tail] = true
			}
		}

		// Process worklist
		for len(worklist) > 0 {
			block := worklist[0]
			worklist = worklist[1:]

			loop.Blocks = append(loop.Blocks, block)

			// Add predecessors to worklist
			for _, pred := range block.Preds {
				if !inLoop[pred] {
					inLoop[pred] = true
					worklist = append(worklist, pred)
				}
			}
		}

		la.Loops[header] = loop
		la.AllLoops = append(la.AllLoops, loop)
	}
}

// buildLoopHierarchy builds the loop nesting hierarchy.
func (la *LoopAnalysis) buildLoopHierarchy() {
	// For each loop, find its parent (smallest enclosing loop)
	for _, loop := range la.AllLoops {
		var parent *Loop
		minSize := int(^uint(0) >> 1) // max int

		for _, other := range la.AllLoops {
			if other == loop {
				continue
			}

			// Check if loop is contained in other
			if la.loopContains(other, loop) {
				if len(other.Blocks) < minSize {
					parent = other
					minSize = len(other.Blocks)
				}
			}
		}

		loop.Parent = parent
		if parent != nil {
			parent.Children = append(parent.Children, loop)
		}
	}

	// Create synthetic root if there are multiple top-level loops
	topLevel := make([]*Loop, 0)
	for _, loop := range la.AllLoops {
		if loop.Parent == nil {
			topLevel = append(topLevel, loop)
		}
	}

	if len(topLevel) > 1 {
		la.Hierarchy = &Loop{
			Header:   nil,
			Children: topLevel,
		}
	} else if len(topLevel) == 1 {
		la.Hierarchy = topLevel[0]
	}
}

// loopContains checks if loop1 contains loop2.
func (la *LoopAnalysis) loopContains(loop1, loop2 *Loop) bool {
	for _, block := range loop2.Blocks {
		found := false
		for _, b := range loop1.Blocks {
			if b == block {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// classifyLoops classifies loops into counted, iterator-based, condition-based, or irreducible.
func (la *LoopAnalysis) classifyLoops(_ *CFG) {
	for _, loop := range la.AllLoops {
		// Check for irreducible loop (multiple entry points)
		entryCount := 0
		for _, block := range loop.Blocks {
			for _, pred := range block.Preds {
				if !la.blockInLoop(pred, loop) {
					entryCount++
					break
				}
			}
		}

		if entryCount > 1 {
			loop.IsIrreducible = true
			loop.Classification = LoopIrreducible
			continue
		}

		// Try to classify as counted loop
		if la.isCountedLoop(loop) {
			loop.Classification = LoopCounted
			continue
		}

		// Try to classify as iterator-based loop
		if la.isIteratorLoop(loop) {
			loop.Classification = LoopIterator
			continue
		}

		// Default to condition-based loop
		loop.Classification = LoopCondition
	}
}

// blockInLoop checks if a block is in a loop.
func (la *LoopAnalysis) blockInLoop(block *BasicBlock, loop *Loop) bool {
	for _, b := range loop.Blocks {
		if b == block {
			return true
		}
	}
	return false
}

// isCountedLoop checks if a loop is a counted loop (for loop with induction variable).
func (la *LoopAnalysis) isCountedLoop(loop *Loop) bool {
	// A counted loop has:
	// 1. A single back edge
	// 2. An induction variable that is incremented/decremented
	// 3. A loop condition that compares the induction variable

	if len(loop.BackEdges) != 1 {
		return false
	}

	// Look for induction variable pattern
	// This is a simplified check; a full implementation would analyze the loop body
	return false // Placeholder
}

// isIteratorLoop checks if a loop is an iterator-based loop (for-each).
func (la *LoopAnalysis) isIteratorLoop(_ *Loop) bool {
	// An iterator loop has:
	// 1. An iterator object
	// 2. Calls to hasNext() and next()
	// 3. A loop condition based on hasNext()

	// This is a simplified check; a full implementation would analyze the loop body
	return false // Placeholder
}

// GetLoopForBlock returns the innermost loop containing a block.
func (la *LoopAnalysis) GetLoopForBlock(block *BasicBlock) *Loop {
	var innermost *Loop
	minSize := int(^uint(0) >> 1) // max int

	for _, loop := range la.AllLoops {
		if la.blockInLoop(block, loop) {
			if len(loop.Blocks) < minSize {
				innermost = loop
				minSize = len(loop.Blocks)
			}
		}
	}

	return innermost
}

// IsLoopHeader checks if a block is a loop header.
func (la *LoopAnalysis) IsLoopHeader(block *BasicBlock) bool {
	_, ok := la.Loops[block]
	return ok
}

// GetLoopByHeader returns the loop with the given header.
func (la *LoopAnalysis) GetLoopByHeader(header *BasicBlock) *Loop {
	return la.Loops[header]
}

// LoopCount returns the total number of loops.
func (la *LoopAnalysis) LoopCount() int {
	return len(la.AllLoops)
}

// NestedLoopDepth returns the maximum nesting depth of loops.
func (la *LoopAnalysis) NestedLoopDepth() int {
	if la.Hierarchy == nil {
		return 0
	}
	return la.maxDepth(la.Hierarchy)
}

// maxDepth computes the maximum depth of a loop tree.
func (la *LoopAnalysis) maxDepth(loop *Loop) int {
	if len(loop.Children) == 0 {
		return 1
	}

	maxChildDepth := 0
	for _, child := range loop.Children {
		depth := la.maxDepth(child)
		if depth > maxChildDepth {
			maxChildDepth = depth
		}
	}

	return 1 + maxChildDepth
}
