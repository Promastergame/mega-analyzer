package apkloader

// ═══════════════════════════════════════════════════════════════════════════════
// HYPERION ENGINE v3.0 — Phase 3: Control Flow Graph (CFG) Builder
// ═══════════════════════════════════════════════════════════════════════════════
//
// Builds a CFG from MIR instructions. Basic blocks are split at:
//   1. Branch targets (leaders)
//   2. Instructions after branches (leaders)
//   3. Exception handler entries (leaders)
//
// Exception handling is modeled with:
//   - Exception edges from protected regions to handler entry blocks
//   - Dedicated entry blocks for exception handlers (with move-exception)
//   - Critical edge splitting for SSA construction
//
// The CFG is the prerequisite for SSA construction, dominance analysis,
// and taint tracking (license gate detection).

// EdgeKind classifies the type of control flow edge.
type EdgeKind uint8

const (
	EdgeNormal EdgeKind = iota
	EdgeException
	EdgeCritical // split edge (from block with multiple successors to block with multiple predecessors)
)

// ExceptionEdge represents an edge from a protected region to an exception handler.
type ExceptionEdge struct {
	From          *BasicBlock // block in protected region
	To            *BasicBlock // exception handler entry block
	ExceptionType string      // exception type name (or "" for catch-all)
	TypeIdx       int32       // exception type index (-1 for catch-all)
}

// BasicBlock represents a single basic block in the CFG.
type BasicBlock struct {
	ID    int       // unique block index
	Start int       // index of first MIR instruction
	End   int       // index past last MIR instruction (exclusive)
	Insns []MIRInsn // instructions in this block (slice of method's MIR)

	// Edges
	Succs []*BasicBlock // successors (outgoing edges)
	Preds []*BasicBlock // predecessors (incoming edges)

	// Edge classification
	IsFallthrough bool // has a fallthrough edge to next block
	IsLoopHeader  bool // is a loop header (has a back-edge predecessor)

	// Exception handling
	IsExceptionHandler bool     // is an exception handler entry block
	HasMoveException   bool     // contains move-exception instruction
	ExceptionTypes     []string // exception types this handler catches
	ExceptionTypeIdxs  []int32  // exception type indices

	// Dominator tree (populated by ComputeDominance)
	IDom     *BasicBlock   // immediate dominator
	Children []*BasicBlock // blocks this dominates
	DomDepth int           // depth in dominator tree

	// Dominance frontier (populated by ComputeDominanceFrontier)
	DomFrontier []*BasicBlock // dominance frontier for SSA phi placement

	// Liveness (for future SSA)
	LiveIn  []bool // registers live at block entry
	LiveOut []bool // registers live at block exit

	// Reachability
	IsReachable bool // is reachable from entry block

	// inDomFrontierOf is a per-block scratch flag used by ComputeDominanceFrontier
	// to replace the O(n) blockSliceContains scan with an O(1) membership check.
	// It is validated against cfg.domFrontierGen, so no reset pass is needed.
	inDomFrontierOf int // generation counter; valid only when it equals cfg.domFrontierGen
}

// CFG is the control flow graph for a single method.
type CFG struct {
	Blocks []*BasicBlock // all basic blocks, index 0 = entry
	Entry  *BasicBlock   // entry block
	Exit   *BasicBlock   // exit block (may be synthetic)

	// Exception handling
	ExceptionEdges []*ExceptionEdge // all exception edges in the CFG
	HandlerBlocks  []*BasicBlock    // all exception handler entry blocks

	// Lookup maps
	offsetToBlock map[uint32]*BasicBlock // MIR offset → containing block

	// domFrontierGen is a monotonically increasing generation counter used by
	// the O(1) dominance-frontier membership check in ComputeDominanceFrontier.
	// It is bumped once per merge-point iteration so that membership stays
	// scoped to a single frontier walk, exactly like the old contains-check.
	domFrontierGen int
}

// BuildCFG constructs a CFG from a stream of MIR instructions.
// If handlers is provided, exception edges are modeled.
func BuildCFG(mir []MIRInsn) *CFG {
	return BuildCFGWithHandlers(mir, nil)
}

// BuildCFGWithHandlers constructs a CFG from MIR instructions with exception handling.
// handlers: exception handler metadata from DEX (TryItem and CatchHandler)
func BuildCFGWithHandlers(mir []MIRInsn, handlers *CodeItem) *CFG {
	if len(mir) == 0 {
		return &CFG{}
	}

	cfg := &CFG{
		offsetToBlock:  make(map[uint32]*BasicBlock),
		ExceptionEdges: make([]*ExceptionEdge, 0),
		HandlerBlocks:  make([]*BasicBlock, 0),
	}

	// Step 1: Identify leaders (basic block boundaries)
	leaders := cfg.findLeaders(mir, handlers)

	// Step 2: Create basic blocks
	cfg.createBlocks(mir, leaders)

	// Step 3: Connect normal edges (including switch targets)
	cfg.connectEdgesWithHandlers(handlers)

	// Step 4: Connect exception edges (if handlers provided)
	if handlers != nil {
		cfg.connectExceptionEdges(mir, handlers)
	}

	// Step 5: Set entry/exit
	if len(cfg.Blocks) > 0 {
		cfg.Entry = cfg.Blocks[0]
	}

	// Step 6: Mark reachable blocks
	cfg.markReachable()

	return cfg
}

// findLeaders identifies instruction indices that start basic blocks.
// leaders is a []bool indexed by instruction position — O(1) set/test with
// no heap map. Indices are always in [0, len(mir)), so the slice is exact.
func (cfg *CFG) findLeaders(mir []MIRInsn, handlers *CodeItem) []bool {
	leaders := make([]bool, len(mir))
	leaders[0] = true // first instruction is always a leader

	// Add exception handler entry points as leaders
	if handlers != nil {
		for _, tryItem := range handlers.Tries {
			for _, handler := range tryItem.CatchHandlers {
				// Find the instruction index for this handler address
				handlerIdx := cfg.findInsnByOffset(mir, handler.HandlerAddr)
				if handlerIdx >= 0 {
					leaders[handlerIdx] = true
				}
				// Catch-all handler
				if handler.HasCatchAll && handler.CatchAllAddr > 0 {
					catchAllIdx := cfg.findInsnByOffset(mir, handler.CatchAllAddr)
					if catchAllIdx >= 0 {
						leaders[catchAllIdx] = true
					}
				}
			}
		}
	}

	for i, insn := range mir {
		switch insn.Kind {
		case MIR_GOTO:
			// Target is a leader
			target := int(int32(insn.Offset) + int32(insn.Imm))
			targetIdx := cfg.findInsnByOffset(mir, uint32(target))
			if targetIdx >= 0 {
				leaders[targetIdx] = true
			}
			// Next instruction is a leader
			if i+1 < len(mir) {
				leaders[i+1] = true
			}

		case MIR_IF:
			// Branch target is a leader
			target := int(int32(insn.Offset) + int32(insn.Imm))
			targetIdx := cfg.findInsnByOffset(mir, uint32(target))
			if targetIdx >= 0 {
				leaders[targetIdx] = true
			}
			// Fallthrough is a leader
			if i+1 < len(mir) {
				leaders[i+1] = true
			}

		case MIR_SWITCH:
			// Switch targets + fallthrough
			if handlers != nil && len(handlers.Insns) > 0 {
				targets := extractSwitchTargetsFromCode(&insn, handlers.Insns)
				for _, t := range targets {
					targetIdx := cfg.findInsnByOffset(mir, t)
					if targetIdx >= 0 {
						leaders[targetIdx] = true
					}
				}
			}
			// Next instruction is a leader (fallthrough after switch)
			if i+1 < len(mir) {
				leaders[i+1] = true
			}

		case MIR_RETURN, MIR_THROW:
			// Next instruction is a leader (dead code or exception handler)
			if i+1 < len(mir) {
				leaders[i+1] = true
			}
		}
	}

	return leaders
}

func extractSwitchTargetsFromCode(insn *MIRInsn, codeUnits []uint16) []uint32 {
	if insn.Kind != MIR_SWITCH || len(codeUnits) == 0 {
		return nil
	}
	payloadPos := uint32(int32(insn.Offset) + int32(insn.Imm))
	if payloadPos+2 > uint32(len(codeUnits)) {
		return nil
	}
	ident := codeUnits[payloadPos]
	var targets []uint32

	switch ident {
	case 0x0100: // packed-switch
		size := codeUnits[payloadPos+1]
		totalSize := uint32(4) + uint32(size)*2
		if payloadPos+totalSize <= uint32(len(codeUnits)) {
			for i := uint16(0); i < size; i++ {
				tPos := payloadPos + 4 + uint32(i)*2
				targetRel := int32(uint32(codeUnits[tPos]) | uint32(codeUnits[tPos+1])<<16)
				targetAbs := uint32(int32(insn.Offset) + targetRel)
				targets = append(targets, targetAbs)
			}
		}
	case 0x0200: // sparse-switch
		size := codeUnits[payloadPos+1]
		totalSize := uint32(2) + uint32(size)*4
		if payloadPos+totalSize <= uint32(len(codeUnits)) {
			targetsStart := payloadPos + 2 + uint32(size)*2
			for i := uint16(0); i < size; i++ {
				tPos := targetsStart + uint32(i)*2
				targetRel := int32(uint32(codeUnits[tPos]) | uint32(codeUnits[tPos+1])<<16)
				targetAbs := uint32(int32(insn.Offset) + targetRel)
				targets = append(targets, targetAbs)
			}
		}
	}
	return targets
}

// findInsnByOffset returns the index of the instruction at the given offset.
func (cfg *CFG) findInsnByOffset(mir []MIRInsn, offset uint32) int {
	// Binary search since MIR is sorted by offset
	lo, hi := 0, len(mir)-1
	for lo <= hi {
		mid := (lo + hi) / 2
		if mir[mid].Offset == offset {
			return mid
		} else if mir[mid].Offset < offset {
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	return -1
}

// createBlocks splits MIR instructions into basic blocks.
func (cfg *CFG) createBlocks(mir []MIRInsn, leaders []bool) {
	var current *BasicBlock
	blockID := 0

	for i := range mir {
		if leaders[i] || current == nil {
			// Start new block
			if current != nil {
				current.End = i
				current.Insns = mir[current.Start:current.End]
			}
			current = &BasicBlock{
				ID:    blockID,
				Start: i,
			}
			cfg.Blocks = append(cfg.Blocks, current)
			cfg.offsetToBlock[mir[i].Offset] = current
			blockID++
		}
	}

	// Close last block
	if current != nil {
		current.End = len(mir)
		current.Insns = mir[current.Start:current.End]
	}
}

// connectEdges wires up successor/predecessor edges between blocks.
func (cfg *CFG) connectEdges() {
	cfg.connectEdgesWithHandlers(nil)
}

// connectEdgesWithHandlers connects normal and switch target edges.
func (cfg *CFG) connectEdgesWithHandlers(handlers *CodeItem) {
	for i, block := range cfg.Blocks {
		if len(block.Insns) == 0 {
			continue
		}

		lastInsn := &block.Insns[len(block.Insns)-1]

		switch lastInsn.Kind {
		case MIR_GOTO:
			// Unconditional jump — single successor
			target := uint32(int32(lastInsn.Offset) + int32(lastInsn.Imm))
			if succ := cfg.offsetToBlock[target]; succ != nil {
				addEdge(block, succ)
			}

		case MIR_IF:
			// Conditional branch — two successors: taken + fallthrough
			target := uint32(int32(lastInsn.Offset) + int32(lastInsn.Imm))
			if succ := cfg.offsetToBlock[target]; succ != nil {
				addEdge(block, succ) // taken
			}
			// Fallthrough
			if i+1 < len(cfg.Blocks) {
				addEdge(block, cfg.Blocks[i+1])
				block.IsFallthrough = true
			}

		case MIR_RETURN, MIR_THROW:
			// Terminal — no successors

		case MIR_SWITCH:
			// Switch targets
			if handlers != nil && len(handlers.Insns) > 0 {
				targets := extractSwitchTargetsFromCode(lastInsn, handlers.Insns)
				for _, t := range targets {
					if succ := cfg.offsetToBlock[t]; succ != nil {
						addEdge(block, succ)
					}
				}
			}
			// Fallthrough after switch
			if i+1 < len(cfg.Blocks) {
				addEdge(block, cfg.Blocks[i+1])
				block.IsFallthrough = true
			}

		default:
			// Normal flow — fallthrough to next block
			if i+1 < len(cfg.Blocks) {
				addEdge(block, cfg.Blocks[i+1])
				block.IsFallthrough = true
			}
		}
	}
}

// connectExceptionEdges models exception edges from protected regions to handlers.
// This creates exception edges and dedicated entry blocks for handlers.
func (cfg *CFG) connectExceptionEdges(_ []MIRInsn, handlers *CodeItem) {
	if handlers == nil || len(handlers.Tries) == 0 {
		return
	}

	// Build a map of protected regions: offset → try item
	protectedRegions := make(map[uint32]*TryItem)
	for _, tryItem := range handlers.Tries {
		// Mark all offsets in this protected region
		for offset := tryItem.StartAddr; offset < tryItem.StartAddr+uint32(tryItem.InsnCount); offset++ {
			protectedRegions[offset] = tryItem
		}
	}

	// For each block, check if it's in a protected region
	for _, block := range cfg.Blocks {
		if len(block.Insns) == 0 {
			continue
		}

		// Check if any instruction in this block is in a protected region
		for _, insn := range block.Insns {
			if tryItem, isProtected := protectedRegions[insn.Offset]; isProtected {
				// This block is in a protected region
				// Create exception edges to all handlers for this try item
				for _, handler := range tryItem.CatchHandlers {
					// Find or create handler entry block
					handlerBlock := cfg.offsetToBlock[handler.HandlerAddr]
					if handlerBlock != nil {
						// Mark as exception handler
						handlerBlock.IsExceptionHandler = true
						handlerBlock.ExceptionTypes = append(handlerBlock.ExceptionTypes, handler.TypeName)
						handlerBlock.ExceptionTypeIdxs = append(handlerBlock.ExceptionTypeIdxs, handler.TypeIdx)

						// Create exception edge
						edge := &ExceptionEdge{
							From:          block,
							To:            handlerBlock,
							ExceptionType: handler.TypeName,
							TypeIdx:       handler.TypeIdx,
						}
						cfg.ExceptionEdges = append(cfg.ExceptionEdges, edge)

						// Add to successors/predecessors (exception edges are implicit in CFG)
						// We don't add them to Succs/Preds here; they're tracked separately
						// This allows SSA construction to handle them specially
					}

					// Handle catch-all
					if handler.HasCatchAll && handler.CatchAllAddr > 0 {
						catchAllBlock := cfg.offsetToBlock[handler.CatchAllAddr]
						if catchAllBlock != nil {
							catchAllBlock.IsExceptionHandler = true
							catchAllBlock.ExceptionTypes = append(catchAllBlock.ExceptionTypes, "")
							catchAllBlock.ExceptionTypeIdxs = append(catchAllBlock.ExceptionTypeIdxs, -1)

							edge := &ExceptionEdge{
								From:          block,
								To:            catchAllBlock,
								ExceptionType: "",
								TypeIdx:       -1,
							}
							cfg.ExceptionEdges = append(cfg.ExceptionEdges, edge)
						}
					}
				}
				break // Only need to mark once per block
			}
		}
	}

	// Collect unique handler blocks without an allocating map:
	// the IsExceptionHandler flag (already set above) deduplicates.
	for _, block := range cfg.Blocks {
		if block.IsExceptionHandler {
			cfg.HandlerBlocks = append(cfg.HandlerBlocks, block)
		}
	}

	// Mark blocks with move-exception instructions
	for _, block := range cfg.HandlerBlocks {
		for _, insn := range block.Insns {
			if insn.Kind == MIR_MOVE_EXCEPTION {
				block.HasMoveException = true
				break
			}
		}
	}
}

// markReachable marks all blocks reachable from the entry block.
// Unreachable blocks are identified for potential removal.
// Uses a []bool indexed by block ID instead of a pointer-keyed map.
func (cfg *CFG) markReachable() {
	if cfg.Entry == nil {
		return
	}

	n := len(cfg.Blocks)
	visited := make([]bool, n)
	queue := make([]*BasicBlock, 0, n)
	queue = append(queue, cfg.Entry)
	visited[cfg.Entry.ID] = true

	for len(queue) > 0 {
		block := queue[0]
		queue = queue[1:]
		block.IsReachable = true

		// Visit successors
		for _, succ := range block.Succs {
			if !visited[succ.ID] {
				visited[succ.ID] = true
				queue = append(queue, succ)
			}
		}

		// Visit exception handler targets
		for _, edge := range cfg.ExceptionEdges {
			if edge.From == block && !visited[edge.To.ID] {
				visited[edge.To.ID] = true
				queue = append(queue, edge.To)
			}
		}
	}
}

// addEdge connects a predecessor to a successor.
func addEdge(from, to *BasicBlock) {
	from.Succs = append(from.Succs, to)
	to.Preds = append(to.Preds, from)
}

// ═══════════════════════════════════════════════════════════════════════════════
// DOMINANCE: Lengauer-Tarjan Algorithm (simplified Cooper-Harvey-Kennedy)
// ═══════════════════════════════════════════════════════════════════════════════

// ComputeDominance computes the immediate dominator for each block.
// Uses the iterative algorithm from Cooper, Harvey, Kennedy (2001) —
// simpler than Lengauer-Tarjan and fast enough for method-level CFGs.
func (cfg *CFG) ComputeDominance() {
	if cfg.Entry == nil || len(cfg.Blocks) == 0 {
		return
	}

	n := len(cfg.Blocks)

	// Reverse post-order numbering, using []bool and []int instead of maps.
	rpo := make([]*BasicBlock, 0, n)
	visited := make([]bool, n)
	var dfs func(b *BasicBlock)
	dfs = func(b *BasicBlock) {
		if visited[b.ID] {
			return
		}
		visited[b.ID] = true
		for _, s := range b.Succs {
			dfs(s)
		}
		rpo = append(rpo, b)
	}
	dfs(cfg.Entry)

	// Reverse to get RPO order
	for i, j := 0, len(rpo)-1; i < j; i, j = i+1, j-1 {
		rpo[i], rpo[j] = rpo[j], rpo[i]
	}

	// Assign RPO numbers: rpoNum[blockID] = position in RPO ([]int replaces map[int]int).
	rpoNum := make([]int, n)
	for i, b := range rpo {
		rpoNum[b.ID] = i
	}

	// Initialize dominators: idom[blockID] = immediate dominator
	// ([]*BasicBlock replaces map[int]*BasicBlock; nil = unknown).
	idom := make([]*BasicBlock, n)
	idom[cfg.Entry.ID] = cfg.Entry

	// Intersect helper
	intersect := func(b1, b2 *BasicBlock) *BasicBlock {
		f1, f2 := b1, b2
		for f1 != f2 {
			for rpoNum[f1.ID] > rpoNum[f2.ID] {
				f1 = idom[f1.ID]
			}
			for rpoNum[f2.ID] > rpoNum[f1.ID] {
				f2 = idom[f2.ID]
			}
		}
		return f1
	}

	// Iterate until convergence
	changed := true
	for changed {
		changed = false
		for _, b := range rpo[1:] { // skip entry
			var newIDom *BasicBlock
			for _, p := range b.Preds {
				if idom[p.ID] == nil {
					continue
				}
				if newIDom == nil {
					newIDom = p
				} else {
					newIDom = intersect(newIDom, p)
				}
			}
			if newIDom != nil && idom[b.ID] != newIDom {
				idom[b.ID] = newIDom
				changed = true
			}
		}
	}

	// Set IDom on blocks and build children
	for _, b := range cfg.Blocks {
		if dom := idom[b.ID]; dom != nil && dom != b {
			b.IDom = dom
			dom.Children = append(dom.Children, b)
		}
	}

	// Compute depths
	var setDepth func(b *BasicBlock, depth int)
	setDepth = func(b *BasicBlock, depth int) {
		b.DomDepth = depth
		for _, child := range b.Children {
			setDepth(child, depth+1)
		}
	}
	setDepth(cfg.Entry, 0)

	// Compute dominance frontiers
	cfg.ComputeDominanceFrontier()
}

// ComputeDominanceFrontier computes the dominance frontier for each block.
// The dominance frontier of a node X is the set of all nodes Y such that:
//   - X dominates a predecessor of Y, but
//   - X does not strictly dominate Y
//
// This is used for phi-function placement in SSA construction.
//
// Membership in a block's DomFrontier is checked in O(1) with a generation
// counter stored directly on BasicBlock (inDomFrontierOf), replacing the old
// O(n) blockSliceContains scan. The generation is bumped once per merge
// point so membership stays scoped to a single frontier walk — exactly the
// old per-(runner, Y) contains semantics. DomFrontier is rebuilt from scratch
// on every call, so repeated calls (e.g. via TransformSession.RebuildAnalysis)
// stay idempotent just like the old contains-guarded appends.
func (cfg *CFG) ComputeDominanceFrontier() {
	if cfg.Entry == nil {
		return
	}

	for _, b := range cfg.Blocks {
		b.DomFrontier = b.DomFrontier[:0]
	}

	// For each block Y
	for _, y := range cfg.Blocks {
		if len(y.Preds) < 2 {
			continue // Only merge points have non-empty DF
		}

		// Advance the generation for this merge point so stale
		// inDomFrontierOf values are invalidated without a reset pass.
		cfg.domFrontierGen++
		gen := cfg.domFrontierGen

		// For each predecessor P of Y
		for _, p := range y.Preds {
			runner := p
			// Walk up dominator tree from P
			for runner != y.IDom {
				// Add Y to DF(runner), O(1) membership check.
				if runner.inDomFrontierOf != gen {
					runner.inDomFrontierOf = gen
					runner.DomFrontier = append(runner.DomFrontier, y)
				}
				runner = runner.IDom
				if runner == nil {
					break
				}
			}
		}
	}
}

// DetectLoops marks basic blocks that are loop headers.
// A block is a loop header if it has a predecessor with a higher RPO number
// (i.e., a back-edge in the dominator tree).
func (cfg *CFG) DetectLoops() {
	for _, block := range cfg.Blocks {
		for _, pred := range block.Preds {
			if cfg.dominates(block, pred) {
				block.IsLoopHeader = true
				break
			}
		}
	}
}

// dominates returns true if a dominates b.
func (cfg *CFG) dominates(a, b *BasicBlock) bool {
	cur := b
	for cur != nil {
		if cur == a {
			return true
		}
		cur = cur.IDom
	}
	return false
}

// BlockCount returns the number of basic blocks.
func (cfg *CFG) BlockCount() int {
	return len(cfg.Blocks)
}

// FindBlock returns the block containing the given MIR offset.
func (cfg *CFG) FindBlock(offset uint32) *BasicBlock {
	return cfg.offsetToBlock[offset]
}

// UnreachableBlocks returns all blocks that are not reachable from the entry.
func (cfg *CFG) UnreachableBlocks() []*BasicBlock {
	var unreachable []*BasicBlock
	for _, block := range cfg.Blocks {
		if !block.IsReachable {
			unreachable = append(unreachable, block)
		}
	}
	return unreachable
}

// GetExceptionHandlers returns all exception handler entry blocks.
func (cfg *CFG) GetExceptionHandlers() []*BasicBlock {
	return cfg.HandlerBlocks
}

// GetExceptionEdgesFrom returns all exception edges originating from a block.
func (cfg *CFG) GetExceptionEdgesFrom(block *BasicBlock) []*ExceptionEdge {
	var edges []*ExceptionEdge
	for _, edge := range cfg.ExceptionEdges {
		if edge.From == block {
			edges = append(edges, edge)
		}
	}
	return edges
}

// GetExceptionEdgesTo returns all exception edges targeting a block.
func (cfg *CFG) GetExceptionEdgesTo(block *BasicBlock) []*ExceptionEdge {
	var edges []*ExceptionEdge
	for _, edge := range cfg.ExceptionEdges {
		if edge.To == block {
			edges = append(edges, edge)
		}
	}
	return edges
}
