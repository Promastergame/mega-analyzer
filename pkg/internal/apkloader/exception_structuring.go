package apkloader

// ═══════════════════════════════════════════════════════════════════════════════
// EXCEPTION STRUCTURING — Phase 3: Structural Recovery
// ═══════════════════════════════════════════════════════════════════════════════
//
// Reconstructs proper try-catch-finally blocks from raw exception handlers.
// Builds on top of the CFG with exception edge support (Phase 1).
//
// Key responsibilities:
//   1. Group exception handlers by protected region (try block)
//   2. Identify try block boundaries from exception edges
//   3. Detect nested exception handling structures
//   4. Build exception handler hierarchy
//   5. Identify finally blocks
//   6. Preserve finally semantics

// StructuredExceptionHandler represents a try-catch-finally block.
type StructuredExceptionHandler struct {
	// Try block: the protected region
	TryBlocks []*BasicBlock

	// Exception handlers: catch blocks
	Handlers []*ExceptionHandlerInfo

	// Finally block: executed regardless of exception
	FinallyBlocks []*BasicBlock

	// Nested handlers: try-catch blocks nested within this one
	NestedHandlers []*StructuredExceptionHandler

	// Parent handler: the enclosing try-catch block (if nested)
	Parent *StructuredExceptionHandler

	// Depth in nesting hierarchy
	NestingDepth int
}

// ExceptionHandlerInfo represents a single catch block.
type ExceptionHandlerInfo struct {
	// Exception type being caught
	ExceptionType string
	TypeIdx       int32

	// Handler entry block (contains move-exception)
	EntryBlock *BasicBlock

	// All blocks in this handler
	Blocks []*BasicBlock

	// Is this a catch-all handler?
	IsCatchAll bool
}

// ExceptionStructuringResult contains the structured exception handling information.
type ExceptionStructuringResult struct {
	// Top-level exception handlers
	Handlers []*StructuredExceptionHandler

	// All handlers (including nested)
	AllHandlers []*StructuredExceptionHandler

	// Mapping from protected region to handler
	ProtectedRegionToHandler map[*BasicBlock]*StructuredExceptionHandler

	// Mapping from handler block to handler info
	HandlerBlockToInfo map[*BasicBlock]*ExceptionHandlerInfo

	// Finally blocks identified
	FinallyBlocks []*BasicBlock

	// Nesting depth
	MaxNestingDepth int
}

// StructureExceptionHandling analyzes the CFG and builds structured exception handling.
func StructureExceptionHandling(cfg *CFG) *ExceptionStructuringResult {
	result := &ExceptionStructuringResult{
		Handlers:                 make([]*StructuredExceptionHandler, 0),
		AllHandlers:              make([]*StructuredExceptionHandler, 0),
		ProtectedRegionToHandler: make(map[*BasicBlock]*StructuredExceptionHandler),
		HandlerBlockToInfo:       make(map[*BasicBlock]*ExceptionHandlerInfo),
		FinallyBlocks:            make([]*BasicBlock, 0),
		MaxNestingDepth:          0,
	}

	if len(cfg.ExceptionEdges) == 0 {
		return result
	}

	// Step 1: Group exception handlers by protected region
	protectedRegions := groupHandlersByProtectedRegion(cfg)

	// Step 2: Identify try block boundaries
	tryBlocks := identifyTryBlockBoundaries(cfg, protectedRegions)

	// Step 3: Create structured handlers
	handlers := createStructuredHandlers(cfg, tryBlocks, protectedRegions)

	// Step 4: Detect nested exception handling
	detectNestedHandling(handlers)

	// Step 5: Identify finally blocks
	identifyFinallyBlocks(cfg, handlers, result)

	// Step 6: Build result
	result.Handlers = handlers
	result.AllHandlers = flattenHandlers(handlers)
	result.MaxNestingDepth = computeMaxNestingDepth(handlers)

	// Build mapping from protected region to handler
	for _, handler := range result.AllHandlers {
		for _, block := range handler.TryBlocks {
			result.ProtectedRegionToHandler[block] = handler
		}
	}

	// Build mapping from handler block to handler info
	for _, handler := range result.AllHandlers {
		for _, handlerInfo := range handler.Handlers {
			result.HandlerBlockToInfo[handlerInfo.EntryBlock] = handlerInfo
		}
	}

	return result
}

// groupHandlersByProtectedRegion groups exception handlers by their protected regions.
// Returns a map from protected region (basic block) to list of handlers.
func groupHandlersByProtectedRegion(cfg *CFG) map[*BasicBlock][]*ExceptionEdge {
	groups := make(map[*BasicBlock][]*ExceptionEdge)

	for _, edge := range cfg.ExceptionEdges {
		groups[edge.From] = append(groups[edge.From], edge)
	}

	return groups
}

// identifyTryBlockBoundaries identifies the boundaries of try blocks.
// A try block is the set of all basic blocks that can throw exceptions to the same handler.
func identifyTryBlockBoundaries(_ *CFG, protectedRegions map[*BasicBlock][]*ExceptionEdge) map[*BasicBlock][]*BasicBlock {
	tryBlocks := make(map[*BasicBlock][]*BasicBlock)

	// For each protected region, collect all blocks that are part of the try block
	visited := make(map[*BasicBlock]bool)

	for protectedBlock := range protectedRegions {
		if visited[protectedBlock] {
			continue
		}

		// Find all blocks in this try block using BFS
		tryBlockSet := make(map[*BasicBlock]bool)
		var queue []*BasicBlock
		queue = append(queue, protectedBlock)
		tryBlockSet[protectedBlock] = true

		for len(queue) > 0 {
			block := queue[0]
			queue = queue[1:]

			// Add successors that are also protected
			for _, succ := range block.Succs {
				if !tryBlockSet[succ] && len(protectedRegions[succ]) > 0 {
					tryBlockSet[succ] = true
					queue = append(queue, succ)
				}
			}
		}

		// Convert set to slice
		var tryBlockSlice []*BasicBlock
		for block := range tryBlockSet {
			tryBlockSlice = append(tryBlockSlice, block)
			visited[block] = true
		}

		// Use first block as key
		if len(tryBlockSlice) > 0 {
			tryBlocks[tryBlockSlice[0]] = tryBlockSlice
		}
	}

	return tryBlocks
}

// createStructuredHandlers creates structured exception handlers from try blocks.
func createStructuredHandlers(cfg *CFG, tryBlocks map[*BasicBlock][]*BasicBlock, _ map[*BasicBlock][]*ExceptionEdge) []*StructuredExceptionHandler {
	handlers := make([]*StructuredExceptionHandler, 0)
	processed := make(map[*BasicBlock]bool)

	for tryBlockStart, tryBlockList := range tryBlocks {
		if processed[tryBlockStart] {
			continue
		}

		// Mark all blocks in this try block as processed
		for _, block := range tryBlockList {
			processed[block] = true
		}

		// Create structured handler
		handler := &StructuredExceptionHandler{
			TryBlocks:      tryBlockList,
			Handlers:       make([]*ExceptionHandlerInfo, 0),
			FinallyBlocks:  make([]*BasicBlock, 0),
			NestedHandlers: make([]*StructuredExceptionHandler, 0),
			NestingDepth:   0,
		}

		// Collect all exception handlers for this try block
		handlerSet := make(map[*BasicBlock]*ExceptionHandlerInfo)

		for _, block := range tryBlockList {
			edges := cfg.GetExceptionEdgesFrom(block)
			for _, edge := range edges {
				if _, exists := handlerSet[edge.To]; !exists {
					handlerInfo := &ExceptionHandlerInfo{
						ExceptionType: edge.ExceptionType,
						TypeIdx:       edge.TypeIdx,
						EntryBlock:    edge.To,
						Blocks:        collectHandlerBlocks(cfg, edge.To),
						IsCatchAll:    edge.ExceptionType == "",
					}
					handlerSet[edge.To] = handlerInfo
				}
			}
		}

		// Convert handler set to slice
		for _, handlerInfo := range handlerSet {
			handler.Handlers = append(handler.Handlers, handlerInfo)
		}

		handlers = append(handlers, handler)
	}

	return handlers
}

// collectHandlerBlocks collects all blocks that are part of a handler.
// Starts from the handler entry block and follows normal control flow.
func collectHandlerBlocks(_ *CFG, handlerEntry *BasicBlock) []*BasicBlock {
	blocks := make([]*BasicBlock, 0)
	visited := make(map[*BasicBlock]bool)
	var queue []*BasicBlock

	queue = append(queue, handlerEntry)
	visited[handlerEntry] = true

	for len(queue) > 0 {
		block := queue[0]
		queue = queue[1:]
		blocks = append(blocks, block)

		// Follow normal successors (not exception edges)
		for _, succ := range block.Succs {
			if !visited[succ] && !succ.IsExceptionHandler {
				visited[succ] = true
				queue = append(queue, succ)
			}
		}
	}

	return blocks
}

// detectNestedHandling detects nested exception handling structures.
// A handler is nested if its try block is contained within another handler's try block.
func detectNestedHandling(handlers []*StructuredExceptionHandler) {
	// For each pair of handlers, check if one is nested in the other
	for i := range handlers {
		for j := range handlers {
			if i == j {
				continue
			}

			// Check if handlers[i] is nested in handlers[j]
			if isNestedIn(handlers[i], handlers[j]) {
				handlers[i].Parent = handlers[j]
				handlers[j].NestedHandlers = append(handlers[j].NestedHandlers, handlers[i])
				handlers[i].NestingDepth = handlers[j].NestingDepth + 1
			}
		}
	}
}

// isNestedIn checks if handler1 is nested within handler2.
// handler1 is nested in handler2 if all blocks in handler1's try block
// are contained within handler2's try block.
func isNestedIn(handler1, handler2 *StructuredExceptionHandler) bool {
	if len(handler1.TryBlocks) == 0 || len(handler2.TryBlocks) == 0 {
		return false
	}

	// Create set of blocks in handler2's try block
	handler2Blocks := make(map[*BasicBlock]bool)
	for _, block := range handler2.TryBlocks {
		handler2Blocks[block] = true
	}

	// Check if all blocks in handler1's try block are in handler2's try block
	for _, block := range handler1.TryBlocks {
		if !handler2Blocks[block] {
			return false
		}
	}

	return true
}

// identifyFinallyBlocks identifies finally blocks in the exception handling structure.
// A finally block is a block that is reachable from all exception handlers and the try block.
func identifyFinallyBlocks(_ *CFG, handlers []*StructuredExceptionHandler, result *ExceptionStructuringResult) {
	for _, handler := range handlers {
		// Find blocks that are reachable from all handlers and the try block
		finallyBlocks := findCommonSuccessors(handler)
		handler.FinallyBlocks = finallyBlocks
		result.FinallyBlocks = append(result.FinallyBlocks, finallyBlocks...)
	}
}

// findCommonSuccessors finds blocks that are reachable from all handlers and the try block.
// These are potential finally blocks.
func findCommonSuccessors(handler *StructuredExceptionHandler) []*BasicBlock {
	if len(handler.TryBlocks) == 0 || len(handler.Handlers) == 0 {
		return make([]*BasicBlock, 0)
	}

	// Find successors of the try block
	trySuccessors := make(map[*BasicBlock]bool)
	for _, block := range handler.TryBlocks {
		for _, succ := range block.Succs {
			trySuccessors[succ] = true
		}
	}

	// Find successors of all handlers
	handlerSuccessors := make(map[*BasicBlock]bool)
	for _, handlerInfo := range handler.Handlers {
		for _, block := range handlerInfo.Blocks {
			for _, succ := range block.Succs {
				handlerSuccessors[succ] = true
			}
		}
	}

	// Find common successors
	commonSuccessors := make([]*BasicBlock, 0)
	for block := range trySuccessors {
		if handlerSuccessors[block] {
			commonSuccessors = append(commonSuccessors, block)
		}
	}

	return commonSuccessors
}

// flattenHandlers flattens the nested handler hierarchy into a single list.
func flattenHandlers(handlers []*StructuredExceptionHandler) []*StructuredExceptionHandler {
	result := make([]*StructuredExceptionHandler, 0)

	var flatten func(h *StructuredExceptionHandler)
	flatten = func(h *StructuredExceptionHandler) {
		result = append(result, h)
		for _, nested := range h.NestedHandlers {
			flatten(nested)
		}
	}

	for _, handler := range handlers {
		flatten(handler)
	}

	return result
}

// computeMaxNestingDepth computes the maximum nesting depth of handlers.
func computeMaxNestingDepth(handlers []*StructuredExceptionHandler) int {
	maxDepth := 0

	var computeDepth func(h *StructuredExceptionHandler)
	computeDepth = func(h *StructuredExceptionHandler) {
		if h.NestingDepth > maxDepth {
			maxDepth = h.NestingDepth
		}
		for _, nested := range h.NestedHandlers {
			computeDepth(nested)
		}
	}

	for _, handler := range handlers {
		computeDepth(handler)
	}

	return maxDepth
}

// GetHandlerCount returns the total number of exception handlers.
func (esr *ExceptionStructuringResult) GetHandlerCount() int {
	return len(esr.AllHandlers)
}

// GetTopLevelHandlerCount returns the number of top-level exception handlers.
func (esr *ExceptionStructuringResult) GetTopLevelHandlerCount() int {
	return len(esr.Handlers)
}

// GetNestedHandlerCount returns the number of nested exception handlers.
func (esr *ExceptionStructuringResult) GetNestedHandlerCount() int {
	return len(esr.AllHandlers) - len(esr.Handlers)
}

// GetFinallyBlockCount returns the number of finally blocks.
func (esr *ExceptionStructuringResult) GetFinallyBlockCount() int {
	return len(esr.FinallyBlocks)
}

// GetHandlerForBlock returns the structured handler that contains the given block.
func (esr *ExceptionStructuringResult) GetHandlerForBlock(block *BasicBlock) *StructuredExceptionHandler {
	return esr.ProtectedRegionToHandler[block]
}

// GetHandlerInfoForBlock returns the exception handler info for the given handler block.
func (esr *ExceptionStructuringResult) GetHandlerInfoForBlock(block *BasicBlock) *ExceptionHandlerInfo {
	return esr.HandlerBlockToInfo[block]
}

// IsFinallyBlock checks if a block is a finally block.
func (esr *ExceptionStructuringResult) IsFinallyBlock(block *BasicBlock) bool {
	for _, finallyBlock := range esr.FinallyBlocks {
		if finallyBlock == block {
			return true
		}
	}
	return false
}

// GetHandlersByType returns all handlers that catch a specific exception type.
func (esr *ExceptionStructuringResult) GetHandlersByType(exceptionType string) []*ExceptionHandlerInfo {
	result := make([]*ExceptionHandlerInfo, 0)
	for _, handler := range esr.AllHandlers {
		for _, handlerInfo := range handler.Handlers {
			if handlerInfo.ExceptionType == exceptionType {
				result = append(result, handlerInfo)
			}
		}
	}
	return result
}

// GetCatchAllHandlers returns all catch-all handlers.
func (esr *ExceptionStructuringResult) GetCatchAllHandlers() []*ExceptionHandlerInfo {
	result := make([]*ExceptionHandlerInfo, 0)
	for _, handler := range esr.AllHandlers {
		for _, handlerInfo := range handler.Handlers {
			if handlerInfo.IsCatchAll {
				result = append(result, handlerInfo)
			}
		}
	}
	return result
}
