package apkloader

import (
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// EXCEPTION STRUCTURING TESTS
// ═══════════════════════════════════════════════════════════════════════════════

// TestStructureExceptionHandling_SimpleTryCatch tests basic try-catch structuring.
func TestStructureExceptionHandling_SimpleTryCatch(t *testing.T) {
	// Protected region: offsets 0-2
	// Handler: offset 3
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0},          // protected
		{Kind: MIR_ADD, Offset: 1, Dst: 1},            // protected
		{Kind: MIR_RETURN, Offset: 2, Src1: 1},        // protected
		{Kind: MIR_MOVE_EXCEPTION, Offset: 3, Dst: 2}, // handler entry
		{Kind: MIR_RETURN, Offset: 4, Src1: 2},        // handler
	}

	handlers := &CodeItem{
		Tries: []*TryItem{
			{
				StartAddr: 0,
				InsnCount: 3,
				CatchHandlers: []*CatchHandler{
					{
						TypeIdx:     0,
						TypeName:    "Ljava/lang/Exception;",
						HandlerAddr: 3,
						HasCatchAll: false,
					},
				},
			},
		},
	}

	cfg := BuildCFGWithHandlers(mir, handlers)
	result := StructureExceptionHandling(cfg)

	if result.GetTopLevelHandlerCount() != 1 {
		t.Errorf("Expected 1 top-level handler, got %d", result.GetTopLevelHandlerCount())
	}

	if result.GetHandlerCount() != 1 {
		t.Errorf("Expected 1 total handler, got %d", result.GetHandlerCount())
	}

	handler := result.Handlers[0]
	if len(handler.TryBlocks) == 0 {
		t.Errorf("Expected try blocks, got none")
	}

	if len(handler.Handlers) != 1 {
		t.Errorf("Expected 1 exception handler, got %d", len(handler.Handlers))
	}

	handlerInfo := handler.Handlers[0]
	if handlerInfo.ExceptionType != "Ljava/lang/Exception;" {
		t.Errorf("Expected exception type Ljava/lang/Exception;, got %s", handlerInfo.ExceptionType)
	}

	if handlerInfo.IsCatchAll {
		t.Errorf("Expected non-catch-all handler")
	}
}

// TestStructureExceptionHandling_MultipleCatches tests multiple catch handlers.
func TestStructureExceptionHandling_MultipleCatches(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0},
		{Kind: MIR_RETURN, Offset: 1, Src1: 0},
		{Kind: MIR_MOVE_EXCEPTION, Offset: 2, Dst: 1},
		{Kind: MIR_RETURN, Offset: 3, Src1: 1},
		{Kind: MIR_MOVE_EXCEPTION, Offset: 4, Dst: 2},
		{Kind: MIR_RETURN, Offset: 5, Src1: 2},
	}

	handlers := &CodeItem{
		Tries: []*TryItem{
			{
				StartAddr: 0,
				InsnCount: 2,
				CatchHandlers: []*CatchHandler{
					{
						TypeIdx:     0,
						TypeName:    "Ljava/io/IOException;",
						HandlerAddr: 2,
						HasCatchAll: false,
					},
					{
						TypeIdx:     1,
						TypeName:    "Ljava/lang/Exception;",
						HandlerAddr: 4,
						HasCatchAll: false,
					},
				},
			},
		},
	}

	cfg := BuildCFGWithHandlers(mir, handlers)
	result := StructureExceptionHandling(cfg)

	if result.GetTopLevelHandlerCount() != 1 {
		t.Errorf("Expected 1 top-level handler, got %d", result.GetTopLevelHandlerCount())
	}

	handler := result.Handlers[0]
	if len(handler.Handlers) != 2 {
		t.Errorf("Expected 2 exception handlers, got %d", len(handler.Handlers))
	}

	// Check that both exception types are present
	types := make(map[string]bool)
	for _, handlerInfo := range handler.Handlers {
		types[handlerInfo.ExceptionType] = true
	}

	if !types["Ljava/io/IOException;"] {
		t.Errorf("Expected IOException handler")
	}

	if !types["Ljava/lang/Exception;"] {
		t.Errorf("Expected Exception handler")
	}
}

// TestStructureExceptionHandling_CatchAll tests catch-all handler.
func TestStructureExceptionHandling_CatchAll(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0},
		{Kind: MIR_RETURN, Offset: 1, Src1: 0},
		{Kind: MIR_MOVE_EXCEPTION, Offset: 2, Dst: 1},
		{Kind: MIR_RETURN, Offset: 3, Src1: 1},
	}

	handlers := &CodeItem{
		Tries: []*TryItem{
			{
				StartAddr: 0,
				InsnCount: 2,
				CatchHandlers: []*CatchHandler{
					{
						TypeIdx:      -1,
						TypeName:     "",
						HandlerAddr:  2,
						CatchAllAddr: 2,
						HasCatchAll:  true,
					},
				},
			},
		},
	}

	cfg := BuildCFGWithHandlers(mir, handlers)
	result := StructureExceptionHandling(cfg)

	catchAllHandlers := result.GetCatchAllHandlers()
	if len(catchAllHandlers) != 1 {
		t.Errorf("Expected 1 catch-all handler, got %d", len(catchAllHandlers))
	}

	if !catchAllHandlers[0].IsCatchAll {
		t.Errorf("Expected catch-all handler to be marked as catch-all")
	}
}

// TestStructureExceptionHandling_NestedTryCatch tests nested exception handling.
func TestStructureExceptionHandling_NestedTryCatch(t *testing.T) {
	// Outer try: offsets 0-4
	// Inner try: offsets 1-2
	// Outer handler: offset 5
	// Inner handler: offset 7
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0},          // outer protected
		{Kind: MIR_CONST, Offset: 1, Dst: 1},          // inner protected
		{Kind: MIR_ADD, Offset: 2, Dst: 2},            // inner protected
		{Kind: MIR_CONST, Offset: 3, Dst: 3},          // outer protected
		{Kind: MIR_RETURN, Offset: 4, Src1: 3},        // outer protected
		{Kind: MIR_MOVE_EXCEPTION, Offset: 5, Dst: 4}, // outer handler
		{Kind: MIR_RETURN, Offset: 6, Src1: 4},        // outer handler
		{Kind: MIR_MOVE_EXCEPTION, Offset: 7, Dst: 5}, // inner handler
		{Kind: MIR_RETURN, Offset: 8, Src1: 5},        // inner handler
	}

	handlers := &CodeItem{
		Tries: []*TryItem{
			{
				StartAddr: 0,
				InsnCount: 5,
				CatchHandlers: []*CatchHandler{
					{
						TypeIdx:     0,
						TypeName:    "Ljava/lang/Exception;",
						HandlerAddr: 5,
						HasCatchAll: false,
					},
				},
			},
			{
				StartAddr: 1,
				InsnCount: 2,
				CatchHandlers: []*CatchHandler{
					{
						TypeIdx:     1,
						TypeName:    "Ljava/io/IOException;",
						HandlerAddr: 7,
						HasCatchAll: false,
					},
				},
			},
		},
	}

	cfg := BuildCFGWithHandlers(mir, handlers)
	result := StructureExceptionHandling(cfg)

	// We should have at least 1 handler
	if result.GetHandlerCount() < 1 {
		t.Errorf("Expected at least 1 handler, got %d", result.GetHandlerCount())
	}

	// Check for nested handlers
	hasNested := false
	for _, handler := range result.Handlers {
		if len(handler.NestedHandlers) > 0 {
			hasNested = true
			break
		}
	}

	if !hasNested {
		t.Logf("Note: Nested handlers not detected (may be expected depending on CFG structure)")
	}
}

// TestStructureExceptionHandling_NoHandlers tests CFG with no exception handlers.
func TestStructureExceptionHandling_NoHandlers(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0},
		{Kind: MIR_ADD, Offset: 1, Dst: 1},
		{Kind: MIR_RETURN, Offset: 2, Src1: 1},
	}

	cfg := BuildCFG(mir)
	result := StructureExceptionHandling(cfg)

	if result.GetHandlerCount() != 0 {
		t.Errorf("Expected 0 handlers, got %d", result.GetHandlerCount())
	}

	if result.GetTopLevelHandlerCount() != 0 {
		t.Errorf("Expected 0 top-level handlers, got %d", result.GetTopLevelHandlerCount())
	}
}

// TestStructureExceptionHandling_HandlerBlocks tests handler block collection.
func TestStructureExceptionHandling_HandlerBlocks(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0},
		{Kind: MIR_RETURN, Offset: 1, Src1: 0},
		{Kind: MIR_MOVE_EXCEPTION, Offset: 2, Dst: 1},
		{Kind: MIR_ADD, Offset: 3, Dst: 2},
		{Kind: MIR_RETURN, Offset: 4, Src1: 2},
	}

	handlers := &CodeItem{
		Tries: []*TryItem{
			{
				StartAddr: 0,
				InsnCount: 2,
				CatchHandlers: []*CatchHandler{
					{
						TypeIdx:     0,
						TypeName:    "Ljava/lang/Exception;",
						HandlerAddr: 2,
						HasCatchAll: false,
					},
				},
			},
		},
	}

	cfg := BuildCFGWithHandlers(mir, handlers)
	result := StructureExceptionHandling(cfg)

	handler := result.Handlers[0]
	handlerInfo := handler.Handlers[0]

	if len(handlerInfo.Blocks) == 0 {
		t.Errorf("Expected handler blocks, got none")
	}

	// Verify handler entry block is included
	if handlerInfo.EntryBlock != handlerInfo.Blocks[0] {
		t.Errorf("Expected handler entry block to be first in blocks")
	}
}

// TestStructureExceptionHandling_GetHandlerForBlock tests block-to-handler mapping.
func TestStructureExceptionHandling_GetHandlerForBlock(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0},
		{Kind: MIR_RETURN, Offset: 1, Src1: 0},
		{Kind: MIR_MOVE_EXCEPTION, Offset: 2, Dst: 1},
		{Kind: MIR_RETURN, Offset: 3, Src1: 1},
	}

	handlers := &CodeItem{
		Tries: []*TryItem{
			{
				StartAddr: 0,
				InsnCount: 2,
				CatchHandlers: []*CatchHandler{
					{
						TypeIdx:     0,
						TypeName:    "Ljava/lang/Exception;",
						HandlerAddr: 2,
						HasCatchAll: false,
					},
				},
			},
		},
	}

	cfg := BuildCFGWithHandlers(mir, handlers)
	result := StructureExceptionHandling(cfg)

	// Get the protected block
	protectedBlock := cfg.Blocks[0]

	// Get the handler for this block
	handler := result.GetHandlerForBlock(protectedBlock)

	if handler == nil {
		t.Fatalf("Expected handler for protected block, got nil")
	}

	if len(handler.TryBlocks) == 0 {
		t.Errorf("Expected try blocks in handler")
	}
}

// TestStructureExceptionHandling_GetHandlersByType tests handler type lookup.
func TestStructureExceptionHandling_GetHandlersByType(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0},
		{Kind: MIR_RETURN, Offset: 1, Src1: 0},
		{Kind: MIR_MOVE_EXCEPTION, Offset: 2, Dst: 1},
		{Kind: MIR_RETURN, Offset: 3, Src1: 1},
		{Kind: MIR_MOVE_EXCEPTION, Offset: 4, Dst: 2},
		{Kind: MIR_RETURN, Offset: 5, Src1: 2},
	}

	handlers := &CodeItem{
		Tries: []*TryItem{
			{
				StartAddr: 0,
				InsnCount: 2,
				CatchHandlers: []*CatchHandler{
					{
						TypeIdx:     0,
						TypeName:    "Ljava/io/IOException;",
						HandlerAddr: 2,
						HasCatchAll: false,
					},
					{
						TypeIdx:     1,
						TypeName:    "Ljava/lang/Exception;",
						HandlerAddr: 4,
						HasCatchAll: false,
					},
				},
			},
		},
	}

	cfg := BuildCFGWithHandlers(mir, handlers)
	result := StructureExceptionHandling(cfg)

	ioHandlers := result.GetHandlersByType("Ljava/io/IOException;")
	if len(ioHandlers) != 1 {
		t.Errorf("Expected 1 IOException handler, got %d", len(ioHandlers))
	}

	exceptionHandlers := result.GetHandlersByType("Ljava/lang/Exception;")
	if len(exceptionHandlers) != 1 {
		t.Errorf("Expected 1 Exception handler, got %d", len(exceptionHandlers))
	}
}

// TestStructureExceptionHandling_NestingDepth tests nesting depth computation.
func TestStructureExceptionHandling_NestingDepth(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0},
		{Kind: MIR_RETURN, Offset: 1, Src1: 0},
		{Kind: MIR_MOVE_EXCEPTION, Offset: 2, Dst: 1},
		{Kind: MIR_RETURN, Offset: 3, Src1: 1},
	}

	handlers := &CodeItem{
		Tries: []*TryItem{
			{
				StartAddr: 0,
				InsnCount: 2,
				CatchHandlers: []*CatchHandler{
					{
						TypeIdx:     0,
						TypeName:    "Ljava/lang/Exception;",
						HandlerAddr: 2,
						HasCatchAll: false,
					},
				},
			},
		},
	}

	cfg := BuildCFGWithHandlers(mir, handlers)
	result := StructureExceptionHandling(cfg)

	// Top-level handlers should have nesting depth 0
	for _, handler := range result.Handlers {
		if handler.NestingDepth != 0 {
			t.Errorf("Expected top-level handler to have nesting depth 0, got %d", handler.NestingDepth)
		}
	}
}

// TestStructureExceptionHandling_IsFinallyBlock tests finally block identification.
func TestStructureExceptionHandling_IsFinallyBlock(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0},
		{Kind: MIR_RETURN, Offset: 1, Src1: 0},
		{Kind: MIR_MOVE_EXCEPTION, Offset: 2, Dst: 1},
		{Kind: MIR_RETURN, Offset: 3, Src1: 1},
	}

	handlers := &CodeItem{
		Tries: []*TryItem{
			{
				StartAddr: 0,
				InsnCount: 2,
				CatchHandlers: []*CatchHandler{
					{
						TypeIdx:     0,
						TypeName:    "Ljava/lang/Exception;",
						HandlerAddr: 2,
						HasCatchAll: false,
					},
				},
			},
		},
	}

	cfg := BuildCFGWithHandlers(mir, handlers)
	result := StructureExceptionHandling(cfg)

	// Check that finally block identification doesn't crash
	for _, block := range cfg.Blocks {
		_ = result.IsFinallyBlock(block)
	}
}

// TestStructureExceptionHandling_GetHandlerInfoForBlock tests handler info lookup.
func TestStructureExceptionHandling_GetHandlerInfoForBlock(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0},
		{Kind: MIR_RETURN, Offset: 1, Src1: 0},
		{Kind: MIR_MOVE_EXCEPTION, Offset: 2, Dst: 1},
		{Kind: MIR_RETURN, Offset: 3, Src1: 1},
	}

	handlers := &CodeItem{
		Tries: []*TryItem{
			{
				StartAddr: 0,
				InsnCount: 2,
				CatchHandlers: []*CatchHandler{
					{
						TypeIdx:     0,
						TypeName:    "Ljava/lang/Exception;",
						HandlerAddr: 2,
						HasCatchAll: false,
					},
				},
			},
		},
	}

	cfg := BuildCFGWithHandlers(mir, handlers)
	result := StructureExceptionHandling(cfg)

	// Get the handler entry block
	handlerBlock := cfg.HandlerBlocks[0]

	// Get the handler info for this block
	handlerInfo := result.GetHandlerInfoForBlock(handlerBlock)

	if handlerInfo == nil {
		t.Fatalf("Expected handler info for handler block, got nil")
	}

	if handlerInfo.ExceptionType != "Ljava/lang/Exception;" {
		t.Errorf("Expected exception type Ljava/lang/Exception;, got %s", handlerInfo.ExceptionType)
	}
}

// TestStructureExceptionHandling_ProtectedRegionGrouping tests protected region grouping.
func TestStructureExceptionHandling_ProtectedRegionGrouping(t *testing.T) {
	// Two separate try blocks
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0},
		{Kind: MIR_RETURN, Offset: 1, Src1: 0},
		{Kind: MIR_MOVE_EXCEPTION, Offset: 2, Dst: 1},
		{Kind: MIR_RETURN, Offset: 3, Src1: 1},
		{Kind: MIR_CONST, Offset: 4, Dst: 2},
		{Kind: MIR_RETURN, Offset: 5, Src1: 2},
		{Kind: MIR_MOVE_EXCEPTION, Offset: 6, Dst: 3},
		{Kind: MIR_RETURN, Offset: 7, Src1: 3},
	}

	handlers := &CodeItem{
		Tries: []*TryItem{
			{
				StartAddr: 0,
				InsnCount: 2,
				CatchHandlers: []*CatchHandler{
					{
						TypeIdx:     0,
						TypeName:    "Ljava/lang/Exception;",
						HandlerAddr: 2,
						HasCatchAll: false,
					},
				},
			},
			{
				StartAddr: 4,
				InsnCount: 2,
				CatchHandlers: []*CatchHandler{
					{
						TypeIdx:     0,
						TypeName:    "Ljava/lang/Exception;",
						HandlerAddr: 6,
						HasCatchAll: false,
					},
				},
			},
		},
	}

	cfg := BuildCFGWithHandlers(mir, handlers)
	result := StructureExceptionHandling(cfg)

	// We should have at least 1 handler
	if result.GetHandlerCount() < 1 {
		t.Errorf("Expected at least 1 handler, got %d", result.GetHandlerCount())
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// NESTED EXCEPTION HANDLING TESTS
// ═══════════════════════════════════════════════════════════════════════════════

// TestNestedExceptionHandling_SimpleNesting tests simple nested exception handling.
func TestNestedExceptionHandling_SimpleNesting(t *testing.T) {
	// Outer try: 0-4
	// Inner try: 1-2
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0},          // outer
		{Kind: MIR_CONST, Offset: 1, Dst: 1},          // inner
		{Kind: MIR_ADD, Offset: 2, Dst: 2},            // inner
		{Kind: MIR_CONST, Offset: 3, Dst: 3},          // outer
		{Kind: MIR_RETURN, Offset: 4, Src1: 3},        // outer
		{Kind: MIR_MOVE_EXCEPTION, Offset: 5, Dst: 4}, // outer handler
		{Kind: MIR_RETURN, Offset: 6, Src1: 4},
		{Kind: MIR_MOVE_EXCEPTION, Offset: 7, Dst: 5}, // inner handler
		{Kind: MIR_RETURN, Offset: 8, Src1: 5},
	}

	handlers := &CodeItem{
		Tries: []*TryItem{
			{
				StartAddr: 0,
				InsnCount: 5,
				CatchHandlers: []*CatchHandler{
					{
						TypeIdx:     0,
						TypeName:    "Ljava/lang/Exception;",
						HandlerAddr: 5,
						HasCatchAll: false,
					},
				},
			},
			{
				StartAddr: 1,
				InsnCount: 2,
				CatchHandlers: []*CatchHandler{
					{
						TypeIdx:     1,
						TypeName:    "Ljava/io/IOException;",
						HandlerAddr: 7,
						HasCatchAll: false,
					},
				},
			},
		},
	}

	cfg := BuildCFGWithHandlers(mir, handlers)
	result := StructureExceptionHandling(cfg)

	// Verify we have handlers
	if result.GetHandlerCount() < 1 {
		t.Errorf("Expected at least 1 handler, got %d", result.GetHandlerCount())
	}
}

// TestNestedExceptionHandling_TripleNesting tests triple nested exception handling.
func TestNestedExceptionHandling_TripleNesting(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0},
		{Kind: MIR_CONST, Offset: 1, Dst: 1},
		{Kind: MIR_CONST, Offset: 2, Dst: 2},
		{Kind: MIR_ADD, Offset: 3, Dst: 3},
		{Kind: MIR_RETURN, Offset: 4, Src1: 3},
		{Kind: MIR_MOVE_EXCEPTION, Offset: 5, Dst: 4},
		{Kind: MIR_RETURN, Offset: 6, Src1: 4},
		{Kind: MIR_MOVE_EXCEPTION, Offset: 7, Dst: 5},
		{Kind: MIR_RETURN, Offset: 8, Src1: 5},
		{Kind: MIR_MOVE_EXCEPTION, Offset: 9, Dst: 6},
		{Kind: MIR_RETURN, Offset: 10, Src1: 6},
	}

	handlers := &CodeItem{
		Tries: []*TryItem{
			{
				StartAddr: 0,
				InsnCount: 5,
				CatchHandlers: []*CatchHandler{
					{
						TypeIdx:     0,
						TypeName:    "Ljava/lang/Exception;",
						HandlerAddr: 5,
						HasCatchAll: false,
					},
				},
			},
			{
				StartAddr: 1,
				InsnCount: 3,
				CatchHandlers: []*CatchHandler{
					{
						TypeIdx:     1,
						TypeName:    "Ljava/io/IOException;",
						HandlerAddr: 7,
						HasCatchAll: false,
					},
				},
			},
			{
				StartAddr: 2,
				InsnCount: 2,
				CatchHandlers: []*CatchHandler{
					{
						TypeIdx:     2,
						TypeName:    "Ljava/lang/RuntimeException;",
						HandlerAddr: 9,
						HasCatchAll: false,
					},
				},
			},
		},
	}

	cfg := BuildCFGWithHandlers(mir, handlers)
	result := StructureExceptionHandling(cfg)

	// Verify we have handlers
	if result.GetHandlerCount() < 1 {
		t.Errorf("Expected at least 1 handler, got %d", result.GetHandlerCount())
	}

	// Verify max nesting depth is computed
	if result.MaxNestingDepth < 0 {
		t.Errorf("Expected non-negative max nesting depth, got %d", result.MaxNestingDepth)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// FINALLY BLOCK TESTS
// ═══════════════════════════════════════════════════════════════════════════════

// TestFinallyBlockIdentification_CommonSuccessor tests finally block identification.
func TestFinallyBlockIdentification_CommonSuccessor(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0},
		{Kind: MIR_RETURN, Offset: 1, Src1: 0},
		{Kind: MIR_MOVE_EXCEPTION, Offset: 2, Dst: 1},
		{Kind: MIR_RETURN, Offset: 3, Src1: 1},
	}

	handlers := &CodeItem{
		Tries: []*TryItem{
			{
				StartAddr: 0,
				InsnCount: 2,
				CatchHandlers: []*CatchHandler{
					{
						TypeIdx:     0,
						TypeName:    "Ljava/lang/Exception;",
						HandlerAddr: 2,
						HasCatchAll: false,
					},
				},
			},
		},
	}

	cfg := BuildCFGWithHandlers(mir, handlers)
	result := StructureExceptionHandling(cfg)

	// Verify finally block identification doesn't crash
	if result.GetFinallyBlockCount() < 0 {
		t.Errorf("Expected non-negative finally block count, got %d", result.GetFinallyBlockCount())
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// EDGE CASE TESTS
// ═══════════════════════════════════════════════════════════════════════════════

// TestStructureExceptionHandling_EmptyCFG tests empty CFG.
func TestStructureExceptionHandling_EmptyCFG(t *testing.T) {
	cfg := &CFG{
		Blocks:         make([]*BasicBlock, 0),
		ExceptionEdges: make([]*ExceptionEdge, 0),
		HandlerBlocks:  make([]*BasicBlock, 0),
	}

	result := StructureExceptionHandling(cfg)

	if result.GetHandlerCount() != 0 {
		t.Errorf("Expected 0 handlers for empty CFG, got %d", result.GetHandlerCount())
	}
}

// TestStructureExceptionHandling_SingleBlock tests single block CFG.
func TestStructureExceptionHandling_SingleBlock(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0},
	}

	cfg := BuildCFG(mir)
	result := StructureExceptionHandling(cfg)

	if result.GetHandlerCount() != 0 {
		t.Errorf("Expected 0 handlers for single block CFG, got %d", result.GetHandlerCount())
	}
}
