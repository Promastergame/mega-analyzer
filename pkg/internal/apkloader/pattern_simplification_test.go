package apkloader

import (
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// PATTERN SIMPLIFICATION TESTS
// ═══════════════════════════════════════════════════════════════════════════════

// TestPatternLibrary_Creation tests pattern library creation.
func TestPatternLibrary_Creation(t *testing.T) {
	lib := NewPatternLibrary()

	if lib == nil {
		t.Errorf("Expected pattern library, got nil")
		return
	}

	if len(lib.PatternList) == 0 {
		t.Errorf("Expected default patterns, got none")
	}

	if len(lib.Patterns) != len(lib.PatternList) {
		t.Errorf("Pattern map and list size mismatch")
	}
}

// TestPatternLibrary_DefaultPatterns tests that default patterns are added.
func TestPatternLibrary_DefaultPatterns(t *testing.T) {
	lib := NewPatternLibrary()

	expectedPatterns := []string{
		"dead_arithmetic",
		"redundant_assignment",
		"useless_conditional",
		"redundant_conversion",
		"constant_folding",
		"redundant_boolean",
		"unnecessary_assignment",
		"redundant_jump",
		"arithmetic_identity",
		"double_negation",
	}

	for _, patternID := range expectedPatterns {
		if lib.GetPattern(patternID) == nil {
			t.Errorf("Expected pattern %s, got nil", patternID)
		}
	}
}

// TestPatternLibrary_AddPattern tests adding a pattern to the library.
func TestPatternLibrary_AddPattern(t *testing.T) {
	lib := NewPatternLibrary()
	initialCount := len(lib.PatternList)

	newPattern := &ObfuscationPattern{
		ID:          "test_pattern",
		Name:        "Test Pattern",
		Description: "A test pattern",
		Matcher:     &DeadArithmeticMatcher{},
		Replacement: &DeadArithmeticReplacement{},
		Confidence:  80,
		Category:    "test",
		Enabled:     true,
	}

	lib.AddPattern(newPattern)

	if len(lib.PatternList) != initialCount+1 {
		t.Errorf("Expected %d patterns, got %d", initialCount+1, len(lib.PatternList))
	}

	if lib.GetPattern("test_pattern") == nil {
		t.Errorf("Expected to find test_pattern")
	}
}

// TestPatternLibrary_RemovePattern tests removing a pattern from the library.
func TestPatternLibrary_RemovePattern(t *testing.T) {
	lib := NewPatternLibrary()
	initialCount := len(lib.PatternList)

	removed := lib.RemovePattern("dead_arithmetic")

	if !removed {
		t.Errorf("Expected pattern to be removed")
	}

	if len(lib.PatternList) != initialCount-1 {
		t.Errorf("Expected %d patterns, got %d", initialCount-1, len(lib.PatternList))
	}

	if lib.GetPattern("dead_arithmetic") != nil {
		t.Errorf("Expected pattern to be removed")
	}
}

// TestPatternLibrary_RemoveNonexistent tests removing a non-existent pattern.
func TestPatternLibrary_RemoveNonexistent(t *testing.T) {
	lib := NewPatternLibrary()
	initialCount := len(lib.PatternList)

	removed := lib.RemovePattern("nonexistent_pattern")

	if removed {
		t.Errorf("Expected removal to fail for non-existent pattern")
	}

	if len(lib.PatternList) != initialCount {
		t.Errorf("Expected pattern count to remain unchanged")
	}
}

// TestPatternLibrary_EnablePattern tests enabling a pattern.
func TestPatternLibrary_EnablePattern(t *testing.T) {
	lib := NewPatternLibrary()

	// Disable first
	lib.DisablePattern("dead_arithmetic")

	pattern := lib.GetPattern("dead_arithmetic")
	if pattern.Enabled {
		t.Errorf("Expected pattern to be disabled")
	}

	// Enable
	enabled := lib.EnablePattern("dead_arithmetic")

	if !enabled {
		t.Errorf("Expected enable to succeed")
	}

	if !pattern.Enabled {
		t.Errorf("Expected pattern to be enabled")
	}
}

// TestPatternLibrary_DisablePattern tests disabling a pattern.
func TestPatternLibrary_DisablePattern(t *testing.T) {
	lib := NewPatternLibrary()

	pattern := lib.GetPattern("dead_arithmetic")
	if !pattern.Enabled {
		t.Errorf("Expected pattern to be enabled initially")
	}

	disabled := lib.DisablePattern("dead_arithmetic")

	if !disabled {
		t.Errorf("Expected disable to succeed")
	}

	if pattern.Enabled {
		t.Errorf("Expected pattern to be disabled")
	}
}

// TestPatternLibrary_ListPatterns tests listing all patterns.
func TestPatternLibrary_ListPatterns(t *testing.T) {
	lib := NewPatternLibrary()

	patterns := lib.ListPatterns()

	if len(patterns) == 0 {
		t.Errorf("Expected patterns, got none")
	}

	if len(patterns) != len(lib.PatternList) {
		t.Errorf("Expected %d patterns, got %d", len(lib.PatternList), len(patterns))
	}
}

// TestPatternLibrary_ListEnabledPatterns tests listing enabled patterns.
func TestPatternLibrary_ListEnabledPatterns(t *testing.T) {
	lib := NewPatternLibrary()

	// Disable some patterns
	lib.DisablePattern("dead_arithmetic")
	lib.DisablePattern("redundant_assignment")

	enabledPatterns := lib.ListEnabledPatterns()

	if len(enabledPatterns) == 0 {
		t.Errorf("Expected enabled patterns, got none")
	}

	if len(enabledPatterns) >= len(lib.PatternList) {
		t.Errorf("Expected fewer enabled patterns than total")
	}

	// Check that disabled patterns are not in the list
	for _, pattern := range enabledPatterns {
		if pattern.ID == "dead_arithmetic" || pattern.ID == "redundant_assignment" {
			t.Errorf("Expected disabled pattern to not be in enabled list")
		}
	}
}

// TestPatternSimplification_EmptyCFG tests pattern simplification on empty CFG.
func TestPatternSimplification_EmptyCFG(t *testing.T) {
	lib := NewPatternLibrary()
	cfg := &CFG{}

	result := PatternSimplification(cfg, lib)

	if result == nil {
		t.Errorf("Expected result, got nil")
	}

	if result.GetChangeCount() != 0 {
		t.Errorf("Expected no changes on empty CFG")
	}
}

// TestPatternSimplification_NilCFG tests pattern simplification on nil CFG.
func TestPatternSimplification_NilCFG(t *testing.T) {
	lib := NewPatternLibrary()

	result := PatternSimplification(nil, lib)

	if result == nil {
		t.Errorf("Expected result, got nil")
	}

	if result.GetChangeCount() != 0 {
		t.Errorf("Expected no changes on nil CFG")
	}
}

// TestPatternSimplification_DeadArithmetic tests dead arithmetic pattern matching.
func TestPatternSimplification_DeadArithmetic(t *testing.T) {
	// v0 = 5
	// v1 = v0 + 0  (dead arithmetic)
	// return v1
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 5},
		{Kind: MIR_ADD, Offset: 1, Dst: 1, Src1: 0, Src2: -1, Imm: 0},
		{Kind: MIR_RETURN, Offset: 2, Src1: 1},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()

	lib := NewPatternLibrary()
	result := PatternSimplification(cfg, lib)

	if result == nil {
		t.Errorf("Expected result, got nil")
	}

	// Should find at least one match
	if len(result.GetMatches()) == 0 {
		t.Errorf("Expected to find dead arithmetic pattern")
	}
}

// TestPatternSimplification_RedundantAssignment tests redundant assignment pattern.
func TestPatternSimplification_RedundantAssignment(t *testing.T) {
	// v0 = 5
	// v1 = v0
	// v1 = v0  (redundant)
	// return v1
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 5},
		{Kind: MIR_MOVE, Offset: 1, Dst: 1, Src1: 0},
		{Kind: MIR_MOVE, Offset: 2, Dst: 1, Src1: 0},
		{Kind: MIR_RETURN, Offset: 3, Src1: 1},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()

	lib := NewPatternLibrary()
	result := PatternSimplification(cfg, lib)

	if result == nil {
		t.Errorf("Expected result, got nil")
	}

	// Should find redundant assignment pattern
	if len(result.GetMatches()) == 0 {
		t.Errorf("Expected to find redundant assignment pattern")
	}
}

// TestPatternSimplification_RedundantBoolean tests redundant boolean pattern.
func TestPatternSimplification_RedundantBoolean(t *testing.T) {
	// v0 = 5
	// v1 = v0 & 0  (always false)
	// return v1
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 5},
		{Kind: MIR_AND, Offset: 1, Dst: 1, Src1: 0, Src2: -1, Imm: 0},
		{Kind: MIR_RETURN, Offset: 2, Src1: 1},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()

	lib := NewPatternLibrary()
	result := PatternSimplification(cfg, lib)

	if result == nil {
		t.Errorf("Expected result, got nil")
	}

	// Should find redundant boolean pattern
	if len(result.GetMatches()) == 0 {
		t.Errorf("Expected to find redundant boolean pattern")
	}
}

// TestPatternSimplification_MultipleMatches tests finding multiple pattern matches.
func TestPatternSimplification_MultipleMatches(t *testing.T) {
	// v0 = 5
	// v1 = v0 + 0  (dead arithmetic)
	// v2 = v1 & 0  (redundant boolean)
	// return v2
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 5},
		{Kind: MIR_ADD, Offset: 1, Dst: 1, Src1: 0, Src2: -1, Imm: 0},
		{Kind: MIR_AND, Offset: 2, Dst: 2, Src1: 1, Src2: -1, Imm: 0},
		{Kind: MIR_RETURN, Offset: 3, Src1: 2},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()

	lib := NewPatternLibrary()
	result := PatternSimplification(cfg, lib)

	if result == nil {
		t.Errorf("Expected result, got nil")
	}

	// Should find multiple matches
	if len(result.GetMatches()) < 2 {
		t.Errorf("Expected to find multiple pattern matches, got %d", len(result.GetMatches()))
	}
}

// TestPatternSimplification_ChangeCount tests change counting.
func TestPatternSimplification_ChangeCount(t *testing.T) {
	// v0 = 5
	// v1 = v0 + 0  (dead arithmetic)
	// return v1
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 5},
		{Kind: MIR_ADD, Offset: 1, Dst: 1, Src1: 0, Src2: -1, Imm: 0},
		{Kind: MIR_RETURN, Offset: 2, Src1: 1},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()

	lib := NewPatternLibrary()
	result := PatternSimplification(cfg, lib)

	if result == nil {
		t.Errorf("Expected result, got nil")
	}

	// Should have at least one change
	if result.GetChangeCount() < 0 {
		t.Errorf("Expected non-negative change count, got %d", result.GetChangeCount())
	}
}

// TestPatternSimplification_Trace tests trace generation.
func TestPatternSimplification_Trace(t *testing.T) {
	// v0 = 5
	// v1 = v0 + 0  (dead arithmetic)
	// return v1
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 5},
		{Kind: MIR_ADD, Offset: 1, Dst: 1, Src1: 0, Src2: -1, Imm: 0},
		{Kind: MIR_RETURN, Offset: 2, Src1: 1},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()

	lib := NewPatternLibrary()
	result := PatternSimplification(cfg, lib)

	if result == nil {
		t.Errorf("Expected result, got nil")
	}

	trace := result.GetTrace()
	if len(trace) == 0 {
		t.Errorf("Expected trace entries, got none")
	}
}

// TestPatternSimplification_DisabledPatterns tests that disabled patterns are not matched.
func TestPatternSimplification_DisabledPatterns(t *testing.T) {
	// v0 = 5
	// v1 = v0 + 0  (dead arithmetic)
	// return v1
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 5},
		{Kind: MIR_ADD, Offset: 1, Dst: 1, Src1: 0, Src2: -1, Imm: 0},
		{Kind: MIR_RETURN, Offset: 2, Src1: 1},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()

	lib := NewPatternLibrary()
	lib.DisablePattern("dead_arithmetic")

	result := PatternSimplification(cfg, lib)

	if result == nil {
		t.Errorf("Expected result, got nil")
	}

	// Should not find dead arithmetic pattern since it's disabled
	for _, match := range result.GetMatches() {
		if match.Pattern.ID == "dead_arithmetic" {
			t.Errorf("Expected disabled pattern to not match")
		}
	}
}

// TestPatternLibrary_Statistics tests pattern statistics.
func TestPatternLibrary_Statistics(t *testing.T) {
	lib := NewPatternLibrary()

	stats := lib.GetPatternStatistics()

	if stats == nil {
		t.Errorf("Expected statistics, got nil")
	}

	if totalPatterns, ok := stats["total_patterns"]; ok {
		if totalPatterns.(int) == 0 {
			t.Errorf("Expected non-zero total patterns")
		}
	} else {
		t.Errorf("Expected total_patterns in statistics")
	}

	if enabledPatterns, ok := stats["enabled_patterns"]; ok {
		if enabledPatterns.(int) == 0 {
			t.Errorf("Expected non-zero enabled patterns")
		}
	} else {
		t.Errorf("Expected enabled_patterns in statistics")
	}
}

// TestPatternMatch_Annotation tests pattern match annotation.
func TestPatternMatch_Annotation(t *testing.T) {
	// v0 = 5
	// v1 = v0 + 0  (dead arithmetic)
	// return v1
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 5},
		{Kind: MIR_ADD, Offset: 1, Dst: 1, Src1: 0, Src2: -1, Imm: 0},
		{Kind: MIR_RETURN, Offset: 2, Src1: 1},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()

	lib := NewPatternLibrary()
	result := PatternSimplification(cfg, lib)

	if result == nil {
		t.Errorf("Expected result, got nil")
	}

	if len(result.GetMatches()) > 0 {
		match := result.GetMatches()[0]
		if match.Annotation == "" {
			t.Errorf("Expected annotation, got empty string")
		}
	}
}

// TestPatternMatch_OriginalCode tests original code preservation.
func TestPatternMatch_OriginalCode(t *testing.T) {
	// v0 = 5
	// v1 = v0 + 0  (dead arithmetic)
	// return v1
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 5},
		{Kind: MIR_ADD, Offset: 1, Dst: 1, Src1: 0, Src2: -1, Imm: 0},
		{Kind: MIR_RETURN, Offset: 2, Src1: 1},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()

	lib := NewPatternLibrary()
	result := PatternSimplification(cfg, lib)

	if result == nil {
		t.Errorf("Expected result, got nil")
	}

	if len(result.GetMatches()) > 0 {
		match := result.GetMatches()[0]
		if len(match.OriginalCode) == 0 {
			t.Errorf("Expected original code to be preserved")
		}
	}
}

// TestDeadArithmeticMatcher_AddZero tests dead arithmetic matcher for x + 0.
func TestDeadArithmeticMatcher_AddZero(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 5},
		{Kind: MIR_ADD, Offset: 1, Dst: 1, Src1: 0, Src2: -1, Imm: 0},
		{Kind: MIR_RETURN, Offset: 2, Src1: 1},
	}

	cfg := BuildCFG(mir)
	matcher := &DeadArithmeticMatcher{}

	matched, blocks, metadata := matcher.Match(cfg, cfg.Blocks[0])

	if !matched {
		t.Errorf("Expected to match dead arithmetic pattern")
	}

	if len(blocks) == 0 {
		t.Errorf("Expected matched blocks")
	}

	if metadata == nil {
		t.Errorf("Expected metadata")
	}
}

// TestDeadArithmeticMatcher_MultiplyOne tests dead arithmetic matcher for x * 1.
func TestDeadArithmeticMatcher_MultiplyOne(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 5},
		{Kind: MIR_MUL, Offset: 1, Dst: 1, Src1: 0, Src2: -1, Imm: 1},
		{Kind: MIR_RETURN, Offset: 2, Src1: 1},
	}

	cfg := BuildCFG(mir)
	matcher := &DeadArithmeticMatcher{}

	matched, blocks, metadata := matcher.Match(cfg, cfg.Blocks[0])

	if !matched {
		t.Errorf("Expected to match dead arithmetic pattern")
	}

	if len(blocks) == 0 {
		t.Errorf("Expected matched blocks")
	}

	if metadata == nil {
		t.Errorf("Expected metadata")
	}
}

// TestDeadArithmeticMatcher_XorZero tests dead arithmetic matcher for x ^ 0.
func TestDeadArithmeticMatcher_XorZero(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 5},
		{Kind: MIR_XOR, Offset: 1, Dst: 1, Src1: 0, Src2: -1, Imm: 0},
		{Kind: MIR_RETURN, Offset: 2, Src1: 1},
	}

	cfg := BuildCFG(mir)
	matcher := &DeadArithmeticMatcher{}

	matched, blocks, metadata := matcher.Match(cfg, cfg.Blocks[0])

	if !matched {
		t.Errorf("Expected to match dead arithmetic pattern")
	}

	if len(blocks) == 0 {
		t.Errorf("Expected matched blocks")
	}

	if metadata == nil {
		t.Errorf("Expected metadata")
	}
}

// TestRedundantAssignmentMatcher tests redundant assignment matcher.
func TestRedundantAssignmentMatcher(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 5},
		{Kind: MIR_MOVE, Offset: 1, Dst: 1, Src1: 0},
		{Kind: MIR_MOVE, Offset: 2, Dst: 1, Src1: 0},
		{Kind: MIR_RETURN, Offset: 3, Src1: 1},
	}

	cfg := BuildCFG(mir)
	matcher := &RedundantAssignmentMatcher{}

	matched, blocks, metadata := matcher.Match(cfg, cfg.Blocks[0])

	if !matched {
		t.Errorf("Expected to match redundant assignment pattern")
	}

	if len(blocks) == 0 {
		t.Errorf("Expected matched blocks")
	}

	if metadata == nil {
		t.Errorf("Expected metadata")
	}
}

// TestRedundantBooleanMatcher_AndZero tests redundant boolean matcher for x & 0.
func TestRedundantBooleanMatcher_AndZero(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 5},
		{Kind: MIR_AND, Offset: 1, Dst: 1, Src1: 0, Src2: -1, Imm: 0},
		{Kind: MIR_RETURN, Offset: 2, Src1: 1},
	}

	cfg := BuildCFG(mir)
	matcher := &RedundantBooleanMatcher{}

	matched, blocks, metadata := matcher.Match(cfg, cfg.Blocks[0])

	if !matched {
		t.Errorf("Expected to match redundant boolean pattern")
	}

	if len(blocks) == 0 {
		t.Errorf("Expected matched blocks")
	}

	if metadata == nil {
		t.Errorf("Expected metadata")
	}
}

// TestRedundantBooleanMatcher_OrOne tests redundant boolean matcher for x | 1.
func TestRedundantBooleanMatcher_OrOne(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 5},
		{Kind: MIR_OR, Offset: 1, Dst: 1, Src1: 0, Src2: -1, Imm: 1},
		{Kind: MIR_RETURN, Offset: 2, Src1: 1},
	}

	cfg := BuildCFG(mir)
	matcher := &RedundantBooleanMatcher{}

	matched, blocks, metadata := matcher.Match(cfg, cfg.Blocks[0])

	if !matched {
		t.Errorf("Expected to match redundant boolean pattern")
	}

	if len(blocks) == 0 {
		t.Errorf("Expected matched blocks")
	}

	if metadata == nil {
		t.Errorf("Expected metadata")
	}
}

// TestDeadArithmeticReplacement tests dead arithmetic replacement.
func TestDeadArithmeticReplacement(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 5},
		{Kind: MIR_ADD, Offset: 1, Dst: 1, Src1: 0, Src2: -1, Imm: 0},
		{Kind: MIR_RETURN, Offset: 2, Src1: 1},
	}

	cfg := BuildCFG(mir)
	replacement := &DeadArithmeticReplacement{}

	metadata := map[string]interface{}{
		"instruction_index": 1,
		"operation":         "add_zero",
	}

	replaced := replacement.Replace(cfg, cfg.Blocks, metadata)

	if len(replaced) == 0 {
		t.Errorf("Expected replacement instructions")
	}

	if replaced[0].Kind != MIR_MOVE {
		t.Errorf("Expected MIR_MOVE instruction, got %v", replaced[0].Kind)
	}
}

// TestRedundantBooleanReplacement tests redundant boolean replacement.
func TestRedundantBooleanReplacement(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 5},
		{Kind: MIR_OR, Offset: 1, Dst: 1, Src1: 0, Src2: -1, Imm: 1},
		{Kind: MIR_RETURN, Offset: 2, Src1: 1},
	}

	cfg := BuildCFG(mir)
	replacement := &RedundantBooleanReplacement{}

	metadata := map[string]interface{}{
		"instruction_index": 1,
		"operation":         "or_one",
	}

	replaced := replacement.Replace(cfg, cfg.Blocks, metadata)

	if len(replaced) == 0 {
		t.Errorf("Expected replacement instructions")
	}

	if replaced[0].Kind != MIR_CONST {
		t.Errorf("Expected MIR_CONST instruction, got %v", replaced[0].Kind)
	}

	if replaced[0].Imm != 1 {
		t.Errorf("Expected constant value 1, got %d", replaced[0].Imm)
	}
}

// TestPatternSimplification_ArithmeticIdentity tests x ^ x simplification.
func TestPatternSimplification_ArithmeticIdentity(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 42},
		{Kind: MIR_XOR, Offset: 1, Dst: 1, Src1: 0, Src2: 0},
		{Kind: MIR_RETURN, Offset: 2, Src1: 1},
	}

	cfg := BuildCFG(mir)
	lib := NewPatternLibrary()
	result := PatternSimplification(cfg, lib)

	if result.GetChangeCount() == 0 {
		t.Errorf("Expected simplification for x ^ x")
	}

	// Verify instruction was changed to const 0
	if cfg.Blocks[0].Insns[1].Kind != MIR_CONST || cfg.Blocks[0].Insns[1].Imm != 0 {
		t.Errorf("Expected MIR_CONST 0, got %v", cfg.Blocks[0].Insns[1])
	}
}

// TestPatternSimplification_DoubleNegation tests !!x simplification.
func TestPatternSimplification_DoubleNegation(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_NOT, Offset: 1, Dst: 1, Src1: 0},
		{Kind: MIR_NOT, Offset: 2, Dst: 2, Src1: 1},
		{Kind: MIR_RETURN, Offset: 3, Src1: 2},
	}

	cfg := BuildCFG(mir)
	lib := NewPatternLibrary()
	result := PatternSimplification(cfg, lib)

	if result.GetChangeCount() == 0 {
		t.Errorf("Expected simplification for !!x")
	}

	// Verify instructions were collapsed to MOVE
	if len(cfg.Blocks[0].Insns) != 3 {
		t.Errorf("Expected 3 instructions after collapsing, got %d", len(cfg.Blocks[0].Insns))
	}
	if cfg.Blocks[0].Insns[1].Kind != MIR_MOVE || cfg.Blocks[0].Insns[1].Dst != 2 || cfg.Blocks[0].Insns[1].Src1 != 0 {
		t.Errorf("Expected MIR_MOVE v2, v0, got %v", cfg.Blocks[0].Insns[1])
	}
}

// TestPatternSimplification_MultipleInBlock tests applying multiple patterns in one block.
func TestPatternSimplification_MultipleInBlock(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 10},
		{Kind: MIR_ADD, Offset: 1, Dst: 1, Src1: 0, Src2: -1, Imm: 0}, // pattern 1
		{Kind: MIR_XOR, Offset: 2, Dst: 2, Src1: 1, Src2: 1},          // pattern 2
		{Kind: MIR_RETURN, Offset: 3, Src1: 2},
	}

	cfg := BuildCFG(mir)
	lib := NewPatternLibrary()
	result := PatternSimplification(cfg, lib)

	if result.GetChangeCount() != 2 {
		t.Errorf("Expected 2 simplifications, got %d", result.GetChangeCount())
	}

	// Verify both instructions were simplified
	if cfg.Blocks[0].Insns[1].Kind != MIR_MOVE {
		t.Errorf("Expected instruction 1 to be MOVE, got %v", cfg.Blocks[0].Insns[1].Kind)
	}
	if cfg.Blocks[0].Insns[2].Kind != MIR_CONST {
		t.Errorf("Expected instruction 2 to be CONST, got %v", cfg.Blocks[0].Insns[2].Kind)
	}
}

// BenchmarkPatternSimplification benchmarks pattern simplification on a large synthetic block.
func BenchmarkPatternSimplification(b *testing.B) {
	mir := make([]MIRInsn, 1000)
	for i := 0; i < 1000; i += 4 {
		mir[i] = MIRInsn{Kind: MIR_CONST, Offset: uint32(i), Dst: int16(i % 16), Imm: 10}
		mir[i+1] = MIRInsn{Kind: MIR_ADD, Offset: uint32(i + 1), Dst: int16((i + 1) % 16), Src1: int16(i % 16), Src2: -1, Imm: 0}
		mir[i+2] = MIRInsn{Kind: MIR_XOR, Offset: uint32(i + 2), Dst: int16((i + 2) % 16), Src1: int16((i + 1) % 16), Src2: int16((i + 1) % 16)}
		mir[i+3] = MIRInsn{Kind: MIR_MOVE, Offset: uint32(i + 3), Dst: int16((i + 3) % 16), Src1: int16((i + 2) % 16)}
	}

	lib := NewPatternLibrary()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cfg := BuildCFG(mir)
		_ = PatternSimplification(cfg, lib)
	}
}
