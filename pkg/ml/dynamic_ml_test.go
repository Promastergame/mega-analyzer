package ml

import (
	"os"
	"testing"
)

func TestDynamicMLPatternsCRUD(t *testing.T) {
	oldPath := dynamicMLFilePath
	dynamicMLFilePath = "configs/dynamic_rules/ml_patterns_test.json"
	defer func() {
		_ = os.Remove(dynamicMLFilePath)
		dynamicMLFilePath = oldPath
	}()

	dynamicMLPatterns = []VulnerablePattern{}

	pattern := VulnerablePattern{
		ID:          "CUSTOM_TEST_PATTERN",
		Category:    "premium_check",
		Description: "Verify dynamic pattern matching flows.",
		ReturnType:  "Z",
		PatchType:   "return_true",
		Weight:      1.5,
	}

	// 1. Add pattern
	err := AddDynamicMLPattern(pattern)
	if err != nil {
		t.Fatalf("Failed to add ml pattern: %v", err)
	}

	// 2. Fetch patterns
	patterns := GetDynamicMLPatterns()
	if len(patterns) != 1 || patterns[0].ID != "CUSTOM_TEST_PATTERN" {
		t.Fatalf("Expected 1 pattern with ID 'CUSTOM_TEST_PATTERN', got: %v", patterns)
	}

	// 3. Update pattern
	pattern.Description = "Updated Pattern Flow"
	err = UpdateDynamicMLPattern("CUSTOM_TEST_PATTERN", pattern)
	if err != nil {
		t.Fatalf("Failed to update ml pattern: %v", err)
	}

	patterns = GetDynamicMLPatterns()
	if patterns[0].Description != "Updated Pattern Flow" {
		t.Fatalf("Expected description 'Updated Pattern Flow', got: %s", patterns[0].Description)
	}

	// 4. Delete pattern
	err = DeleteDynamicMLPattern("CUSTOM_TEST_PATTERN")
	if err != nil {
		t.Fatalf("Failed to delete ml pattern: %v", err)
	}

	patterns = GetDynamicMLPatterns()
	if len(patterns) != 0 {
		t.Fatalf("Expected 0 patterns remaining, got: %d", len(patterns))
	}
}
