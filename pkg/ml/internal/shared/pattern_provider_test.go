package shared

import (
	"testing"
)

func TestPatternProvider(t *testing.T) {
	// Initially should be nil
	RegisterBasePatternsProvider(nil)
	if BasePatterns() != nil {
		t.Error("expected nil")
	}

	callCount := 0
	provider := func() []VulnerablePattern {
		callCount++
		return []VulnerablePattern{{ID: "TEST", Category: "Test"}}
	}

	RegisterBasePatternsProvider(provider)

	patterns := BasePatterns()
	if callCount != 1 {
		t.Errorf("expected call count 1, got %d", callCount)
	}
	if len(patterns) != 1 || patterns[0].ID != "TEST" {
		t.Errorf("unexpected patterns returned: %+v", patterns)
	}
}
