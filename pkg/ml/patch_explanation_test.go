package ml

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestPatchExplanation_Structure verifies the PatchExplanation struct has all required fields
func TestPatchExplanation_Structure(t *testing.T) {
	explanation := PatchExplanation{
		Reason:       "Method bypasses root detection check",
		WhatItDoes:   "Returns false when root is detected",
		WhyThisPatch: "Inverting return value will strengthen security",
		Impact:       "App will properly detect rooted devices",
		Signals:      []string{"root_detection", "security_check"},
	}

	// Verify all fields are accessible
	if explanation.Reason == "" {
		t.Error("Reason field should not be empty")
	}
	if explanation.WhatItDoes == "" {
		t.Error("WhatItDoes field should not be empty")
	}
	if explanation.WhyThisPatch == "" {
		t.Error("WhyThisPatch field should not be empty")
	}
	if explanation.Impact == "" {
		t.Error("Impact field should not be empty")
	}
	if len(explanation.Signals) == 0 {
		t.Error("Signals field should not be empty")
	}
}

// TestPatchExplanation_JSONSerialization verifies JSON serialization works correctly
func TestPatchExplanation_JSONSerialization(t *testing.T) {
	explanation := PatchExplanation{
		Reason:       "Test reason",
		WhatItDoes:   "Test behavior",
		WhyThisPatch: "Test justification",
		Impact:       "Test impact",
		Signals:      []string{"signal1", "signal2"},
	}

	// Marshal to JSON
	data, err := json.Marshal(explanation)
	if err != nil {
		t.Fatalf("Failed to marshal PatchExplanation: %v", err)
	}

	// Unmarshal back
	var decoded PatchExplanation
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal PatchExplanation: %v", err)
	}

	// Verify all fields match
	if decoded.Reason != explanation.Reason {
		t.Errorf("Reason mismatch: got %q, want %q", decoded.Reason, explanation.Reason)
	}
	if decoded.WhatItDoes != explanation.WhatItDoes {
		t.Errorf("WhatItDoes mismatch: got %q, want %q", decoded.WhatItDoes, explanation.WhatItDoes)
	}
	if decoded.WhyThisPatch != explanation.WhyThisPatch {
		t.Errorf("WhyThisPatch mismatch: got %q, want %q", decoded.WhyThisPatch, explanation.WhyThisPatch)
	}
	if decoded.Impact != explanation.Impact {
		t.Errorf("Impact mismatch: got %q, want %q", decoded.Impact, explanation.Impact)
	}
	if len(decoded.Signals) != len(explanation.Signals) {
		t.Errorf("Signals length mismatch: got %d, want %d", len(decoded.Signals), len(explanation.Signals))
	}
}

// TestPatchExplanation_JSONTags verifies JSON tags are correct
func TestPatchExplanation_JSONTags(t *testing.T) {
	explanation := PatchExplanation{
		Reason:       "Test",
		WhatItDoes:   "Test",
		WhyThisPatch: "Test",
		Impact:       "Test",
		Signals:      []string{"test"},
	}

	data, err := json.Marshal(explanation)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	jsonStr := string(data)

	// Verify JSON field names match the tags
	expectedFields := []string{
		`"reason"`,
		`"what_it_does"`,
		`"why_this_patch"`,
		`"impact"`,
		`"signals"`,
	}

	for _, field := range expectedFields {
		if !strings.Contains(jsonStr, field) {
			t.Errorf("JSON output missing expected field: %s", field)
		}
	}
}
