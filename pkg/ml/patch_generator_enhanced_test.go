package ml

import (
	"encoding/json"
	"testing"
)

// TestGeneratedPatchEnhancedFields verifies that the enhanced GeneratedPatch struct
// includes all new fields and maintains backward compatibility
func TestGeneratedPatchEnhancedFields(t *testing.T) {
	// Create a GeneratedPatch with all fields populated
	patch := &GeneratedPatch{
		// Existing fields
		OriginalCode: ".method public isRooted()Z\n    # original code\n.end method",
		PatchedCode:  ".method public isRooted()Z\n    const/4 v0, 0x0\n    return v0\n.end method",
		DiffView:     "--- original\n+++ patched",
		PatchType:    PatchReturnFalse,
		Description:  "Return false to bypass root detection",
		MethodName:   "isRooted",
		FilePath:     "com/example/RootDetector.smali",

		// New enhanced fields
		Mode: PatchModeResearch,
		Explanation: PatchExplanation{
			Reason:       "Method appears to be a root detection check",
			WhatItDoes:   "Checks if device is rooted",
			WhyThisPatch: "Returning false bypasses the root detection",
			Impact:       "App will not detect rooted devices",
			Signals:      []string{"name_match", "api_call"},
		},
		Confidence: 0.85,
		ConfidenceBreakdown: &ConfidenceBreakdown{
			BaseConfidence: 0.75,
			SignalContributions: []SignalContribution{
				{
					SignalType:   "name",
					Value:        "isRooted",
					Weight:       1.0,
					Confidence:   0.9,
					Contribution: 0.9,
				},
				{
					SignalType:   "api_call",
					Value:        "Runtime.exec",
					Weight:       1.1,
					Confidence:   0.8,
					Contribution: 0.88,
				},
			},
			MultiSignalBonus:  0.08,
			ObfuscationAdjust: 0.02,
			FinalConfidence:   0.85,
		},
	}

	// Test that all fields are accessible
	if patch.Mode != PatchModeResearch {
		t.Errorf("Expected Mode to be %s, got %s", PatchModeResearch, patch.Mode)
	}

	if patch.Explanation.Reason == "" {
		t.Error("Expected Explanation.Reason to be non-empty")
	}

	if patch.Confidence != 0.85 {
		t.Errorf("Expected Confidence to be 0.85, got %f", patch.Confidence)
	}

	if patch.ConfidenceBreakdown == nil {
		t.Fatal("Expected ConfidenceBreakdown to be non-nil")
	}

	if patch.ConfidenceBreakdown.FinalConfidence != 0.85 {
		t.Errorf("Expected FinalConfidence to be 0.85, got %f", patch.ConfidenceBreakdown.FinalConfidence)
	}

	// Test backward compatibility - existing fields should still work
	if patch.OriginalCode == "" {
		t.Error("Expected OriginalCode to be non-empty")
	}

	if patch.PatchedCode == "" {
		t.Error("Expected PatchedCode to be non-empty")
	}

	if patch.DiffView == "" {
		t.Error("Expected DiffView to be non-empty")
	}

	if patch.Description == "" {
		t.Error("Expected Description to be non-empty")
	}

	if patch.MethodName == "" {
		t.Error("Expected MethodName to be non-empty")
	}

	if patch.FilePath == "" {
		t.Error("Expected FilePath to be non-empty")
	}

	if patch.PatchType != PatchReturnFalse {
		t.Errorf("Expected PatchType to be %s, got %s", PatchReturnFalse, patch.PatchType)
	}
}

// TestGeneratedPatchJSONSerialization verifies that the enhanced struct
// can be serialized to and from JSON correctly
func TestGeneratedPatchJSONSerialization(t *testing.T) {
	original := &GeneratedPatch{
		OriginalCode: "original",
		PatchedCode:  "patched",
		DiffView:     "diff",
		PatchType:    PatchReturnTrue,
		MethodName:   "testMethod",
		FilePath:     "test.smali",
		Mode:         PatchModeDefensive,
		Explanation: PatchExplanation{
			Reason:       "test reason",
			WhatItDoes:   "test behavior",
			WhyThisPatch: "test justification",
			Impact:       "test impact",
			Signals:      []string{"signal1", "signal2"},
		},
		Confidence: 0.75,
		ConfidenceBreakdown: &ConfidenceBreakdown{
			BaseConfidence:   0.70,
			MultiSignalBonus: 0.05,
			FinalConfidence:  0.75,
		},
	}

	// Serialize to JSON
	jsonData, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Failed to marshal GeneratedPatch: %v", err)
	}

	// Deserialize from JSON
	var deserialized GeneratedPatch
	err = json.Unmarshal(jsonData, &deserialized)
	if err != nil {
		t.Fatalf("Failed to unmarshal GeneratedPatch: %v", err)
	}

	// Verify fields
	if deserialized.Mode != original.Mode {
		t.Errorf("Mode mismatch: expected %s, got %s", original.Mode, deserialized.Mode)
	}

	if deserialized.Explanation.Reason != original.Explanation.Reason {
		t.Errorf("Explanation.Reason mismatch: expected %s, got %s",
			original.Explanation.Reason, deserialized.Explanation.Reason)
	}

	if deserialized.Confidence != original.Confidence {
		t.Errorf("Confidence mismatch: expected %f, got %f",
			original.Confidence, deserialized.Confidence)
	}

	if deserialized.ConfidenceBreakdown == nil {
		t.Fatal("ConfidenceBreakdown should not be nil after deserialization")
	}

	if deserialized.ConfidenceBreakdown.FinalConfidence != original.ConfidenceBreakdown.FinalConfidence {
		t.Errorf("FinalConfidence mismatch: expected %f, got %f",
			original.ConfidenceBreakdown.FinalConfidence,
			deserialized.ConfidenceBreakdown.FinalConfidence)
	}
}

// TestGeneratedPatchBackwardCompatibility verifies that patches created
// without the new fields still work correctly
func TestGeneratedPatchBackwardCompatibility(t *testing.T) {
	// Create a patch using only the original fields
	patch := &GeneratedPatch{
		OriginalCode:  "original",
		OriginalLines: 1,
		PatchedCode:   "patched",
		PatchedLines:  1,
		DiffView:      "diff",
		PatchType:     PatchReturnVoid,
		Description:   "test description",
		MethodName:    "testMethod",
		FilePath:      "test.smali",
		Mode:          PatchModeDefensive, // 🆕 Mode is now required for valid JSON
	}

	// Verify the patch is valid even without new fields
	if patch.OriginalCode == "" {
		t.Error("OriginalCode should be accessible")
	}

	if patch.PatchType != PatchReturnVoid {
		t.Error("PatchType should be accessible")
	}

	// Mode should be set
	if patch.Mode == "" {
		t.Error("Mode should be set for valid patches")
	}

	if patch.Confidence != 0.0 {
		t.Errorf("Confidence should be 0.0, got %f", patch.Confidence)
	}

	if patch.ConfidenceBreakdown != nil {
		t.Error("ConfidenceBreakdown should be nil")
	}

	// Should be able to serialize and deserialize
	jsonData, err := json.Marshal(patch)
	if err != nil {
		t.Fatalf("Failed to marshal backward-compatible patch: %v", err)
	}

	var deserialized GeneratedPatch
	err = json.Unmarshal(jsonData, &deserialized)
	if err != nil {
		t.Fatalf("Failed to unmarshal backward-compatible patch: %v", err)
	}

	if deserialized.OriginalCode != patch.OriginalCode {
		t.Error("OriginalCode should match after deserialization")
	}
}

// TestConfidenceBreakdownStructure verifies the ConfidenceBreakdown struct
func TestConfidenceBreakdownStructure(t *testing.T) {
	breakdown := &ConfidenceBreakdown{
		BaseConfidence: 0.70,
		SignalContributions: []SignalContribution{
			{
				SignalType:   "name",
				Value:        "isRooted",
				Weight:       1.0,
				Confidence:   0.9,
				Contribution: 0.9,
			},
			{
				SignalType:   "structure",
				Value:        "boolean_return",
				Weight:       0.9,
				Confidence:   0.8,
				Contribution: 0.72,
			},
		},
		MultiSignalBonus:  0.08,
		ObfuscationAdjust: 0.02,
		FinalConfidence:   0.80,
	}

	// Verify structure
	if breakdown.BaseConfidence != 0.70 {
		t.Errorf("Expected BaseConfidence 0.70, got %f", breakdown.BaseConfidence)
	}

	if len(breakdown.SignalContributions) != 2 {
		t.Errorf("Expected 2 signal contributions, got %d", len(breakdown.SignalContributions))
	}

	if breakdown.SignalContributions[0].SignalType != "name" {
		t.Errorf("Expected first signal type 'name', got %s", breakdown.SignalContributions[0].SignalType)
	}

	if breakdown.MultiSignalBonus != 0.08 {
		t.Errorf("Expected MultiSignalBonus 0.08, got %f", breakdown.MultiSignalBonus)
	}

	if breakdown.FinalConfidence != 0.80 {
		t.Errorf("Expected FinalConfidence 0.80, got %f", breakdown.FinalConfidence)
	}

	// Test JSON serialization
	jsonData, err := json.Marshal(breakdown)
	if err != nil {
		t.Fatalf("Failed to marshal ConfidenceBreakdown: %v", err)
	}

	var deserialized ConfidenceBreakdown
	err = json.Unmarshal(jsonData, &deserialized)
	if err != nil {
		t.Fatalf("Failed to unmarshal ConfidenceBreakdown: %v", err)
	}

	if deserialized.FinalConfidence != breakdown.FinalConfidence {
		t.Error("FinalConfidence should match after deserialization")
	}
}
