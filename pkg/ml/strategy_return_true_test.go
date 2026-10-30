package ml

import (
	"strings"
	"testing"

	"mega-analyzer/pkg/ml/internal/shared"
)

// ═══════════════════════════════════════════════════════════════════════════════
// RETURN TRUE STRATEGY TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestReturnTrueStrategy_CanApply(t *testing.T) {
	strategy := NewReturnTrueStrategy()

	tests := []struct {
		name     string
		mi       *shared.MethodInfo
		mode     PatchMode
		expected bool
	}{
		{
			name: "root detection in defensive mode",
			mi: &shared.MethodInfo{
				Name:           "isRooted",
				ClassName:      "RootDetector",
				ReturnsBoolean: true,
				ReturnType:     "Z",
			},
			mode:     PatchModeDefensive,
			expected: true,
		},
		{
			name: "root detection in research mode",
			mi: &shared.MethodInfo{
				Name:           "isRooted",
				ClassName:      "RootDetector",
				ReturnsBoolean: true,
				ReturnType:     "Z",
			},
			mode:     PatchModeResearch,
			expected: false, // Should use return false in research mode
		},
		{
			name: "premium check in research mode",
			mi: &shared.MethodInfo{
				Name:           "isPremium",
				ClassName:      "LicenseChecker",
				ReturnsBoolean: true,
				ReturnType:     "Z",
			},
			mode:     PatchModeResearch,
			expected: true,
		},
		{
			name: "premium check in defensive mode",
			mi: &shared.MethodInfo{
				Name:           "isPremium",
				ClassName:      "LicenseChecker",
				ReturnsBoolean: true,
				ReturnType:     "Z",
			},
			mode:     PatchModeDefensive,
			expected: false, // Should use return false in defensive mode
		},
		{
			name: "non-boolean method",
			mi: &shared.MethodInfo{
				Name:           "getStatus",
				ClassName:      "StatusChecker",
				ReturnsBoolean: false,
				ReturnType:     "I",
			},
			mode:     PatchModeDefensive,
			expected: false,
		},
		{
			name: "emulator detection in defensive mode",
			mi: &shared.MethodInfo{
				Name:           "isEmulator",
				ClassName:      "EmulatorDetector",
				ReturnsBoolean: true,
				ReturnType:     "Z",
			},
			mode:     PatchModeDefensive,
			expected: true,
		},
		{
			name: "billing check in research mode",
			mi: &shared.MethodInfo{
				Name:           "hasPurchased",
				ClassName:      "BillingManager",
				ReturnsBoolean: true,
				ReturnType:     "Z",
			},
			mode:     PatchModeResearch,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := strategy.CanApply(tt.mi, tt.mode)
			if result != tt.expected {
				t.Errorf("CanApply() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestReturnTrueStrategy_Generate(t *testing.T) {
	strategy := NewReturnTrueStrategy()

	tests := []struct {
		name           string
		mi             *shared.MethodInfo
		mode           PatchMode
		expectError    bool
		checkSmali     bool
		expectedInCode []string
	}{
		{
			name: "static method",
			mi: &shared.MethodInfo{
				Name:           "isRooted",
				ClassName:      "RootDetector",
				ReturnsBoolean: true,
				ReturnType:     "Z",
				IsStatic:       true,
				IsPublic:       true,
				MethodHeader:   ".method public static isRooted()Z",
				RawBody:        []string{".method public static isRooted()Z", "    .registers 2", "    # original code", ".end method"},
			},
			mode:        PatchModeDefensive,
			expectError: false,
			checkSmali:  true,
			expectedInCode: []string{
				".method public static isRooted()Z",
				".registers 1",
				"const/4 v0, 0x1",
				"return v0",
				".end method",
			},
		},
		{
			name: "instance method",
			mi: &shared.MethodInfo{
				Name:           "isPremium",
				ClassName:      "LicenseChecker",
				ReturnsBoolean: true,
				ReturnType:     "Z",
				IsStatic:       false,
				IsPublic:       true,
				MethodHeader:   ".method public isPremium()Z",
				RawBody:        []string{".method public isPremium()Z", "    .registers 3", "    # original code", ".end method"},
			},
			mode:        PatchModeResearch,
			expectError: false,
			checkSmali:  true,
			expectedInCode: []string{
				".method public isPremium()Z",
				".registers 2",
				"const/4 v0, 0x1",
				"return v0",
				".end method",
			},
		},
		{
			name: "private final method",
			mi: &shared.MethodInfo{
				Name:           "checkDebug",
				ClassName:      "DebugDetector",
				ReturnsBoolean: true,
				ReturnType:     "Z",
				IsStatic:       false,
				IsPrivate:      true,
				IsFinal:        true,
				MethodHeader:   ".method private final checkDebug()Z",
				RawBody:        []string{".method private final checkDebug()Z", "    .registers 1", "    # code", ".end method"},
			},
			mode:        PatchModeDefensive,
			expectError: false,
			checkSmali:  true,
			expectedInCode: []string{
				".method private final checkDebug()Z",
				".registers 2",
				"const/4 v0, 0x1",
				"return v0",
			},
		},
		{
			name:        "nil method info",
			mi:          nil,
			mode:        PatchModeDefensive,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			patch, err := strategy.Generate(tt.mi, tt.mode)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if patch == nil {
				t.Fatal("Expected patch but got nil")
			}

			// Check patch type
			if patch.PatchType != PatchReturnTrue {
				t.Errorf("PatchType = %v, expected %v", patch.PatchType, PatchReturnTrue)
			}

			// Check mode
			if patch.Mode != tt.mode {
				t.Errorf("Mode = %v, expected %v", patch.Mode, tt.mode)
			}

			// Check explanation fields are non-empty
			if patch.Explanation.Reason == "" {
				t.Error("Explanation.Reason is empty")
			}
			if patch.Explanation.WhatItDoes == "" {
				t.Error("Explanation.WhatItDoes is empty")
			}
			if patch.Explanation.WhyThisPatch == "" {
				t.Error("Explanation.WhyThisPatch is empty")
			}
			if patch.Explanation.Impact == "" {
				t.Error("Explanation.Impact is empty")
			}

			// Check Smali code
			if tt.checkSmali {
				for _, expected := range tt.expectedInCode {
					if !strings.Contains(patch.PatchedCode, expected) {
						t.Errorf("PatchedCode missing expected string: %q\nGot:\n%s", expected, patch.PatchedCode)
					}
				}
			}
		})
	}
}

func TestReturnTrueStrategy_CalculateRequiredRegisters(t *testing.T) {
	strategy := NewReturnTrueStrategy()

	tests := []struct {
		name     string
		mi       *shared.MethodInfo
		expected int
	}{
		{
			name: "static method",
			mi: &shared.MethodInfo{
				IsStatic: true,
			},
			expected: 1, // Only v0
		},
		{
			name: "instance method",
			mi: &shared.MethodInfo{
				IsStatic: false,
			},
			expected: 2, // v0 + p0
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := strategy.calculateRequiredRegisters(tt.mi)
			if result != tt.expected {
				t.Errorf("calculateRequiredRegisters() = %d, expected %d", result, tt.expected)
			}
		})
	}
}

func TestReturnTrueStrategy_GetPriority(t *testing.T) {
	strategy := NewReturnTrueStrategy()
	priority := strategy.GetPriority()

	if priority <= 0 {
		t.Errorf("GetPriority() = %d, expected positive value", priority)
	}
}

func TestReturnTrueStrategy_GetDescription(t *testing.T) {
	strategy := NewReturnTrueStrategy()
	desc := strategy.GetDescription()

	if desc == "" {
		t.Error("GetDescription() returned empty string")
	}

	if !strings.Contains(desc, "true") {
		t.Error("GetDescription() should mention 'true'")
	}
}

func TestReturnTrueStrategy_ExplanationContent(t *testing.T) {
	strategy := NewReturnTrueStrategy()

	tests := []struct {
		name        string
		mi          *shared.MethodInfo
		mode        PatchMode
		checkReason string
		checkImpact string
	}{
		{
			name: "root detection defensive",
			mi: &shared.MethodInfo{
				Name:           "isRooted",
				ClassName:      "RootDetector",
				ReturnsBoolean: true,
				ReturnType:     "Z",
				MethodHeader:   ".method public isRooted()Z",
				RawBody:        []string{".method public isRooted()Z", ".end method"},
			},
			mode:        PatchModeDefensive,
			checkReason: "root",
			checkImpact: "root",
		},
		{
			name: "premium check research",
			mi: &shared.MethodInfo{
				Name:           "isPremium",
				ClassName:      "LicenseChecker",
				ReturnsBoolean: true,
				ReturnType:     "Z",
				MethodHeader:   ".method public isPremium()Z",
				RawBody:        []string{".method public isPremium()Z", ".end method"},
			},
			mode:        PatchModeResearch,
			checkReason: "premium",
			checkImpact: "Premium",
		},
		{
			name: "billing check research",
			mi: &shared.MethodInfo{
				Name:           "hasPurchased",
				ClassName:      "BillingManager",
				ReturnsBoolean: true,
				ReturnType:     "Z",
				MethodHeader:   ".method public hasPurchased()Z",
				RawBody:        []string{".method public hasPurchased()Z", ".end method"},
			},
			mode:        PatchModeResearch,
			checkReason: "billing",
			checkImpact: "Paid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			patch, err := strategy.Generate(tt.mi, tt.mode)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			reasonLower := strings.ToLower(patch.Explanation.Reason)
			if !strings.Contains(reasonLower, strings.ToLower(tt.checkReason)) {
				t.Errorf("Reason should mention %q, got: %s", tt.checkReason, patch.Explanation.Reason)
			}

			impactLower := strings.ToLower(patch.Explanation.Impact)
			if !strings.Contains(impactLower, strings.ToLower(tt.checkImpact)) {
				t.Errorf("Impact should mention %q, got: %s", tt.checkImpact, patch.Explanation.Impact)
			}
		})
	}
}
