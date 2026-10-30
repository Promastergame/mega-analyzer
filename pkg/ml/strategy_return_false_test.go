package ml

import (
	"strings"
	"testing"

	"mega-analyzer/pkg/ml/internal/shared"
)

// ═══════════════════════════════════════════════════════════════════════════════
// RETURN FALSE STRATEGY TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestReturnFalseStrategy_CanApply(t *testing.T) {
	strategy := NewReturnFalseStrategy()

	tests := []struct {
		name     string
		mi       *shared.MethodInfo
		mode     PatchMode
		expected bool
	}{
		{
			name: "root detection in research mode",
			mi: &shared.MethodInfo{
				Name:           "isRooted",
				ClassName:      "RootDetector",
				ReturnsBoolean: true,
				ReturnType:     "Z",
			},
			mode:     PatchModeResearch,
			expected: true,
		},
		{
			name: "root detection in defensive mode",
			mi: &shared.MethodInfo{
				Name:           "isRooted",
				ClassName:      "RootDetector",
				ReturnsBoolean: true,
				ReturnType:     "Z",
			},
			mode:     PatchModeDefensive,
			expected: false, // Should use return true in defensive mode
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
			expected: true,
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
			expected: false, // Should use return true in research mode
		},
		{
			name: "non-boolean method",
			mi: &shared.MethodInfo{
				Name:           "getStatus",
				ClassName:      "StatusChecker",
				ReturnsBoolean: false,
				ReturnType:     "I",
			},
			mode:     PatchModeResearch,
			expected: false,
		},
		{
			name: "emulator detection in research mode",
			mi: &shared.MethodInfo{
				Name:           "isEmulator",
				ClassName:      "EmulatorDetector",
				ReturnsBoolean: true,
				ReturnType:     "Z",
			},
			mode:     PatchModeResearch,
			expected: true,
		},
		{
			name: "billing check in defensive mode",
			mi: &shared.MethodInfo{
				Name:           "hasPurchased",
				ClassName:      "BillingManager",
				ReturnsBoolean: true,
				ReturnType:     "Z",
			},
			mode:     PatchModeDefensive,
			expected: true,
		},
		{
			name: "debug detection in research mode",
			mi: &shared.MethodInfo{
				Name:           "isDebuggerAttached",
				ClassName:      "DebugDetector",
				ReturnsBoolean: true,
				ReturnType:     "Z",
			},
			mode:     PatchModeResearch,
			expected: true,
		},
		{
			name: "tamper detection in research mode",
			mi: &shared.MethodInfo{
				Name:           "isTampered",
				ClassName:      "IntegrityChecker",
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

func TestReturnFalseStrategy_Generate(t *testing.T) {
	strategy := NewReturnFalseStrategy()

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
			mode:        PatchModeResearch,
			expectError: false,
			checkSmali:  true,
			expectedInCode: []string{
				".method public static isRooted()Z",
				".registers 1",
				"const/4 v0, 0x0",
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
			mode:        PatchModeDefensive,
			expectError: false,
			checkSmali:  true,
			expectedInCode: []string{
				".method public isPremium()Z",
				".registers 2",
				"const/4 v0, 0x0",
				"return v0",
				".end method",
			},
		},
		{
			name: "private final method",
			mi: &shared.MethodInfo{
				Name:           "checkEmulator",
				ClassName:      "EmulatorDetector",
				ReturnsBoolean: true,
				ReturnType:     "Z",
				IsStatic:       false,
				IsPrivate:      true,
				IsFinal:        true,
				MethodHeader:   ".method private final checkEmulator()Z",
				RawBody:        []string{".method private final checkEmulator()Z", "    .registers 1", "    # code", ".end method"},
			},
			mode:        PatchModeResearch,
			expectError: false,
			checkSmali:  true,
			expectedInCode: []string{
				".method private final checkEmulator()Z",
				".registers 2",
				"const/4 v0, 0x0",
				"return v0",
			},
		},
		{
			name:        "nil method info",
			mi:          nil,
			mode:        PatchModeResearch,
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
			if patch.PatchType != PatchReturnFalse {
				t.Errorf("PatchType = %v, expected %v", patch.PatchType, PatchReturnFalse)
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

func TestReturnFalseStrategy_CalculateRequiredRegisters(t *testing.T) {
	strategy := NewReturnFalseStrategy()

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

func TestReturnFalseStrategy_GetPriority(t *testing.T) {
	strategy := NewReturnFalseStrategy()
	priority := strategy.GetPriority()

	if priority <= 0 {
		t.Errorf("GetPriority() = %d, expected positive value", priority)
	}
}

func TestReturnFalseStrategy_GetDescription(t *testing.T) {
	strategy := NewReturnFalseStrategy()
	desc := strategy.GetDescription()

	if desc == "" {
		t.Error("GetDescription() returned empty string")
	}

	if !strings.Contains(desc, "false") {
		t.Error("GetDescription() should mention 'false'")
	}
}

func TestReturnFalseStrategy_ExplanationContent(t *testing.T) {
	strategy := NewReturnFalseStrategy()

	tests := []struct {
		name        string
		mi          *shared.MethodInfo
		mode        PatchMode
		checkReason string
		checkImpact string
	}{
		{
			name: "root detection research",
			mi: &shared.MethodInfo{
				Name:           "isRooted",
				ClassName:      "RootDetector",
				ReturnsBoolean: true,
				ReturnType:     "Z",
				MethodHeader:   ".method public isRooted()Z",
				RawBody:        []string{".method public isRooted()Z", ".end method"},
			},
			mode:        PatchModeResearch,
			checkReason: "root",
			checkImpact: "root",
		},
		{
			name: "premium check defensive",
			mi: &shared.MethodInfo{
				Name:           "isPremium",
				ClassName:      "LicenseChecker",
				ReturnsBoolean: true,
				ReturnType:     "Z",
				MethodHeader:   ".method public isPremium()Z",
				RawBody:        []string{".method public isPremium()Z", ".end method"},
			},
			mode:        PatchModeDefensive,
			checkReason: "premium",
			checkImpact: "Premium",
		},
		{
			name: "billing check defensive",
			mi: &shared.MethodInfo{
				Name:           "hasPurchased",
				ClassName:      "BillingManager",
				ReturnsBoolean: true,
				ReturnType:     "Z",
				MethodHeader:   ".method public hasPurchased()Z",
				RawBody:        []string{".method public hasPurchased()Z", ".end method"},
			},
			mode:        PatchModeDefensive,
			checkReason: "billing",
			checkImpact: "Paid",
		},
		{
			name: "emulator detection research",
			mi: &shared.MethodInfo{
				Name:           "isEmulator",
				ClassName:      "EmulatorDetector",
				ReturnsBoolean: true,
				ReturnType:     "Z",
				MethodHeader:   ".method public isEmulator()Z",
				RawBody:        []string{".method public isEmulator()Z", ".end method"},
			},
			mode:        PatchModeResearch,
			checkReason: "emulator",
			checkImpact: "emulator",
		},
		{
			name: "debug detection research",
			mi: &shared.MethodInfo{
				Name:           "isDebuggerAttached",
				ClassName:      "DebugDetector",
				ReturnsBoolean: true,
				ReturnType:     "Z",
				MethodHeader:   ".method public isDebuggerAttached()Z",
				RawBody:        []string{".method public isDebuggerAttached()Z", ".end method"},
			},
			mode:        PatchModeResearch,
			checkReason: "debug",
			checkImpact: "debug",
		},
		{
			name: "tamper detection research",
			mi: &shared.MethodInfo{
				Name:           "isTampered",
				ClassName:      "IntegrityChecker",
				ReturnsBoolean: true,
				ReturnType:     "Z",
				MethodHeader:   ".method public isTampered()Z",
				RawBody:        []string{".method public isTampered()Z", ".end method"},
			},
			mode:        PatchModeResearch,
			checkReason: "tamper",
			checkImpact: "tamper",
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

func TestReturnFalseStrategy_SignalCollection(t *testing.T) {
	strategy := NewReturnFalseStrategy()

	mi := &shared.MethodInfo{
		Name:               "isRooted",
		ClassName:          "RootDetector",
		ReturnsBoolean:     true,
		ReturnType:         "Z",
		MethodHeader:       ".method public isRooted()Z",
		RawBody:            []string{".method public isRooted()Z", ".end method"},
		HasSecurityName:    true,
		HasSecurityAPI:     true,
		HasSecurityStrings: true,
		SecurityCalls:      []string{"checkRootBinary", "checkSuExists"},
		SecurityStrings:    []string{"/system/bin/su", "/system/xbin/su"},
	}

	patch, err := strategy.Generate(mi, PatchModeResearch)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Check that signals are collected
	if len(patch.Explanation.Signals) == 0 {
		t.Error("Expected signals to be collected, got none")
	}

	// Check for specific signal types
	hasNameSignal := false
	hasAPISignal := false
	hasStringSignal := false

	for _, signal := range patch.Explanation.Signals {
		if strings.Contains(signal, "Method name") {
			hasNameSignal = true
		}
		if strings.Contains(signal, "Security API calls") {
			hasAPISignal = true
		}
		if strings.Contains(signal, "Security strings") {
			hasStringSignal = true
		}
	}

	if !hasNameSignal {
		t.Error("Expected method name signal")
	}
	if !hasAPISignal {
		t.Error("Expected security API signal")
	}
	if !hasStringSignal {
		t.Error("Expected security strings signal")
	}
}
