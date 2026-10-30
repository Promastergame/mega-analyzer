package ml

import (
	"strings"
	"testing"

	"mega-analyzer/pkg/ml/internal/shared"
)

// ═══════════════════════════════════════════════════════════════════════════════
// CONDITION INVERSION STRATEGY TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestConditionInversionStrategy_CanApply(t *testing.T) {
	strategy := NewConditionInversionStrategy()

	tests := []struct {
		name     string
		mi       *shared.MethodInfo
		mode     PatchMode
		expected bool
	}{
		{
			name: "boolean method with dual return and conditionals",
			mi: &shared.MethodInfo{
				Name:           "isRooted",
				ClassName:      "RootDetector",
				ReturnsBoolean: true,
				ReturnType:     "Z",
				IfCheckCount:   2,
				HasDualReturn:  true,
				RawBody: []string{
					".method public isRooted()Z",
					"    .registers 2",
					"    invoke-static {}, Lcom/example/Utils;->checkSu()Z",
					"    move-result v0",
					"    if-eqz v0, :cond_1",
					"    const/4 v0, 0x1",
					"    return v0",
					"    :cond_1",
					"    const/4 v0, 0x0",
					"    return v0",
					".end method",
				},
			},
			mode:     PatchModeDefensive,
			expected: true,
		},
		{
			name: "boolean method without conditionals",
			mi: &shared.MethodInfo{
				Name:           "isPremium",
				ClassName:      "LicenseChecker",
				ReturnsBoolean: true,
				ReturnType:     "Z",
				IfCheckCount:   0,
				HasDualReturn:  false,
				RawBody: []string{
					".method public isPremium()Z",
					"    .registers 1",
					"    const/4 v0, 0x1",
					"    return v0",
					".end method",
				},
			},
			mode:     PatchModeResearch,
			expected: false,
		},
		{
			name: "boolean method with conditionals but no dual return",
			mi: &shared.MethodInfo{
				Name:           "checkStatus",
				ClassName:      "StatusChecker",
				ReturnsBoolean: true,
				ReturnType:     "Z",
				IfCheckCount:   1,
				HasDualReturn:  false,
				RawBody: []string{
					".method public checkStatus()Z",
					"    .registers 2",
					"    const/4 v0, 0x1",
					"    if-eqz v0, :cond_1",
					"    const/4 v0, 0x1",
					"    :cond_1",
					"    return v0",
					".end method",
				},
			},
			mode:     PatchModeDefensive,
			expected: false,
		},
		{
			name: "non-boolean method",
			mi: &shared.MethodInfo{
				Name:           "getStatus",
				ClassName:      "StatusChecker",
				ReturnsBoolean: false,
				ReturnType:     "I",
				IfCheckCount:   2,
				HasDualReturn:  true,
				RawBody: []string{
					".method public getStatus()I",
					"    .registers 2",
					"    if-eqz v0, :cond_1",
					"    const/4 v0, 0x1",
					"    return v0",
					"    :cond_1",
					"    const/4 v0, 0x0",
					"    return v0",
					".end method",
				},
			},
			mode:     PatchModeDefensive,
			expected: false,
		},
		{
			name: "emulator detection with multiple conditionals",
			mi: &shared.MethodInfo{
				Name:           "isEmulator",
				ClassName:      "EmulatorDetector",
				ReturnsBoolean: true,
				ReturnType:     "Z",
				IfCheckCount:   3,
				HasDualReturn:  true,
				RawBody: []string{
					".method public isEmulator()Z",
					"    .registers 3",
					"    invoke-static {}, Lcom/example/Utils;->checkBuild()Z",
					"    move-result v0",
					"    if-nez v0, :cond_1",
					"    invoke-static {}, Lcom/example/Utils;->checkFiles()Z",
					"    move-result v1",
					"    if-eqz v1, :cond_2",
					"    :cond_1",
					"    const/4 v0, 0x1",
					"    return v0",
					"    :cond_2",
					"    const/4 v0, 0x0",
					"    return v0",
					".end method",
				},
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

func TestConditionInversionStrategy_Generate(t *testing.T) {
	strategy := NewConditionInversionStrategy()

	tests := []struct {
		name               string
		mi                 *shared.MethodInfo
		mode               PatchMode
		expectError        bool
		expectedInversions map[string]string // original -> inverted
	}{
		{
			name: "invert if-eqz to if-nez",
			mi: &shared.MethodInfo{
				Name:           "isRooted",
				ClassName:      "RootDetector",
				FilePath:       "com/example/RootDetector.smali",
				ReturnsBoolean: true,
				ReturnType:     "Z",
				IfCheckCount:   1,
				HasDualReturn:  true,
				MethodHeader:   ".method public isRooted()Z",
				RawBody: []string{
					".method public isRooted()Z",
					"    .registers 2",
					"    invoke-static {}, Lcom/example/Utils;->checkSu()Z",
					"    move-result v0",
					"    if-eqz v0, :cond_1",
					"    const/4 v0, 0x1",
					"    return v0",
					"    :cond_1",
					"    const/4 v0, 0x0",
					"    return v0",
					".end method",
				},
			},
			mode:        PatchModeDefensive,
			expectError: false,
			expectedInversions: map[string]string{
				"if-eqz": "if-nez",
			},
		},
		{
			name: "invert if-nez to if-eqz",
			mi: &shared.MethodInfo{
				Name:           "isPremium",
				ClassName:      "LicenseChecker",
				FilePath:       "com/example/LicenseChecker.smali",
				ReturnsBoolean: true,
				ReturnType:     "Z",
				IfCheckCount:   1,
				HasDualReturn:  true,
				MethodHeader:   ".method public isPremium()Z",
				RawBody: []string{
					".method public isPremium()Z",
					"    .registers 2",
					"    invoke-virtual {p0}, Lcom/example/LicenseChecker;->checkLicense()Z",
					"    move-result v0",
					"    if-nez v0, :cond_1",
					"    const/4 v0, 0x0",
					"    return v0",
					"    :cond_1",
					"    const/4 v0, 0x1",
					"    return v0",
					".end method",
				},
			},
			mode:        PatchModeResearch,
			expectError: false,
			expectedInversions: map[string]string{
				"if-nez": "if-eqz",
			},
		},
		{
			name: "invert multiple conditionals",
			mi: &shared.MethodInfo{
				Name:           "isEmulator",
				ClassName:      "EmulatorDetector",
				FilePath:       "com/example/EmulatorDetector.smali",
				ReturnsBoolean: true,
				ReturnType:     "Z",
				IfCheckCount:   3,
				HasDualReturn:  true,
				MethodHeader:   ".method public isEmulator()Z",
				RawBody: []string{
					".method public isEmulator()Z",
					"    .registers 3",
					"    invoke-static {}, Lcom/example/Utils;->checkBuild()Z",
					"    move-result v0",
					"    if-nez v0, :cond_1",
					"    invoke-static {}, Lcom/example/Utils;->checkFiles()Z",
					"    move-result v1",
					"    if-eqz v1, :cond_2",
					"    :cond_1",
					"    const/4 v0, 0x1",
					"    return v0",
					"    :cond_2",
					"    const/4 v0, 0x0",
					"    return v0",
					".end method",
				},
			},
			mode:        PatchModeResearch,
			expectError: false,
			expectedInversions: map[string]string{
				"if-nez": "if-eqz",
				"if-eqz": "if-nez",
			},
		},
		{
			name: "invert comparison conditionals",
			mi: &shared.MethodInfo{
				Name:           "checkValue",
				ClassName:      "ValueChecker",
				FilePath:       "com/example/ValueChecker.smali",
				ReturnsBoolean: true,
				ReturnType:     "Z",
				IfCheckCount:   2,
				HasDualReturn:  true,
				MethodHeader:   ".method public checkValue()Z",
				RawBody: []string{
					".method public checkValue()Z",
					"    .registers 3",
					"    const/4 v0, 0xa",
					"    const/4 v1, 0x5",
					"    if-lt v0, v1, :cond_1",
					"    if-gt v0, v1, :cond_2",
					"    const/4 v0, 0x1",
					"    return v0",
					"    :cond_1",
					"    :cond_2",
					"    const/4 v0, 0x0",
					"    return v0",
					".end method",
				},
			},
			mode:        PatchModeDefensive,
			expectError: false,
			expectedInversions: map[string]string{
				"if-lt": "if-ge",
				"if-gt": "if-le",
			},
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

			// Verify patch metadata
			if patch.MethodName != tt.mi.Name {
				t.Errorf("MethodName = %v, expected %v", patch.MethodName, tt.mi.Name)
			}

			if patch.FilePath != tt.mi.FilePath {
				t.Errorf("FilePath = %v, expected %v", patch.FilePath, tt.mi.FilePath)
			}

			if patch.Mode != tt.mode {
				t.Errorf("Mode = %v, expected %v", patch.Mode, tt.mode)
			}

			// Verify inversions occurred
			for original, inverted := range tt.expectedInversions {
				if !strings.Contains(patch.PatchedCode, inverted) {
					t.Errorf("Expected patched code to contain %q but it doesn't", inverted)
				}

				// Count occurrences in original vs patched
				originalCount := strings.Count(patch.OriginalCode, original)
				invertedCount := strings.Count(patch.PatchedCode, inverted)

				if originalCount > 0 && invertedCount == 0 {
					t.Errorf("Expected %q to be inverted to %q but found no inversions", original, inverted)
				}
			}

			// Verify explanation fields are non-empty (Requirements 2.1, 2.2, 2.3, 2.4)
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
		})
	}
}

func TestConditionInversionStrategy_InvertConditionalInstruction(t *testing.T) {
	strategy := NewConditionInversionStrategy()

	tests := []struct {
		name           string
		input          string
		expectedOutput string
		expectedInvert bool
	}{
		{
			name:           "if-eqz to if-nez",
			input:          "    if-eqz v0, :cond_1",
			expectedOutput: "    if-nez v0, :cond_1",
			expectedInvert: true,
		},
		{
			name:           "if-nez to if-eqz",
			input:          "    if-nez v1, :label_2",
			expectedOutput: "    if-eqz v1, :label_2",
			expectedInvert: true,
		},
		{
			name:           "if-eq to if-ne",
			input:          "    if-eq v0, v1, :cond_3",
			expectedOutput: "    if-ne v0, v1, :cond_3",
			expectedInvert: true,
		},
		{
			name:           "if-ne to if-eq",
			input:          "    if-ne v2, v3, :label_4",
			expectedOutput: "    if-eq v2, v3, :label_4",
			expectedInvert: true,
		},
		{
			name:           "if-lt to if-ge",
			input:          "    if-lt v0, v1, :cond_5",
			expectedOutput: "    if-ge v0, v1, :cond_5",
			expectedInvert: true,
		},
		{
			name:           "if-ge to if-lt",
			input:          "    if-ge v0, v1, :cond_6",
			expectedOutput: "    if-lt v0, v1, :cond_6",
			expectedInvert: true,
		},
		{
			name:           "if-gt to if-le",
			input:          "    if-gt v0, v1, :cond_7",
			expectedOutput: "    if-le v0, v1, :cond_7",
			expectedInvert: true,
		},
		{
			name:           "if-le to if-gt",
			input:          "    if-le v0, v1, :cond_8",
			expectedOutput: "    if-gt v0, v1, :cond_8",
			expectedInvert: true,
		},
		{
			name:           "if-ltz to if-gez",
			input:          "    if-ltz v0, :cond_9",
			expectedOutput: "    if-gez v0, :cond_9",
			expectedInvert: true,
		},
		{
			name:           "if-gez to if-ltz",
			input:          "    if-gez v0, :cond_10",
			expectedOutput: "    if-ltz v0, :cond_10",
			expectedInvert: true,
		},
		{
			name:           "if-gtz to if-lez",
			input:          "    if-gtz v0, :cond_11",
			expectedOutput: "    if-lez v0, :cond_11",
			expectedInvert: true,
		},
		{
			name:           "if-lez to if-gtz",
			input:          "    if-lez v0, :cond_12",
			expectedOutput: "    if-gtz v0, :cond_12",
			expectedInvert: true,
		},
		{
			name:           "non-conditional instruction",
			input:          "    const/4 v0, 0x1",
			expectedOutput: "    const/4 v0, 0x1",
			expectedInvert: false,
		},
		{
			name:           "method header",
			input:          ".method public isRooted()Z",
			expectedOutput: ".method public isRooted()Z",
			expectedInvert: false,
		},
		{
			name:           "label",
			input:          "    :cond_1",
			expectedOutput: "    :cond_1",
			expectedInvert: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, wasInverted := strategy.invertConditionalInstruction(tt.input)

			if output != tt.expectedOutput {
				t.Errorf("invertConditionalInstruction() output = %q, expected %q", output, tt.expectedOutput)
			}

			if wasInverted != tt.expectedInvert {
				t.Errorf("invertConditionalInstruction() wasInverted = %v, expected %v", wasInverted, tt.expectedInvert)
			}
		})
	}
}

func TestConditionInversionStrategy_GetPriority(t *testing.T) {
	strategy := NewConditionInversionStrategy()
	priority := strategy.GetPriority()

	if priority != 60 {
		t.Errorf("GetPriority() = %d, expected 60", priority)
	}
}

func TestConditionInversionStrategy_GetDescription(t *testing.T) {
	strategy := NewConditionInversionStrategy()
	description := strategy.GetDescription()

	if description == "" {
		t.Error("GetDescription() returned empty string")
	}

	// Verify description mentions key concepts
	descLower := strings.ToLower(description)
	if !strings.Contains(descLower, "conditional") {
		t.Error("Description should mention 'conditional'")
	}
	if !strings.Contains(descLower, "invert") {
		t.Error("Description should mention 'invert'")
	}
}

func TestConditionInversionStrategy_ExplanationCompleteness(t *testing.T) {
	strategy := NewConditionInversionStrategy()

	mi := &shared.MethodInfo{
		Name:               "isRooted",
		ClassName:          "RootDetector",
		FilePath:           "com/example/RootDetector.smali",
		ReturnsBoolean:     true,
		ReturnType:         "Z",
		IfCheckCount:       2,
		HasDualReturn:      true,
		HasSecurityName:    true,
		HasSecurityAPI:     true,
		SecurityCalls:      []string{"checkSu", "checkBusybox"},
		HasSecurityStrings: true,
		SecurityStrings:    []string{"/system/bin/su"},
		MethodHeader:       ".method public isRooted()Z",
		RawBody: []string{
			".method public isRooted()Z",
			"    .registers 2",
			"    if-eqz v0, :cond_1",
			"    const/4 v0, 0x1",
			"    return v0",
			"    :cond_1",
			"    const/4 v0, 0x0",
			"    return v0",
			".end method",
		},
	}

	modes := []PatchMode{PatchModeDefensive, PatchModeResearch}

	for _, mode := range modes {
		t.Run(string(mode), func(t *testing.T) {
			patch, err := strategy.Generate(mi, mode)
			if err != nil {
				t.Fatalf("Generate() error = %v", err)
			}

			// Verify all explanation fields are non-empty (Requirements 2.1, 2.2, 2.3, 2.4)
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

			// Verify signals are listed (Requirements 2.6)
			if len(patch.Explanation.Signals) == 0 {
				t.Error("Explanation.Signals is empty, expected matched signals")
			}

			// Verify signals include expected information
			hasMethodName := false
			hasSecurityAPI := false
			hasSecurityStrings := false
			hasDualReturn := false

			for _, signal := range patch.Explanation.Signals {
				if strings.Contains(signal, "Method name") {
					hasMethodName = true
				}
				if strings.Contains(signal, "Security API calls") {
					hasSecurityAPI = true
				}
				if strings.Contains(signal, "Security strings") {
					hasSecurityStrings = true
				}
				if strings.Contains(signal, "Dual return pattern") {
					hasDualReturn = true
				}
			}

			if !hasMethodName {
				t.Error("Expected signal about method name")
			}
			if !hasSecurityAPI {
				t.Error("Expected signal about security API calls")
			}
			if !hasSecurityStrings {
				t.Error("Expected signal about security strings")
			}
			if !hasDualReturn {
				t.Error("Expected signal about dual return pattern")
			}
		})
	}
}
