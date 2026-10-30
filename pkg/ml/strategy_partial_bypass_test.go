package ml

import (
	"strings"
	"testing"

	"mega-analyzer/pkg/ml/internal/shared"
)

func TestPartialBypassStrategy_CanApply(t *testing.T) {
	strategy := NewPartialBypassStrategy()

	tests := []struct {
		name     string
		mi       *shared.MethodInfo
		mode     PatchMode
		expected bool
	}{
		{
			name: "applies to boolean method with multiple conditionals and security API",
			mi: &shared.MethodInfo{
				Name:           "checkRootAndValidate",
				ReturnsBoolean: true,
				IfCheckCount:   3,
				HasDualReturn:  true,
				HasSecurityAPI: true,
				SecurityCalls:  []string{"checkRoot", "validateIntegrity"},
			},
			mode:     PatchModeResearch,
			expected: true,
		},
		{
			name: "applies to boolean method with multiple conditionals and security strings",
			mi: &shared.MethodInfo{
				Name:               "isPremiumUser",
				ReturnsBoolean:     true,
				IfCheckCount:       2,
				HasDualReturn:      true,
				HasSecurityAPI:     false,
				HasSecurityStrings: true,
				SecurityStrings:    []string{"root", "su"},
			},
			mode:     PatchModeResearch,
			expected: true,
		},
		{
			name: "does not apply to non-boolean method",
			mi: &shared.MethodInfo{
				Name:           "checkRoot",
				ReturnsBoolean: false,
				IfCheckCount:   3,
				HasDualReturn:  true,
				HasSecurityAPI: true,
			},
			mode:     PatchModeResearch,
			expected: false,
		},
		{
			name: "does not apply to method with single conditional",
			mi: &shared.MethodInfo{
				Name:           "checkRoot",
				ReturnsBoolean: true,
				IfCheckCount:   1,
				HasDualReturn:  true,
				HasSecurityAPI: true,
			},
			mode:     PatchModeResearch,
			expected: false,
		},
		{
			name: "does not apply to method without security content",
			mi: &shared.MethodInfo{
				Name:               "isValid",
				ReturnsBoolean:     true,
				IfCheckCount:       3,
				HasDualReturn:      true,
				HasSecurityAPI:     false,
				HasSecurityStrings: false,
			},
			mode:     PatchModeResearch,
			expected: false,
		},
		{
			name: "does not apply to method without dual return",
			mi: &shared.MethodInfo{
				Name:           "checkRoot",
				ReturnsBoolean: true,
				IfCheckCount:   3,
				HasDualReturn:  false,
				HasSecurityAPI: true,
			},
			mode:     PatchModeResearch,
			expected: false,
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

func TestPartialBypassStrategy_Generate(t *testing.T) {
	strategy := NewPartialBypassStrategy()

	tests := []struct {
		name         string
		mi           *shared.MethodInfo
		mode         PatchMode
		expectError  bool
		checkPatched func(t *testing.T, patch *GeneratedPatch)
	}{
		{
			name: "generates patch for research mode",
			mi: &shared.MethodInfo{
				Name:           "checkRootAndValidate",
				ClassName:      "RootDetector",
				FilePath:       "com/example/RootDetector.smali",
				ReturnsBoolean: true,
				IfCheckCount:   2,
				HasDualReturn:  true,
				HasSecurityAPI: true,
				SecurityCalls:  []string{"checkRoot"},
				MethodHeader:   ".method public checkRootAndValidate()Z",
				RawBody: []string{
					".method public checkRootAndValidate()Z",
					"    .registers 2",
					"    ",
					"    invoke-static {}, Lcom/example/RootChecker;->checkRoot()Z",
					"    move-result v0",
					"    if-eqz v0, :cond_1",
					"    ",
					"    const/4 v0, 0x1",
					"    return v0",
					"    ",
					"    :cond_1",
					"    const/4 v0, 0x0",
					"    return v0",
					".end method",
				},
			},
			mode:        PatchModeResearch,
			expectError: false,
			checkPatched: func(t *testing.T, patch *GeneratedPatch) {
				if patch == nil {
					t.Fatal("patch is nil")
				}
				if patch.Mode != PatchModeResearch {
					t.Errorf("Mode = %v, expected %v", patch.Mode, PatchModeResearch)
				}
				if patch.PatchType != PatchNop {
					t.Errorf("PatchType = %v, expected %v", patch.PatchType, PatchNop)
				}
				if !strings.Contains(patch.Description, "security-related condition") {
					t.Errorf("Description should mention security-related conditions, got: %s", patch.Description)
				}
				// Check that explanation fields are populated
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
			},
		},
		{
			name: "generates patch for defensive mode",
			mi: &shared.MethodInfo{
				Name:           "checkRootAndValidate",
				ClassName:      "RootDetector",
				FilePath:       "com/example/RootDetector.smali",
				ReturnsBoolean: true,
				IfCheckCount:   2,
				HasDualReturn:  true,
				HasSecurityAPI: true,
				SecurityCalls:  []string{"checkRoot"},
				MethodHeader:   ".method public checkRootAndValidate()Z",
				RawBody: []string{
					".method public checkRootAndValidate()Z",
					"    .registers 2",
					"    ",
					"    invoke-static {}, Lcom/example/RootChecker;->checkRoot()Z",
					"    move-result v0",
					"    if-eqz v0, :cond_1",
					"    ",
					"    const/4 v0, 0x1",
					"    return v0",
					"    ",
					"    :cond_1",
					"    const/4 v0, 0x0",
					"    return v0",
					".end method",
				},
			},
			mode:        PatchModeDefensive,
			expectError: false,
			checkPatched: func(t *testing.T, patch *GeneratedPatch) {
				if patch == nil {
					t.Fatal("patch is nil")
				}
				if patch.Mode != PatchModeDefensive {
					t.Errorf("Mode = %v, expected %v", patch.Mode, PatchModeDefensive)
				}
			},
		},
		{
			name:        "returns error for nil method info",
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
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.checkPatched != nil {
				tt.checkPatched(t, patch)
			}
		})
	}
}

func TestPartialBypassStrategy_GetPriority(t *testing.T) {
	strategy := NewPartialBypassStrategy()
	priority := strategy.GetPriority()

	if priority != 70 {
		t.Errorf("GetPriority() = %d, expected 70", priority)
	}
}

func TestPartialBypassStrategy_GetDescription(t *testing.T) {
	strategy := NewPartialBypassStrategy()
	desc := strategy.GetDescription()

	if desc == "" {
		t.Error("GetDescription() returned empty string")
	}

	if !strings.Contains(desc, "Surgically") {
		t.Errorf("Description should mention 'Surgically', got: %s", desc)
	}
}

func TestPartialBypassStrategy_isSecurityRelatedLine(t *testing.T) {
	strategy := NewPartialBypassStrategy()

	tests := []struct {
		name     string
		line     string
		mi       *shared.MethodInfo
		expected bool
	}{
		{
			name: "detects security API call",
			line: "    invoke-static {}, Lcom/example/RootChecker;->checkRoot()Z",
			mi: &shared.MethodInfo{
				SecurityCalls: []string{"checkRoot"},
			},
			expected: true,
		},
		{
			name: "detects security string",
			line: "    const-string v0, \"su\"",
			mi: &shared.MethodInfo{
				SecurityStrings: []string{"su"},
			},
			expected: true,
		},
		{
			name: "detects root pattern in invoke",
			line: "    invoke-virtual {v0}, Lcom/example/RootDetector;->isRooted()Z",
			mi: &shared.MethodInfo{
				SecurityCalls: []string{},
			},
			expected: true,
		},
		{
			name: "does not detect non-security line",
			line: "    const/4 v0, 0x1",
			mi: &shared.MethodInfo{
				SecurityCalls:   []string{},
				SecurityStrings: []string{},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := strategy.isSecurityRelatedLine(tt.line, tt.mi)
			if result != tt.expected {
				t.Errorf("isSecurityRelatedLine() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestPartialBypassStrategy_isConditional(t *testing.T) {
	strategy := NewPartialBypassStrategy()

	tests := []struct {
		name     string
		line     string
		expected bool
	}{
		{
			name:     "detects if-eqz",
			line:     "if-eqz v0, :cond_1",
			expected: true,
		},
		{
			name:     "detects if-nez",
			line:     "if-nez v0, :cond_1",
			expected: true,
		},
		{
			name:     "detects if-eq",
			line:     "if-eq v0, v1, :cond_1",
			expected: true,
		},
		{
			name:     "does not detect non-conditional",
			line:     "const/4 v0, 0x1",
			expected: false,
		},
		{
			name:     "does not detect invoke",
			line:     "invoke-static {}, Lcom/example/Test;->method()V",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := strategy.isConditional(tt.line)
			if result != tt.expected {
				t.Errorf("isConditional() = %v, expected %v for line: %s", result, tt.expected, tt.line)
			}
		})
	}
}

func TestPartialBypassStrategy_modifyConditional(t *testing.T) {
	strategy := NewPartialBypassStrategy()

	tests := []struct {
		name     string
		line     string
		mode     PatchMode
		expected string
	}{
		{
			name:     "inverts if-eqz in research mode",
			line:     "    if-eqz v0, :cond_1",
			mode:     PatchModeResearch,
			expected: "    if-nez v0, :cond_1",
		},
		{
			name:     "inverts if-nez in research mode",
			line:     "    if-nez v0, :cond_1",
			mode:     PatchModeResearch,
			expected: "    if-eqz v0, :cond_1",
		},
		{
			name:     "preserves line in defensive mode",
			line:     "    if-eqz v0, :cond_1",
			mode:     PatchModeDefensive,
			expected: "    if-eqz v0, :cond_1",
		},
		{
			name:     "preserves indentation",
			line:     "        if-eqz v0, :cond_1",
			mode:     PatchModeResearch,
			expected: "        if-nez v0, :cond_1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := strategy.modifyConditional(tt.line, tt.mode)
			if result != tt.expected {
				t.Errorf("modifyConditional() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

func TestPartialBypassStrategy_Explanation(t *testing.T) {
	strategy := NewPartialBypassStrategy()

	mi := &shared.MethodInfo{
		Name:               "checkRootAndValidate",
		ClassName:          "RootDetector",
		FilePath:           "com/example/RootDetector.smali",
		ReturnsBoolean:     true,
		IfCheckCount:       3,
		HasDualReturn:      true,
		HasSecurityAPI:     true,
		HasSecurityName:    true,
		HasSecurityStrings: true,
		SecurityCalls:      []string{"checkRoot", "validateIntegrity"},
		SecurityStrings:    []string{"su", "root"},
		MethodHeader:       ".method public checkRootAndValidate()Z",
		RawBody: []string{
			".method public checkRootAndValidate()Z",
			"    .registers 2",
			"    invoke-static {}, Lcom/example/RootChecker;->checkRoot()Z",
			"    move-result v0",
			"    if-eqz v0, :cond_1",
			"    const/4 v0, 0x1",
			"    return v0",
			"    :cond_1",
			"    const/4 v0, 0x0",
			"    return v0",
			".end method",
		},
	}

	t.Run("research mode explanation", func(t *testing.T) {
		patch, err := strategy.Generate(mi, PatchModeResearch)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		exp := patch.Explanation

		// Check all required fields are populated
		if exp.Reason == "" {
			t.Error("Reason is empty")
		}
		if exp.WhatItDoes == "" {
			t.Error("WhatItDoes is empty")
		}
		if exp.WhyThisPatch == "" {
			t.Error("WhyThisPatch is empty")
		}
		if exp.Impact == "" {
			t.Error("Impact is empty")
		}

		// Check signals are populated
		if len(exp.Signals) == 0 {
			t.Error("Signals are empty")
		}

		// Verify signals contain expected information
		hasMethodName := false
		hasSecurityAPI := false
		hasSecurityStrings := false
		hasMultiPath := false

		for _, signal := range exp.Signals {
			if strings.Contains(signal, "Method name") {
				hasMethodName = true
			}
			if strings.Contains(signal, "Security API calls") {
				hasSecurityAPI = true
			}
			if strings.Contains(signal, "Security strings") {
				hasSecurityStrings = true
			}
			if strings.Contains(signal, "Multi-path method") {
				hasMultiPath = true
			}
		}

		if !hasMethodName {
			t.Error("Signals should include method name")
		}
		if !hasSecurityAPI {
			t.Error("Signals should include security API calls")
		}
		if !hasSecurityStrings {
			t.Error("Signals should include security strings")
		}
		if !hasMultiPath {
			t.Error("Signals should include multi-path information")
		}
	})

	t.Run("defensive mode explanation", func(t *testing.T) {
		patch, err := strategy.Generate(mi, PatchModeDefensive)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		exp := patch.Explanation

		// Check all required fields are populated
		if exp.Reason == "" {
			t.Error("Reason is empty")
		}
		if exp.WhatItDoes == "" {
			t.Error("WhatItDoes is empty")
		}
		if exp.WhyThisPatch == "" {
			t.Error("WhyThisPatch is empty")
		}
		if exp.Impact == "" {
			t.Error("Impact is empty")
		}
	})
}
