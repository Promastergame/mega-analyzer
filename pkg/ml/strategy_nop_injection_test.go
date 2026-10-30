package ml

import (
	"strings"
	"testing"

	"mega-analyzer/pkg/ml/internal/shared"
)

func TestNopInjectionStrategy_CanApply(t *testing.T) {
	strategy := NewNopInjectionStrategy()

	tests := []struct {
		name     string
		mi       *shared.MethodInfo
		mode     PatchMode
		expected bool
	}{
		{
			name: "applies to method with security API calls",
			mi: &shared.MethodInfo{
				Name:             "checkSecurity",
				ReturnsBoolean:   false,
				IsShortMethod:    false,
				InstructionCount: 10,
				HasSecurityAPI:   true,
				SecurityCalls:    []string{"Landroid/os/Debug;->isDebuggerConnected()Z"},
			},
			mode:     PatchModeResearch,
			expected: true,
		},
		{
			name: "applies to method with security strings",
			mi: &shared.MethodInfo{
				Name:               "validateIntegrity",
				ReturnsBoolean:     false,
				IsShortMethod:      false,
				InstructionCount:   8,
				HasSecurityStrings: true,
				SecurityStrings:    []string{"/system/bin/su"},
			},
			mode:     PatchModeDefensive,
			expected: true,
		},
		{
			name: "applies to method with security name",
			mi: &shared.MethodInfo{
				Name:             "isRooted",
				ReturnsBoolean:   false,
				IsShortMethod:    false,
				InstructionCount: 15,
				HasSecurityName:  true,
			},
			mode:     PatchModeResearch,
			expected: true,
		},
		{
			name: "does not apply to simple boolean method",
			mi: &shared.MethodInfo{
				Name:             "isPremium",
				ReturnsBoolean:   true,
				IsShortMethod:    true,
				InstructionCount: 3,
				HasSecurityName:  true,
			},
			mode:     PatchModeResearch,
			expected: false,
		},
		{
			name: "does not apply to method with too few instructions",
			mi: &shared.MethodInfo{
				Name:             "check",
				ReturnsBoolean:   false,
				InstructionCount: 1,
				HasSecurityAPI:   true,
			},
			mode:     PatchModeResearch,
			expected: false,
		},
		{
			name: "does not apply to method without security content",
			mi: &shared.MethodInfo{
				Name:             "calculate",
				ReturnsBoolean:   false,
				InstructionCount: 10,
				HasSecurityAPI:   false,
				HasSecurityName:  false,
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

func TestNopInjectionStrategy_Generate(t *testing.T) {
	strategy := NewNopInjectionStrategy()

	tests := []struct {
		name         string
		mi           *shared.MethodInfo
		mode         PatchMode
		expectError  bool
		checkPatched func(*testing.T, *GeneratedPatch)
	}{
		{
			name: "generates nop patch for security method",
			mi: &shared.MethodInfo{
				Name:           "checkRoot",
				ClassName:      "RootDetector",
				FilePath:       "com/example/RootDetector.smali",
				ReturnType:     "Z",
				ReturnsBoolean: true,
				IsPublic:       true,
				IsStatic:       false,
				RegisterCount:  3,
				HasSecurityAPI: true,
				SecurityCalls:  []string{"Ljava/io/File;->exists()Z"},
				RawBody: []string{
					".method public checkRoot()Z",
					"    .registers 3",
					"    const-string v0, \"/system/bin/su\"",
					"    invoke-static {v0}, Ljava/io/File;->exists()Z",
					"    move-result v1",
					"    return v1",
					".end method",
				},
				MethodHeader: ".method public checkRoot()Z",
			},
			mode:        PatchModeResearch,
			expectError: false,
			checkPatched: func(t *testing.T, patch *GeneratedPatch) {
				if patch.PatchType != PatchNop {
					t.Errorf("Expected PatchNop, got %v", patch.PatchType)
				}
				if !strings.Contains(patch.PatchedCode, "nop") {
					t.Errorf("Patched code should contain nop instruction")
				}
				if !strings.Contains(patch.PatchedCode, ".method public checkRoot()Z") {
					t.Errorf("Patched code should preserve method header")
				}
				if !strings.Contains(patch.PatchedCode, ".end method") {
					t.Errorf("Patched code should have .end method")
				}
			},
		},
		{
			name: "generates nop patch for void method",
			mi: &shared.MethodInfo{
				Name:           "performCheck",
				ClassName:      "SecurityChecker",
				FilePath:       "com/example/SecurityChecker.smali",
				ReturnType:     "V",
				ReturnsVoid:    true,
				IsPublic:       true,
				IsStatic:       true,
				RegisterCount:  2,
				HasSecurityAPI: true,
				SecurityCalls:  []string{"Landroid/os/Debug;->isDebuggerConnected()Z"},
				RawBody: []string{
					".method public static performCheck()V",
					"    .registers 2",
					"    invoke-static {}, Landroid/os/Debug;->isDebuggerConnected()Z",
					"    move-result v0",
					"    if-eqz v0, :cond_0",
					"    invoke-static {v0}, Ljava/lang/System;->exit(I)V",
					"    :cond_0",
					"    return-void",
					".end method",
				},
				MethodHeader: ".method public static performCheck()V",
			},
			mode:        PatchModeDefensive,
			expectError: false,
			checkPatched: func(t *testing.T, patch *GeneratedPatch) {
				if patch.PatchType != PatchNop {
					t.Errorf("Expected PatchNop, got %v", patch.PatchType)
				}
				if !strings.Contains(patch.PatchedCode, "nop") {
					t.Errorf("Patched code should contain nop instruction")
				}
			},
		},
		{
			name: "handles method without raw body",
			mi: &shared.MethodInfo{
				Name:           "check",
				ClassName:      "Checker",
				FilePath:       "com/example/Checker.smali",
				ReturnType:     "I",
				ReturnsInt:     true,
				IsPublic:       true,
				IsStatic:       false,
				HasSecurityAPI: true,
				RawBody:        []string{},
				MethodHeader:   ".method public check()I",
			},
			mode:        PatchModeResearch,
			expectError: false,
			checkPatched: func(t *testing.T, patch *GeneratedPatch) {
				if patch.PatchType != PatchNop {
					t.Errorf("Expected PatchNop, got %v", patch.PatchType)
				}
				if !strings.Contains(patch.PatchedCode, "nop") {
					t.Errorf("Patched code should contain nop instruction")
				}
				if !strings.Contains(patch.PatchedCode, "return") {
					t.Errorf("Patched code should have return instruction")
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
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if patch == nil {
				t.Fatal("Expected patch but got nil")
			}

			// Run custom checks
			if tt.checkPatched != nil {
				tt.checkPatched(t, patch)
			}

			// Common checks
			if patch.MethodName != tt.mi.Name {
				t.Errorf("MethodName = %v, expected %v", patch.MethodName, tt.mi.Name)
			}
			if patch.Mode != tt.mode {
				t.Errorf("Mode = %v, expected %v", patch.Mode, tt.mode)
			}
			if patch.Explanation.Reason == "" {
				t.Errorf("Explanation.Reason should not be empty")
			}
			if patch.Explanation.WhatItDoes == "" {
				t.Errorf("Explanation.WhatItDoes should not be empty")
			}
			if patch.Explanation.WhyThisPatch == "" {
				t.Errorf("Explanation.WhyThisPatch should not be empty")
			}
			if patch.Explanation.Impact == "" {
				t.Errorf("Explanation.Impact should not be empty")
			}
		})
	}
}

func TestNopInjectionStrategy_GetPriority(t *testing.T) {
	strategy := NewNopInjectionStrategy()
	priority := strategy.GetPriority()

	if priority != 60 {
		t.Errorf("GetPriority() = %d, expected 60", priority)
	}
}

func TestNopInjectionStrategy_GetDescription(t *testing.T) {
	strategy := NewNopInjectionStrategy()
	desc := strategy.GetDescription()

	if desc == "" {
		t.Error("GetDescription() should not return empty string")
	}

	if !strings.Contains(desc, "nop") {
		t.Error("Description should mention 'nop'")
	}
}

func TestNopInjectionStrategy_ExplanationFields(t *testing.T) {
	strategy := NewNopInjectionStrategy()

	mi := &shared.MethodInfo{
		Name:               "isDebuggerConnected",
		ClassName:          "DebugDetector",
		FilePath:           "com/example/DebugDetector.smali",
		ReturnType:         "Z",
		ReturnsBoolean:     true,
		IsPublic:           true,
		InstructionCount:   10,
		HasSecurityAPI:     true,
		HasSecurityName:    true,
		SecurityCalls:      []string{"Landroid/os/Debug;->isDebuggerConnected()Z"},
		SecurityStrings:    []string{"debugger"},
		HasSecurityStrings: true,
		RawBody: []string{
			".method public isDebuggerConnected()Z",
			"    .registers 2",
			"    invoke-static {}, Landroid/os/Debug;->isDebuggerConnected()Z",
			"    move-result v0",
			"    return v0",
			".end method",
		},
		MethodHeader: ".method public isDebuggerConnected()Z",
	}

	modes := []PatchMode{PatchModeDefensive, PatchModeResearch}

	for _, mode := range modes {
		t.Run(string(mode), func(t *testing.T) {
			patch, err := strategy.Generate(mi, mode)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			// Check all explanation fields are populated
			if patch.Explanation.Reason == "" {
				t.Error("Reason should not be empty")
			}
			if patch.Explanation.WhatItDoes == "" {
				t.Error("WhatItDoes should not be empty")
			}
			if patch.Explanation.WhyThisPatch == "" {
				t.Error("WhyThisPatch should not be empty")
			}
			if patch.Explanation.Impact == "" {
				t.Error("Impact should not be empty")
			}

			// Check signals are included
			if len(patch.Explanation.Signals) == 0 {
				t.Error("Signals should not be empty for method with security indicators")
			}

			// Verify signals contain expected information
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
				t.Error("Should have method name signal")
			}
			if !hasAPISignal {
				t.Error("Should have API call signal")
			}
			if !hasStringSignal {
				t.Error("Should have security string signal")
			}
		})
	}
}

func TestNopInjectionStrategy_RegisterCalculation(t *testing.T) {
	strategy := NewNopInjectionStrategy()

	tests := []struct {
		name         string
		mi           *shared.MethodInfo
		minRegisters int
	}{
		{
			name: "static void method",
			mi: &shared.MethodInfo{
				IsStatic:    true,
				ReturnsVoid: true,
			},
			minRegisters: 2, // Minimum safety threshold
		},
		{
			name: "instance void method",
			mi: &shared.MethodInfo{
				IsStatic:    false,
				ReturnsVoid: true,
			},
			minRegisters: 2, // p0 + safety
		},
		{
			name: "static non-void method",
			mi: &shared.MethodInfo{
				IsStatic:    true,
				ReturnsVoid: false,
			},
			minRegisters: 2, // v0 + safety
		},
		{
			name: "instance non-void method",
			mi: &shared.MethodInfo{
				IsStatic:    false,
				ReturnsVoid: false,
			},
			minRegisters: 2, // p0 + v0
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			regs := strategy.calculateRequiredRegisters(tt.mi)
			if regs < tt.minRegisters {
				t.Errorf("calculateRequiredRegisters() = %d, expected at least %d", regs, tt.minRegisters)
			}
		})
	}
}
