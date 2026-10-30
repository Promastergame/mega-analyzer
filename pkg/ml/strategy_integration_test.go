package ml

import (
	"strings"
	"testing"

	"mega-analyzer/pkg/ml/internal/shared"
)

// ═══════════════════════════════════════════════════════════════════════════════
// STRATEGY INTEGRATION TESTS
//
// Tests that verify all strategies generate valid Smali code that passes
// validation. This ensures the integration between strategies and SmaliValidator.
//
// Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6
// ═══════════════════════════════════════════════════════════════════════════════

func TestAllStrategies_GenerateValidSmali(t *testing.T) {
	validator := NewSmaliValidator()

	// Test method info with various characteristics
	testMethods := []struct {
		name string
		mi   *shared.MethodInfo
	}{
		{
			name: "static boolean method",
			mi: &shared.MethodInfo{
				Name:           "isRooted",
				ClassName:      "RootDetector",
				FilePath:       "com/example/RootDetector.smali",
				ReturnsBoolean: true,
				ReturnType:     "Z",
				IsStatic:       true,
				IsPublic:       true,
				MethodHeader:   ".method public static isRooted()Z",
				RawBody:        []string{".method public static isRooted()Z", "    .registers 2", "    const/4 v0, 0x1", "    return v0", ".end method"},
			},
		},
		{
			name: "instance boolean method",
			mi: &shared.MethodInfo{
				Name:           "isPremium",
				ClassName:      "LicenseChecker",
				FilePath:       "com/example/LicenseChecker.smali",
				ReturnsBoolean: true,
				ReturnType:     "Z",
				IsStatic:       false,
				IsPublic:       true,
				MethodHeader:   ".method public isPremium()Z",
				RawBody:        []string{".method public isPremium()Z", "    .registers 3", "    const/4 v0, 0x1", "    return v0", ".end method"},
			},
		},
		{
			name: "method with conditionals",
			mi: &shared.MethodInfo{
				Name:           "checkSecurity",
				ClassName:      "SecurityChecker",
				FilePath:       "com/example/SecurityChecker.smali",
				ReturnsBoolean: true,
				ReturnType:     "Z",
				IsStatic:       false,
				IsPublic:       true,
				IfCheckCount:   2,
				HasDualReturn:  true,
				MethodHeader:   ".method public checkSecurity()Z",
				RawBody: []string{
					".method public checkSecurity()Z",
					"    .registers 2",
					"    invoke-static {}, Lcom/example/Utils;->check()Z",
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
		},
		{
			name: "method with security API",
			mi: &shared.MethodInfo{
				Name:             "detectDebug",
				ClassName:        "DebugDetector",
				FilePath:         "com/example/DebugDetector.smali",
				ReturnsBoolean:   false,
				ReturnType:       "V",
				ReturnsVoid:      true,
				IsStatic:         true,
				IsPublic:         true,
				HasSecurityAPI:   true,
				SecurityCalls:    []string{"Landroid/os/Debug;->isDebuggerConnected()Z"},
				InstructionCount: 5,
				MethodHeader:     ".method public static detectDebug()V",
				RawBody: []string{
					".method public static detectDebug()V",
					"    .registers 2",
					"    invoke-static {}, Landroid/os/Debug;->isDebuggerConnected()Z",
					"    move-result v0",
					"    return-void",
					".end method",
				},
			},
		},
	}

	strategies := []struct {
		name     string
		strategy PatchStrategy
		modes    []PatchMode
	}{
		{
			name:     "ReturnTrueStrategy",
			strategy: NewReturnTrueStrategy(),
			modes:    []PatchMode{PatchModeDefensive, PatchModeResearch},
		},
		{
			name:     "ReturnFalseStrategy",
			strategy: NewReturnFalseStrategy(),
			modes:    []PatchMode{PatchModeDefensive, PatchModeResearch},
		},
		{
			name:     "ConditionInversionStrategy",
			strategy: NewConditionInversionStrategy(),
			modes:    []PatchMode{PatchModeDefensive, PatchModeResearch},
		},
		{
			name:     "PartialBypassStrategy",
			strategy: NewPartialBypassStrategy(),
			modes:    []PatchMode{PatchModeDefensive, PatchModeResearch},
		},
		{
			name:     "NopInjectionStrategy",
			strategy: NewNopInjectionStrategy(),
			modes:    []PatchMode{PatchModeDefensive, PatchModeResearch},
		},
	}

	for _, tm := range testMethods {
		for _, strat := range strategies {
			for _, mode := range strat.modes {
				testName := tm.name + "_" + strat.name + "_" + string(mode)
				t.Run(testName, func(t *testing.T) {
					// Check if strategy can apply
					if !strat.strategy.CanApply(tm.mi, mode) {
						t.Skip("Strategy not applicable to this method")
						return
					}

					// Generate patch
					patch, err := strat.strategy.Generate(tm.mi, mode)
					if err != nil {
						t.Fatalf("Failed to generate patch: %v", err)
					}

					// Validate generated Smali
					result := validator.Validate(patch.PatchedCode)
					if !result.Valid {
						t.Errorf("Generated Smali is invalid:\nCode:\n%s\n\nErrors: %v",
							patch.PatchedCode, result.Errors)
					}

					// Verify basic structure
					if !strings.Contains(patch.PatchedCode, ".method") {
						t.Error("Patched code missing .method directive")
					}
					if !strings.Contains(patch.PatchedCode, ".end method") {
						t.Error("Patched code missing .end method directive")
					}
					if !strings.Contains(patch.PatchedCode, ".registers") {
						t.Error("Patched code missing .registers directive")
					}
				})
			}
		}
	}
}

func TestAllStrategies_SufficientRegisters(t *testing.T) {
	validator := NewSmaliValidator()

	testCases := []struct {
		name     string
		mi       *shared.MethodInfo
		strategy PatchStrategy
		mode     PatchMode
	}{
		{
			name: "ReturnTrue static",
			mi: &shared.MethodInfo{
				Name:           "test",
				ReturnsBoolean: true,
				ReturnType:     "Z",
				IsStatic:       true,
				MethodHeader:   ".method public static test()Z",
				RawBody:        []string{".method public static test()Z", ".end method"},
			},
			strategy: NewReturnTrueStrategy(),
			mode:     PatchModeDefensive,
		},
		{
			name: "ReturnTrue instance",
			mi: &shared.MethodInfo{
				Name:           "test",
				ReturnsBoolean: true,
				ReturnType:     "Z",
				IsStatic:       false,
				MethodHeader:   ".method public test()Z",
				RawBody:        []string{".method public test()Z", ".end method"},
			},
			strategy: NewReturnTrueStrategy(),
			mode:     PatchModeDefensive,
		},
		{
			name: "ReturnFalse static",
			mi: &shared.MethodInfo{
				Name:           "test",
				ReturnsBoolean: true,
				ReturnType:     "Z",
				IsStatic:       true,
				MethodHeader:   ".method public static test()Z",
				RawBody:        []string{".method public static test()Z", ".end method"},
			},
			strategy: NewReturnFalseStrategy(),
			mode:     PatchModeResearch,
		},
		{
			name: "ReturnFalse instance",
			mi: &shared.MethodInfo{
				Name:           "test",
				ReturnsBoolean: true,
				ReturnType:     "Z",
				IsStatic:       false,
				MethodHeader:   ".method public test()Z",
				RawBody:        []string{".method public test()Z", ".end method"},
			},
			strategy: NewReturnFalseStrategy(),
			mode:     PatchModeResearch,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Generate patch
			patch, err := tc.strategy.Generate(tc.mi, tc.mode)
			if err != nil {
				t.Fatalf("Failed to generate patch: %v", err)
			}

			// Calculate minimum required registers
			minRegs := validator.CalculateMinRegisters(patch.PatchType, tc.mi.IsStatic)

			// Extract actual register count from generated code
			lines := strings.Split(patch.PatchedCode, "\n")
			actualRegs := validator.extractRegisterCount(lines)

			// Verify sufficient registers
			if actualRegs < minRegs {
				t.Errorf("Insufficient registers: generated %d, minimum required %d",
					actualRegs, minRegs)
			}
		})
	}
}

func TestAllStrategies_ExplanationCompleteness(t *testing.T) {
	testMethods := []struct {
		name string
		mi   *shared.MethodInfo
	}{
		{
			name: "root detection",
			mi: &shared.MethodInfo{
				Name:           "isRooted",
				ClassName:      "RootDetector",
				ReturnsBoolean: true,
				ReturnType:     "Z",
				MethodHeader:   ".method public isRooted()Z",
				RawBody:        []string{".method public isRooted()Z", ".end method"},
			},
		},
		{
			name: "premium check",
			mi: &shared.MethodInfo{
				Name:           "isPremium",
				ClassName:      "LicenseChecker",
				ReturnsBoolean: true,
				ReturnType:     "Z",
				MethodHeader:   ".method public isPremium()Z",
				RawBody:        []string{".method public isPremium()Z", ".end method"},
			},
		},
	}

	strategies := []PatchStrategy{
		NewReturnTrueStrategy(),
		NewReturnFalseStrategy(),
		NewConditionInversionStrategy(),
		NewPartialBypassStrategy(),
		NewNopInjectionStrategy(),
	}

	modes := []PatchMode{PatchModeDefensive, PatchModeResearch}

	for _, tm := range testMethods {
		for _, strategy := range strategies {
			for _, mode := range modes {
				testName := tm.name + "_" + string(mode)
				t.Run(testName, func(t *testing.T) {
					// Check if strategy can apply
					if !strategy.CanApply(tm.mi, mode) {
						t.Skip("Strategy not applicable")
						return
					}

					// Generate patch
					patch, err := strategy.Generate(tm.mi, mode)
					if err != nil {
						t.Fatalf("Failed to generate patch: %v", err)
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

					// Verify mode is set correctly
					if patch.Mode != mode {
						t.Errorf("Mode = %v, expected %v", patch.Mode, mode)
					}
				})
			}
		}
	}
}

func TestAllStrategies_ModeConsistency(t *testing.T) {
	// Test that strategies respect mode-specific behavior

	rootDetectionMethod := &shared.MethodInfo{
		Name:           "isRooted",
		ClassName:      "RootDetector",
		ReturnsBoolean: true,
		ReturnType:     "Z",
		MethodHeader:   ".method public isRooted()Z",
		RawBody:        []string{".method public isRooted()Z", ".end method"},
	}

	premiumCheckMethod := &shared.MethodInfo{
		Name:           "isPremium",
		ClassName:      "LicenseChecker",
		ReturnsBoolean: true,
		ReturnType:     "Z",
		MethodHeader:   ".method public isPremium()Z",
		RawBody:        []string{".method public isPremium()Z", ".end method"},
	}

	t.Run("root detection defensive mode uses return true", func(t *testing.T) {
		strategy := NewReturnTrueStrategy()
		if !strategy.CanApply(rootDetectionMethod, PatchModeDefensive) {
			t.Error("ReturnTrueStrategy should apply to root detection in defensive mode")
		}
	})

	t.Run("root detection research mode uses return false", func(t *testing.T) {
		strategy := NewReturnFalseStrategy()
		if !strategy.CanApply(rootDetectionMethod, PatchModeResearch) {
			t.Error("ReturnFalseStrategy should apply to root detection in research mode")
		}
	})

	t.Run("premium check defensive mode uses return false", func(t *testing.T) {
		strategy := NewReturnFalseStrategy()
		if !strategy.CanApply(premiumCheckMethod, PatchModeDefensive) {
			t.Error("ReturnFalseStrategy should apply to premium check in defensive mode")
		}
	})

	t.Run("premium check research mode uses return true", func(t *testing.T) {
		strategy := NewReturnTrueStrategy()
		if !strategy.CanApply(premiumCheckMethod, PatchModeResearch) {
			t.Error("ReturnTrueStrategy should apply to premium check in research mode")
		}
	})
}

func TestAllStrategies_DifferentReturnTypes(t *testing.T) {
	validator := NewSmaliValidator()

	testCases := []struct {
		name       string
		returnType string
		isBoolean  bool
		isVoid     bool
		isInt      bool
	}{
		{
			name:       "boolean",
			returnType: "Z",
			isBoolean:  true,
		},
		{
			name:       "void",
			returnType: "V",
			isVoid:     true,
		},
		{
			name:       "int",
			returnType: "I",
			isInt:      true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mi := &shared.MethodInfo{
				Name:           "test",
				ClassName:      "Test",
				ReturnType:     tc.returnType,
				ReturnsBoolean: tc.isBoolean,
				ReturnsVoid:    tc.isVoid,
				ReturnsInt:     tc.isInt,
				IsStatic:       true,
				IsPublic:       true,
				MethodHeader:   ".method public static test()" + tc.returnType,
				RawBody:        []string{".method public static test()" + tc.returnType, ".end method"},
			}

			// Try strategies that might apply
			strategies := []PatchStrategy{
				NewReturnTrueStrategy(),
				NewReturnFalseStrategy(),
			}

			for _, strategy := range strategies {
				if strategy.CanApply(mi, PatchModeDefensive) {
					patch, err := strategy.Generate(mi, PatchModeDefensive)
					if err != nil {
						t.Errorf("Strategy %T failed: %v", strategy, err)
						continue
					}

					// Validate generated code
					result := validator.Validate(patch.PatchedCode)
					if !result.Valid {
						t.Errorf("Strategy %T generated invalid Smali: %v",
							strategy, result.Errors)
					}
				}
			}
		})
	}
}

func TestAllStrategies_MethodAccessModifiers(t *testing.T) {
	validator := NewSmaliValidator()

	testCases := []struct {
		name      string
		isPublic  bool
		isPrivate bool
		isFinal   bool
		isStatic  bool
	}{
		{
			name:     "public static",
			isPublic: true,
			isStatic: true,
		},
		{
			name:     "public instance",
			isPublic: true,
			isStatic: false,
		},
		{
			name:      "private final",
			isPrivate: true,
			isFinal:   true,
			isStatic:  false,
		},
		{
			name:      "private static final",
			isPrivate: true,
			isFinal:   true,
			isStatic:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mi := &shared.MethodInfo{
				Name:           "test",
				ClassName:      "Test",
				ReturnsBoolean: true,
				ReturnType:     "Z",
				IsPublic:       tc.isPublic,
				IsPrivate:      tc.isPrivate,
				IsFinal:        tc.isFinal,
				IsStatic:       tc.isStatic,
				MethodHeader:   ".method test()Z",
				RawBody:        []string{".method test()Z", ".end method"},
			}

			strategy := NewReturnTrueStrategy()
			if !strategy.CanApply(mi, PatchModeDefensive) {
				t.Skip("Strategy not applicable")
				return
			}

			patch, err := strategy.Generate(mi, PatchModeDefensive)
			if err != nil {
				t.Fatalf("Failed to generate patch: %v", err)
			}

			// Validate generated code
			result := validator.Validate(patch.PatchedCode)
			if !result.Valid {
				t.Errorf("Generated invalid Smali: %v", result.Errors)
			}

			// Verify method header preserves access modifiers
			// Note: The strategy reconstructs the method header from MethodInfo fields
			// We verify the generated code is valid, not that it preserves the exact header
			if !strings.Contains(patch.PatchedCode, ".method") {
				t.Error("Method header should contain '.method'")
			}
		})
	}
}
