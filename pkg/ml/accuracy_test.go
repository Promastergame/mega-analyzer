package ml

import (
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// ACCURACY ENHANCEMENT TESTS
// ═══════════════════════════════════════════════════════════════════════════════

// TestDecoyDetection tests decoy code detection
func TestDecoyDetection(t *testing.T) {
	tests := []struct {
		name          string
		method        *MethodInfo
		expectDecoy   bool
		minIndicators int
	}{
		{
			name: "Trivial security method (decoy)",
			method: &MethodInfo{
				Name:             "isLicensed",
				HasSecurityName:  true,
				InstructionCount: 2,
				ReturnsBoolean:   true,
			},
			expectDecoy:   false, // Only 1 indicator, needs 2+ for likely decoy
			minIndicators: 1,
		},
		{
			name: "Boolean with no conditions (decoy)",
			method: &MethodInfo{
				Name:             "checkPremium",
				ReturnsBoolean:   true,
				IfCheckCount:     0,
				InstructionCount: 5,
			},
			expectDecoy:   false, // Only 1 indicator
			minIndicators: 1,
		},
		{
			name: "Security name but no logic (decoy)",
			method: &MethodInfo{
				Name:               "verifyLicense",
				HasSecurityName:    true,
				HasSecurityAPI:     false,
				HasSecurityStrings: false,
				InstructionCount:   10,
			},
			expectDecoy:   false, // Only 1 indicator
			minIndicators: 1,
		},
		{
			name: "Multiple decoy indicators (likely decoy)",
			method: &MethodInfo{
				Name:               "isLicensed",
				HasSecurityName:    true,
				HasSecurityAPI:     false,
				HasSecurityStrings: false,
				ReturnsBoolean:     true,
				IfCheckCount:       0,
				InstructionCount:   3,
			},
			expectDecoy:   true, // 2+ indicators: trivial + no conditions
			minIndicators: 2,
		},
		{
			name: "Legitimate security check (not decoy)",
			method: &MethodInfo{
				Name:             "isLicensed",
				HasSecurityName:  true,
				HasSecurityAPI:   true,
				ReturnsBoolean:   true,
				HasDualReturn:    true,
				IfCheckCount:     2,
				InstructionCount: 15,
			},
			expectDecoy:   false,
			minIndicators: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis := AnalyzeDecoyCharacteristics(tt.method)

			if analysis.IsLikelyDecoy != tt.expectDecoy {
				t.Errorf("Expected IsLikelyDecoy=%v, got %v", tt.expectDecoy, analysis.IsLikelyDecoy)
			}

			if len(analysis.Indicators) < tt.minIndicators {
				t.Errorf("Expected at least %d indicators, got %d", tt.minIndicators, len(analysis.Indicators))
			}

			t.Logf("Decoy analysis: %d indicators, penalty=%.1f, confidence=%.2f",
				len(analysis.Indicators), analysis.TotalPenalty, analysis.Confidence)
		})
	}
}

// TestAdvancedThreatDetection tests advanced threat detection
func TestAdvancedThreatDetection(t *testing.T) {
	tests := []struct {
		name           string
		method         *MethodInfo
		expectThreats  int
		expectCategory ThreatCategory
	}{
		{
			name: "Emulator detection",
			method: &MethodInfo{
				Name: "isEmulator",
				Calls: []CallInfo{
					{FullCall: "build;->fingerprint"},
					{FullCall: "build;->model"},
				},
				StringConsts: []string{"generic", "goldfish"},
			},
			expectThreats:  1,
			expectCategory: ThreatAntiEmulator,
		},
		{
			name: "Debugger detection",
			method: &MethodInfo{
				Name: "checkDebug",
				Calls: []CallInfo{
					{FullCall: "debug;->isdebuggerconnected"},
				},
			},
			expectThreats:  1,
			expectCategory: ThreatAntiDebugger,
		},
		{
			name: "Root detection",
			method: &MethodInfo{
				Name: "isRooted",
				Calls: []CallInfo{
					{FullCall: "runtime;->exec"},
					{FullCall: "file;->exists"},
				},
				StringConsts: []string{"/system/xbin/su", "com.topjohnwu.magisk"},
			},
			expectThreats:  1,
			expectCategory: ThreatAntiRoot,
		},
		{
			name: "Reflection obfuscation",
			method: &MethodInfo{
				Name: "invokeHidden",
				Calls: []CallInfo{
					{FullCall: "method;->invoke"},
					{FullCall: "field;->get"},
					{FullCall: "class;->forname"},
				},
			},
			expectThreats:  1,
			expectCategory: ThreatReflection,
		},
		{
			name: "Dynamic code loading",
			method: &MethodInfo{
				Name: "loadPlugin",
				Calls: []CallInfo{
					{FullCall: "dexclassloader;-><init>"},
				},
				StringConsts: []string{"plugin.dex"},
			},
			expectThreats:  1,
			expectCategory: ThreatDynamicLoading,
		},
		{
			name: "Multiple threats",
			method: &MethodInfo{
				Name: "securityCheck",
				Calls: []CallInfo{
					{FullCall: "debug;->isdebuggerconnected"},
					{FullCall: "runtime;->exec"},
					{FullCall: "method;->invoke"},
					{FullCall: "class;->forname"},
				},
				StringConsts: []string{"/system/xbin/su", "frida"},
			},
			expectThreats: 2, // debugger + root (reflection needs 2+ indicators, only has 2 calls)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis := DetectAdvancedThreats(tt.method)

			if analysis.ThreatCount < tt.expectThreats {
				t.Errorf("Expected at least %d threats, got %d", tt.expectThreats, analysis.ThreatCount)
			}

			if tt.expectCategory != "" {
				found := false
				for _, threat := range analysis.Threats {
					if threat.Category == tt.expectCategory {
						found = true
						t.Logf("Found %s threat: %s (confidence=%.2f)",
							threat.Category, threat.Description, threat.Confidence)
						break
					}
				}
				if !found {
					t.Errorf("Expected threat category %s not found", tt.expectCategory)
				}
			}

			t.Logf("Detected %d threats, highest severity: %s",
				analysis.ThreatCount, analysis.HighestSeverity)
		})
	}
}

// TestEnhancedScoring tests the enhanced scoring engine
func TestEnhancedScoring(t *testing.T) {
	tests := []struct {
		name               string
		method             *MethodInfo
		patterns           []PatternMatch
		expectHighConf     bool
		expectDecoyPenalty bool
		expectThreatBonus  bool
	}{
		{
			name: "High confidence match",
			method: &MethodInfo{
				Name:               "isLicensed",
				HasSecurityName:    true,
				HasSecurityAPI:     true,
				HasSecurityStrings: true,
				ReturnsBoolean:     true,
				HasDualReturn:      true,
				IsAppCode:          true,
				InstructionCount:   15,
				IfCheckCount:       2,
				SecurityCalls:      []string{"checklicense"},
				SecurityStrings:    []string{"license_key"},
			},
			patterns: []PatternMatch{
				{
					MatchScore: 50.0,
					MatchedParts: []string{
						"method_name:licensed",
						"call:checklicense",
						"string:license",
						"return_type:Z",
					},
				},
			},
			expectHighConf:     true, // Should be 1.0 confidence (all evidence)
			expectDecoyPenalty: false,
			expectThreatBonus:  false,
		},
		{
			name: "Low confidence with decoy penalty",
			method: &MethodInfo{
				Name:               "isLicensed",
				HasSecurityName:    true,
				HasSecurityAPI:     false,
				HasSecurityStrings: false,
				ReturnsBoolean:     true,
				InstructionCount:   2,
			},
			patterns: []PatternMatch{
				{
					MatchScore: 20.0,
					MatchedParts: []string{
						"method_name:licensed",
					},
				},
			},
			expectHighConf:     false,
			expectDecoyPenalty: true,
			expectThreatBonus:  false,
		},
		{
			name: "With advanced threat bonus",
			method: &MethodInfo{
				Name:             "checkSecurity",
				HasSecurityName:  true,
				HasSecurityAPI:   true,
				ReturnsBoolean:   true,
				InstructionCount: 20,
				SecurityCalls:    []string{"runtime;->exec"},
				Calls: []CallInfo{
					{FullCall: "debug;->isdebuggerconnected"},
					{FullCall: "runtime;->exec"},
				},
				StringConsts: []string{"/system/xbin/su"},
			},
			patterns: []PatternMatch{
				{
					MatchScore: 40.0,
					MatchedParts: []string{
						"method_name:security",
						"call:exec",
					},
				},
			},
			expectHighConf:     false, // 0.50 confidence (name + API, no strings/structure/context)
			expectDecoyPenalty: false,
			expectThreatBonus:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := CalculateEnhancedScore(tt.method, tt.patterns)

			if score.IsHighConfidence != tt.expectHighConf {
				t.Errorf("Expected IsHighConfidence=%v, got %v (confidence=%.2f)",
					tt.expectHighConf, score.IsHighConfidence, score.Confidence)
			}

			if tt.expectDecoyPenalty && score.DecoyPenalty >= 0 {
				t.Errorf("Expected decoy penalty, got %.1f", score.DecoyPenalty)
			}

			if tt.expectThreatBonus && score.ThreatBonus <= 0 {
				t.Errorf("Expected threat bonus, got %.1f", score.ThreatBonus)
			}

			t.Logf("Score breakdown: base=%.1f, confidence=%.2f, structural=%.1f, decoy=%.1f, threat=%.1f, final=%.1f",
				score.BaseScore, score.Confidence, score.StructuralBonus,
				score.DecoyPenalty, score.ThreatBonus, score.FinalScore)
		})
	}
}

// TestConfidenceCalculation tests confidence calculation
func TestConfidenceCalculation(t *testing.T) {
	tests := []struct {
		name    string
		method  *MethodInfo
		minConf float64
		maxConf float64
	}{
		{
			name: "All evidence sources",
			method: &MethodInfo{
				HasSecurityName:    true,
				HasCheckPrefix:     true,
				HasSecurityAPI:     true,
				SecurityCalls:      []string{"checklicense"},
				HasSecurityStrings: true,
				SecurityStrings:    []string{"license_key"},
				ReturnsBoolean:     true,
				HasDualReturn:      true,
				IsAppCode:          true,
			},
			minConf: 0.8,
			maxConf: 1.0,
		},
		{
			name: "Name only",
			method: &MethodInfo{
				HasSecurityName: true,
			},
			minConf: 0.2,
			maxConf: 0.3,
		},
		{
			name: "API calls only",
			method: &MethodInfo{
				HasSecurityAPI: true,
				SecurityCalls:  []string{"checklicense"},
			},
			minConf: 0.25,
			maxConf: 0.35,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conf := calculateConfidence(tt.method, []PatternMatch{{MatchScore: 50}})

			if conf < tt.minConf || conf > tt.maxConf {
				t.Errorf("Expected confidence in range [%.2f, %.2f], got %.2f",
					tt.minConf, tt.maxConf, conf)
			}

			t.Logf("Confidence: %.2f", conf)
		})
	}
}

// TestSuperficialMatchDetection tests superficial match detection
func TestSuperficialMatchDetection(t *testing.T) {
	tests := []struct {
		name              string
		method            *MethodInfo
		match             *PatternMatch
		expectSuperficial bool
	}{
		{
			name: "Name only match (superficial)",
			method: &MethodInfo{
				Name: "isLicensed",
			},
			match: &PatternMatch{
				MatchScore: 20.0,
				MatchedParts: []string{
					"method_name:licensed",
				},
			},
			expectSuperficial: true,
		},
		{
			name: "Multiple evidence (not superficial)",
			method: &MethodInfo{
				Name: "isLicensed",
			},
			match: &PatternMatch{
				MatchScore: 50.0,
				MatchedParts: []string{
					"method_name:licensed",
					"call:checklicense",
					"string:license_key",
					"return_type:Z",
				},
			},
			expectSuperficial: false,
		},
		{
			name: "Low score (superficial)",
			method: &MethodInfo{
				Name: "check",
			},
			match: &PatternMatch{
				MatchScore: 10.0,
				MatchedParts: []string{
					"method_name:check",
				},
			},
			expectSuperficial: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isSuperficial := IsSuperficialMatch(tt.method, tt.match)

			if isSuperficial != tt.expectSuperficial {
				t.Errorf("Expected IsSuperficialMatch=%v, got %v",
					tt.expectSuperficial, isSuperficial)
			}

			if isSuperficial {
				penalized := ApplySuperficialPenalty(tt.match.MatchScore, true)
				expectedPenalty := tt.match.MatchScore * 0.70
				if penalized != expectedPenalty {
					t.Errorf("Expected 30%% penalty: %.1f, got %.1f",
						expectedPenalty, penalized)
				}
				t.Logf("Applied 30%% penalty: %.1f -> %.1f", tt.match.MatchScore, penalized)
			}
		})
	}
}

// BenchmarkDecoyDetection benchmarks decoy detection
func BenchmarkDecoyDetection(b *testing.B) {
	mi := &MethodInfo{
		Name:             "isLicensed",
		HasSecurityName:  true,
		HasSecurityAPI:   true,
		ReturnsBoolean:   true,
		HasDualReturn:    true,
		InstructionCount: 15,
		IfCheckCount:     2,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = AnalyzeDecoyCharacteristics(mi)
	}
}

// BenchmarkAdvancedThreatDetection benchmarks threat detection
func BenchmarkAdvancedThreatDetection(b *testing.B) {
	mi := &MethodInfo{
		Name: "securityCheck",
		Calls: []CallInfo{
			{FullCall: "debug;->isdebuggerconnected"},
			{FullCall: "runtime;->exec"},
			{FullCall: "method;->invoke"},
		},
		StringConsts:     []string{"/system/xbin/su", "frida", "xposed"},
		InstructionCount: 50,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = DetectAdvancedThreats(mi)
	}
}

// BenchmarkEnhancedScoring benchmarks enhanced scoring
func BenchmarkEnhancedScoring(b *testing.B) {
	mi := &MethodInfo{
		Name:               "isLicensed",
		HasSecurityName:    true,
		HasSecurityAPI:     true,
		HasSecurityStrings: true,
		ReturnsBoolean:     true,
		HasDualReturn:      true,
		IsAppCode:          true,
		InstructionCount:   15,
		IfCheckCount:       2,
		Calls: []CallInfo{
			{FullCall: "checklicense"},
		},
		StringConsts: []string{"license_key"},
	}

	matches := []PatternMatch{
		{
			MatchScore: 50.0,
			MatchedParts: []string{
				"method_name:licensed",
				"call:checklicense",
				"string:license",
				"return_type:Z",
			},
		},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = CalculateEnhancedScore(mi, matches)
	}
}
