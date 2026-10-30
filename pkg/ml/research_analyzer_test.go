package ml

import (
	"strings"
	"testing"
)

// TestResearchAnalyzer_RootDetection тест анализа root detection
func TestResearchAnalyzer_RootDetection(t *testing.T) {
	analyzer := NewResearchAnalyzer()

	mi := &MethodInfo{
		Name:             "isRooted",
		ClassName:        "com/myapp/security/RootChecker",
		FilePath:         "com/myapp/security/RootChecker.smali",
		InstructionCount: 50,
		IfCheckCount:     3,
		ReturnsBoolean:   true,
		Calls: []CallInfo{
			{FullCall: "Ljava/io/File;->exists()Z", Method: "exists"},
			{FullCall: "Ljava/lang/Runtime;->exec", Method: "exec"},
		},
		StringConsts: []string{
			"/system/bin/su",
			"/system/xbin/su",
			"Superuser.apk",
		},
	}

	analysis := analyzer.Analyze(mi)

	if analysis == nil {
		t.Fatal("Expected analysis, got nil")
	}

	if analysis.Type != PROTECTION_ROOT_DETECTION {
		t.Errorf("Expected ROOT_DETECTION, got %v", analysis.Type)
	}

	if len(analysis.Indicators) == 0 {
		t.Error("Expected indicators to be found")
	}

	if len(analysis.ResearchPointers) == 0 {
		t.Error("Expected research pointers")
	}

	if analysis.BypassDifficulty < 1 || analysis.BypassDifficulty > 10 {
		t.Errorf("Invalid bypass difficulty: %d", analysis.BypassDifficulty)
	}

	t.Logf("Analysis: %s", analysis.TypeName)
	t.Logf("Strength: %s", analysis.StrengthName)
	t.Logf("Bypass Difficulty: %d/10", analysis.BypassDifficulty)
	t.Logf("Indicators: %d", len(analysis.Indicators))
	t.Logf("Research Pointers: %d", len(analysis.ResearchPointers))
}

// TestResearchAnalyzer_EmulatorDetection тест анализа emulator detection
func TestResearchAnalyzer_EmulatorDetection(t *testing.T) {
	analyzer := NewResearchAnalyzer()

	mi := &MethodInfo{
		Name:             "isEmulator",
		ClassName:        "com/myapp/security/EmulatorDetector",
		FilePath:         "com/myapp/security/EmulatorDetector.smali",
		InstructionCount: 80,
		IfCheckCount:     5,
		ReturnsBoolean:   true,
		Calls: []CallInfo{
			{FullCall: "Landroid/os/Build;->FINGERPRINT", Method: "FINGERPRINT"},
			{FullCall: "Landroid/os/Build;->MODEL", Method: "MODEL"},
		},
		StringConsts: []string{
			"generic",
			"goldfish",
			"sdk",
		},
	}

	analysis := analyzer.Analyze(mi)

	if analysis == nil {
		t.Fatal("Expected analysis, got nil")
	}

	if analysis.Type != PROTECTION_EMULATOR_DETECTION {
		t.Errorf("Expected EMULATOR_DETECTION, got %v", analysis.Type)
	}

	if analysis.Strength == STRENGTH_WEAK {
		t.Error("Expected stronger protection for complex emulator detection")
	}
}

// TestResearchAnalyzer_SSLPinning тест анализа SSL pinning
func TestResearchAnalyzer_SSLPinning(t *testing.T) {
	analyzer := NewResearchAnalyzer()

	mi := &MethodInfo{
		Name:             "checkServerTrusted",
		ClassName:        "com/myapp/network/CustomTrustManager",
		FilePath:         "com/myapp/network/CustomTrustManager.smali",
		InstructionCount: 120,
		IfCheckCount:     8,
		ReturnsBoolean:   false,
		ReturnType:       "V",
		Calls: []CallInfo{
			{FullCall: "Ljava/security/cert/Certificate;->getEncoded", Method: "getEncoded"},
			{FullCall: "Ljava/security/MessageDigest;->digest", Method: "digest"},
		},
		StringConsts: []string{
			"SHA-256",
			"Certificate pinning failed",
		},
	}

	analysis := analyzer.Analyze(mi)

	if analysis == nil {
		t.Fatal("Expected analysis, got nil")
	}

	if analysis.Type != PROTECTION_SSL_PINNING {
		t.Errorf("Expected SSL_PINNING, got %v", analysis.Type)
	}

	// SSL pinning with many checks should be strong
	if analysis.Strength < STRENGTH_MEDIUM {
		t.Errorf("Expected at least MEDIUM strength, got %v", analysis.StrengthName)
	}
}

// TestResearchAnalyzer_LicenseCheck тест анализа license check
func TestResearchAnalyzer_LicenseCheck(t *testing.T) {
	analyzer := NewResearchAnalyzer()

	mi := &MethodInfo{
		Name:             "verifyLicense",
		ClassName:        "com/myapp/billing/LicenseValidator",
		FilePath:         "com/myapp/billing/LicenseValidator.smali",
		InstructionCount: 30,
		IfCheckCount:     2,
		ReturnsBoolean:   true,
		Calls: []CallInfo{
			{FullCall: "Landroid/content/SharedPreferences;->getString", Method: "getString"},
		},
		StringConsts: []string{
			"license_key",
			"premium_status",
		},
	}

	analysis := analyzer.Analyze(mi)

	if analysis == nil {
		t.Fatal("Expected analysis, got nil")
	}

	if analysis.Type != PROTECTION_LICENSE_CHECK {
		t.Errorf("Expected LICENSE_CHECK, got %v", analysis.Type)
	}

	// Simple license check should have weaknesses
	if len(analysis.Weaknesses) == 0 {
		t.Error("Expected weaknesses for simple license check")
	}
}

// TestResearchAnalyzer_StrengthCalculation тест расчета силы защиты
func TestResearchAnalyzer_StrengthCalculation(t *testing.T) {
	analyzer := NewResearchAnalyzer()

	testCases := []struct {
		name             string
		instructionCount int
		ifCheckCount     int
		hasNative        bool
		expectedMin      ProtectionStrength
	}{
		{
			name:             "Weak protection",
			instructionCount: 20,
			ifCheckCount:     1,
			hasNative:        false,
			expectedMin:      STRENGTH_WEAK,
		},
		{
			name:             "Medium protection",
			instructionCount: 60,
			ifCheckCount:     3,
			hasNative:        false,
			expectedMin:      STRENGTH_MEDIUM,
		},
		{
			name:             "Strong protection",
			instructionCount: 120,
			ifCheckCount:     6,
			hasNative:        true,
			expectedMin:      STRENGTH_STRONG,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mi := &MethodInfo{
				Name:             "checkSecurity",
				ClassName:        "com/myapp/Security",
				InstructionCount: tc.instructionCount,
				IfCheckCount:     tc.ifCheckCount,
			}

			if tc.hasNative {
				mi.Calls = []CallInfo{
					{FullCall: "native_check", Method: "native_check"},
				}
			}

			strength := analyzer.analyzeStrength(mi, PROTECTION_ROOT_DETECTION)

			if strength < tc.expectedMin {
				t.Errorf("Expected at least %v, got %v", tc.expectedMin, strength)
			}
		})
	}
}

// TestResearchAnalyzer_NoAutoPatch проверяет, что НЕТ автопатча
func TestResearchAnalyzer_NoAutoPatch(t *testing.T) {
	analyzer := NewResearchAnalyzer()

	mi := &MethodInfo{
		Name:           "isRooted",
		ClassName:      "com/myapp/Security",
		ReturnsBoolean: true,
	}

	analysis := analyzer.Analyze(mi)

	if analysis == nil {
		t.Skip("No analysis for this method")
	}

	// Проверяем, что НЕТ конкретных патчей в research pointers
	for _, pointer := range analysis.ResearchPointers {
		pointerLower := strings.ToLower(pointer)

		// Эти фразы НЕ должны быть в research pointers
		forbiddenPhrases := []string{
			"return true",
			"return false",
			"const/4 v0",
			"patch with",
			"replace with",
			"change to",
		}

		for _, phrase := range forbiddenPhrases {
			if strings.Contains(pointerLower, phrase) {
				t.Errorf("Research pointer contains forbidden phrase '%s': %s", phrase, pointer)
			}
		}
	}

	// Research pointers должны содержать только аналитические указания
	hasResearchKeyword := false
	for _, pointer := range analysis.ResearchPointers {
		pointerLower := strings.ToLower(pointer)
		if strings.Contains(pointerLower, "research") ||
			strings.Contains(pointerLower, "analyze") ||
			strings.Contains(pointerLower, "check") ||
			strings.Contains(pointerLower, "look for") {
			hasResearchKeyword = true
			break
		}
	}

	if !hasResearchKeyword {
		t.Error("Research pointers should contain analytical guidance, not patches")
	}
}
