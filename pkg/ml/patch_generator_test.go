package ml

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mega-analyzer/pkg/ml/internal/shared"
)

// Import local PatchType constants for tests
const (
	testPatchReturnTrue   = PatchReturnTrue
	testPatchReturnFalse  = PatchReturnFalse
	testPatchReturnVoid   = PatchReturnVoid
	testPatchReturnMaxInt = PatchReturnMaxInt
)

func TestGeneratePatchReturnTrue(t *testing.T) {
	gen := NewPatchGenerator()

	point := &PatchPoint{
		MethodName:     "isLicensed",
		ClassName:      "LicenseChecker",
		FilePath:       "com/app/LicenseChecker.smali",
		SuggestedPatch: testPatchReturnTrue,
		ReturnType:     "Z",
		MethodHeader:   ".method public isLicensed()Z",
		MethodBody: []string{
			".method public isLicensed()Z",
			"    .registers 2",
			"    invoke-virtual {p0}, Lcom/app/LicenseChecker;->checkLicense()I",
			"    move-result v0",
			"    const/4 v0, 0x0",
			"    return v0",
			".end method",
		},
	}

	patch := gen.Generate(point)

	if patch == nil {
		t.Fatal("Generate returned nil")
	}
	if !strings.Contains(patch.PatchedCode, "const/4 v0, 0x1") {
		t.Error("Patched code should contain const/4 v0, 0x1")
	}
	if !strings.Contains(patch.PatchedCode, "return v0") {
		t.Error("Patched code should contain return v0")
	}
	if patch.PatchedLines == 0 {
		t.Error("PatchedLines should not be 0")
	}
	if patch.DiffView == "" {
		t.Error("DiffView should not be empty")
	}
}

func TestGeneratePatchReturnFalse(t *testing.T) {
	gen := NewPatchGenerator()

	point := &PatchPoint{
		MethodName:     "isRooted",
		ClassName:      "RootDetector",
		SuggestedPatch: testPatchReturnFalse,
		ReturnType:     "Z",
		MethodHeader:   ".method public static isRooted()Z",
		MethodBody: []string{
			".method public static isRooted()Z",
			"    .registers 2",
			"    const/4 v0, 0x1",
			"    return v0",
			".end method",
		},
	}

	patch := gen.Generate(point)

	if !strings.Contains(patch.PatchedCode, "const/4 v0, 0x0") {
		t.Error("Should contain const/4 v0, 0x0")
	}
}

func TestGeneratePatchReturnVoid(t *testing.T) {
	gen := NewPatchGenerator()

	point := &PatchPoint{
		MethodName:     "showAd",
		ClassName:      "AdManager",
		SuggestedPatch: testPatchReturnVoid,
		ReturnType:     "V",
		MethodHeader:   ".method public showAd()V",
		MethodBody: []string{
			".method public showAd()V",
			"    .registers 3",
			"    invoke-virtual {p0}, Lcom/ads/Manager;->loadAd()V",
			"    return-void",
			".end method",
		},
	}

	patch := gen.Generate(point)

	if !strings.Contains(patch.PatchedCode, "return-void") {
		t.Error("Should contain return-void")
	}
}

func TestGeneratePatchMaxInt(t *testing.T) {
	gen := NewPatchGenerator()

	point := &PatchPoint{
		MethodName:     "getCoins",
		ClassName:      "Player",
		SuggestedPatch: testPatchReturnMaxInt,
		ReturnType:     "I",
		MethodHeader:   ".method public getCoins()I",
		MethodBody: []string{
			".method public getCoins()I",
			"    .registers 2",
			"    iget v0, p0, Lcom/game/Player;->coins:I",
			"    return v0",
			".end method",
		},
	}

	patch := gen.Generate(point)

	if !strings.Contains(patch.PatchedCode, "0x7fffffff") {
		t.Error("Should contain 0x7fffffff (max int)")
	}
}

func TestGenerateFromSignature(t *testing.T) {
	gen := NewPatchGenerator()

	point := &PatchPoint{
		MethodName:     "isValid",
		ClassName:      "Validator",
		SuggestedPatch: testPatchReturnTrue,
		ReturnType:     "Z",
		MethodHeader:   ".method public isValid()Z",
		IsAppCode:      true,
		// No body!
	}

	patch := gen.Generate(point)

	if patch == nil {
		t.Fatal("Should generate patch even without body")
	}
	if !strings.Contains(patch.PatchedCode, "const/4 v0, 0x1") {
		t.Error("Should generate return true patch")
	}
}

func TestFormatForTerminal(t *testing.T) {
	gen := NewPatchGenerator()

	point := &PatchPoint{
		MethodName:     "isLicensed",
		ClassName:      "LicenseChecker",
		FilePath:       "com/app/LicenseChecker.smali",
		SuggestedPatch: testPatchReturnTrue,
		ReturnType:     "Z",
		MethodHeader:   ".method public isLicensed()Z",
		MethodBody: []string{
			".method public isLicensed()Z",
			"    .registers 2",
			"    const/4 v0, 0x0",
			"    return v0",
			".end method",
		},
	}

	patch := gen.Generate(point)
	formatted := FormatForTerminal(patch)

	if formatted == "" {
		t.Fatal("FormatForTerminal returned empty")
	}
	if !strings.Contains(formatted, "ORIGINAL") {
		t.Error("Should contain ORIGINAL header")
	}
	if !strings.Contains(formatted, "PATCHED") {
		t.Error("Should contain PATCHED header")
	}
}

func TestGenerateAll(t *testing.T) {
	gen := NewPatchGenerator()

	prediction := &PatchPrediction{
		HighRisk: []PatchPoint{
			{
				MethodName:     "isLicensed",
				ClassName:      "License",
				FilePath:       "com/app/License.smali",
				SuggestedPatch: testPatchReturnTrue,
				ReturnType:     "Z",
				MethodHeader:   ".method public isLicensed()Z",
				MethodBody:     []string{".method public isLicensed()Z", "    return v0", ".end method"},
			},
		},
		MediumRisk: []PatchPoint{
			{
				MethodName:     "isRooted",
				ClassName:      "Root",
				FilePath:       "com/app/Root.smali",
				SuggestedPatch: testPatchReturnFalse,
				ReturnType:     "Z",
				MethodHeader:   ".method public isRooted()Z",
				MethodBody:     []string{".method public isRooted()Z", "    return v0", ".end method"},
			},
		},
		LowRisk: []PatchPoint{},
	}

	patches := gen.GenerateAll(prediction)

	if len(patches) != 2 {
		t.Errorf("Expected 2 patches, got %d", len(patches))
	}
}

func TestPatchArtifactUnifiedDiffAndApplySafety(t *testing.T) {
	gen := NewPatchGenerator()
	point := &PatchPoint{
		MethodName:      "isLicensed",
		MethodSignature: "isLicensed()Z",
		FilePath:        "com/app/License.smali",
		SuggestedPatch:  PatchReturnTrue,
		ReturnType:      "Z",
		MethodHeader:    ".method public isLicensed()Z",
		MethodBody: []string{
			".method public isLicensed()Z",
			"    .registers 2",
			"    const/4 v0, 0x0",
			"    return v0",
			".end method",
		},
	}

	patch := gen.Generate(point)
	if patch.Artifact == nil {
		t.Fatal("expected artifact")
	}
	if patch.Artifact.OriginalHash == "" || patch.Artifact.PatchedHash == "" {
		t.Fatalf("expected hashes: %+v", patch.Artifact)
	}
	if !strings.Contains(patch.Artifact.UnifiedDiff, "--- a/com/app/License.smali") {
		t.Fatalf("expected unified diff header, got:\n%s", patch.Artifact.UnifiedDiff)
	}
	if !patch.Artifact.ApplySafety.CanWrite {
		t.Fatalf("expected writable artifact: %+v", patch.Artifact.ApplySafety)
	}
}

func TestApplyArtifactRejectsMismatchedContext(t *testing.T) {
	gen := NewPatchGenerator()
	point := &PatchPoint{
		MethodName:      "isLicensed",
		MethodSignature: "isLicensed()Z",
		FilePath:        "License.smali",
		SuggestedPatch:  PatchReturnTrue,
		ReturnType:      "Z",
		MethodHeader:    ".method public isLicensed()Z",
		MethodBody: []string{
			".method public isLicensed()Z",
			"    .registers 2",
			"    const/4 v0, 0x0",
			"    return v0",
			".end method",
		},
	}
	patch := gen.Generate(point)
	tmp := testTempDir(t)
	if err := os.WriteFile(filepath.Join(tmp, "License.smali"), []byte(".class public LLicense;\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := ApplyArtifactToBase(tmp, patch.Artifact); err == nil {
		t.Fatal("expected context mismatch")
	}
}

func TestPatchReturnObjectAndWideUseCompatibleReturns(t *testing.T) {
	gen := NewPatchGenerator()
	tests := []struct {
		name       string
		returnType string
	}{
		{name: "object", returnType: "Ljava/lang/String;"},
		{name: "array", returnType: "[I"},
		{name: "wide", returnType: "J"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			returnInstruction := "    return-object v0"
			if tt.name == "wide" {
				returnInstruction = "    return-wide v0"
			}
			original := []string{
				".method public value()" + tt.returnType,
				"    .registers 2",
				"    const/4 v0, 0x0",
				returnInstruction,
				".end method",
			}
			point := &PatchPoint{
				MethodName:     "value",
				FilePath:       "Value.smali",
				SuggestedPatch: PatchReturnMaxInt,
				ReturnType:     tt.returnType,
				MethodHeader:   original[0],
				MethodBody:     original,
			}
			patch := gen.Generate(point)
			if !strings.Contains(patch.PatchedCode, "const/4 v0, 0x0") || !strings.Contains(patch.PatchedCode, returnInstruction) {
				t.Fatalf("patched code must preserve the real body =\n%s", patch.PatchedCode)
			}
			if !patch.Artifact.Validation.Valid {
				t.Fatalf("validation errors: %+v", patch.Artifact.Validation.Errors)
			}
		})
	}
}

func TestReportBrokenReturnTypesFixed(t *testing.T) {
	gen := NewPatchGenerator()
	gen.SetMode(PatchModeResearch)

	tests := []struct {
		name       string
		point      *PatchPoint
		wantReturn string
		notWant    string
	}{
		{
			// Method names are incidental to this test's assertions (return
			// opcode preservation); the DRM-flavoured name carries the gate
			// justification the object strategy requires since the body has
			// no swappable constant of its own.
			name: "byte array DRM adjustDrmToken",
			point: &PatchPoint{
				MethodName:      "adjustDrmToken",
				MethodSignature: "adjustDrmToken(Ljava/util/UUID;[B)[B",
				SuggestedPatch:  PatchReturnVoid,
				MethodHeader:    ".method private static adjustDrmToken(Ljava/util/UUID;[B)[B",
				MethodBody: []string{
					".method private static adjustDrmToken(Ljava/util/UUID;[B)[B",
					"    .registers 4",
					"    return-object v0",
					".end method",
				},
			},
			wantReturn: "return-object v0",
			notWant:    "return-void",
		},
		{
			name: "int emulator F()",
			point: &PatchPoint{
				MethodName:      "F",
				MethodSignature: "F()I",
				ReturnType:      "I",
				SuggestedPatch:  PatchReturnVoid,
				MethodHeader:    ".method public static F()I",
				MethodBody: []string{
					".method public static F()I",
					"    .registers 2",
					"    sget-object v0, Landroid/os/Build;->MODEL:Ljava/lang/String;",
					"    const-string v4, \"Emulator\"",
					"    invoke-virtual {v0, v4}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z",
					"    move-result v0",
					"    return v0",
					".end method",
				},
			},
			wantReturn: "return v0",
			notWant:    "return-void",
		},
		{
			name: "String operator v()",
			point: &PatchPoint{
				MethodName:      "v",
				MethodSignature: "v(Landroid/content/Context;)Ljava/lang/String;",
				SuggestedPatch:  PatchReturnVoid,
				MethodHeader:    ".method public v(Landroid/content/Context;)Ljava/lang/String;",
				MethodBody: []string{
					".method public v(Landroid/content/Context;)Ljava/lang/String;",
					"    .registers 3",
					"    const-string v0, \"operator\"",
					"    return-object v0",
					".end method",
				},
			},
			wantReturn: "return-object v0",
			notWant:    "return-void",
		},
		{
			// Same note as above: the auth-flavoured name justifies the
			// stub; the assertions only pin return-opcode preservation.
			name: "object getAuthConnection",
			point: &PatchPoint{
				MethodName:      "getAuthConnection",
				MethodSignature: "getAuthConnection()Lokhttp3/internal/connection/RealConnection;",
				SuggestedPatch:  PatchReturnVoid,
				MethodHeader:    ".method public final getAuthConnection()Lokhttp3/internal/connection/RealConnection;",
				MethodBody: []string{
					".method public final getAuthConnection()Lokhttp3/internal/connection/RealConnection;",
					"    .registers 2",
					"    const/4 v0, 0x0",
					"    return-object v0",
					".end method",
				},
			},
			wantReturn: "return-object v0",
			notWant:    "return-void",
		},
		{
			name: "String root ik()",
			point: &PatchPoint{
				MethodName:      "ik",
				MethodSignature: "ik(Ljava/lang/String;)Ljava/lang/String;",
				SuggestedPatch:  PatchReturnVoid,
				MethodHeader:    ".method private static ik(Ljava/lang/String;)Ljava/lang/String;",
				MethodBody: []string{
					".method private static ik(Ljava/lang/String;)Ljava/lang/String;",
					"    .registers 2",
					"    const-string v0, \"ro.build.tags\"",
					"    return-object v0",
					".end method",
				},
			},
			wantReturn: "return-object v0",
			notWant:    "return-void",
		},
		{
			name: "empty ReturnType inferred from signature",
			point: &PatchPoint{
				MethodName:      "getToken",
				MethodSignature: "getToken()Ljava/lang/String;",
				SuggestedPatch:  "",
				MethodHeader:    ".method public getToken()Ljava/lang/String;",
				MethodBody: []string{
					".method public getToken()Ljava/lang/String;",
					"    .registers 2",
					"    return-object v0",
					".end method",
				},
			},
			wantReturn: "return-object v0",
			notWant:    "return-void",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			patch := gen.GenerateWithMode(tt.point, PatchModeResearch)
			if patch == nil {
				t.Fatal("expected patch")
			}
			if strings.Contains(patch.PatchedCode, tt.notWant) {
				t.Fatalf("patched code must not contain %q:\n%s", tt.notWant, patch.PatchedCode)
			}
			if !strings.Contains(patch.PatchedCode, tt.wantReturn) {
				t.Fatalf("patched code must contain %q:\n%s", tt.wantReturn, patch.PatchedCode)
			}
			if patch.Artifact == nil || !patch.Artifact.Validation.Valid {
				t.Fatalf("expected valid artifact, errors: %+v", patch.Artifact)
			}
		})
	}
}

func TestIsStaticMethod(t *testing.T) {
	tests := []struct {
		header string
		want   bool
	}{
		{".method public static isRooted()Z", true},
		{".method public isLicensed()Z", false},
		{".method private static final check()V", true},
	}

	for _, tt := range tests {
		got := isStaticMethod(tt.header)
		if got != tt.want {
			t.Errorf("isStaticMethod(%q) = %v, want %v", tt.header, got, tt.want)
		}
	}
}

// TestContextAnalysisIntegration verifies that ContextAnalyzer is called
// during patch generation and context information is included in explanations
// Requirements: 6.5, 6.6, 6.7
func TestContextAnalysisIntegration(t *testing.T) {
	gen := NewPatchGenerator()

	tests := []struct {
		name              string
		point             *PatchPoint
		expectedCheckType shared.SecurityCheckType
		mode              PatchMode
	}{
		{
			name: "Root detection method",
			point: &PatchPoint{
				MethodName:     "isRooted",
				ClassName:      "RootDetector",
				FilePath:       "com/app/security/RootDetector.smali",
				SuggestedPatch: testPatchReturnFalse,
				ReturnType:     "Z",
				MethodHeader:   ".method public isRooted()Z",
				CategoryName:   "root_detection",
				MatchedParts:   []string{"root", "su"},
				Confidence:     0.85,
				MethodBody: []string{
					".method public isRooted()Z",
					"    .registers 2",
					"    const/4 v0, 0x1",
					"    return v0",
					".end method",
				},
			},
			expectedCheckType: shared.CheckTypeRoot,
			mode:              PatchModeResearch,
		},
		{
			name: "Premium check method",
			point: &PatchPoint{
				MethodName:     "isPremium",
				ClassName:      "LicenseChecker",
				FilePath:       "com/app/billing/LicenseChecker.smali",
				SuggestedPatch: testPatchReturnTrue,
				ReturnType:     "Z",
				MethodHeader:   ".method public isPremium()Z",
				CategoryName:   "premium_check",
				MatchedParts:   []string{"premium", "license"},
				Confidence:     0.90,
				MethodBody: []string{
					".method public isPremium()Z",
					"    .registers 2",
					"    const/4 v0, 0x0",
					"    return v0",
					".end method",
				},
			},
			expectedCheckType: shared.CheckTypePremium,
			mode:              PatchModeResearch,
		},
		{
			name: "Emulator detection method",
			point: &PatchPoint{
				MethodName:     "isEmulator",
				ClassName:      "EmulatorDetector",
				FilePath:       "com/app/security/EmulatorDetector.smali",
				SuggestedPatch: testPatchReturnFalse,
				ReturnType:     "Z",
				MethodHeader:   ".method public isEmulator()Z",
				CategoryName:   "emulator_detection",
				MatchedParts:   []string{"emulator", "virtual"},
				Confidence:     0.88,
				MethodBody: []string{
					".method public isEmulator()Z",
					"    .registers 2",
					"    const/4 v0, 0x1",
					"    return v0",
					".end method",
				},
			},
			expectedCheckType: shared.CheckTypeEmulator,
			mode:              PatchModeResearch,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set mode on patch point
			tt.point.MethodBody[0] = tt.point.MethodHeader

			patch := gen.Generate(tt.point)

			if patch == nil {
				t.Fatal("Generate returned nil")
			}

			// Verify explanation is populated (Requirement 2.1, 2.2, 2.3, 2.4)
			if patch.Explanation.Reason == "" {
				t.Error("Explanation.Reason should not be empty")
			}
			if patch.Explanation.WhatItDoes == "" {
				t.Error("Explanation.WhatItDoes should not be empty")
			}
			if patch.Explanation.WhyThisPatch == "" {
				t.Error("Explanation.WhyThisPatch should not be empty")
			}
			if patch.Explanation.Impact == "" {
				t.Error("Explanation.Impact should not be empty")
			}

			// Verify signals are included (Requirement 2.6)
			if len(patch.Explanation.Signals) == 0 {
				t.Error("Explanation.Signals should not be empty")
			}

			// Verify context information is in explanation (Requirement 6.7)
			if !strings.Contains(patch.Explanation.Reason, string(tt.expectedCheckType)) {
				t.Errorf("Explanation should mention context type %s, got: %s",
					tt.expectedCheckType, patch.Explanation.Reason)
			}

			// Verify matched parts are in signals
			foundMatchedParts := false
			for _, signal := range patch.Explanation.Signals {
				for _, part := range tt.point.MatchedParts {
					if strings.Contains(strings.ToLower(signal), strings.ToLower(part)) {
						foundMatchedParts = true
						break
					}
				}
			}
			if !foundMatchedParts && len(tt.point.MatchedParts) > 0 {
				t.Error("Signals should include matched parts from PatchPoint")
			}
		})
	}
}

// TestContextAnalysisWithMode verifies mode-specific explanations
// Requirements: 3.3, 3.4, 6.6
func TestContextAnalysisWithMode(t *testing.T) {
	gen := NewPatchGenerator()

	point := &PatchPoint{
		MethodName:     "isRooted",
		ClassName:      "RootDetector",
		FilePath:       "com/app/security/RootDetector.smali",
		SuggestedPatch: testPatchReturnFalse,
		ReturnType:     "Z",
		MethodHeader:   ".method public isRooted()Z",
		CategoryName:   "root_detection",
		MatchedParts:   []string{"root"},
		Confidence:     0.85,
		MethodBody: []string{
			".method public isRooted()Z",
			"    .registers 2",
			"    const/4 v0, 0x1",
			"    return v0",
			".end method",
		},
	}

	tests := []struct {
		name           string
		mode           PatchMode
		expectInWhy    string
		expectInImpact string
	}{
		{
			name:           "Research mode",
			mode:           PatchModeResearch,
			expectInWhy:    "bypass",
			expectInImpact: "bypass",
		},
		{
			name:           "Defensive mode",
			mode:           PatchModeDefensive,
			expectInWhy:    "strengthen",
			expectInImpact: "hardening",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a copy of the point with the mode set
			testPoint := *point

			// Generate patch
			patch := gen.Generate(&testPoint)

			// Manually set mode and regenerate explanation for testing
			patch.Mode = tt.mode
			methodInfo := &shared.MethodInfo{
				Name:      testPoint.MethodName,
				ClassName: testPoint.ClassName,
				FilePath:  testPoint.FilePath,
			}
			checkType := gen.contextAnalyzer.DetermineCheckType(methodInfo)
			patch.Explanation = buildExplanation(&testPoint, checkType, tt.mode)

			// Verify mode-specific language in explanation
			whyLower := strings.ToLower(patch.Explanation.WhyThisPatch)
			if !strings.Contains(whyLower, tt.expectInWhy) {
				t.Errorf("WhyThisPatch should contain '%s' for %s mode, got: %s",
					tt.expectInWhy, tt.mode, patch.Explanation.WhyThisPatch)
			}

			impactLower := strings.ToLower(patch.Explanation.Impact)
			if !strings.Contains(impactLower, tt.expectInImpact) {
				t.Errorf("Impact should contain '%s' for %s mode, got: %s",
					tt.expectInImpact, tt.mode, patch.Explanation.Impact)
			}
		})
	}
}

// TestExplanationCompleteness verifies all explanation fields are populated
// Requirements: 2.1, 2.2, 2.3, 2.4
func TestExplanationCompleteness(t *testing.T) {
	gen := NewPatchGenerator()

	point := &PatchPoint{
		MethodName:     "checkLicense",
		ClassName:      "LicenseValidator",
		FilePath:       "com/app/license/LicenseValidator.smali",
		SuggestedPatch: testPatchReturnTrue,
		ReturnType:     "Z",
		MethodHeader:   ".method public checkLicense()Z",
		CategoryName:   "license_check",
		PatternID:      "license_001",
		MatchedParts:   []string{"license", "valid"},
		Confidence:     0.92,
		MethodBody: []string{
			".method public checkLicense()Z",
			"    .registers 2",
			"    const/4 v0, 0x0",
			"    return v0",
			".end method",
		},
	}

	patch := gen.Generate(point)

	if patch == nil {
		t.Fatal("Generate returned nil")
	}

	// Verify all required explanation fields are non-empty
	if patch.Explanation.Reason == "" {
		t.Error("Explanation.Reason must not be empty (Requirement 2.1)")
	}
	if patch.Explanation.WhatItDoes == "" {
		t.Error("Explanation.WhatItDoes must not be empty (Requirement 2.2)")
	}
	if patch.Explanation.WhyThisPatch == "" {
		t.Error("Explanation.WhyThisPatch must not be empty (Requirement 2.3)")
	}
	if patch.Explanation.Impact == "" {
		t.Error("Explanation.Impact must not be empty (Requirement 2.4)")
	}

	// Verify signals include pattern information (Requirement 2.6)
	hasPatternID := false
	hasConfidence := false
	hasCategory := false
	for _, signal := range patch.Explanation.Signals {
		if strings.Contains(signal, point.PatternID) {
			hasPatternID = true
		}
		if strings.Contains(signal, "Confidence") {
			hasConfidence = true
		}
		if strings.Contains(signal, point.CategoryName) {
			hasCategory = true
		}
	}

	if !hasPatternID {
		t.Error("Signals should include pattern ID")
	}
	if !hasConfidence {
		t.Error("Signals should include confidence value")
	}
	if !hasCategory {
		t.Error("Signals should include category name")
	}
}
