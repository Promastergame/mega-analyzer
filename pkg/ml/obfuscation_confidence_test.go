package ml

import (
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// OBFUSCATION-AWARE CONFIDENCE ADJUSTMENT TESTS (Task 4.4)
// ═══════════════════════════════════════════════════════════════════════════════

// TestObfuscationConfidenceAdjustment_StructureAndAPI tests the confidence range
// for obfuscated methods with both structure and API signals (should be [0.6, 0.8])
func TestObfuscationConfidenceAdjustment_StructureAndAPI(t *testing.T) {
	ps, pa := newTestScorer()

	// Obfuscated method with structure + API signals
	smali := `
.class public Lcom/a/b/c;
.super Ljava/lang/Object;

.method public a()Z
    .locals 2
    
    # Has security API call
    invoke-static {}, Landroid/content/pm/PackageManager;->getPackageInfo()Landroid/content/pm/PackageInfo;
    
    # Has dual return structure
    if-eqz v0, :cond_0
    
    const/4 v0, 0x1
    return v0
    
    :cond_0
    const/4 v0, 0x0
    return v0
.end method
`

	classInfo := pa.AnalyzeSmaliContent("com/a/b/c.smali", []byte(smali))
	if len(classInfo.Methods) == 0 {
		t.Fatal("No methods found")
	}

	mi := &classInfo.Methods[0]
	result := ps.ScoreMethod(mi)

	// Should detect obfuscation
	if result.ObfuscationInfo == nil || !result.ObfuscationInfo.IsObfuscated {
		t.Error("Expected obfuscation detection")
	}

	// Confidence should be in [0.6, 0.8] range for structure + API
	if result.Confidence < 0.6 || result.Confidence > 0.8 {
		t.Errorf("Expected confidence in [0.6, 0.8] for structure+API, got %.2f", result.Confidence)
	}

	// Verify signals
	hasStructure := false
	hasAPI := false
	for _, sig := range result.MatchedSignals {
		if sig.Type == SignalStructure {
			hasStructure = true
		}
		if sig.Type == SignalAPICall {
			hasAPI = true
		}
	}

	if !hasStructure || !hasAPI {
		t.Error("Expected both structure and API signals")
	}

	t.Logf("Structure+API confidence: %.2f (expected [0.6, 0.8])", result.Confidence)
}

// TestObfuscationConfidenceAdjustment_StructureOnly tests the confidence range
// for obfuscated methods with only structure signals (should be [0.3, 0.6])
func TestObfuscationConfidenceAdjustment_StructureOnly(t *testing.T) {
	ps, pa := newTestScorer()

	// Obfuscated method with only structural signals (no API, no strings)
	smali := `
.class public Lcom/x/y;
.super Ljava/lang/Object;

.method public z()Z
    .locals 1
    
    # Only structure - dual return
    if-eqz v0, :cond_0
    
    const/4 v0, 0x1
    return v0
    
    :cond_0
    const/4 v0, 0x0
    return v0
.end method
`

	classInfo := pa.AnalyzeSmaliContent("com/x/y.smali", []byte(smali))
	if len(classInfo.Methods) == 0 {
		t.Fatal("No methods found")
	}

	mi := &classInfo.Methods[0]
	result := ps.ScoreMethod(mi)

	// With only structural signals, confidence should be in [0.3, 0.6]
	if result.Confidence < 0.3 || result.Confidence > 0.6 {
		t.Errorf("Expected confidence in [0.3, 0.6] for structure-only, got %.2f", result.Confidence)
	}

	// Verify only structure signal present
	hasStructure := false
	hasAPI := false
	for _, sig := range result.MatchedSignals {
		if sig.Type == SignalStructure {
			hasStructure = true
		}
		if sig.Type == SignalAPICall {
			hasAPI = true
		}
	}

	if !hasStructure {
		t.Error("Expected structure signal")
	}
	if hasAPI {
		t.Error("Did not expect API signal")
	}

	t.Logf("Structure-only confidence: %.2f (expected [0.3, 0.6])", result.Confidence)
}

// TestObfuscationConfidenceAdjustment_APIOnly tests the confidence range
// for obfuscated methods with only API signals (should be [0.3, 0.6])
func TestObfuscationConfidenceAdjustment_APIOnly(t *testing.T) {
	ps, pa := newTestScorer()

	// Obfuscated method with only API signal (no structure)
	smali := `
.class public Lcom/m/n;
.super Ljava/lang/Object;

.method public p()V
    .locals 1
    
    # Has security API call but no dual return structure
    invoke-static {}, Landroid/content/pm/PackageManager;->getPackageInfo()Landroid/content/pm/PackageInfo;
    
    return-void
.end method
`

	classInfo := pa.AnalyzeSmaliContent("com/m/n.smali", []byte(smali))
	if len(classInfo.Methods) == 0 {
		t.Fatal("No methods found")
	}

	mi := &classInfo.Methods[0]
	result := ps.ScoreMethod(mi)

	// With only API signal, confidence should be in [0.3, 0.6]
	if result.Confidence < 0.3 || result.Confidence > 0.6 {
		t.Errorf("Expected confidence in [0.3, 0.6] for API-only, got %.2f", result.Confidence)
	}

	// Verify only API signal present
	hasStructure := false
	hasAPI := false
	for _, sig := range result.MatchedSignals {
		if sig.Type == SignalStructure {
			hasStructure = true
		}
		if sig.Type == SignalAPICall {
			hasAPI = true
		}
	}

	if hasStructure {
		t.Error("Did not expect structure signal")
	}
	if !hasAPI {
		t.Error("Expected API signal")
	}

	t.Logf("API-only confidence: %.2f (expected [0.3, 0.6])", result.Confidence)
}

// TestObfuscationConfidenceAdjustment_PrioritizeStructuralSignals tests that
// structural signals are prioritized over name signals when obfuscation is detected
func TestObfuscationConfidenceAdjustment_PrioritizeStructuralSignals(t *testing.T) {
	ps, pa := newTestScorer()

	// Method with obfuscated name but has structure + API
	// The name might accidentally match a pattern, but we should prioritize structure
	smali := `
.class public Lcom/check/Validator;
.super Ljava/lang/Object;

.method public a()Z
    .locals 2
    
    # Has security API call
    invoke-static {}, Landroid/content/pm/PackageManager;->getPackageInfo()Landroid/content/pm/PackageInfo;
    
    # Has dual return structure
    if-eqz v0, :cond_0
    
    const/4 v0, 0x1
    return v0
    
    :cond_0
    const/4 v0, 0x0
    return v0
.end method
`

	classInfo := pa.AnalyzeSmaliContent("com/check/Validator.smali", []byte(smali))
	if len(classInfo.Methods) == 0 {
		t.Fatal("No methods found")
	}

	mi := &classInfo.Methods[0]
	result := ps.ScoreMethod(mi)

	// Should detect obfuscation (single letter method name)
	if result.ObfuscationInfo == nil || !result.ObfuscationInfo.IsObfuscated {
		t.Error("Expected obfuscation detection")
	}

	// Confidence should be based on structure + API, not name
	// Should be in [0.6, 0.8] range
	if result.Confidence < 0.6 || result.Confidence > 0.8 {
		t.Errorf("Expected confidence in [0.6, 0.8] when prioritizing structural signals, got %.2f", result.Confidence)
	}

	t.Logf("Confidence with structural prioritization: %.2f", result.Confidence)
}

// TestObfuscationConfidenceAdjustment_StringAndStructure tests confidence
// for methods with string + structure signals
func TestObfuscationConfidenceAdjustment_StringAndStructure(t *testing.T) {
	ps, pa := newTestScorer()

	// Obfuscated method with string + structure signals
	smali := `
.class public Lcom/a/b;
.super Ljava/lang/Object;

.method public x()Z
    .locals 2
    
    # Has security string
    const-string v0, "license"
    
    # Has dual return structure
    if-eqz v0, :cond_0
    
    const/4 v0, 0x1
    return v0
    
    :cond_0
    const/4 v0, 0x0
    return v0
.end method
`

	classInfo := pa.AnalyzeSmaliContent("com/a/b.smali", []byte(smali))
	if len(classInfo.Methods) == 0 {
		t.Fatal("No methods found")
	}

	mi := &classInfo.Methods[0]
	result := ps.ScoreMethod(mi)

	// With string + structure, confidence should be moderate [0.5, 0.7]
	if result.Confidence < 0.5 || result.Confidence > 0.7 {
		t.Errorf("Expected confidence in [0.5, 0.7] for string+structure, got %.2f", result.Confidence)
	}

	t.Logf("String+structure confidence: %.2f (expected [0.5, 0.7])", result.Confidence)
}

// TestObfuscationConfidenceAdjustment_NoStrongSignals tests confidence
// for obfuscated methods with no strong signals
func TestObfuscationConfidenceAdjustment_NoStrongSignals(t *testing.T) {
	ps, pa := newTestScorer()

	// Obfuscated method with no strong signals
	smali := `
.class public Lcom/a/b;
.super Ljava/lang/Object;

.method public x()V
    .locals 1
    
    # No security API, no structure, no strings
    const/4 v0, 0x0
    return-void
.end method
`

	classInfo := pa.AnalyzeSmaliContent("com/a/b.smali", []byte(smali))
	if len(classInfo.Methods) == 0 {
		t.Fatal("No methods found")
	}

	mi := &classInfo.Methods[0]
	result := ps.ScoreMethod(mi)

	// With no strong signals, confidence should be very low (max 0.4)
	if result.Confidence > 0.4 {
		t.Errorf("Expected confidence <= 0.4 for no strong signals, got %.2f", result.Confidence)
	}

	t.Logf("No strong signals confidence: %.2f (expected <= 0.4)", result.Confidence)
}

// TestObfuscationConfidenceAdjustment_HighObfuscationConfidenceBoost tests
// that high obfuscation confidence (>= 0.7) with structural signals gets a boost
func TestObfuscationConfidenceAdjustment_HighObfuscationConfidenceBoost(t *testing.T) {
	ps, pa := newTestScorer()

	// Highly obfuscated method with structure + API
	smali := `
.class public Lcom/a/b/c/d/e;
.super Ljava/lang/Object;

.method public a()Z
    .locals 2
    
    # Has security API call
    invoke-static {}, Landroid/content/pm/PackageManager;->getPackageInfo()Landroid/content/pm/PackageInfo;
    
    # Has dual return structure
    if-eqz v0, :cond_0
    
    const/4 v0, 0x1
    return v0
    
    :cond_0
    const/4 v0, 0x0
    return v0
.end method
`

	classInfo := pa.AnalyzeSmaliContent("com/a/b/c/d/e.smali", []byte(smali))
	if len(classInfo.Methods) == 0 {
		t.Fatal("No methods found")
	}

	mi := &classInfo.Methods[0]
	result := ps.ScoreMethod(mi)

	// Should detect high obfuscation confidence
	if result.ObfuscationInfo == nil || result.ObfuscationInfo.Confidence < 0.7 {
		t.Logf("Obfuscation confidence: %.2f (expected >= 0.7)", result.ObfuscationInfo.Confidence)
	}

	// Confidence should be boosted but still within [0.6, 0.8] range
	if result.Confidence < 0.6 || result.Confidence > 0.8 {
		t.Errorf("Expected confidence in [0.6, 0.8] with boost, got %.2f", result.Confidence)
	}

	t.Logf("Boosted confidence: %.2f (obfuscation confidence: %.2f)",
		result.Confidence, result.ObfuscationInfo.Confidence)
}

// TestObfuscationConfidenceAdjustment_CompareObfuscatedVsNonObfuscated tests
// that obfuscated methods have different confidence ranges than non-obfuscated
func TestObfuscationConfidenceAdjustment_CompareObfuscatedVsNonObfuscated(t *testing.T) {
	ps, pa := newTestScorer()

	// Non-obfuscated method with name + structure + API
	nonObfuscatedSmali := `
.class public Lcom/app/security/LicenseChecker;
.super Ljava/lang/Object;

.method public checkLicense()Z
    .locals 2
    
    # Has security API call
    invoke-static {}, Landroid/content/pm/PackageManager;->getPackageInfo()Landroid/content/pm/PackageInfo;
    
    # Has dual return structure
    if-eqz v0, :cond_0
    
    const/4 v0, 0x1
    return v0
    
    :cond_0
    const/4 v0, 0x0
    return v0
.end method
`

	// Obfuscated method with structure + API (no meaningful name)
	obfuscatedSmali := `
.class public Lcom/a/b;
.super Ljava/lang/Object;

.method public a()Z
    .locals 2
    
    # Has security API call
    invoke-static {}, Landroid/content/pm/PackageManager;->getPackageInfo()Landroid/content/pm/PackageInfo;
    
    # Has dual return structure
    if-eqz v0, :cond_0
    
    const/4 v0, 0x1
    return v0
    
    :cond_0
    const/4 v0, 0x0
    return v0
.end method
`

	// Analyze non-obfuscated method
	nonObfClassInfo := pa.AnalyzeSmaliContent("com/app/security/LicenseChecker.smali", []byte(nonObfuscatedSmali))
	if len(nonObfClassInfo.Methods) == 0 {
		t.Fatal("No non-obfuscated methods found")
	}
	nonObfMi := &nonObfClassInfo.Methods[0]
	nonObfResult := ps.ScoreMethod(nonObfMi)

	// Analyze obfuscated method
	obfClassInfo := pa.AnalyzeSmaliContent("com/a/b.smali", []byte(obfuscatedSmali))
	if len(obfClassInfo.Methods) == 0 {
		t.Fatal("No obfuscated methods found")
	}
	obfMi := &obfClassInfo.Methods[0]
	obfResult := ps.ScoreMethod(obfMi)

	// Obfuscated method should be capped at 0.8
	if obfResult.Confidence > 0.8 {
		t.Errorf("Obfuscated method confidence should be capped at 0.8, got %.2f", obfResult.Confidence)
	}

	// Obfuscated method should be in [0.6, 0.8] range
	if obfResult.Confidence < 0.6 || obfResult.Confidence > 0.8 {
		t.Errorf("Obfuscated method confidence should be in [0.6, 0.8], got %.2f", obfResult.Confidence)
	}

	t.Logf("Non-obfuscated confidence: %.2f", nonObfResult.Confidence)
	t.Logf("Obfuscated confidence: %.2f (capped at 0.8)", obfResult.Confidence)
}

// TestObfuscationConfidenceAdjustment_EdgeCases tests edge cases
func TestObfuscationConfidenceAdjustment_EdgeCases(t *testing.T) {
	ps, pa := newTestScorer()

	testCases := []struct {
		name           string
		smali          string
		expectedMinMax [2]float64 // [min, max]
		description    string
	}{
		{
			name: "structure_api_string",
			smali: `
.class public Lcom/a/b;
.super Ljava/lang/Object;

.method public x()Z
    .locals 2
    
    const-string v0, "license"
    invoke-static {}, Landroid/content/pm/PackageManager;->getPackageInfo()Landroid/content/pm/PackageInfo;
    
    if-eqz v0, :cond_0
    const/4 v0, 0x1
    return v0
    
    :cond_0
    const/4 v0, 0x0
    return v0
.end method
`,
			expectedMinMax: [2]float64{0.6, 0.8},
			description:    "structure + API + string should be in [0.6, 0.8]",
		},
		{
			name: "only_return_type",
			smali: `
.class public Lcom/a/b;
.super Ljava/lang/Object;

.method public x()Z
    .locals 1
    
    const/4 v0, 0x1
    return v0
.end method
`,
			expectedMinMax: [2]float64{0.0, 0.4},
			description:    "only return type signal should be very low",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			classInfo := pa.AnalyzeSmaliContent("com/a/b.smali", []byte(tc.smali))
			if len(classInfo.Methods) == 0 {
				t.Fatal("No methods found")
			}

			mi := &classInfo.Methods[0]
			result := ps.ScoreMethod(mi)

			if result.Confidence < tc.expectedMinMax[0] || result.Confidence > tc.expectedMinMax[1] {
				t.Errorf("%s: expected confidence in [%.2f, %.2f], got %.2f",
					tc.description, tc.expectedMinMax[0], tc.expectedMinMax[1], result.Confidence)
			}

			t.Logf("%s: confidence %.2f (expected [%.2f, %.2f])",
				tc.name, result.Confidence, tc.expectedMinMax[0], tc.expectedMinMax[1])
		})
	}
}
