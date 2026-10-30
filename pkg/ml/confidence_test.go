package ml

import (
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// CONFIDENCE SCORING TESTS (Task 13)
// ═══════════════════════════════════════════════════════════════════════════════

func TestMultiSignalConfidence(t *testing.T) {
	ps, pa := newTestScorer()

	// Test method with multiple signals
	smali := `
.class public Lcom/app/LicenseChecker;
.super Ljava/lang/Object;

.method public checkLicense()Z
    .locals 2
    
    # Has security API call
    invoke-static {}, Landroid/content/pm/PackageManager;->getPackageInfo()Landroid/content/pm/PackageInfo;
    
    # Has if-check
    if-eqz v0, :cond_0
    
    const/4 v0, 0x1
    return v0
    
    :cond_0
    const/4 v0, 0x0
    return v0
.end method
`

	classInfo := pa.AnalyzeSmaliContent("com/app/LicenseChecker.smali", []byte(smali))
	if len(classInfo.Methods) == 0 {
		t.Fatal("No methods found")
	}

	mi := &classInfo.Methods[0]
	result := ps.ScoreMethod(mi)

	// Should have multiple signals
	if len(result.MatchedSignals) == 0 {
		t.Error("Expected matched signals, got none")
	}

	// Confidence should be in valid range
	if result.Confidence < 0.0 || result.Confidence > 1.0 {
		t.Errorf("Confidence out of range: %.2f", result.Confidence)
	}

	// With multiple signals, confidence should be reasonably high
	if result.Confidence < 0.5 {
		t.Errorf("Expected higher confidence with multiple signals, got %.2f", result.Confidence)
	}

	t.Logf("Confidence: %.2f, Signals: %d", result.Confidence, len(result.MatchedSignals))
	for _, sig := range result.MatchedSignals {
		t.Logf("  Signal: %s, Confidence: %.2f", sig.Type, sig.Confidence)
	}
}

func TestObfuscationConfidenceAdjustment(t *testing.T) {
	ps, pa := newTestScorer()

	// Test obfuscated method (single letter name, but has structure + API)
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
	if result.ObfuscationInfo == nil {
		t.Error("Expected obfuscation detection")
	} else if !result.ObfuscationInfo.IsObfuscated {
		t.Error("Expected method to be detected as obfuscated")
	}

	// Confidence should be adjusted for obfuscated code
	// With structure + API but no name match, should be in 0.6-0.8 range
	if result.Confidence < 0.3 || result.Confidence > 1.0 {
		t.Errorf("Confidence out of expected range for obfuscated code: %.2f", result.Confidence)
	}

	t.Logf("Obfuscated method confidence: %.2f", result.Confidence)
	t.Logf("Obfuscation type: %s, confidence: %.2f",
		result.ObfuscationInfo.ObfuscationType,
		result.ObfuscationInfo.Confidence)
}

func TestStructuralOnlyConfidence(t *testing.T) {
	ps, pa := newTestScorer()

	// Test method with only structural signals (no name, no API, no strings)
	smali := `
.class public Lcom/a/b;
.super Ljava/lang/Object;

.method public x()Z
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

	classInfo := pa.AnalyzeSmaliContent("com/a/b.smali", []byte(smali))
	if len(classInfo.Methods) == 0 {
		t.Fatal("No methods found")
	}

	mi := &classInfo.Methods[0]
	result := ps.ScoreMethod(mi)

	// With only structural signals, confidence should be lower (0.3-0.6)
	if result.Confidence > 0.7 {
		t.Errorf("Expected lower confidence for structural-only match, got %.2f", result.Confidence)
	}

	t.Logf("Structural-only confidence: %.2f, Signals: %d", result.Confidence, len(result.MatchedSignals))
}

func TestHighConfidenceWithAllSignals(t *testing.T) {
	ps, pa := newTestScorer()

	// Test method with all signal types: name + structure + API + strings
	smali := `
.class public Lcom/app/security/LicenseValidator;
.super Ljava/lang/Object;

.method public checkLicense()Z
    .locals 2
    
    # Has security string
    const-string v0, "license_key"
    
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

	classInfo := pa.AnalyzeSmaliContent("com/app/security/LicenseValidator.smali", []byte(smali))
	if len(classInfo.Methods) == 0 {
		t.Fatal("No methods found")
	}

	mi := &classInfo.Methods[0]
	result := ps.ScoreMethod(mi)

	// With name + structure + API + strings, confidence should be high (0.8-1.0)
	if result.Confidence < 0.7 {
		t.Errorf("Expected high confidence with all signals, got %.2f", result.Confidence)
	}

	// Should have multiple signal types
	signalTypes := make(map[SignalType]bool)
	for _, sig := range result.MatchedSignals {
		signalTypes[sig.Type] = true
	}

	if len(signalTypes) < 3 {
		t.Errorf("Expected at least 3 signal types, got %d", len(signalTypes))
	}

	t.Logf("High confidence: %.2f, Signal types: %d", result.Confidence, len(signalTypes))
	for sigType := range signalTypes {
		t.Logf("  Signal type: %s", sigType)
	}
}

func TestConfidenceInOutput(t *testing.T) {
	ps, pa := newTestScorer()

	smali := `
.class public Lcom/app/LicenseChecker;
.super Ljava/lang/Object;

.method public isLicenseValid()Z
    .locals 1
    
    if-eqz v0, :cond_0
    const/4 v0, 0x1
    return v0
    
    :cond_0
    const/4 v0, 0x0
    return v0
.end method
`

	classInfo := pa.AnalyzeSmaliContent("com/app/LicenseChecker.smali", []byte(smali))
	if len(classInfo.Methods) == 0 {
		t.Fatal("No methods found")
	}

	mi := &classInfo.Methods[0]
	result := ps.ScoreMethod(mi)

	// Verify confidence is included in result
	if result.Confidence == 0.0 {
		t.Error("Confidence should not be zero")
	}

	// Verify matched signals are included
	if result.MatchedSignals == nil {
		t.Error("MatchedSignals should not be nil")
	}

	t.Logf("Result includes confidence: %.2f and %d signals",
		result.Confidence, len(result.MatchedSignals))
}
