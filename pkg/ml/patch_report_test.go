package ml

import (
	"bytes"
	"strings"
	"testing"
)

func buildTestPrediction() *PatchPrediction {
	return &PatchPrediction{
		HighRisk: []PatchPoint{
			{
				FilePath:        "com/app/LicenseChecker.smali",
				ClassName:       "Lcom/app/LicenseChecker;",
				MethodName:      "isLicensed",
				MethodSignature: "isLicensed()Z",
				RiskScore:       92.5,
				RiskLevel:       RiskClassHigh,
				Confidence:      0.85,
				Category:        PatchCatLicense,
				CategoryName:    "License Check",
				PatternID:       "LICENSE_BOOL_CHECK",
				PatternDesc:     "Boolean license validation method",
				SuggestedPatch:  PatchReturnTrue,
				PatchDesc:       "Always return true (bypass check)",
				WhyVulnerable:   []string{"Boolean return with license check", "Has dual return paths"},
				MatchedParts:    []string{"method_name:islicensed", "class:license", "return_type:Z"},
				IsAppCode:       true,
				ReturnType:      "Z",
				MethodHeader:    ".method public isLicensed()Z",
				MethodBody: []string{
					".method public isLicensed()Z",
					"    .registers 2",
					"    const/4 v0, 0x0",
					"    return v0",
					".end method",
				},
			},
		},
		MediumRisk: []PatchPoint{
			{
				FilePath:        "com/app/security/RootDetector.smali",
				ClassName:       "Lcom/app/security/RootDetector;",
				MethodName:      "isDeviceRooted",
				MethodSignature: "isDeviceRooted()Z",
				RiskScore:       58.0,
				RiskLevel:       RiskClassMedium,
				Confidence:      0.7,
				Category:        PatchCatRootDetect,
				CategoryName:    "Root Detection",
				SuggestedPatch:  PatchReturnFalse,
				PatchDesc:       "Always return false (disable detection)",
				WhyVulnerable:   []string{"Detects rooted device"},
				MatchedParts:    []string{"method_name:isdevicerooted"},
				IsAppCode:       true,
				ReturnType:      "Z",
				MethodHeader:    ".method public static isDeviceRooted()Z",
				MethodBody: []string{
					".method public static isDeviceRooted()Z",
					"    .registers 2",
					"    const/4 v0, 0x1",
					"    return v0",
					".end method",
				},
			},
		},
		LowRisk: []PatchPoint{
			{
				FilePath:       "com/app/ads/AdManager.smali",
				MethodName:     "shouldShowAd",
				RiskScore:      35.0,
				RiskLevel:      RiskClassLow,
				Category:       PatchCatAds,
				CategoryName:   "Ad Control",
				SuggestedPatch: PatchReturnFalse,
				IsAppCode:      true,
				ReturnType:     "Z",
			},
		},
		Stats: PredictionStats{
			TotalFilesScanned: 100,
			TotalMethodsFound: 500,
			MethodsAnalyzed:   150,
			MethodsSkipped:    350,
			PatchPointsFound:  3,
			HighRiskCount:     1,
			MediumRiskCount:   1,
			LowRiskCount:      1,
			ByCategory:        map[string]int{"license_check": 1, "root_detection": 1, "ads": 1},
			TopCategories: []CategoryCount{
				{Category: PatchCatLicense, Name: "License Check", Count: 1},
				{Category: PatchCatRootDetect, Name: "Root Detection", Count: 1},
				{Category: PatchCatAds, Name: "Ad Control", Count: 1},
			},
			AvgScore: 61.8,
			MaxScore: 92.5,
		},
	}
}

func TestGenerateMarkdown(t *testing.T) {
	prediction := buildTestPrediction()
	gen := NewPatchReportGenerator(prediction, "test-app.apk", false)

	md := gen.GenerateMarkdown()

	if md == "" {
		t.Fatal("Markdown is empty")
	}
	if !strings.Contains(md, "# 🎯 Patch Points Analysis") {
		t.Error("Should contain title")
	}
	if !strings.Contains(md, "LicenseChecker") {
		t.Error("Should contain LicenseChecker")
	}
	if !strings.Contains(md, "RootDetector") {
		t.Error("Should contain RootDetector")
	}
	if !strings.Contains(md, "92.5%") {
		t.Error("Should contain risk score")
	}
	if !strings.Contains(md, "High Risk") {
		t.Error("Should contain High Risk section")
	}
	if !strings.Contains(md, "Medium Risk") {
		t.Error("Should contain Medium Risk section")
	}
	if !strings.Contains(md, "Summary") {
		t.Error("Should contain Summary")
	}

	// Should NOT contain fix sections
	if strings.Contains(md, "ORIGINAL") || strings.Contains(md, "PATCHED") {
		t.Error("Without --show-fix, should not contain fix sections")
	}
}

func TestGenerateMarkdownWithFix(t *testing.T) {
	prediction := buildTestPrediction()
	gen := NewPatchReportGenerator(prediction, "test-app.apk", true)

	md := gen.GenerateMarkdown()

	if !strings.Contains(md, "Fix Suggestions") {
		t.Error("Should contain Fix Suggestions in title")
	}
	if !strings.Contains(md, "Original code") {
		t.Error("Should contain original code section")
	}
	if !strings.Contains(md, "Hardened version") {
		t.Error("Should contain hardened version section")
	}
	if !strings.Contains(md, "const/4 v0, 0x1") {
		t.Error("Should contain patch for return true")
	}
	if !strings.Contains(md, "const/4 v0, 0x0") {
		t.Error("Should contain patch for return false")
	}
	if !strings.Contains(md, "diff") || !strings.Contains(md, "Diff") {
		t.Error("Should contain diff view")
	}
}

func TestGenerateMarkdownEmpty(t *testing.T) {
	prediction := &PatchPrediction{
		HighRisk:   []PatchPoint{},
		MediumRisk: []PatchPoint{},
		LowRisk:    []PatchPoint{},
		Stats:      PredictionStats{ByCategory: make(map[string]int)},
	}
	gen := NewPatchReportGenerator(prediction, "empty.apk", false)

	md := gen.GenerateMarkdown()

	if md == "" {
		t.Fatal("Should generate markdown even for empty prediction")
	}
	if !strings.Contains(md, "Summary") {
		t.Error("Should contain Summary even when empty")
	}
}

func TestGenerateMarkdownCategories(t *testing.T) {
	prediction := buildTestPrediction()
	gen := NewPatchReportGenerator(prediction, "test.apk", false)

	md := gen.GenerateMarkdown()

	if !strings.Contains(md, "Categories") {
		t.Error("Should contain Categories section")
	}
	if !strings.Contains(md, "License Check") {
		t.Error("Should contain License Check category")
	}
	if !strings.Contains(md, "Root Detection") {
		t.Error("Should contain Root Detection category")
	}
}

func TestGenerateMarkdownFooter(t *testing.T) {
	prediction := buildTestPrediction()
	gen := NewPatchReportGenerator(prediction, "test.apk", false)

	md := gen.GenerateMarkdown()

	if !strings.Contains(md, "Disclaimer") {
		t.Error("Should contain disclaimer")
	}
	if !strings.Contains(md, "Risk thresholds") {
		t.Error("Should explain risk thresholds")
	}
}

func TestRenderToTerminalWithFix(t *testing.T) {
	prediction := buildTestPrediction()
	var buf bytes.Buffer

	RenderToTerminalWithFix(&buf, prediction)

	output := buf.String()
	if output == "" {
		t.Fatal("Terminal output is empty")
	}
	if !strings.Contains(output, "PATCH POINTS") {
		t.Error("Should contain header")
	}
	if !strings.Contains(output, "HARDENING") {
		t.Error("Should contain HARDENING in header")
	}
	if !strings.Contains(output, "Suggested hardening") {
		t.Error("Should contain suggested hardening section")
	}
}

func TestRenderEmptyPrediction(t *testing.T) {
	prediction := &PatchPrediction{
		HighRisk:   []PatchPoint{},
		MediumRisk: []PatchPoint{},
		LowRisk:    []PatchPoint{},
		Stats:      PredictionStats{ByCategory: make(map[string]int)},
	}

	var buf bytes.Buffer
	RenderToTerminalWithFix(&buf, prediction)

	output := buf.String()
	if !strings.Contains(output, "No patch points detected") {
		t.Error("Should say no patch points detected")
	}
}

func TestBoolYesNo(t *testing.T) {
	if boolYesNo(true) != "✅ Yes" {
		t.Error("boolYesNo(true) should be Yes")
	}
	if boolYesNo(false) != "❌ No" {
		t.Error("boolYesNo(false) should be No")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// INTEGRATION TEST — полный цикл
// ═══════════════════════════════════════════════════════════════════════════════

func TestFullPipeline(t *testing.T) {
	// 1. Analyze
	var buf bytes.Buffer
	predictor := NewPatchPredictor(&buf)

	candidates := []AnalysisCandidate{
		{FilePath: "com/app/LicenseChecker.smali", Content: []byte(smaliLicenseCheck), IsAppCode: true},
		{FilePath: "com/app/security/RootDetector.smali", Content: []byte(smaliRootCheck), IsAppCode: true},
		{FilePath: "com/app/PremiumManager.smali", Content: []byte(smaliPremiumCheck), IsAppCode: true},
		{FilePath: "com/app/ads/AdManager.smali", Content: []byte(smaliAdShow), IsAppCode: true},
		{FilePath: "com/app/TrialManager.smali", Content: []byte(smaliTrialExpiry), IsAppCode: true},
		{FilePath: "com/app/billing/SubscriptionManager.smali", Content: []byte(smaliSubscription), IsAppCode: true},
		{FilePath: "com/app/EmulatorDetector.smali", Content: []byte(smaliEmulatorCheck), IsAppCode: true},
		{FilePath: "com/app/User.smali", Content: []byte(smaliGetter), IsAppCode: true},
		{FilePath: "com/app/Helper.smali", Content: []byte(smaliConstructor), IsAppCode: true},
		{FilePath: "com/google/ads/AdView.smali", Content: []byte(smaliSynthetic), IsAppCode: false},
	}

	// 2. Predict
	prediction := predictor.PredictFromCandidates(candidates)

	if prediction.Stats.PatchPointsFound == 0 {
		t.Fatal("Full pipeline should find patch points")
	}

	// 3. Render to terminal
	predictor.RenderToTerminal(prediction)
	terminalOutput := buf.String()
	if terminalOutput == "" {
		t.Error("Terminal output should not be empty")
	}

	// 4. Generate markdown report
	reportGen := NewPatchReportGenerator(prediction, "test-full.apk", false)
	md := reportGen.GenerateMarkdown()
	if len(md) < 100 {
		t.Error("Markdown report too short")
	}

	// 5. Generate markdown with fixes
	reportGenFix := NewPatchReportGenerator(prediction, "test-full.apk", true)
	mdFix := reportGenFix.GenerateMarkdown()
	if !strings.Contains(mdFix, "const/4") {
		t.Error("Fix report should contain patch code")
	}

	// 6. Generate all patches
	gen := NewPatchGenerator()
	patches := gen.GenerateAll(prediction)
	if len(patches) == 0 {
		t.Error("Should generate patches")
	}

	t.Logf("Full pipeline: %d files → %d patch points → %d patches → %d bytes MD → %d bytes MD+fix",
		len(candidates), prediction.Stats.PatchPointsFound, len(patches), len(md), len(mdFix))
}
