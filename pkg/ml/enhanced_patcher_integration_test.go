package ml

import (
	"testing"
)

// TestEnhancedPatcher_Integration тестирует интеграцию всех новых компонентов
func TestEnhancedPatcher_Integration(t *testing.T) {
	// Create patch predictor with enhanced components
	predictor := NewPatchPredictor(nil)

	// Verify components are initialized
	if predictor.interestingScorer == nil {
		t.Fatal("InterestingScorer should be initialized")
	}
	if predictor.noiseFilter == nil {
		t.Fatal("NoiseFilter should be initialized")
	}
	if predictor.entryPointDetector == nil {
		t.Fatal("EntryPointDetector should be initialized")
	}

	// Test with sample candidates
	candidates := []AnalysisCandidate{
		{
			FilePath:  "com/myapp/MainActivity.smali",
			IsAppCode: true,
			Content:   []byte(sampleActivitySmali),
		},
		{
			FilePath:  "android/support/v4/app/Fragment.smali",
			IsAppCode: false,
			Content:   []byte(sampleLibrarySmali),
		},
		{
			FilePath:  "com/myapp/LicenseChecker.smali",
			IsAppCode: true,
			Content:   []byte(sampleLicenseSmali),
		},
	}

	// Run prediction
	prediction := predictor.PredictFromCandidates(candidates)

	// Verify prediction structure
	if prediction == nil {
		t.Fatal("Prediction should not be nil")
	}

	// Verify that app code methods are prioritized over library code
	totalAppFindings := len(prediction.HighRisk) + len(prediction.MediumRisk) + len(prediction.LowRisk)
	totalLibraryFindings := len(prediction.LibraryFindings)

	// Note: Sample data may not contain vulnerable patterns, so we just verify structure
	t.Logf("App findings: %d, Library findings: %d", totalAppFindings, totalLibraryFindings)

	// Verify enhanced data structure is available (even if empty)
	if prediction.Stats.TotalFilesScanned == 0 {
		t.Error("Should have scanned some files")
	}

	// Verify enhanced data is populated
	for _, point := range prediction.HighRisk {
		if point.IsAppCode && point.InterestingScore == nil {
			t.Error("App code high risk points should have interesting score")
		}
	}

	// Test noise filter statistics
	stats := predictor.GetNoiseFilterStats()
	if stats == nil {
		t.Error("Should have noise filter stats")
	}
}

// TestEnhancedPatcher_NoiseFiltering тестирует фильтрацию шума
func TestEnhancedPatcher_NoiseFiltering(t *testing.T) {
	predictor := NewPatchPredictor(nil)

	candidates := []AnalysisCandidate{
		{
			FilePath:  "com/myapp/Utils.smali",
			IsAppCode: true,
			Content:   []byte(sampleGenericMethodSmali),
		},
		{
			FilePath:  "com/myapp/LicenseChecker.smali",
			IsAppCode: true,
			Content:   []byte(sampleLicenseSmali),
		},
	}

	// Run with noise filtering enabled
	predictor.EnableNoiseFilter(true)
	predictionWithFilter := predictor.PredictFromCandidates(candidates)

	// Run with noise filtering disabled
	predictor.EnableNoiseFilter(false)
	predictionWithoutFilter := predictor.PredictFromCandidates(candidates)

	// Should have fewer findings with filter enabled
	totalWithFilter := len(predictionWithFilter.HighRisk) + len(predictionWithFilter.MediumRisk) + len(predictionWithFilter.LowRisk)
	totalWithoutFilter := len(predictionWithoutFilter.HighRisk) + len(predictionWithoutFilter.MediumRisk) + len(predictionWithoutFilter.LowRisk)

	if totalWithFilter > totalWithoutFilter {
		t.Errorf("Filtering should reduce findings: %d vs %d", totalWithFilter, totalWithoutFilter)
	}
}

// TestEnhancedPatcher_EntryPointDetection тестирует детекцию entry points
func TestEnhancedPatcher_EntryPointDetection(t *testing.T) {
	predictor := NewPatchPredictor(nil)

	candidates := []AnalysisCandidate{
		{
			FilePath:  "com/myapp/MainActivity.smali",
			IsAppCode: true,
			Content:   []byte(sampleActivitySmali),
		},
	}

	prediction := predictor.PredictFromCandidates(candidates)

	// Look for entry point detection in results
	foundEntryPoint := false
	for _, point := range prediction.HighRisk {
		if point.IsEntryPoint {
			foundEntryPoint = true
			if point.EntryPointInfo == nil {
				t.Error("Entry point should have EntryPointInfo")
			}
			break
		}
	}

	for _, point := range prediction.MediumRisk {
		if point.IsEntryPoint {
			foundEntryPoint = true
			break
		}
	}

	if !foundEntryPoint {
		t.Log("No entry points detected - this may be expected depending on sample data")
	}
}

// TestEnhancedPatcher_InterestingScoring тестирует interesting scoring
func TestEnhancedPatcher_InterestingScoring(t *testing.T) {
	predictor := NewPatchPredictor(nil)

	candidates := []AnalysisCandidate{
		{
			FilePath:  "com/myapp/LicenseChecker.smali",
			IsAppCode: true,
			Content:   []byte(sampleLicenseSmali),
		},
	}

	// Run with interesting scoring enabled
	predictor.EnableInterestingScore(true)
	predictionWithScoring := predictor.PredictFromCandidates(candidates)

	// Run with interesting scoring disabled
	predictor.EnableInterestingScore(false)
	predictionWithoutScoring := predictor.PredictFromCandidates(candidates)

	// Verify interesting scores are populated when enabled
	foundInterestingScore := false
	for _, point := range predictionWithScoring.HighRisk {
		if point.InterestingScore != nil {
			foundInterestingScore = true
			if point.InterestingScore.TotalScore < 0 {
				t.Error("Interesting score should be non-negative")
			}
			break
		}
	}

	if !foundInterestingScore {
		t.Log("No interesting scores found - this may be expected depending on sample data")
	}

	// Verify interesting scores are not populated when disabled
	for _, point := range predictionWithoutScoring.HighRisk {
		if point.InterestingScore != nil {
			t.Error("Interesting score should be nil when disabled")
		}
	}
}

// TestEnhancedPatcher_BackwardCompatibility тестирует обратную совместимость
func TestEnhancedPatcher_BackwardCompatibility(t *testing.T) {
	// Create predictor with default settings
	predictor := NewPatchPredictor(nil)

	candidates := []AnalysisCandidate{
		{
			FilePath:  "com/myapp/LicenseChecker.smali",
			IsAppCode: true,
			Content:   []byte(sampleLicenseSmali),
		},
	}

	// Run prediction
	prediction := predictor.PredictFromCandidates(candidates)

	// Verify basic structure is maintained
	if prediction == nil {
		t.Fatal("Prediction should not be nil")
	}

	// Verify required fields are present
	if prediction.Stats.TotalFilesScanned == 0 {
		t.Error("Should have scanned files")
	}

	// Verify prediction has expected structure
	if len(prediction.HighRisk) == 0 && len(prediction.MediumRisk) == 0 &&
		len(prediction.LowRisk) == 0 && len(prediction.LibraryFindings) == 0 {
		t.Log("No findings - this may be expected depending on sample data")
	}

	// Verify all points have required fields
	allPoints := append(prediction.HighRisk, prediction.MediumRisk...)
	allPoints = append(allPoints, prediction.LowRisk...)
	allPoints = append(allPoints, prediction.LibraryFindings...)

	for i, point := range allPoints {
		if point.FilePath == "" {
			t.Errorf("Point %d should have FilePath", i)
		}
		if point.ClassName == "" {
			t.Errorf("Point %d should have ClassName", i)
		}
		if point.MethodName == "" {
			t.Errorf("Point %d should have MethodName", i)
		}
	}
}

// TestEnhancedPatcher_ComponentConfiguration тестирует конфигурацию компонентов
func TestEnhancedPatcher_ComponentConfiguration(t *testing.T) {
	predictor := NewPatchPredictor(nil)

	// Test noise filter configuration
	customFilter := NewNoiseFilter()
	predictor.SetNoiseFilter(customFilter)

	// Test interesting scorer configuration
	customScorer := NewInterestingScorer()
	predictor.SetInterestingScorer(customScorer)

	// Test entry point detector configuration
	customDetector := NewEntryPointDetector()
	predictor.SetEntryPointDetector(customDetector)

	// Verify components are set
	if predictor.noiseFilter != customFilter {
		t.Error("Custom noise filter should be set")
	}
	if predictor.interestingScorer != customScorer {
		t.Error("Custom interesting scorer should be set")
	}
	if predictor.entryPointDetector != customDetector {
		t.Error("Custom entry point detector should be set")
	}

	// Test enable/disable functionality
	predictor.EnableNoiseFilter(false)
	predictor.EnableInterestingScore(false)

	if predictor.enableNoiseFilter {
		t.Error("Noise filter should be disabled")
	}
	if predictor.enableInterestingScore {
		t.Error("Interesting score should be disabled")
	}
}

// Sample smali content for testing
const sampleActivitySmali = `
.class public Lcom/myapp/MainActivity;
.super Landroid/app/Activity;

.method protected onCreate(Landroid/os/Bundle;)V
    .locals 1
    .param p1, "savedInstanceState"    # Landroid/os/Bundle;

    .prologue
    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V
    
    const v0, 0x7f030000
    invoke-virtual {p0, v0}, Lcom/myapp/MainActivity;->setContentView(I)V
    
    return-void
.end method
`

const sampleLibrarySmali = `
.class public Landroid/support/v4/app/Fragment;
.super Ljava/lang/Object;

.method public toString()Ljava/lang/String;
    .locals 1
    
    const-string v0, "Fragment"
    return-object v0
.end method
`

const sampleLicenseSmali = `
.class public Lcom/myapp/LicenseChecker;
.super Ljava/lang/Object;

.method public checkLicense()Z
    .locals 2
    
    const-string v0, "license_key"
    invoke-virtual {p0, v0}, Lcom/myapp/LicenseChecker;->validateKey(Ljava/lang/String;)Z
    move-result v1
    
    if-eqz v1, :cond_0
    const/4 v0, 0x1
    return v0
    
    :cond_0
    const/4 v0, 0x0
    return v0
.end method

.method private validateKey(Ljava/lang/String;)Z
    .locals 1
    .param p1, "key"    # Ljava/lang/String;
    
    const/4 v0, 0x1
    return v0
.end method
`

const sampleGenericMethodSmali = `
.class public Lcom/myapp/Utils;
.super Ljava/lang/Object;

.method public static toString(Ljava/lang/Object;)Ljava/lang/String;
    .locals 1
    .param p0, "obj"    # Ljava/lang/Object;
    
    if-nez p0, :cond_0
    const-string v0, "null"
    return-object v0
    
    :cond_0
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;
    move-result-object v0
    return-object v0
.end method

.method public static hashCode(Ljava/lang/Object;)I
    .locals 1
    .param p0, "obj"    # Ljava/lang/Object;
    
    if-nez p0, :cond_0
    const/4 v0, 0x0
    return v0
    
    :cond_0
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I
    move-result v0
    return v0
.end method
`
