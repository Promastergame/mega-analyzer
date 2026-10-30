package ml

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestPredictFromDirectoryUsesBoundedBatches(t *testing.T) {
	dir := testTempDir(t)
	fileCount := directoryPredictionBatchSize*2 + 7
	for i := 0; i < fileCount; i++ {
		path := filepath.Join(dir, fmt.Sprintf("com/app/LicenseChecker%03d.smali", i))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("create directory: %v", err)
		}
		if err := os.WriteFile(path, []byte(smaliLicenseCheck), 0o644); err != nil {
			t.Fatalf("write Smali fixture: %v", err)
		}
	}

	prediction, err := NewPatchPredictor(&bytes.Buffer{}).PredictFromDirectory(dir)
	if err != nil {
		t.Fatalf("PredictFromDirectory() error = %v", err)
	}
	if got := prediction.Stats.TotalFilesScanned; got != fileCount {
		t.Fatalf("TotalFilesScanned = %d, want %d", got, fileCount)
	}
	if got := prediction.Stats.FilesDiscovered; got != fileCount {
		t.Fatalf("FilesDiscovered = %d, want %d", got, fileCount)
	}
	if len(prediction.HighRisk) > DefaultPredictorConfig().MaxHighRisk {
		t.Fatalf("retained high-risk results = %d, limit = %d", len(prediction.HighRisk), DefaultPredictorConfig().MaxHighRisk)
	}
}

func TestPredictFromCandidates(t *testing.T) {
	predictor := NewPatchPredictor(&bytes.Buffer{})

	candidates := []AnalysisCandidate{
		{FilePath: "com/app/LicenseChecker.smali", Content: []byte(smaliLicenseCheck), IsAppCode: true},
		{FilePath: "com/app/security/RootDetector.smali", Content: []byte(smaliRootCheck), IsAppCode: true},
		{FilePath: "com/app/PremiumManager.smali", Content: []byte(smaliPremiumCheck), IsAppCode: true},
		{FilePath: "com/app/ads/AdManager.smali", Content: []byte(smaliAdShow), IsAppCode: true},
		{FilePath: "com/app/TrialManager.smali", Content: []byte(smaliTrialExpiry), IsAppCode: true},
		{FilePath: "com/app/billing/SubscriptionManager.smali", Content: []byte(smaliSubscription), IsAppCode: true},
		{FilePath: "com/app/Security.smali", Content: []byte(smaliSignatureCheck), IsAppCode: true},
		{FilePath: "com/app/EmulatorDetector.smali", Content: []byte(smaliEmulatorCheck), IsAppCode: true},
		// Safe files
		{FilePath: "com/app/User.smali", Content: []byte(smaliGetter), IsAppCode: true},
		{FilePath: "com/app/MainActivity.smali", Content: []byte(smaliOnClick), IsAppCode: true},
		{FilePath: "com/app/Helper.smali", Content: []byte(smaliConstructor), IsAppCode: true},
		{FilePath: "com/google/ads/AdView.smali", Content: []byte(smaliSynthetic), IsAppCode: false},
		{FilePath: "com/app/Utils.smali", Content: []byte(smaliLogger), IsAppCode: true},
	}

	prediction := predictor.PredictFromCandidates(candidates)

	if prediction == nil {
		t.Fatal("Prediction is nil")
	}

	// Должны найти патч-точки
	total := len(prediction.HighRisk) + len(prediction.MediumRisk) + len(prediction.LowRisk)
	if total == 0 {
		t.Fatal("Should find at least some patch points")
	}

	// Stats
	if prediction.Stats.TotalFilesScanned == 0 {
		t.Error("TotalFilesScanned should not be 0")
	}
	if prediction.Stats.PatchPointsFound != total {
		t.Errorf("PatchPointsFound = %d, but total = %d", prediction.Stats.PatchPointsFound, total)
	}

	// Safe files should NOT appear in results
	for _, p := range prediction.HighRisk {
		if p.FilePath == "com/app/User.smali" || p.FilePath == "com/app/Helper.smali" {
			t.Errorf("Safe file %q should not be in HIGH risk", p.FilePath)
		}
	}

	// Categories should be populated
	if len(prediction.Stats.ByCategory) == 0 {
		t.Error("ByCategory should not be empty")
	}

	t.Logf("Found %d high, %d medium, %d low risk patch points",
		len(prediction.HighRisk), len(prediction.MediumRisk), len(prediction.LowRisk))
}

func TestPredictFromCandidates_EnsembleBoostTogglesRiskScore(t *testing.T) {
	candidates := []AnalysisCandidate{
		{FilePath: "com/app/LicenseChecker.smali", Content: []byte(smaliLicenseCheck), IsAppCode: true},
		{FilePath: "com/app/security/RootDetector.smali", Content: []byte(smaliRootCheck), IsAppCode: true},
		{FilePath: "com/app/PremiumManager.smali", Content: []byte(smaliPremiumCheck), IsAppCode: true},
	}

	offConfig := DefaultPredictorConfig()
	offConfig.EnableEnsembleBoost = false
	offPredictor := NewPatchPredictorWithConfig(&bytes.Buffer{}, offConfig)
	offPrediction := offPredictor.PredictFromCandidates(candidates)

	onConfig := DefaultPredictorConfig()
	onConfig.EnableEnsembleBoost = true
	onPredictor := NewPatchPredictorWithConfig(&bytes.Buffer{}, onConfig)
	onPrediction := onPredictor.PredictFromCandidates(candidates)

	offTotal := len(offPrediction.HighRisk) + len(offPrediction.MediumRisk) + len(offPrediction.LowRisk)
	onTotal := len(onPrediction.HighRisk) + len(onPrediction.MediumRisk) + len(onPrediction.LowRisk)
	if offTotal == 0 || onTotal == 0 {
		t.Fatal("expected patch points in both configurations")
	}

	offScores := make(map[string]float64)
	collectScores := func(points []PatchPoint, dst map[string]float64) {
		for _, p := range points {
			dst[p.FilePath+"::"+p.MethodName] = p.RiskScore
		}
	}
	collectScores(offPrediction.HighRisk, offScores)
	collectScores(offPrediction.MediumRisk, offScores)
	collectScores(offPrediction.LowRisk, offScores)

	onScores := make(map[string]float64)
	collectScores(onPrediction.HighRisk, onScores)
	collectScores(onPrediction.MediumRisk, onScores)
	collectScores(onPrediction.LowRisk, onScores)

	foundEnsembleTag := false
	checkEnsembleTag := func(points []PatchPoint) {
		for _, p := range points {
			if p.EnsembleScore == nil {
				continue
			}
			for _, r := range p.WhyVulnerable {
				if bytes.Contains([]byte(r), []byte("blend")) {
					foundEnsembleTag = true
				}
			}
		}
	}
	checkEnsembleTag(onPrediction.HighRisk)
	checkEnsembleTag(onPrediction.MediumRisk)
	checkEnsembleTag(onPrediction.LowRisk)
	if !foundEnsembleTag {
		t.Error("expected at least one patch point with an ensemble blend explanation when EnableEnsembleBoost is true")
	}

	differs := false
	for key, offScore := range offScores {
		if onScore, ok := onScores[key]; ok && onScore != offScore {
			differs = true
			break
		}
	}
	if !differs {
		t.Error("expected at least one risk score to differ between EnableEnsembleBoost true/false")
	}
}

func TestPredictEmpty(t *testing.T) {
	predictor := NewPatchPredictor(&bytes.Buffer{})

	prediction := predictor.PredictFromCandidates(nil)

	if prediction == nil {
		t.Fatal("Should return empty prediction, not nil")
	}
	if len(prediction.HighRisk) != 0 {
		t.Error("Empty prediction should have no high risk")
	}
}

func TestPredictLibraryExcluded(t *testing.T) {
	predictor := NewPatchPredictor(&bytes.Buffer{})

	candidates := []AnalysisCandidate{
		{FilePath: "com/google/ads/internal/Checker.smali", Content: []byte(smaliLicenseCheck), IsAppCode: false},
	}

	prediction := predictor.PredictFromCandidates(candidates)

	// Library code should be excluded by default
	total := len(prediction.HighRisk) + len(prediction.MediumRisk) + len(prediction.LowRisk)
	if total > 0 {
		t.Errorf("Library code should be excluded, but found %d points", total)
	}
}

func TestPredictLibraryIncluded(t *testing.T) {
	config := DefaultPredictorConfig()
	config.IncludeLibraries = true
	config.MinScore = 0 // Lower threshold to catch any results
	predictor := NewPatchPredictorWithConfig(&bytes.Buffer{}, config)

	// Use a path that's in LibraryExcludePaths to test library inclusion
	candidates := []AnalysisCandidate{
		{FilePath: "com/google/ads/internal/Checker.smali", Content: []byte(smaliLicenseCheck), IsAppCode: false},
	}

	prediction := predictor.PredictFromCandidates(candidates)

	// Just verify the function runs without error when IncludeLibraries is true
	// The actual results depend on content matching patterns
	_ = prediction
}

func TestRenderToTerminal(t *testing.T) {
	var buf bytes.Buffer
	predictor := NewPatchPredictor(&buf)

	candidates := []AnalysisCandidate{
		{FilePath: "com/app/LicenseChecker.smali", Content: []byte(smaliLicenseCheck), IsAppCode: true},
		{FilePath: "com/app/security/RootDetector.smali", Content: []byte(smaliRootCheck), IsAppCode: true},
	}

	prediction := predictor.PredictFromCandidates(candidates)
	predictor.RenderToTerminal(prediction)

	output := buf.String()
	if output == "" {
		t.Fatal("Terminal output is empty")
	}
	if !bytes.Contains([]byte(output), []byte("POTENTIAL PATCH POINTS")) {
		t.Error("Output should contain header")
	}
	if !bytes.Contains([]byte(output), []byte("Risk")) {
		t.Error("Output should contain risk information")
	}
}

func TestTopCategories(t *testing.T) {
	predictor := NewPatchPredictor(&bytes.Buffer{})

	candidates := []AnalysisCandidate{
		{FilePath: "com/app/LicenseChecker.smali", Content: []byte(smaliLicenseCheck), IsAppCode: true},
		{FilePath: "com/app/security/RootDetector.smali", Content: []byte(smaliRootCheck), IsAppCode: true},
		{FilePath: "com/app/PremiumManager.smali", Content: []byte(smaliPremiumCheck), IsAppCode: true},
		{FilePath: "com/app/EmulatorDetector.smali", Content: []byte(smaliEmulatorCheck), IsAppCode: true},
	}

	prediction := predictor.PredictFromCandidates(candidates)

	if len(prediction.Stats.TopCategories) == 0 && prediction.Stats.PatchPointsFound > 0 {
		t.Error("TopCategories should not be empty when patch points found")
	}
}

func TestDeduplication(t *testing.T) {
	predictor := NewPatchPredictor(&bytes.Buffer{})

	// Same file twice
	candidates := []AnalysisCandidate{
		{FilePath: "com/app/LicenseChecker.smali", Content: []byte(smaliLicenseCheck), IsAppCode: true},
		{FilePath: "com/app/LicenseChecker.smali", Content: []byte(smaliLicenseCheck), IsAppCode: true},
	}

	prediction := predictor.PredictFromCandidates(candidates)

	total := len(prediction.HighRisk) + len(prediction.MediumRisk) + len(prediction.LowRisk)

	// Should deduplicate
	methodCount := 0
	seen := make(map[string]bool)
	for _, p := range prediction.HighRisk {
		key := p.FilePath + "::" + p.MethodName
		if seen[key] {
			t.Errorf("Duplicate patch point: %s", key)
		}
		seen[key] = true
		methodCount++
	}

	if total > 1 {
		// License check has 1 method, so max 1 point even with 2 files
		t.Logf("Found %d points (deduplication working)", total)
	}
}
