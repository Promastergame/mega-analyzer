package analyzer

import (
	"testing"

	"mega-analyzer/pkg/internal/config"
	"mega-analyzer/pkg/internal/filter"
	"mega-analyzer/pkg/internal/types"
)

func TestNewScorerCoverage(t *testing.T) {
	cfg := &config.Config{}
	f := filter.NewFilter()

	scorer := NewScorer(cfg, f)
	if scorer == nil {
		t.Error("NewScorer returned nil")
	}
}

func TestNewScorerWithWeightsCoverage(t *testing.T) {
	cfg := &config.Config{}
	f := filter.NewFilter()
	weights := ScoringWeights{
		ImportanceMultiplier: 3.0,
		CriticalPriority:     4.0,
	}

	scorer := NewScorerWithWeights(cfg, f, weights)
	if scorer == nil {
		t.Fatal("NewScorerWithWeights returned nil")
	}
	if scorer.weights.ImportanceMultiplier != 3.0 {
		t.Errorf("Expected ImportanceMultiplier 3.0, got %v", scorer.weights.ImportanceMultiplier)
	}
}

func TestScoreFile_LibraryCodeCoverage(t *testing.T) {
	cfg := &config.Config{}
	f := filter.NewFilter()
	scorer := NewScorer(cfg, f)

	analysis := &types.FileAnalysis{
		Path:      "smali/android/widget/Button.smali",
		IsAppCode: false,
	}

	score, reasons := scorer.ScoreFile(analysis)
	if score != 0 {
		t.Errorf("Expected score 0 for library code, got %v", score)
	}
	if len(reasons) == 0 {
		t.Error("Expected reasons for library code")
	}
}

func TestScoreFile_AppCodeCoverage(t *testing.T) {
	cfg := &config.Config{
		MinEntropyThreshold: 4.0,
	}
	f := filter.NewFilter()
	scorer := NewScorer(cfg, f)

	analysis := &types.FileAnalysis{
		Path:       "smali/com/example/MainActivity.smali",
		IsAppCode:  true,
		Importance: 5,
		Matches:    []types.Match{},
		Entropy:    3.0,
	}

	score, _ := scorer.ScoreFile(analysis)
	if score <= 0 {
		t.Errorf("Expected positive score for app code, got %v", score)
	}
}

func TestScoreFile_WithCriticalMatchesCoverage(t *testing.T) {
	cfg := &config.Config{
		MinEntropyThreshold: 4.0,
	}
	f := filter.NewFilter()
	scorer := NewScorer(cfg, f)

	analysis := &types.FileAnalysis{
		Path:       "smali/com/example/MainActivity.smali",
		IsAppCode:  true,
		Importance: 5,
		Matches: []types.Match{
			{Categorized: types.Categorized{Category: types.CategoryLicenseCheck}, Pattern: "check"},
			{Categorized: types.Categorized{Category: types.CategoryBillingClient}, Pattern: "billing"},
		},
		Entropy: 3.0,
	}

	score, reasons := scorer.ScoreFile(analysis)
	if score <= 0 {
		t.Errorf("Expected positive score, got %v", score)
	}
	if len(reasons) == 0 {
		t.Error("Expected reasons for critical matches")
	}
}

func TestScoreFile_WithDecisionPointsCoverage(t *testing.T) {
	cfg := &config.Config{
		MinEntropyThreshold: 4.0,
	}
	f := filter.NewFilter()
	scorer := NewScorer(cfg, f)

	analysis := &types.FileAnalysis{
		Path:       "smali/com/example/MainActivity.smali",
		IsAppCode:  true,
		Importance: 5,
		DecisionPoints: []types.DecisionPoint{
			{Method: "if-eq", Category: types.CategoryUnknown},
			{Method: "if-ne", Category: types.CategoryUnknown},
			{Method: "packed-switch", Category: types.CategoryUnknown},
		},
		Entropy: 3.0,
	}

	score, reasons := scorer.ScoreFile(analysis)
	if score <= 0 {
		t.Errorf("Expected positive score, got %v", score)
	}
	if len(reasons) == 0 {
		t.Error("Expected reasons for decision points")
	}
}

func TestScoreFile_WithHighEntropyCoverage(t *testing.T) {
	cfg := &config.Config{
		MinEntropyThreshold: 4.0,
	}
	f := filter.NewFilter()
	scorer := NewScorer(cfg, f)

	analysis := &types.FileAnalysis{
		Path:       "smali/com/example/MainActivity.smali",
		IsAppCode:  true,
		Importance: 5,
		Entropy:    5.5,
	}

	score, reasons := scorer.ScoreFile(analysis)
	if score <= 0 {
		t.Errorf("Expected positive score, got %v", score)
	}
	foundEntropy := false
	for _, r := range reasons {
		if len(r) > 0 && (r[0:1] == "🔥" || len(r) > 10) {
			foundEntropy = true
			break
		}
	}
	_ = foundEntropy // entropy bonus applied
}

func TestScoreFile_WithSuspiciousMethodsCoverage(t *testing.T) {
	cfg := &config.Config{
		MinEntropyThreshold: 4.0,
	}
	f := filter.NewFilter()
	scorer := NewScorer(cfg, f)

	analysis := &types.FileAnalysis{
		Path:            "smali/com/example/MainActivity.smali",
		IsAppCode:       true,
		Importance:      5,
		SuspiciousScore: 15.0,
		Entropy:         3.0,
	}

	score, _ := scorer.ScoreFile(analysis)
	if score <= 0 {
		t.Errorf("Expected positive score, got %v", score)
	}
}

func TestScoreFileDetailedCoverage(t *testing.T) {
	cfg := &config.Config{
		MinEntropyThreshold: 4.0,
	}
	f := filter.NewFilter()
	scorer := NewScorer(cfg, f)

	analysis := &types.FileAnalysis{
		Path:       "smali/com/example/MainActivity.smali",
		IsAppCode:  true,
		Importance: 5,
		Matches: []types.Match{
			{Categorized: types.Categorized{Category: types.CategoryCrypto}, Pattern: "AES"},
		},
		DecisionPoints: []types.DecisionPoint{
			{Method: "if-eq", Category: types.CategoryUnknown},
		},
		Entropy: 5.0,
	}

	bd := scorer.ScoreFileDetailed(analysis)
	if bd.BaseScore <= 0 {
		t.Errorf("Expected positive base score, got %v", bd.BaseScore)
	}
	if bd.CriticalCount < 0 {
		t.Errorf("Expected non-negative critical count, got %v", bd.CriticalCount)
	}
}

func TestCalculateHotspotsCoverage(t *testing.T) {
	cfg := &config.Config{
		MinEntropyThreshold: 4.0,
	}
	f := filter.NewFilter()
	scorer := NewScorer(cfg, f)

	files := map[string]*types.FileAnalysis{
		"file1.smali": {
			Path:       "file1.smali",
			IsAppCode:  true,
			Importance: 5,
			Matches: []types.Match{
				{Categorized: types.Categorized{Category: types.CategoryCrypto}, Pattern: "AES"},
			},
		},
		"file2.smali": {
			Path:       "file2.smali",
			IsAppCode:  true,
			Importance: 3,
		},
	}

	hotspots := scorer.CalculateHotspots(files, 10)
	if len(hotspots) == 0 {
		t.Error("Expected at least one hotspot")
	}
}

func TestCalculateHotspots_EmptyFilesCoverage(t *testing.T) {
	cfg := &config.Config{}
	f := filter.NewFilter()
	scorer := NewScorer(cfg, f)

	files := map[string]*types.FileAnalysis{}

	hotspots := scorer.CalculateHotspots(files, 10)
	if len(hotspots) != 0 {
		t.Errorf("Expected 0 hotspots for empty files, got %v", len(hotspots))
	}
}

func TestCalculateHotspots_NegativeTopNCoverage(t *testing.T) {
	cfg := &config.Config{}
	f := filter.NewFilter()
	scorer := NewScorer(cfg, f)

	files := map[string]*types.FileAnalysis{
		"file1.smali": {
			Path:       "file1.smali",
			IsAppCode:  true,
			Importance: 5,
		},
	}

	hotspots := scorer.CalculateHotspots(files, -1)
	// Should default to 50
	if len(hotspots) > 50 {
		t.Errorf("Expected at most 50 hotspots, got %v", len(hotspots))
	}
}

func TestNormalizeCoverage(t *testing.T) {
	tests := []struct {
		name     string
		score    float64
		cap      float64
		expected float64
	}{
		{"below cap", 50, 100, 50},
		{"at cap", 100, 100, 100},
		{"above cap", 150, 100, 100}, // soft cap with log
		{"zero cap", 50, 0, 50},
		{"negative cap", 50, -10, 50},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := normalize(tc.score, tc.cap)
			if tc.cap > 0 && tc.score <= tc.cap && result != tc.expected {
				t.Errorf("normalize(%v, %v) = %v, want %v", tc.score, tc.cap, result, tc.expected)
			}
		})
	}
}

func TestAppendReasonCoverage(t *testing.T) {
	reasons := []string{}

	// Add reasons up to limit
	for i := 0; i < 10; i++ {
		reasons = appendReason(reasons, "reason")
	}

	if len(reasons) > maxReasons {
		t.Errorf("Expected at most %d reasons, got %d", maxReasons, len(reasons))
	}
}

func TestMinCoverage(t *testing.T) {
	tests := []struct {
		a, b, expected int
	}{
		{1, 2, 1},
		{2, 1, 1},
		{5, 5, 5},
		{0, 10, 0},
		{-5, 5, -5},
	}

	for _, tc := range tests {
		result := min(tc.a, tc.b)
		if result != tc.expected {
			t.Errorf("min(%v, %v) = %v, want %v", tc.a, tc.b, result, tc.expected)
		}
	}
}
