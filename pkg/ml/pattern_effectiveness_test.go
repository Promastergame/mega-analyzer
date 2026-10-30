package ml

import (
	"strings"
	"testing"
)

// TestPatternEffectivenessCalculateRates tests rate calculation (Requirements 1.2)
func TestPatternEffectivenessCalculateRates(t *testing.T) {
	tests := []struct {
		name              string
		truePositives     int
		falsePositives    int
		totalDetections   int
		crashCount        int
		expectedTPRate    float64
		expectedFPRate    float64
		expectedCrashRate float64
	}{
		{
			name:              "High accuracy pattern",
			truePositives:     90,
			falsePositives:    10,
			totalDetections:   100,
			crashCount:        2,
			expectedTPRate:    0.9,
			expectedFPRate:    0.1,
			expectedCrashRate: 0.02,
		},
		{
			name:              "Low accuracy pattern",
			truePositives:     40,
			falsePositives:    60,
			totalDetections:   100,
			crashCount:        5,
			expectedTPRate:    0.4,
			expectedFPRate:    0.6,
			expectedCrashRate: 0.05,
		},
		{
			name:              "Zero detections",
			truePositives:     0,
			falsePositives:    0,
			totalDetections:   0,
			crashCount:        0,
			expectedTPRate:    0.0,
			expectedFPRate:    0.0,
			expectedCrashRate: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pe := &PatternEffectiveness{
				TruePositives:   tt.truePositives,
				FalsePositives:  tt.falsePositives,
				TotalDetections: tt.totalDetections,
				CrashCount:      tt.crashCount,
			}

			pe.CalculateRates()

			if pe.TruePositiveRate != tt.expectedTPRate {
				t.Errorf("TruePositiveRate = %v, want %v", pe.TruePositiveRate, tt.expectedTPRate)
			}
			if pe.FalsePositiveRate != tt.expectedFPRate {
				t.Errorf("FalsePositiveRate = %v, want %v", pe.FalsePositiveRate, tt.expectedFPRate)
			}
			if pe.CrashRate != tt.expectedCrashRate {
				t.Errorf("CrashRate = %v, want %v", pe.CrashRate, tt.expectedCrashRate)
			}
		})
	}
}

// TestTierClassification tests tier classification logic (Requirements 1.3)
func TestTierClassification(t *testing.T) {
	pea := NewPatternEffectivenessAnalyzer()

	tests := []struct {
		name         string
		tpRate       float64
		fpRate       float64
		crashRate    float64
		tp           int
		fp           int
		expectedTier PatternTier
	}{
		{
			name:         "IMBA tier - high success, low FP",
			tpRate:       0.85,
			fpRate:       0.08,
			crashRate:    0.02,
			tp:           85,
			fp:           8,
			expectedTier: TierIMBA,
		},
		{
			name:         "Normal tier - acceptable metrics",
			tpRate:       0.70,
			fpRate:       0.20,
			crashRate:    0.05,
			tp:           70,
			fp:           20,
			expectedTier: TierNormal,
		},
		{
			name:         "Trash tier - low success rate",
			tpRate:       0.50,
			fpRate:       0.30,
			crashRate:    0.08,
			tp:           50,
			fp:           30,
			expectedTier: TierTrash,
		},
		{
			name:         "Trash tier - high FP rate",
			tpRate:       0.55,
			fpRate:       0.45,
			crashRate:    0.03,
			tp:           55,
			fp:           45,
			expectedTier: TierTrash,
		},
		{
			name:         "Trash tier - high crash rate",
			tpRate:       0.75,
			fpRate:       0.15,
			crashRate:    0.12,
			tp:           75,
			fp:           15,
			expectedTier: TierTrash,
		},
		{
			name:         "Unknown tier - insufficient labeled observations",
			tpRate:       0.83,
			fpRate:       0.17,
			crashRate:    0.0,
			tp:           5,
			fp:           1,
			expectedTier: TierUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pe := &PatternEffectiveness{
				TruePositiveRate:  tt.tpRate,
				FalsePositiveRate: tt.fpRate,
				CrashRate:         tt.crashRate,
				TruePositives:     tt.tp,
				FalsePositives:    tt.fp,
			}

			tier, reason := pea.classifyTier(pe)

			if tier != tt.expectedTier {
				t.Errorf("Tier = %v, want %v (reason: %s)", tier, tt.expectedTier, reason)
			}

			// Verify reason is non-empty (Requirements 1.5)
			if tier == TierTrash && reason == "" {
				t.Error("Trash tier must have non-empty reason")
			}
		})
	}
}

// TestAnalyzeAll tests analyzing all patterns (Requirements 1.1)
func TestAnalyzeAll(t *testing.T) {
	pea := NewPatternEffectivenessAnalyzer()

	results := pea.AnalyzeAll()

	// Should analyze all 90 patterns
	if len(results) != 90 {
		t.Errorf("AnalyzeAll returned %d patterns, want 90", len(results))
	}

	// Each pattern should have effectiveness data
	for patternID, effectiveness := range results {
		if effectiveness.PatternID != patternID {
			t.Errorf("Pattern ID mismatch: %s != %s", effectiveness.PatternID, patternID)
		}

		// Rates should be in valid range [0, 1]
		if effectiveness.TruePositiveRate < 0 || effectiveness.TruePositiveRate > 1 {
			t.Errorf("Invalid TruePositiveRate for %s: %v", patternID, effectiveness.TruePositiveRate)
		}
		if effectiveness.FalsePositiveRate < 0 || effectiveness.FalsePositiveRate > 1 {
			t.Errorf("Invalid FalsePositiveRate for %s: %v", patternID, effectiveness.FalsePositiveRate)
		}

		// Tier should be set
		if effectiveness.Tier == "" {
			t.Errorf("Tier not set for pattern %s", patternID)
		}

		// Trash tier must have reason (Requirements 1.5)
		if effectiveness.Tier == TierTrash && effectiveness.TierReason == "" {
			t.Errorf("Trash tier pattern %s missing reason", patternID)
		}
	}
}

// TestGenerateReport tests report generation (Requirements 1.4)
func TestGenerateReport(t *testing.T) {
	pea := NewPatternEffectivenessAnalyzer()

	report := pea.GenerateReport()

	// Report should have all patterns
	if report.TotalPatterns != 90 {
		t.Errorf("Report TotalPatterns = %d, want 90", report.TotalPatterns)
	}

	// Without a feedback store every pattern is unmeasured: tier counts plus
	// unknown must sum to the total, and no empirical averages may appear.
	totalCounted := report.IMBACount + report.NormalCount + report.TrashCount + report.UnknownCount
	if totalCounted != report.TotalPatterns {
		t.Errorf("Tier counts sum to %d, want %d", totalCounted, report.TotalPatterns)
	}
	if report.UnknownCount != 90 {
		t.Errorf("UnknownCount = %d, want 90 (no observations)", report.UnknownCount)
	}
	if report.MeasuredPatterns != 0 {
		t.Errorf("MeasuredPatterns = %d, want 0 (no observations)", report.MeasuredPatterns)
	}

	// Each tier list should match count
	if len(report.IMBAPatterns) != report.IMBACount {
		t.Errorf("IMBAPatterns length %d != IMBACount %d", len(report.IMBAPatterns), report.IMBACount)
	}
	if len(report.NormalPatterns) != report.NormalCount {
		t.Errorf("NormalPatterns length %d != NormalCount %d", len(report.NormalPatterns), report.NormalCount)
	}
	if len(report.TrashPatterns) != report.TrashCount {
		t.Errorf("TrashPatterns length %d != TrashCount %d", len(report.TrashPatterns), report.TrashCount)
	}

	// Average rates should be in valid range
	if report.AvgTruePositiveRate < 0 || report.AvgTruePositiveRate > 1 {
		t.Errorf("Invalid AvgTruePositiveRate: %v", report.AvgTruePositiveRate)
	}
	if report.AvgFalsePositiveRate < 0 || report.AvgFalsePositiveRate > 1 {
		t.Errorf("Invalid AvgFalsePositiveRate: %v", report.AvgFalsePositiveRate)
	}
}

// stubFeedbackStore is a deterministic FeedbackStore for tests.
type stubFeedbackStore struct {
	metrics map[string][5]int
}

func (s stubFeedbackStore) GetMetrics(patternID string) (total, tp, fp, crash, apks int, found bool) {
	m, ok := s.metrics[patternID]
	if !ok {
		return 0, 0, 0, 0, 0, false
	}
	return m[0], m[1], m[2], m[3], m[4], true
}

// TestGenerateReportMeasured verifies tiers come from real observations only.
func TestGenerateReportMeasured(t *testing.T) {
	if len(VulnerablePatterns) < 3 {
		t.Skip("need at least 3 patterns")
	}
	ids := []string{VulnerablePatterns[0].ID, VulnerablePatterns[1].ID, VulnerablePatterns[2].ID}
	store := stubFeedbackStore{metrics: map[string][5]int{
		ids[0]: {100, 85, 8, 2, 60},  // 91.4% success -> IMBA
		ids[1]: {100, 70, 20, 5, 40}, // 77.8% success -> NORMAL
		ids[2]: {100, 50, 40, 8, 25}, // 55.6% success -> TRASH
	}}
	pea := NewPatternEffectivenessAnalyzer(store)
	report := pea.GenerateReport()

	if report.MeasuredPatterns != 3 {
		t.Errorf("MeasuredPatterns = %d, want 3", report.MeasuredPatterns)
	}
	if report.IMBACount != 1 || report.NormalCount != 1 || report.TrashCount != 1 {
		t.Errorf("tiers = IMBA:%d NORMAL:%d TRASH:%d, want 1/1/1",
			report.IMBACount, report.NormalCount, report.TrashCount)
	}
	if report.UnknownCount != report.TotalPatterns-3 {
		t.Errorf("UnknownCount = %d, want %d", report.UnknownCount, report.TotalPatterns-3)
	}
	all := pea.AnalyzeAll()
	if all[ids[0]].Tier != TierIMBA || all[ids[1]].Tier != TierNormal || all[ids[2]].Tier != TierTrash {
		t.Errorf("tiers = %s/%s/%s, want elite/normal/trash",
			all[ids[0]].Tier, all[ids[1]].Tier, all[ids[2]].Tier)
	}
	if !all[ids[0]].Measured || all[ids[0]].DataSource != "feedback" {
		t.Errorf("measured pattern not marked measured/feedback: %+v", all[ids[0]])
	}
}

// TestRecommendRemoval tests trash pattern identification (Requirements 16.1)
func TestRecommendRemoval(t *testing.T) {
	pea := NewPatternEffectivenessAnalyzer()

	recommendations := pea.RecommendRemoval()

	// Should return some recommendations (patterns classified as trash)
	if len(recommendations) == 0 {
		t.Log("No patterns recommended for removal (all patterns are effective)")
	}

	// Verify all recommendations are actually trash tier
	allEffectiveness := pea.AnalyzeAll()
	for _, pattern := range recommendations {
		effectiveness, ok := allEffectiveness[pattern.ID]
		if !ok {
			t.Errorf("Recommended pattern %s not found in effectiveness data", pattern.ID)
			continue
		}

		if effectiveness.Tier != TierTrash {
			t.Errorf("Recommended pattern %s has tier %s, want %s", pattern.ID, effectiveness.Tier, TierTrash)
		}
	}
}

// TestFormatReport tests report formatting
func TestFormatReport(t *testing.T) {
	pea := NewPatternEffectivenessAnalyzer()
	report := pea.GenerateReport()

	formatted := FormatReport(report)

	// Report should contain the header and the honest no-data statement
	for _, section := range []string{
		"PATTERN EFFECTIVENESS ANALYSIS REPORT",
		"Total Patterns Analyzed",
		"No measured outcomes",
	} {
		if !strings.Contains(formatted, section) {
			t.Errorf("Report missing section: %s", section)
		}
	}

	// Without measurements there must be no empirical tier distribution
	for _, section := range []string{"TIER DISTRIBUTION", "AVERAGE METRICS"} {
		if strings.Contains(formatted, section) {
			t.Errorf("Report must not show %q without measured outcomes", section)
		}
	}
}

// TestFormatReportMeasured tests formatting with real observations.
func TestFormatReportMeasured(t *testing.T) {
	if len(VulnerablePatterns) < 3 {
		t.Skip("need at least 3 patterns")
	}
	ids := []string{VulnerablePatterns[0].ID, VulnerablePatterns[1].ID, VulnerablePatterns[2].ID}
	store := stubFeedbackStore{metrics: map[string][5]int{
		ids[0]: {100, 85, 8, 2, 60},
		ids[1]: {100, 70, 20, 5, 40},
		ids[2]: {100, 50, 40, 8, 25},
	}}
	pea := NewPatternEffectivenessAnalyzer(store)
	formatted := FormatReport(pea.GenerateReport())

	for _, section := range []string{
		"PATTERN EFFECTIVENESS ANALYSIS REPORT",
		"TIER DISTRIBUTION",
		"AVERAGE METRICS",
		"Total Patterns Analyzed",
		"IMBA",
		"NORMAL",
		"TRASH",
	} {
		if !strings.Contains(formatted, section) {
			t.Errorf("Report missing section: %s", section)
		}
	}
}
