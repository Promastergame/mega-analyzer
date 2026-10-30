package gamemode

import (
	"testing"

	"mega-analyzer/pkg/ml"
)

// TestEpicOutputFormatter_FormatEpicResult тестирует эпичный вывод
func TestEpicOutputFormatter_FormatEpicResult(t *testing.T) {
	formatter := NewEpicOutputFormatter()

	// Create test game data
	gameData := &GameData{
		ThreatResult: &ThreatResult{
			TotalScore: 750.0,
			ByCategory: map[string]float64{
				"billing": 300.0,
				"license": 250.0,
				"tamper":  200.0,
			},
			CategoryBreakdown: []CategoryBreakdown{
				{Category: "billing", Points: 300.0, Count: 3},
				{Category: "license", Points: 250.0, Count: 2},
				{Category: "tamper", Points: 200.0, Count: 1},
			},
			DiversityBonus: 0.2,
		},
		XPData: &XPData{
			TotalXP:      4200,
			CurrentLevel: 12,
			XPThreshold:  5000,
			LastUpdated:  "2026-04-18T12:00:00Z",
			StaticLevel:  12,
		},
		XPGained: 500,
		XPGainedBreakdown: XPGainBreakdown{
			StaticXP: 500,
		},
		RankData: &RankData{
			CurrentRank: Rank{
				ID:          8,
				Title:       "BOSS MALWARE",
				Emoji:       "🔴",
				MinThreat:   700,
				Description: "Master of malware analysis",
			},
			RankHistory: []RankHistory{
				{Rank: Rank{ID: 7, Title: "Malware Hunter", Emoji: "🎯"}},
			},
		},
	}

	// Create test prediction
	prediction := &ml.PatchPrediction{
		HighRisk: []ml.PatchPoint{
			{Category: ml.PatchCatBilling, RiskLevel: ml.RiskClassHigh},
			{Category: ml.PatchCatLicense, RiskLevel: ml.RiskClassHigh},
			{Category: ml.PatchCatTamper, RiskLevel: ml.RiskClassHigh},
		},
		MediumRisk: []ml.PatchPoint{
			{Category: ml.PatchCatPremium, RiskLevel: ml.RiskClassMedium},
		},
		LowRisk: []ml.PatchPoint{
			{Category: ml.PatchCatAds, RiskLevel: ml.RiskClassLow},
		},
	}

	// Format epic result
	output := formatter.FormatEpicResult("malware.apk", gameData, prediction)

	// Verify output contains expected elements
	if output == "" {
		t.Error("Output should not be empty")
	}

	// Check for epic elements
	expectedElements := []string{
		"🔥 ANALYSIS COMPLETE 🔥",
		"TARGET:",
		"malware.apk",
		"RANK:",
		"BOSS MALWARE",
		"LEVEL:",
		"XP GAINED:",
		"COMBO:",
		"CRITICAL FINDINGS",
		"THREAT METER:",
		"BREAKDOWN:",
		"ACHIEVEMENT UNLOCKED",
		"GAME MODE ACTIVE",
	}

	for _, elem := range expectedElements {
		if !contains(output, elem) {
			t.Errorf("Output should contain '%s'", elem)
		}
	}

	// Print the output for visual inspection
	t.Logf("\n%s", output)
}

// TestEpicOutputFormatter_ThreatBar тестирует создание threat bar
func TestEpicOutputFormatter_ThreatBar(t *testing.T) {
	formatter := NewEpicOutputFormatter()

	testCases := []struct {
		name     string
		score    float64
		expected string
	}{
		{
			name:     "Critical threat",
			score:    750.0,
			expected: "[",
		},
		{
			name:     "High threat",
			score:    550.0,
			expected: "[",
		},
		{
			name:     "Medium threat",
			score:    350.0,
			expected: "[",
		},
		{
			name:     "Low threat",
			score:    50.0,
			expected: "[",
		},
		{
			name:     "Zero threat",
			score:    0.0,
			expected: "[                    ]",
		},
		{
			name:     "Max threat",
			score:    1000.0,
			expected: "[",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			bar := formatter.createThreatBar(tc.score)
			if bar == "" {
				t.Error("Bar should not be empty")
			}
			if !contains(bar, tc.expected) {
				t.Errorf("Bar should contain '%s', got '%s'", tc.expected, bar)
			}
		})
	}
}

// TestEpicOutputFormatter_MiniBar тестирует создание mini bar
func TestEpicOutputFormatter_MiniBar(t *testing.T) {
	formatter := NewEpicOutputFormatter()

	testCases := []struct {
		name  string
		value float64
		max   float64
	}{
		{"Half full", 50.0, 100.0},
		{"Full", 100.0, 100.0},
		{"Empty", 0.0, 100.0},
		{"Over full", 150.0, 100.0},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			bar := formatter.createMiniBar(tc.value, tc.max)
			if bar == "" {
				t.Error("Bar should not be empty")
			}
			if !contains(bar, "[") || !contains(bar, "]") {
				t.Errorf("Bar should contain brackets, got '%s'", bar)
			}
		})
	}
}

// TestEpicOutputFormatter_EpicQuotes тестирует эпичные цитаты
func TestEpicOutputFormatter_EpicQuotes(t *testing.T) {
	formatter := NewEpicOutputFormatter()

	testCases := []struct {
		name            string
		threatScore     float64
		expectedInQuote string
	}{
		{"Critical", 750.0, "nasty"},
		{"High", 550.0, "dangerous"},
		{"Medium", 350.0, "suspicious"},
		{"Low", 150.0, "potential"},
		{"Minimal", 50.0, "clean"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gameData := &GameData{
				ThreatResult: &ThreatResult{
					TotalScore: tc.threatScore,
				},
			}

			quote := formatter.getEpicQuote(gameData)
			if quote == "" {
				t.Error("Quote should not be empty")
			}
			if !contains(quote, tc.expectedInQuote) {
				t.Errorf("Quote should contain '%s', got '%s'", tc.expectedInQuote, quote)
			}
		})
	}
}

// TestEpicGameModeManager тестирует EpicGameModeManager
func TestEpicGameModeManager(t *testing.T) {
	manager := NewEpicGameModeManager("test_user")

	if !manager.IsEnabled() {
		t.Error("Manager should be enabled by default")
	}

	if manager.epicFormatter == nil {
		t.Error("Epic formatter should be initialized")
	}
}

// Helper function to check if string contains substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
