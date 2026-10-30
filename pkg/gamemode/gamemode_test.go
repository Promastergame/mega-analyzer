package gamemode

import (
	"path/filepath"
	"strings"
	"testing"

	"mega-analyzer/pkg/ml"
)

// ═══════════════════════════════════════════════════════════════════════════════
// BASIC UNIT TESTS FOR GAMEMODE COMPONENTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestThreatCalculator(t *testing.T) {
	calc := NewThreatCalculator()

	// Test with empty patch points
	result := calc.CalculateThreatScore([]ml.PatchPoint{}, nil)
	if result.TotalScore != 0 {
		t.Errorf("Expected 0 threat score for empty patch points, got %.2f", result.TotalScore)
	}

	// Test with single high-risk patch point
	patchPoints := []ml.PatchPoint{
		{
			RiskScore:     100.0,
			RiskLevel:     ml.RiskClassHigh,
			Category:      ml.PatchCatBilling,
			IsLibraryCode: false,
		},
	}

	result = calc.CalculateThreatScore(patchPoints, nil)
	if result.TotalScore <= 0 {
		t.Errorf("Expected positive threat score, got %.2f", result.TotalScore)
	}

	// Test library code penalty
	libraryPatchPoints := []ml.PatchPoint{
		{
			RiskScore:     100.0,
			RiskLevel:     ml.RiskClassHigh,
			Category:      ml.PatchCatBilling,
			IsLibraryCode: true,
		},
	}

	libraryResult := calc.CalculateThreatScore(libraryPatchPoints, nil)
	if libraryResult.TotalScore >= result.TotalScore {
		t.Errorf("Expected library code to have lower threat score")
	}
}

func TestXPSystem(t *testing.T) {
	// Create XP system with temporary directory for testing
	tempDir := t.TempDir()
	xpSystem := &DefaultXPSystem{
		dataFile: filepath.Join(tempDir, "xp_data.json"),
		userData: make(map[string]*XPData),
	}

	// Test XP calculation
	breakdown := xpSystem.CalculateXP(100.0, 5, nil, true, true, true)
	if breakdown.StaticXP <= 0 {
		t.Errorf("Expected positive StaticXP, got %d", breakdown.StaticXP)
	}

	// Test level calculation
	level := xpSystem.GetLevel("test_user")
	if level != 1 {
		t.Errorf("Expected level 1 for new user, got %d", level)
	}

	// Test adding XP
	err := xpSystem.AddXP("test_user", XPGainBreakdown{StaticXP: 200})
	if err != nil {
		t.Errorf("Failed to add XP: %v", err)
	}

	// Check if level increased (200 XP should put user at level 2)
	newLevel := xpSystem.GetLevel("test_user")
	if newLevel < 2 {
		t.Errorf("Expected level >= 2 after adding 200 XP, got %d", newLevel)
	}
}

func TestRankSystem(t *testing.T) {
	rankSystem := NewRankSystem()

	// Test rank assignment for low threat
	rank := rankSystem.AssignRank(50.0)
	if rank.Title == "" {
		t.Errorf("Expected valid rank title")
	}

	// Test rank assignment for high threat
	highRank := rankSystem.AssignRank(800.0)
	if highRank.ID <= rank.ID {
		t.Errorf("Expected higher rank ID for higher threat score")
	}

	// Test updating rank
	err := rankSystem.UpdateRank("test_user", highRank)
	if err != nil {
		t.Errorf("Failed to update rank: %v", err)
	}

	// Check current rank
	currentRank := rankSystem.GetCurrentRank("test_user")
	if currentRank.ID != highRank.ID {
		t.Errorf("Expected rank ID %d, got %d", highRank.ID, currentRank.ID)
	}
}

func TestOutputFormatter(t *testing.T) {
	formatter := NewOutputFormatter()

	// Create test game data
	gameData := &GameData{
		ThreatResult: &ThreatResult{
			TotalScore: 500.0,
			CategoryBreakdown: []CategoryBreakdown{
				{Category: "billing", Points: 300.0, Count: 2},
				{Category: "license", Points: 200.0, Count: 1},
			},
		},
		XPData: &XPData{
			TotalXP:      250,
			CurrentLevel: 3,
			XPThreshold:  450,
		},
		RankData: &RankData{
			CurrentRank: DefaultRanks[4], // Threat Analyst
		},
	}

	// Test terminal formatting
	terminalOutput := formatter.FormatResult(nil, gameData)
	if !strings.Contains(terminalOutput, "GAME MODE ACTIVE") {
		t.Errorf("Expected game mode header in terminal output")
	}

	// Test markdown formatting
	markdownOutput := formatter.FormatMarkdown(nil, gameData)
	if !strings.Contains(markdownOutput, "# 🎮 Game Mode Analysis Report") {
		t.Errorf("Expected markdown header in markdown output")
	}

	// Test JSON formatting
	jsonOutput, err := formatter.FormatJSON(nil, gameData)
	if err != nil {
		t.Errorf("Failed to format JSON: %v", err)
	}
	if len(jsonOutput) == 0 {
		t.Errorf("Expected non-empty JSON output")
	}
}
