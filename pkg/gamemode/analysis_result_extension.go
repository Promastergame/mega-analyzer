package gamemode

import (
	"path/filepath"

	"mega-analyzer/pkg/internal/types"
	"mega-analyzer/pkg/ml"
)

// ═══════════════════════════════════════════════════════════════════════════════
// ANALYSIS RESULT EXTENSION FOR GAME MODE
// ═══════════════════════════════════════════════════════════════════════════════

// EnhancedAnalysisResult extends the standard AnalysisResult with game mode data
type EnhancedAnalysisResult struct {
	*types.AnalysisResult
	GameData *GameData `json:"game_data,omitempty"`
}

// NewEnhancedAnalysisResult creates a new enhanced analysis result
func NewEnhancedAnalysisResult(result *types.AnalysisResult) *EnhancedAnalysisResult {
	return &EnhancedAnalysisResult{
		AnalysisResult: result,
		GameData:       nil,
	}
}

// SetGameData sets the game mode data
func (ear *EnhancedAnalysisResult) SetGameData(gameData *GameData) {
	ear.GameData = gameData
}

// GetGameData returns the game mode data
func (ear *EnhancedAnalysisResult) GetGameData() *GameData {
	return ear.GameData
}

// HasGameData returns true if game mode data is present
func (ear *EnhancedAnalysisResult) HasGameData() bool {
	return ear.GameData != nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// GAME MODE MANAGER - Coordinates all game mode components
// ═══════════════════════════════════════════════════════════════════════════════

// GameModeManager coordinates all game mode components
type GameModeManager struct {
	threatCalculator ThreatCalculator
	xpSystem         XPSystem
	rankSystem       RankSystem
	outputFormatter  OutputFormatter
	badgeSystem      *BadgeSystem
	streakSystem     *StreakSystem
	enabled          bool
	userID           string
}

// NewGameModeManager creates a new game mode manager
func NewGameModeManager(userID string) *GameModeManager {
	return &GameModeManager{
		threatCalculator: NewThreatCalculator(),
		xpSystem:         NewXPSystem(),
		rankSystem:       NewRankSystem(),
		outputFormatter:  NewOutputFormatter(),
		badgeSystem:      NewBadgeSystem(),
		streakSystem:     NewStreakSystem(),
		enabled:          true,
		userID:           userID,
	}
}

// ProcessAnalysis processes an analysis result and adds game mode data
func (gmm *GameModeManager) ProcessAnalysis(
	result *types.AnalysisResult,
	patchPoints []ml.PatchPoint,
	isStatic bool,
	isPatcher bool,
	isFeedback bool,
) *EnhancedAnalysisResult {
	enhanced := NewEnhancedAnalysisResult(result)

	if !gmm.enabled {
		return enhanced
	}

	// Calculate threat score
	threatResult := gmm.threatCalculator.CalculateThreatScore(patchPoints, result)

	// Calculate XP breakdown based on threat score, complexity and analysis result details (file size/extra modules)
	complexity := len(patchPoints)
	breakdown := gmm.xpSystem.CalculateXP(threatResult.TotalScore, complexity, result, isStatic, isPatcher, isFeedback)
	xpGained := breakdown.StaticXP + breakdown.PatcherXP + breakdown.FeedbackXP

	// Add XP to user
	if err := gmm.xpSystem.AddXP(gmm.userID, breakdown); err != nil {
		// Log error but continue
	}

	// Get current XP data
	xpData := gmm.xpSystem.GetXPData(gmm.userID)

	// Assign rank based on threat score
	assignedRank := gmm.rankSystem.AssignRank(threatResult.TotalScore)
	currentRankBefore := gmm.rankSystem.GetCurrentRank(gmm.userID)
	rankPromoted := assignedRank.ID > currentRankBefore.ID
	reachedMaxRank := assignedRank.ID == 8

	if err := gmm.rankSystem.UpdateRank(gmm.userID, assignedRank); err != nil {
		// Log error but continue
	}

	// Get rank data
	currentRank := gmm.rankSystem.GetCurrentRank(gmm.userID)
	rankHistory := gmm.rankSystem.GetRankHistory(gmm.userID)

	rankData := &RankData{
		CurrentRank: currentRank,
		RankHistory: rankHistory,
		HighestRank: currentRank, // This should be calculated properly
	}

	// Record streak run
	streakVal := 0
	if gmm.streakSystem != nil {
		if val, err := gmm.streakSystem.RecordRun(gmm.userID); err == nil {
			streakVal = val
		}
	}

	// Evaluate badges
	var unlockedBadges []BadgeID
	if gmm.badgeSystem != nil {
		uniqueCats := make(map[string]bool)
		for _, m := range result.RuleMatches {
			uniqueCats[string(m.Category)] = true
		}

		ctx := EvalContext{
			UserID:          gmm.userID,
			APKName:         filepath.Base(result.TargetDir),
			ThreatScore:     threatResult.TotalScore,
			PatchPointCount: len(patchPoints),
			UniqueCats:      len(uniqueCats),
			IsStatic:        isStatic,
			IsPatcher:       isPatcher,
			IsFeedback:      isFeedback,
			RankPromoted:    rankPromoted,
			ReachedMaxRank:  reachedMaxRank,
			Prestiged:       false,
			CurrentStreak:   streakVal,
		}
		if ids, err := gmm.badgeSystem.EvalBadges(ctx); err == nil {
			unlockedBadges = ids
		}
	}

	// Create game data
	gameData := &GameData{
		ThreatResult:      &threatResult,
		XPData:            xpData,
		RankData:          rankData,
		XPGained:          xpGained,
		XPGainedBreakdown: breakdown,
		UnlockedBadges:    unlockedBadges,
	}

	enhanced.SetGameData(gameData)
	return enhanced
}

// Enable enables or disables game mode
func (gmm *GameModeManager) Enable(enabled bool) {
	gmm.enabled = enabled
}

// IsEnabled returns true if game mode is enabled
func (gmm *GameModeManager) IsEnabled() bool {
	return gmm.enabled
}

// SetUserID sets the user ID for XP and rank tracking
func (gmm *GameModeManager) SetUserID(userID string) {
	gmm.userID = userID
}

// GetUserID returns the current user ID
func (gmm *GameModeManager) GetUserID() string {
	return gmm.userID
}

// FormatResult formats the enhanced result using the output formatter
func (gmm *GameModeManager) FormatResult(enhanced *EnhancedAnalysisResult) string {
	if !gmm.enabled || !enhanced.HasGameData() {
		return "" // Return empty string if game mode is disabled or no game data
	}

	return gmm.outputFormatter.FormatResult(enhanced.AnalysisResult, enhanced.GameData)
}

// FormatMarkdown formats the enhanced result as markdown
func (gmm *GameModeManager) FormatMarkdown(enhanced *EnhancedAnalysisResult) string {
	if !gmm.enabled || !enhanced.HasGameData() {
		return ""
	}

	return gmm.outputFormatter.FormatMarkdown(enhanced.AnalysisResult, enhanced.GameData)
}

// FormatJSON formats the enhanced result as JSON
func (gmm *GameModeManager) FormatJSON(enhanced *EnhancedAnalysisResult) ([]byte, error) {
	if !gmm.enabled {
		// Return original result without game data using standard JSON marshal
		return gmm.outputFormatter.FormatJSON(enhanced.AnalysisResult, nil)
	}

	return gmm.outputFormatter.FormatJSON(enhanced.AnalysisResult, enhanced.GameData)
}

// GetComponents returns the individual game mode components
func (gmm *GameModeManager) GetComponents() (ThreatCalculator, XPSystem, RankSystem, OutputFormatter) {
	return gmm.threatCalculator, gmm.xpSystem, gmm.rankSystem, gmm.outputFormatter
}

// SetComponents allows setting custom components
func (gmm *GameModeManager) SetComponents(tc ThreatCalculator, xp XPSystem, rs RankSystem, of OutputFormatter) {
	if tc != nil {
		gmm.threatCalculator = tc
	}
	if xp != nil {
		gmm.xpSystem = xp
	}
	if rs != nil {
		gmm.rankSystem = rs
	}
	if of != nil {
		gmm.outputFormatter = of
	}
}
