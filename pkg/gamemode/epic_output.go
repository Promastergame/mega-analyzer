package gamemode

import (
	"fmt"
	"strings"

	"mega-analyzer/pkg/ml"
)

// ═══════════════════════════════════════════════════════════════════════════════
// EPIC GAME MODE OUTPUT - "ВАУ-МОМЕНТ" 🎮
// ═══════════════════════════════════════════════════════════════════════════════

// EpicOutputFormatter creates epic game-style output
type EpicOutputFormatter struct {
	animator *TextAnimator
	caps     ColorCaps
}

// NewEpicOutputFormatter creates a new epic output formatter
func NewEpicOutputFormatter() *EpicOutputFormatter {
	caps := DetectColorCaps()
	return &EpicOutputFormatter{
		animator: NewTextAnimatorWithCaps(caps),
		caps:     caps,
	}
}

// FormatEpicResult creates an epic game-style result screen
func (eof *EpicOutputFormatter) FormatEpicResult(apkName string, gameData *GameData, prediction *ml.PatchPrediction) string {
	var output strings.Builder

	// Epic header with animation effect
	output.WriteString("\n")
	output.WriteString(eof.animator.DoubleLine(60))
	output.WriteString("  🔥 ANALYSIS COMPLETE 🔥\n")
	output.WriteString(eof.animator.DoubleLine(60))
	output.WriteString("\n")

	// Target info
	output.WriteString(fmt.Sprintf("  📱 TARGET: %s\n", eof.animator.Highlight(apkName)))
	output.WriteString("\n")

	// Rank display with epic styling
	if gameData != nil && gameData.RankData != nil {
		rank := gameData.RankData.CurrentRank
		output.WriteString(fmt.Sprintf("  %s RANK: %s\n",
			eof.animator.Pulse(rank.Emoji),
			eof.animator.Rainbow(rank.Title)))
	}

	// Level and XP
	if gameData != nil && gameData.XPData != nil {
		output.WriteString("  ⭐ EXPERIENCE PROGRESS:\n")

		// 1. Static Analysis XP
		if gameData.XPGainedBreakdown.StaticXP > 0 {
			staticLevel := gameData.XPData.StaticLevel
			if staticLevel == 0 {
				staticLevel = 1
			}
			output.WriteString(fmt.Sprintf("     📡 Static Lvl %d (+%d XP)\n", staticLevel, gameData.XPGainedBreakdown.StaticXP))
		}

		// 2. Patcher XP
		if gameData.XPGainedBreakdown.PatcherXP > 0 {
			patcherLevel := gameData.XPData.PatcherLevel
			if patcherLevel == 0 {
				patcherLevel = 1
			}
			output.WriteString(fmt.Sprintf("     🛠️ Patcher Lvl %d (+%d XP)\n", patcherLevel, gameData.XPGainedBreakdown.PatcherXP))
		}

		// 3. ML Feedback XP
		if gameData.XPGainedBreakdown.FeedbackXP > 0 {
			feedbackLevel := gameData.XPData.FeedbackLevel
			if feedbackLevel == 0 {
				feedbackLevel = 1
			}
			output.WriteString(fmt.Sprintf("     🧠 Feedback Lvl %d (+%d XP)\n", feedbackLevel, gameData.XPGainedBreakdown.FeedbackXP))
		}

		output.WriteString(fmt.Sprintf("  👑 OVERALL LEVEL: %d (XP GAINED: +%d)\n", gameData.XPData.CurrentLevel, gameData.XPGained))
	}
	output.WriteString("\n")

	// Combo system
	if prediction != nil {
		combo := eof.calculateCombo(prediction)
		output.WriteString(fmt.Sprintf("  ⚡ COMBO: %d THREATS DETECTED\n", combo))
	}

	// Critical findings
	if prediction != nil && len(prediction.HighRisk) > 0 {
		output.WriteString("\n")
		output.WriteString(eof.animator.SingleLine(60))
		output.WriteString("  💀 CRITICAL FINDINGS:\n")
		output.WriteString(eof.animator.SingleLine(60))

		for i, point := range prediction.HighRisk {
			if i >= 3 { // Show top 3
				break
			}
			emoji := eof.getCategoryEmoji(string(point.Category))
			output.WriteString(fmt.Sprintf("  %s %s\n", emoji, strings.ToUpper(string(point.Category))))
		}
	}

	// Epic quote
	output.WriteString("\n")
	output.WriteString(eof.animator.SingleLine(60))
	output.WriteString(fmt.Sprintf("  \"%s\"\n", eof.getEpicQuote(gameData)))
	output.WriteString(eof.animator.SingleLine(60))
	output.WriteString("\n")

	// Threat breakdown with colored bar
	if gameData != nil && gameData.ThreatResult != nil {
		output.WriteString("\n")
		output.WriteString("  📊 THREAT METER:\n")
		output.WriteString("  ")
		threatBar := ThreatBar(gameData.ThreatResult.TotalScore, eof.caps)
		output.WriteString(threatBar)
		output.WriteString(fmt.Sprintf(" %.0f/1000\n", gameData.ThreatResult.TotalScore))
		output.WriteString("\n")
	}

	// Category breakdown with mini-bars
	if gameData != nil && gameData.ThreatResult != nil && len(gameData.ThreatResult.CategoryBreakdown) > 0 {
		output.WriteString("  🎯 BREAKDOWN:\n")
		for _, cat := range gameData.ThreatResult.CategoryBreakdown {
			emoji := eof.getCategoryEmoji(cat.Category)
			miniBar := eof.createMiniBar(cat.Points, 100.0)
			output.WriteString(fmt.Sprintf("  %s %-12s %s %d\n",
				emoji, strings.Title(cat.Category), miniBar, cat.Count))
		}
	}

	// Achievement unlocked
	if gameData != nil && gameData.RankData != nil {
		if len(gameData.RankData.RankHistory) > 0 {
			output.WriteString("\n")
			output.WriteString("  🏆 ACHIEVEMENT UNLOCKED!\n")
			output.WriteString(fmt.Sprintf("     %s %s\n",
				gameData.RankData.CurrentRank.Emoji,
				gameData.RankData.CurrentRank.Title))
		}
	}

	// Badges unlocked
	if gameData != nil && len(gameData.UnlockedBadges) > 0 {
		output.WriteString("\n")
		output.WriteString("  🎖️ NEW BADGES UNLOCKED!\n")
		for _, badgeID := range gameData.UnlockedBadges {
			if meta, exists := BadgeCatalog[badgeID]; exists {
				output.WriteString(fmt.Sprintf("     %s %s: %s\n",
					meta.Emoji,
					eof.animator.Rainbow(meta.Title),
					meta.Description))
			}
		}
	}

	// Footer
	output.WriteString("\n")
	output.WriteString(eof.animator.DoubleLine(60))
	output.WriteString("  🎮 GAME MODE ACTIVE - KEEP HUNTING! 🎮\n")
	output.WriteString(eof.animator.DoubleLine(60))
	output.WriteString("\n")

	return output.String()
}

// calculateXPGained calculates XP gained from the analysis
func (eof *EpicOutputFormatter) calculateXPGained(gameData *GameData) int {
	if gameData == nil || gameData.ThreatResult == nil {
		return 0
	}

	// Base XP + threat score bonus
	baseXP := 50
	threatBonus := int(gameData.ThreatResult.TotalScore * 0.5)

	return baseXP + threatBonus
}

// calculateCombo calculates the combo count
func (eof *EpicOutputFormatter) calculateCombo(prediction *ml.PatchPrediction) int {
	if prediction == nil {
		return 0
	}

	return len(prediction.HighRisk) + len(prediction.MediumRisk) + len(prediction.LowRisk)
}

// getCategoryEmoji returns emoji for a category
func (eof *EpicOutputFormatter) getCategoryEmoji(category string) string {
	emojis := map[string]string{
		"billing":      "💳",
		"license":      "🔐",
		"premium":      "⭐",
		"subscription": "📅",
		"tamper":       "🛡️",
		"drm":          "🔒",
		"currency":     "💰",
		"server_auth":  "🌐",
		"ads":          "📺",
		"feature_gate": "🚪",
		"installer":    "📦",
		"sast":         "🚨",
	}

	if emoji, exists := emojis[strings.ToLower(category)]; exists {
		return emoji
	}
	return "🔍"
}

// getEpicQuote returns an epic quote based on threat level
func (eof *EpicOutputFormatter) getEpicQuote(gameData *GameData) string {
	if gameData == nil || gameData.ThreatResult == nil {
		return "Ready to hunt some malware..."
	}

	score := gameData.ThreatResult.TotalScore

	// Check from highest to lowest
	if score >= 700 {
		return "this thing is nasty..."
	} else if score >= 500 {
		return "dangerous malware found!"
	} else if score >= 300 {
		return "suspicious patterns detected"
	} else if score >= 100 {
		return "potential vulnerabilities found"
	} else {
		return "clean... for now"
	}
}

// createThreatBar creates threat bar string
func (eof *EpicOutputFormatter) createThreatBar(score float64) string {
	return ThreatBar(score, eof.caps)
}

// createMiniBar creates a mini bar progress indicator
func (eof *EpicOutputFormatter) createMiniBar(value float64, max float64) string {
	if max <= 0 {
		max = 100.0
	}
	filled := int((value / max) * 10)
	if filled > 10 {
		filled = 10
	}
	if filled < 0 {
		filled = 0
	}
	var miniBar strings.Builder
	miniBar.WriteString("[")
	for i := 0; i < 10; i++ {
		if i < filled {
			miniBar.WriteString("●")
		} else {
			miniBar.WriteString("○")
		}
	}
	miniBar.WriteString("]")
	return miniBar.String()
}

// ═══════════════════════════════════════════════════════════════════════════════
// EPIC GAME MODE MANAGER - Enhanced with epic output
// ═══════════════════════════════════════════════════════════════════════════════

// EpicGameModeManager extends GameModeManager with epic output
type EpicGameModeManager struct {
	*GameModeManager
	epicFormatter *EpicOutputFormatter
}

// NewEpicGameModeManager creates a new epic game mode manager
func NewEpicGameModeManager(userID string) *EpicGameModeManager {
	return &EpicGameModeManager{
		GameModeManager: NewGameModeManager(userID),
		epicFormatter:   NewEpicOutputFormatter(),
	}
}

// FormatEpicResult formats the result with epic styling
func (egmm *EpicGameModeManager) FormatEpicResult(apkName string, enhanced *EnhancedAnalysisResult, prediction *ml.PatchPrediction) string {
	if !egmm.enabled || !enhanced.HasGameData() {
		return ""
	}

	return egmm.epicFormatter.FormatEpicResult(apkName, enhanced.GameData, prediction)
}
