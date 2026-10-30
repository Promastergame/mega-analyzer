package gamemode

import (
	"encoding/json"
	"fmt"
	"strings"

	"mega-analyzer/pkg/internal/types"
)

// ═══════════════════════════════════════════════════════════════════════════════
// OUTPUT FORMATTER IMPLEMENTATION
// ═══════════════════════════════════════════════════════════════════════════════

type DefaultOutputFormatter struct{}

func NewOutputFormatter() OutputFormatter {
	return &DefaultOutputFormatter{}
}

func (of *DefaultOutputFormatter) FormatResult(result *types.AnalysisResult, gameData *GameData) string {
	var output strings.Builder

	// Game mode header
	output.WriteString("\n")
	output.WriteString("  ╔══════════════════════════════════════════╗\n")
	output.WriteString("  ║           🎮 GAME MODE ACTIVE            ║\n")
	output.WriteString("  ║        Threat Analysis & Scoring         ║\n")
	output.WriteString("  ╚══════════════════════════════════════════╝\n")
	output.WriteString("\n")

	if gameData == nil {
		output.WriteString("  No game mode data available\n")
		return output.String()
	}

	// Threat level display
	if gameData.ThreatResult != nil {
		threatEmoji := of.getThreatEmoji(gameData.ThreatResult.TotalScore)
		output.WriteString(fmt.Sprintf("  %s THREAT LEVEL: %.0f/1000\n",
			threatEmoji, gameData.ThreatResult.TotalScore))

		if gameData.ThreatResult.DiversityBonus > 0 {
			output.WriteString(fmt.Sprintf("  🎯 Diversity Bonus: +%.1f%%\n",
				gameData.ThreatResult.DiversityBonus*100))
		}
		output.WriteString("\n")
	}

	// XP and Level display
	if gameData.XPData != nil {
		output.WriteString(fmt.Sprintf("  🏆 LEVEL %d\n", gameData.XPData.CurrentLevel))
		output.WriteString(fmt.Sprintf("  ⭐ Total XP: %d\n", gameData.XPData.TotalXP))

		if gameData.XPData.CurrentLevel < len(DefaultLevelThresholds) {
			nextThreshold := gameData.XPData.XPThreshold
			progress := float64(gameData.XPData.TotalXP) / float64(nextThreshold) * 100
			output.WriteString(fmt.Sprintf("  📊 Progress to Level %d: %.1f%% (%d/%d XP)\n",
				gameData.XPData.CurrentLevel+1, progress, gameData.XPData.TotalXP, nextThreshold))
		}
		output.WriteString("\n")
	}

	// Rank display
	if gameData.RankData != nil {
		rank := gameData.RankData.CurrentRank
		output.WriteString(fmt.Sprintf("  %s RANK: %s\n", rank.Emoji, rank.Title))
		output.WriteString(fmt.Sprintf("  📝 %s\n", rank.Description))

		if len(gameData.RankData.RankHistory) > 0 {
			output.WriteString(fmt.Sprintf("  📈 Rank Progression: %d achievements\n",
				len(gameData.RankData.RankHistory)))
		}
		output.WriteString("\n")
	}

	// Category breakdown
	if gameData.ThreatResult != nil && len(gameData.ThreatResult.CategoryBreakdown) > 0 {
		output.WriteString("  📊 THREAT BREAKDOWN BY CATEGORY\n")
		output.WriteString("  ════════════════════════════════\n")

		for _, category := range gameData.ThreatResult.CategoryBreakdown {
			categoryEmoji := of.getCategoryEmoji(category.Category)
			output.WriteString(fmt.Sprintf("  %s %-15s: %.0f points (%d findings)\n",
				categoryEmoji, strings.Title(category.Category), category.Points, category.Count))
		}
		output.WriteString("\n")
	}

	return output.String()
}

func (of *DefaultOutputFormatter) FormatMarkdown(result *types.AnalysisResult, gameData *GameData) string {
	var output strings.Builder

	output.WriteString("# 🎮 Game Mode Analysis Report\n\n")

	if gameData == nil {
		output.WriteString("No game mode data available.\n")
		return output.String()
	}

	// Threat Analysis
	if gameData.ThreatResult != nil {
		threatEmoji := of.getThreatEmoji(gameData.ThreatResult.TotalScore)
		output.WriteString(fmt.Sprintf("## %s Threat Analysis\n\n", threatEmoji))
		output.WriteString(fmt.Sprintf("**Threat Score:** %.0f/1000\n\n", gameData.ThreatResult.TotalScore))

		if gameData.ThreatResult.DiversityBonus > 0 {
			output.WriteString(fmt.Sprintf("**Diversity Bonus:** +%.1f%%\n\n",
				gameData.ThreatResult.DiversityBonus*100))
		}

		// Category breakdown table
		if len(gameData.ThreatResult.CategoryBreakdown) > 0 {
			output.WriteString("### Category Breakdown\n\n")
			output.WriteString("| Category | Points | Findings | Weight |\n")
			output.WriteString("|----------|--------|----------|--------|\n")

			for _, category := range gameData.ThreatResult.CategoryBreakdown {
				categoryEmoji := of.getCategoryEmoji(category.Category)
				output.WriteString(fmt.Sprintf("| %s %s | %.0f | %d | %.1fx |\n",
					categoryEmoji, strings.Title(category.Category),
					category.Points, category.Count, category.Weight))
			}
			output.WriteString("\n")
		}
	}

	// Player Progress
	output.WriteString("## 🏆 Player Progress\n\n")

	if gameData.XPData != nil {
		output.WriteString(fmt.Sprintf("**Level:** %d\n", gameData.XPData.CurrentLevel))
		output.WriteString(fmt.Sprintf("**Total XP:** %d\n", gameData.XPData.TotalXP))

		if gameData.XPData.CurrentLevel < len(DefaultLevelThresholds) {
			nextThreshold := gameData.XPData.XPThreshold
			progress := float64(gameData.XPData.TotalXP) / float64(nextThreshold) * 100
			output.WriteString(fmt.Sprintf("**Progress to Next Level:** %.1f%% (%d/%d XP)\n",
				progress, gameData.XPData.TotalXP, nextThreshold))
		}
		output.WriteString("\n")
	}

	if gameData.RankData != nil {
		rank := gameData.RankData.CurrentRank
		output.WriteString(fmt.Sprintf("**Current Rank:** %s %s\n", rank.Emoji, rank.Title))
		output.WriteString(fmt.Sprintf("**Description:** %s\n", rank.Description))

		if len(gameData.RankData.RankHistory) > 0 {
			output.WriteString(fmt.Sprintf("**Achievements:** %d rank progressions\n",
				len(gameData.RankData.RankHistory)))
		}
		output.WriteString("\n")
	}

	return output.String()
}

func (of *DefaultOutputFormatter) FormatJSON(result *types.AnalysisResult, gameData *GameData) ([]byte, error) {
	// Create enhanced result with game mode data
	enhancedResult := struct {
		*types.AnalysisResult
		GameData *GameData `json:"game_data,omitempty"`
	}{
		AnalysisResult: result,
		GameData:       gameData,
	}

	return json.MarshalIndent(enhancedResult, "", "  ")
}

// Helper functions for emojis and formatting

func (of *DefaultOutputFormatter) getThreatEmoji(score float64) string {
	switch {
	case score >= 700:
		return "🔥" // Critical
	case score >= 500:
		return "⚠️" // High
	case score >= 300:
		return "📊" // Medium
	default:
		return "📋" // Low
	}
}

func (of *DefaultOutputFormatter) getCategoryEmoji(category string) string {
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
	}

	if emoji, exists := emojis[category]; exists {
		return emoji
	}
	return "🔍" // Default
}
