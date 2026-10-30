package gamemode

import (
	"encoding/json"
	"math/rand"
	"strings"
	"testing"
)

// Property test for output formatter
// **Feature: analyzer-gamemode-upgrade, Property: Output Format Consistency**
// **Validates: Requirements 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7**

func TestOutputFormatter_Properties(t *testing.T) {
	formatter := NewOutputFormatter()

	// Property 1: Output should always be non-empty for valid game data
	t.Run("Property_OutputNonEmpty", func(t *testing.T) {
		for i := 0; i < 50; i++ {
			gameData := generateRandomGameData()
			output := formatter.FormatResult(nil, gameData)

			if output == "" {
				t.Error("Output should not be empty for valid game data")
			}
		}
	})

	// Property 2: Output should contain game mode header
	t.Run("Property_ContainsGameModeHeader", func(t *testing.T) {
		for i := 0; i < 50; i++ {
			gameData := generateRandomGameData()
			output := formatter.FormatResult(nil, gameData)

			if !strings.Contains(output, "GAME MODE") {
				t.Error("Output should contain 'GAME MODE' header")
			}
		}
	})

	// Property 3: Output should contain threat level for valid threat result
	t.Run("Property_ContainsThreatLevel", func(t *testing.T) {
		for i := 0; i < 50; i++ {
			gameData := generateRandomGameData()
			if gameData.ThreatResult == nil {
				continue
			}

			output := formatter.FormatResult(nil, gameData)

			if !strings.Contains(output, "THREAT") {
				t.Error("Output should contain 'THREAT' for valid threat result")
			}
		}
	})

	// Property 4: Output should contain level for valid XP data
	t.Run("Property_ContainsLevel", func(t *testing.T) {
		for i := 0; i < 50; i++ {
			gameData := generateRandomGameData()
			if gameData.XPData == nil {
				continue
			}

			output := formatter.FormatResult(nil, gameData)

			if !strings.Contains(output, "LEVEL") {
				t.Error("Output should contain 'LEVEL' for valid XP data")
			}
		}
	})

	// Property 5: Output should contain rank for valid rank data
	t.Run("Property_ContainsRank", func(t *testing.T) {
		for i := 0; i < 50; i++ {
			gameData := generateRandomGameData()
			if gameData.RankData == nil {
				continue
			}

			output := formatter.FormatResult(nil, gameData)

			if !strings.Contains(output, "RANK") {
				t.Error("Output should contain 'RANK' for valid rank data")
			}
		}
	})

	// Property 6: Markdown output should be valid markdown
	t.Run("Property_MarkdownValid", func(t *testing.T) {
		for i := 0; i < 50; i++ {
			gameData := generateRandomGameData()
			output := formatter.FormatMarkdown(nil, gameData)

			// Should contain markdown headers
			if gameData != nil && !strings.Contains(output, "#") {
				t.Error("Markdown output should contain headers")
			}
		}
	})

	// Property 7: JSON output should be valid JSON
	t.Run("Property_JSONValid", func(t *testing.T) {
		for i := 0; i < 50; i++ {
			gameData := generateRandomGameData()
			output, err := formatter.FormatJSON(nil, gameData)

			if err != nil {
				t.Errorf("JSON formatting should not error: %v", err)
				continue
			}

			// Should be valid JSON
			var parsed interface{}
			if err := json.Unmarshal(output, &parsed); err != nil {
				t.Errorf("Output should be valid JSON: %v", err)
			}
		}
	})

	// Property 8: Output should handle nil game data gracefully
	t.Run("Property_HandlesNilGameData", func(t *testing.T) {
		output := formatter.FormatResult(nil, nil)

		if output == "" {
			t.Error("Output should handle nil game data gracefully")
		}

		// Should contain some indication of no data
		if !strings.Contains(output, "No game mode data") && !strings.Contains(output, "GAME MODE") {
			t.Error("Output should indicate no game data or show game mode header")
		}
	})

	// Property 9: Output should contain emojis for visual appeal
	t.Run("Property_ContainsEmojis", func(t *testing.T) {
		for i := 0; i < 50; i++ {
			gameData := generateRandomGameData()
			output := formatter.FormatResult(nil, gameData)

			// Should contain at least one emoji
			emojis := []string{"🎮", "🔥", "⚠️", "📊", "📋", "🏆", "⭐", "📝", "📈", "🎯"}
			hasEmoji := false
			for _, emoji := range emojis {
				if strings.Contains(output, emoji) {
					hasEmoji = true
					break
				}
			}

			if !hasEmoji {
				t.Error("Output should contain emojis for visual appeal")
			}
		}
	})

	// Property 10: Category breakdown should be formatted correctly
	t.Run("Property_CategoryBreakdownFormatted", func(t *testing.T) {
		gameData := &GameData{
			ThreatResult: &ThreatResult{
				TotalScore: 500.0,
				CategoryBreakdown: []CategoryBreakdown{
					{Category: "billing", Points: 200.0, Count: 2},
					{Category: "license", Points: 150.0, Count: 1},
					{Category: "tamper", Points: 150.0, Count: 1},
				},
			},
		}

		output := formatter.FormatResult(nil, gameData)

		// Should contain category names
		if !strings.Contains(strings.ToLower(output), "billing") {
			t.Error("Output should contain 'billing' category")
		}
		if !strings.Contains(strings.ToLower(output), "license") {
			t.Error("Output should contain 'license' category")
		}
	})
}

// generateRandomGameData generates random game data for testing
func generateRandomGameData() *GameData {
	// Randomly decide which components to include
	includeThreat := randomBool()
	includeXP := randomBool()
	includeRank := randomBool()

	gameData := &GameData{}

	if includeThreat {
		gameData.ThreatResult = &ThreatResult{
			TotalScore: randomFloat(0, 1000),
			ByCategory: map[string]float64{
				"billing": randomFloat(0, 300),
				"license": randomFloat(0, 200),
			},
			DiversityBonus: randomFloat(0, 0.5),
		}
	}

	if includeXP {
		gameData.XPData = &XPData{
			TotalXP:      randomInt(0, 10000),
			CurrentLevel: randomInt(1, 20),
			XPThreshold:  randomInt(100, 5000),
			LastUpdated:  "2026-04-18T12:00:00Z",
		}
	}

	if includeRank {
		gameData.RankData = &RankData{
			CurrentRank: Rank{
				ID:          randomInt(1, 8),
				Title:       "Test Rank",
				Emoji:       "🎮",
				MinThreat:   float64(randomInt(0, 700)),
				Description: "Test description",
			},
		}
	}

	return gameData
}

// randomBool returns a random boolean
func randomBool() bool {
	return randomInt(0, 1) == 1
}

// randomInt returns a random integer between min and max
func randomInt(min, max int) int {
	if max <= min {
		return min
	}
	return min + int(randomFloat01()*float64(max-min))
}

// randomFloat returns a random float between min and max
func randomFloat(min, max float64) float64 {
	if max <= min {
		return min
	}
	return min + (max-min)*randomFloat01()
}

// randomFloat01 returns a random float between 0 and 1
func randomFloat01() float64 {
	// Use math/rand instead of calling randomInt to avoid recursion
	return float64(rand.Intn(10000)) / 10000.0
}
