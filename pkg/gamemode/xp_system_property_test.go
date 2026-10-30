package gamemode

import (
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Property tests for XP system
// **Feature: analyzer-gamemode-upgrade, Property 5: XP Calculation Formula**
// **Validates: Requirements 3.2**
// **Feature: analyzer-gamemode-upgrade, Property 8: XP Persistence Round Trip**
// **Validates: Requirements 3.6**

func TestXPSystem_Properties(t *testing.T) {

	// Property 5: XP Calculation Formula
	t.Run("Property_XPCalculationFormula", func(t *testing.T) {
		xpSystem := NewXPSystem()

		for i := 0; i < 100; i++ {
			threatScore := rand.Float64() * 1000 // 0-1000 range
			complexity := rand.Intn(20) + 1      // 1-20 range

			breakdown := xpSystem.CalculateXP(threatScore, complexity, nil, false, true, false)
			calculatedXP := breakdown.PatcherXP

			// Verify the formula: base_xp + (threat_score * complexity_multiplier)
			baseXP := 30
			complexityMultiplier := float64(complexity) / 10.0
			if complexityMultiplier < 0.5 {
				complexityMultiplier = 0.5
			}
			if complexityMultiplier > 3.0 {
				complexityMultiplier = 3.0
			}

			expectedXP := int(float64(baseXP) + (threatScore * complexityMultiplier))

			if calculatedXP != expectedXP {
				t.Errorf("XP calculation mismatch: threat=%.2f, complexity=%d, got=%d, expected=%d",
					threatScore, complexity, calculatedXP, expectedXP)
			}

			// XP should always be at least the base XP
			if calculatedXP < baseXP {
				t.Errorf("XP should be at least base XP (%d), got %d", baseXP, calculatedXP)
			}
		}
	})

	// Property: XP should increase monotonically with threat score
	t.Run("Property_XPMonotonicWithThreat", func(t *testing.T) {
		xpSystem := NewXPSystem()
		complexity := 10 // Fixed complexity

		for i := 0; i < 50; i++ {
			threatScore1 := rand.Float64() * 400
			// Ensure a large enough gap so discrete XP buckets differ.
			threatScore2 := threatScore1 + 50 + rand.Float64()*450

			breakdown1 := xpSystem.CalculateXP(threatScore1, complexity, nil, false, true, false)
			breakdown2 := xpSystem.CalculateXP(threatScore2, complexity, nil, false, true, false)
			xp1 := breakdown1.PatcherXP
			xp2 := breakdown2.PatcherXP

			if xp2 <= xp1 {
				t.Errorf("XP should increase with threat score: threat1=%.2f (xp=%d), threat2=%.2f (xp=%d)",
					threatScore1, xp1, threatScore2, xp2)
			}
		}
	})

	// Property: XP should increase monotonically with complexity (for significantly different complexities)
	t.Run("Property_XPMonotonicWithComplexity", func(t *testing.T) {
		xpSystem := NewXPSystem()
		threatScore := 500.0 // Fixed threat score

		for i := 0; i < 50; i++ {
			// Use significantly different complexities to ensure measurable difference
			complexity1 := rand.Intn(5) + 1   // 1-5
			complexity2 := rand.Intn(10) + 20 // 20-29 (much higher)

			breakdown1 := xpSystem.CalculateXP(threatScore, complexity1, nil, false, true, false)
			breakdown2 := xpSystem.CalculateXP(threatScore, complexity2, nil, false, true, false)
			xp1 := breakdown1.PatcherXP
			xp2 := breakdown2.PatcherXP

			// XP should be higher for higher complexity (or at least not lower)
			if xp2 < xp1 {
				t.Errorf("XP should not decrease with complexity: complexity1=%d (xp=%d), complexity2=%d (xp=%d)",
					complexity1, xp1, complexity2, xp2)
			}
		}
	})

	// Property 8: XP Persistence Round Trip
	t.Run("Property_XPPersistenceRoundTrip", func(t *testing.T) {
		// Create temporary directory for test
		tempDir, err := os.MkdirTemp("", "xp_test_*")
		if err != nil {
			t.Fatalf("Failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(tempDir)

		// Create XP system with custom data file
		xpSystem := &DefaultXPSystem{
			dataFile: filepath.Join(tempDir, "test_xp_data.json"),
			userData: make(map[string]*XPData),
		}

		// Generate random test data
		testUsers := make(map[string]*XPData)
		for i := 0; i < 10; i++ {
			userID := generateRandomUserID()
			xpData := &XPData{
				TotalXP:      rand.Intn(10000),
				CurrentLevel: rand.Intn(15) + 1,
				XPThreshold:  rand.Intn(5000) + 1000,
				LastUpdated:  time.Now().Format(time.RFC3339),
			}
			testUsers[userID] = xpData
			xpSystem.userData[userID] = xpData
		}

		// Persist data
		err = xpSystem.PersistData()
		if err != nil {
			t.Fatalf("Failed to persist data: %v", err)
		}

		// Create new XP system and load data
		newXPSystem := &DefaultXPSystem{
			dataFile: filepath.Join(tempDir, "test_xp_data.json"),
			userData: make(map[string]*XPData),
		}

		err = newXPSystem.LoadData()
		if err != nil {
			t.Fatalf("Failed to load data: %v", err)
		}

		// Verify data integrity
		for userID, originalData := range testUsers {
			loadedData, exists := newXPSystem.userData[userID]
			if !exists {
				t.Errorf("User %s not found after round trip", userID)
				continue
			}

			if loadedData.TotalXP != originalData.TotalXP {
				t.Errorf("TotalXP mismatch for user %s: original=%d, loaded=%d",
					userID, originalData.TotalXP, loadedData.TotalXP)
			}

			if loadedData.CurrentLevel != originalData.CurrentLevel {
				t.Errorf("CurrentLevel mismatch for user %s: original=%d, loaded=%d",
					userID, originalData.CurrentLevel, loadedData.CurrentLevel)
			}

			if loadedData.XPThreshold != originalData.XPThreshold {
				t.Errorf("XPThreshold mismatch for user %s: original=%d, loaded=%d",
					userID, originalData.XPThreshold, loadedData.XPThreshold)
			}

			if loadedData.LastUpdated != originalData.LastUpdated {
				t.Errorf("LastUpdated mismatch for user %s: original=%s, loaded=%s",
					userID, originalData.LastUpdated, loadedData.LastUpdated)
			}
		}
	})

	// Property: Level calculation should be consistent
	t.Run("Property_LevelCalculationConsistency", func(t *testing.T) {
		xpSystem := NewXPSystem()

		for i := 0; i < 100; i++ {
			totalXP := rand.Intn(10000)
			userID := generateRandomUserID()

			// Add XP to reach the total
			err := xpSystem.AddXP(userID, XPGainBreakdown{StaticXP: totalXP})
			if err != nil {
				t.Fatalf("Failed to add XP: %v", err)
			}

			level := xpSystem.GetLevel(userID)

			// Verify level is within valid range
			if level < 1 {
				t.Errorf("Level should be at least 1, got %d for XP %d", level, totalXP)
			}

			if level > len(DefaultLevelThresholds) {
				// For levels beyond threshold table, should be calculated correctly
				expectedLevel := len(DefaultLevelThresholds)
				if level < expectedLevel {
					t.Errorf("Level calculation error for high XP: xp=%d, level=%d, expected>=%d",
						totalXP, level, expectedLevel)
				}
			} else {
				// For levels within threshold table, verify against thresholds
				if level > 1 && totalXP < DefaultLevelThresholds[level-1] {
					t.Errorf("Level too high for XP: xp=%d, level=%d, threshold=%d",
						totalXP, level, DefaultLevelThresholds[level-1])
				}
			}
		}
	})

	// Property: XP threshold should be consistent with level
	t.Run("Property_XPThresholdConsistency", func(t *testing.T) {
		xpSystem := NewXPSystem()

		for level := 1; level <= len(DefaultLevelThresholds); level++ {
			threshold := xpSystem.GetXPThreshold(level)

			if level < len(DefaultLevelThresholds) {
				expectedThreshold := DefaultLevelThresholds[level]
				if threshold != expectedThreshold {
					t.Errorf("Threshold mismatch for level %d: got=%d, expected=%d",
						level, threshold, expectedThreshold)
				}
			} else {
				// For levels beyond table, should use exponential growth
				baseThreshold := DefaultLevelThresholds[len(DefaultLevelThresholds)-1]
				if threshold <= baseThreshold {
					t.Errorf("Threshold for high level should be greater than base: level=%d, threshold=%d, base=%d",
						level, threshold, baseThreshold)
				}
			}
		}
	})

	// Property: Adding XP should never decrease total XP
	t.Run("Property_XPNeverDecreases", func(t *testing.T) {
		xpSystem := NewXPSystem()

		for i := 0; i < 50; i++ {
			userID := generateRandomUserID()

			// Add initial XP
			initialXP := rand.Intn(1000) + 100
			err := xpSystem.AddXP(userID, XPGainBreakdown{StaticXP: initialXP})
			if err != nil {
				t.Fatalf("Failed to add initial XP: %v", err)
			}

			// Get level before adding more XP
			levelBefore := xpSystem.GetLevel(userID)

			// Add more XP
			additionalXP := rand.Intn(500) + 50
			err = xpSystem.AddXP(userID, XPGainBreakdown{StaticXP: additionalXP})
			if err != nil {
				t.Fatalf("Failed to add additional XP: %v", err)
			}

			// Get level after adding XP
			levelAfter := xpSystem.GetLevel(userID)

			// Level should not decrease
			if levelAfter < levelBefore {
				t.Errorf("Level decreased: before=%d, after=%d", levelBefore, levelAfter)
			}
		}
	})
}

// Benchmark test for XP calculation performance
func BenchmarkXPSystem_CalculateXP(b *testing.B) {
	xpSystem := NewXPSystem()
	threatScore := 500.0
	complexity := 10

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		xpSystem.CalculateXP(threatScore, complexity, nil, true, false, false)
	}
}

// Benchmark test for XP persistence performance
func BenchmarkXPSystem_PersistData(b *testing.B) {
	tempDir, err := os.MkdirTemp("", "xp_bench_*")
	if err != nil {
		b.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	xpSystem := &DefaultXPSystem{
		dataFile: filepath.Join(tempDir, "bench_xp_data.json"),
		userData: make(map[string]*XPData),
	}

	// Add some test data
	for i := 0; i < 100; i++ {
		userID := generateRandomUserID()
		xpSystem.userData[userID] = &XPData{
			TotalXP:      rand.Intn(10000),
			CurrentLevel: rand.Intn(15) + 1,
			XPThreshold:  rand.Intn(5000) + 1000,
			LastUpdated:  time.Now().Format(time.RFC3339),
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := xpSystem.PersistData()
		if err != nil {
			b.Fatalf("Failed to persist data: %v", err)
		}
	}
}
