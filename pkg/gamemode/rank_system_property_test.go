package gamemode

import (
	"math/rand"
	"testing"
	"time"
)

// Property test for rank system
// **Feature: analyzer-gamemode-upgrade, Property: Rank Assignment Thresholds**
// **Validates: Requirements 4.3, 4.4, 4.5**

func TestRankSystem_Properties(t *testing.T) {
	rand.Seed(time.Now().UnixNano())

	// Property 1: Rank assignment should be deterministic
	t.Run("Property_RankAssignmentDeterministic", func(t *testing.T) {
		rankSystem := NewRankSystem()

		for i := 0; i < 100; i++ {
			threatScore := rand.Float64() * 1000

			// Assign rank multiple times for same score
			rank1 := rankSystem.AssignRank(threatScore)
			rank2 := rankSystem.AssignRank(threatScore)
			rank3 := rankSystem.AssignRank(threatScore)

			// Should always get same rank for same score
			if rank1.ID != rank2.ID || rank2.ID != rank3.ID {
				t.Errorf("Rank assignment should be deterministic: score=%.2f, ranks=%d,%d,%d",
					threatScore, rank1.ID, rank2.ID, rank3.ID)
			}
		}
	})

	// Property 2: Higher threat scores should result in higher or equal ranks
	t.Run("Property_HigherThreatHigherRank", func(t *testing.T) {
		rankSystem := NewRankSystem()

		for i := 0; i < 100; i++ {
			threatScore1 := rand.Float64() * 500              // 0-500
			threatScore2 := threatScore1 + rand.Float64()*500 // Always higher (0-1000)

			rank1 := rankSystem.AssignRank(threatScore1)
			rank2 := rankSystem.AssignRank(threatScore2)

			// Higher threat should result in higher or equal rank
			if rank2.ID < rank1.ID {
				t.Errorf("Higher threat should result in higher or equal rank: score1=%.2f (rank=%d), score2=%.2f (rank=%d)",
					threatScore1, rank1.ID, threatScore2, rank2.ID)
			}
		}
	})

	// Property 3: Rank thresholds should be respected
	t.Run("Property_RankThresholdsRespected", func(t *testing.T) {
		rankSystem := NewRankSystem()
		ranks := rankSystem.(*DefaultRankSystem).ranks

		for _, rank := range ranks {
			// Test score just above threshold
			scoreAbove := float64(rank.MinThreat) + 1.0
			assignedRank := rankSystem.AssignRank(scoreAbove)

			// Should get at least this rank
			if assignedRank.ID < rank.ID {
				t.Errorf("Score above threshold should qualify for rank: threshold=%.0f, score=%.2f, expected_rank=%d, got_rank=%d",
					float64(rank.MinThreat), scoreAbove, rank.ID, assignedRank.ID)
			}
		}
	})

	// Property 4: All ranks should be reachable
	t.Run("Property_AllRanksReachable", func(t *testing.T) {
		rankSystem := NewRankSystem()
		ranks := rankSystem.(*DefaultRankSystem).ranks

		reachedRanks := make(map[int]bool)

		// Test scores from 0 to 1000
		for score := 0.0; score <= 1000.0; score += 10.0 {
			rank := rankSystem.AssignRank(score)
			reachedRanks[rank.ID] = true
		}

		// Check that all ranks are reachable
		for _, rank := range ranks {
			if !reachedRanks[rank.ID] {
				t.Errorf("Rank %d (%s) should be reachable", rank.ID, rank.Title)
			}
		}
	})

	// Property 5: Rank history should be monotonically increasing
	t.Run("Property_RankHistoryMonotonic", func(t *testing.T) {
		rankSystem := NewRankSystem()
		userID := "test_user_" + generateRandomUserID()

		// Start with low threat score
		threatScore := 50.0
		lastRankID := 0

		for i := 0; i < 10; i++ {
			rank := rankSystem.AssignRank(threatScore)

			// Update rank
			if err := rankSystem.UpdateRank(userID, rank); err != nil {
				t.Fatalf("Failed to update rank: %v", err)
			}

			// Get current rank
			currentRank := rankSystem.GetCurrentRank(userID)

			// Rank should not decrease
			if currentRank.ID < lastRankID {
				t.Errorf("Rank should not decrease: last=%d, current=%d", lastRankID, currentRank.ID)
			}

			lastRankID = currentRank.ID

			// Increase threat score
			threatScore += 100.0
		}
	})

	// Property 6: Rank should have valid emoji
	t.Run("Property_RankHasValidEmoji", func(t *testing.T) {
		rankSystem := NewRankSystem()

		for i := 0; i < 100; i++ {
			threatScore := rand.Float64() * 1000
			rank := rankSystem.AssignRank(threatScore)

			// Rank should have non-empty emoji
			if rank.Emoji == "" {
				t.Errorf("Rank should have emoji: rank=%d, title=%s", rank.ID, rank.Title)
			}

			// Rank should have non-empty title
			if rank.Title == "" {
				t.Errorf("Rank should have title: rank=%d", rank.ID)
			}

			// Rank should have non-empty description
			if rank.Description == "" {
				t.Errorf("Rank should have description: rank=%d, title=%s", rank.ID, rank.Title)
			}
		}
	})

	// Property 7: Rank progression should be continuous
	t.Run("Property_RankProgressionContinuous", func(t *testing.T) {
		rankSystem := NewRankSystem()
		ranks := rankSystem.(*DefaultRankSystem).ranks

		// Check that rank IDs are sequential
		for i, rank := range ranks {
			expectedID := i + 1
			if rank.ID != expectedID {
				t.Errorf("Rank ID should be sequential: expected=%d, got=%d", expectedID, rank.ID)
			}
		}

		// Check that thresholds are non-decreasing
		lastThreshold := 0.0
		for _, rank := range ranks {
			if float64(rank.MinThreat) < lastThreshold {
				t.Errorf("Rank thresholds should be non-decreasing: rank=%d, threshold=%.0f, last=%.0f",
					rank.ID, float64(rank.MinThreat), lastThreshold)
			}
			lastThreshold = float64(rank.MinThreat)
		}
	})

	// Property 8: Zero threat should give lowest rank
	t.Run("Property_ZeroThreatLowestRank", func(t *testing.T) {
		rankSystem := NewRankSystem()

		rank := rankSystem.AssignRank(0.0)

		// Should get the lowest rank (ID = 1)
		if rank.ID != 1 {
			t.Errorf("Zero threat should give lowest rank: expected=1, got=%d", rank.ID)
		}
	})

	// Property 9: Maximum threat should give highest rank
	t.Run("Property_MaxThreatHighestRank", func(t *testing.T) {
		rankSystem := NewRankSystem()
		ranks := rankSystem.(*DefaultRankSystem).ranks

		rank := rankSystem.AssignRank(1000.0)

		// Should get the highest rank
		highestRankID := len(ranks)
		if rank.ID != highestRankID {
			t.Errorf("Maximum threat should give highest rank: expected=%d, got=%d", highestRankID, rank.ID)
		}
	})
}
