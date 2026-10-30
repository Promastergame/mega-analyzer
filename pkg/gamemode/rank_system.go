package gamemode

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
// RANK SYSTEM IMPLEMENTATION
// ═══════════════════════════════════════════════════════════════════════════════

type DefaultRankSystem struct {
	dataFile string
	userData map[string]*RankData
	ranks    []Rank
}

func NewRankSystem() RankSystem {
	dataFile := gamemodeDataFile("rank_data.json")

	system := &DefaultRankSystem{
		dataFile: dataFile,
		userData: make(map[string]*RankData),
		ranks:    DefaultRanks,
	}

	// Try to load existing data
	system.loadData()

	return system
}

func (rs *DefaultRankSystem) AssignRank(threatScore float64) Rank {
	// Find the highest rank that the threat score qualifies for
	assignedRank := rs.ranks[0] // Default to lowest rank

	for _, rank := range rs.ranks {
		if threatScore >= rank.MinThreat {
			assignedRank = rank
		} else {
			break
		}
	}

	return assignedRank
}

func (rs *DefaultRankSystem) GetRankHistory(userID string) []RankHistory {
	if data, exists := rs.userData[userID]; exists {
		return data.RankHistory
	}
	return []RankHistory{}
}

func (rs *DefaultRankSystem) GetCurrentRank(userID string) Rank {
	if data, exists := rs.userData[userID]; exists {
		return data.CurrentRank
	}
	return rs.ranks[0] // Default to lowest rank
}

func (rs *DefaultRankSystem) UpdateRank(userID string, rank Rank) error {
	if rs.userData[userID] == nil {
		rs.userData[userID] = &RankData{
			CurrentRank: rs.ranks[0],
			RankHistory: make([]RankHistory, 0),
			HighestRank: rs.ranks[0],
		}
	}

	data := rs.userData[userID]

	// Only update if it's a higher rank
	if rank.ID > data.CurrentRank.ID {
		// Add to history
		history := RankHistory{
			Rank:      rank,
			Timestamp: time.Now().Format(time.RFC3339),
			APKName:   "", // Will be set by caller if needed
		}
		data.RankHistory = append(data.RankHistory, history)

		// Update current rank
		data.CurrentRank = rank

		// Update highest rank if necessary
		if rank.ID > data.HighestRank.ID {
			data.HighestRank = rank
		}

		return rs.persistData()
	}

	return nil
}

func (rs *DefaultRankSystem) persistData() error {
	// Ensure directory exists
	dir := filepath.Dir(rs.dataFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}

	// Marshal data to JSON
	data, err := json.MarshalIndent(rs.userData, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal rank data: %w", err)
	}

	// Write to file
	if err := os.WriteFile(rs.dataFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write rank data: %w", err)
	}

	return nil
}

func (rs *DefaultRankSystem) loadData() error {
	// Check if file exists
	if _, err := os.Stat(rs.dataFile); os.IsNotExist(err) {
		// File doesn't exist, start with empty data
		return nil
	}

	// Read file
	data, err := os.ReadFile(rs.dataFile)
	if err != nil {
		return fmt.Errorf("failed to read rank data: %w", err)
	}

	// Unmarshal JSON
	if err := json.Unmarshal(data, &rs.userData); err != nil {
		return fmt.Errorf("failed to unmarshal rank data: %w", err)
	}

	return nil
}
