package gamemode

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

type PrestigeData struct {
	PrestigeLevel  int             `json:"prestige_level"`
	PrestigeXP     int             `json:"prestige_xp"`
	LastPrestigeAt string          `json:"last_prestige_at"`
	XPMultiplier   float64         `json:"xp_multiplier"`
	History        []PrestigeEvent `json:"history,omitempty"`
}

type PrestigeEvent struct {
	Level     int    `json:"level"`
	At        string `json:"at"`
	TotalXPAt int    `json:"total_xp_at"`
}

func CanPrestige(xpData *XPData) bool {
	return xpData != nil && xpData.CurrentLevel >= len(DefaultLevelThresholds)
}

func ApplyPrestige(xpData *XPData, pd *PrestigeData, now time.Time) (*XPData, *PrestigeData) {
	if !CanPrestige(xpData) {
		return xpData, pd
	}

	pd.PrestigeXP += xpData.TotalXP
	pd.PrestigeLevel++
	pd.XPMultiplier = 1.0 + float64(pd.PrestigeLevel)*0.25
	pd.LastPrestigeAt = now.Format(time.RFC3339)
	pd.History = append(pd.History, PrestigeEvent{
		Level:     pd.PrestigeLevel,
		At:        pd.LastPrestigeAt,
		TotalXPAt: xpData.TotalXP,
	})

	xpData.TotalXP = 0
	xpData.CurrentLevel = 1
	xpData.XPThreshold = DefaultLevelThresholds[1]
	xpData.StaticXP = 0
	xpData.StaticLevel = 1
	xpData.StaticThreshold = DefaultLevelThresholds[1]
	xpData.PatcherXP = 0
	xpData.PatcherLevel = 1
	xpData.PatcherThreshold = DefaultLevelThresholds[1]
	xpData.FeedbackXP = 0
	xpData.FeedbackLevel = 1
	xpData.FeedbackThreshold = DefaultLevelThresholds[1]

	return xpData, pd
}

type PrestigeStore struct {
	dataFile string
	userData map[string]*PrestigeData
}

func NewPrestigeStore() *PrestigeStore {
	ps := &PrestigeStore{
		dataFile: gamemodeDataFile("prestige_data.json"),
		userData: make(map[string]*PrestigeData),
	}
	_ = ps.Load()
	return ps
}

func (ps *PrestigeStore) Get(userID string) *PrestigeData {
	if d, ok := ps.userData[userID]; ok {
		return d
	}
	return &PrestigeData{XPMultiplier: 1.0}
}

func (ps *PrestigeStore) Set(userID string, pd *PrestigeData) error {
	ps.userData[userID] = pd
	return ps.Persist()
}

func (ps *PrestigeStore) Persist() error {
	dir := filepath.Dir(ps.dataFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(ps.userData, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(ps.dataFile, data, 0644)
}

func (ps *PrestigeStore) Load() error {
	raw, err := os.ReadFile(ps.dataFile)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, &ps.userData)
}
