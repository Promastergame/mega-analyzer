package gamemode

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

type StreakData struct {
	LastRunDate   string `json:"last_run_date"`
	CurrentStreak int    `json:"current_streak"`
	LongestStreak int    `json:"longest_streak"`
}

type StreakSystem struct {
	dataFile string
	userData map[string]*StreakData
}

func NewStreakSystem() *StreakSystem {
	dataFile := gamemodeDataFile("streak_data.json")
	ss := &StreakSystem{
		dataFile: dataFile,
		userData: make(map[string]*StreakData),
	}
	_ = ss.LoadData()
	return ss
}

func (ss *StreakSystem) RecordRun(userID string) (int, error) {
	return ss.RecordRunAt(userID, time.Now())
}

func (ss *StreakSystem) RecordRunAt(userID string, now time.Time) (int, error) {
	today := now.Format("2006-01-02")
	data := ss.ensureUser(userID)

	if data.LastRunDate == today {
		return data.CurrentStreak, ss.PersistData()
	}

	yesterday := now.AddDate(0, 0, -1).Format("2006-01-02")
	if data.LastRunDate == yesterday {
		data.CurrentStreak++
	} else if data.LastRunDate == "" {
		data.CurrentStreak = 1
	} else {
		data.CurrentStreak = 1
	}

	data.LastRunDate = today
	if data.CurrentStreak > data.LongestStreak {
		data.LongestStreak = data.CurrentStreak
	}

	return data.CurrentStreak, ss.PersistData()
}

func (ss *StreakSystem) GetStreak(userID string) *StreakData {
	if d, ok := ss.userData[userID]; ok {
		return d
	}
	return &StreakData{}
}

func (ss *StreakSystem) ensureUser(userID string) *StreakData {
	if ss.userData[userID] == nil {
		ss.userData[userID] = &StreakData{}
	}
	return ss.userData[userID]
}

func (ss *StreakSystem) PersistData() error {
	dir := filepath.Dir(ss.dataFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(ss.userData, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(ss.dataFile, data, 0644)
}

func (ss *StreakSystem) LoadData() error {
	raw, err := os.ReadFile(ss.dataFile)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, &ss.userData)
}
