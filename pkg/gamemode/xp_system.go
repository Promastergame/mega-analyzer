package gamemode

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"mega-analyzer/pkg/internal/types"
)

// ═══════════════════════════════════════════════════════════════════════════════
// XP SYSTEM IMPLEMENTATION
// ═══════════════════════════════════════════════════════════════════════════════

type DefaultXPSystem struct {
	dataFile string
	userData map[string]*XPData
}

func NewXPSystem() XPSystem {
	dataFile := gamemodeDataFile("xp_data.json")

	system := &DefaultXPSystem{
		dataFile: dataFile,
		userData: make(map[string]*XPData),
	}

	// Try to load existing data
	system.LoadData()

	return system
}

func getDirSize(path string) int64 {
	if path == "" {
		return 0
	}
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	if !info.IsDir() {
		return info.Size()
	}
	var size int64
	_ = filepath.Walk(path, func(_ string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			size += fi.Size()
		}
		return nil
	})
	return size
}

func (xp *DefaultXPSystem) CalculateXP(
	threatScore float64,
	complexity int,
	result *types.AnalysisResult,
	isStatic bool,
	isPatcher bool,
	isFeedback bool,
) XPGainBreakdown {
	var breakdown XPGainBreakdown

	if isStatic {
		baseXP := 30 // Base XP for static analysis from user request

		// Бонус за размер приложения (вес)
		var sizeXP int
		if result != nil && result.TargetDir != "" {
			targetSize := getDirSize(result.TargetDir)
			sizeMB := float64(targetSize) / (1024 * 1024)
			// 10 XP за каждый мегабайт, максимум 300 XP
			sizeXP = int(sizeMB * 10.0)
			if sizeXP > 300 {
				sizeXP = 300
			}
		}

		// Бонусы за включение дополнительных модулей/анализаторов
		extraXP := 0
		if result != nil {
			if result.CallGraph != nil {
				extraXP += 30 // Бонус за построение Call Graph (-callgraph)
			}
			if result.Deobfuscation != nil {
				extraXP += 50 // Бонус за деобфускацию
			}
			if len(result.Correlations) > 0 {
				extraXP += 30 // Бонус за межфайловые корреляции (-correlations)
			}
			hasRealGNN := false
			for _, gf := range result.GNNFindings {
				if !gf.Dummy {
					hasRealGNN = true
					break
				}
			}
			if hasRealGNN {
				extraXP += 40 // GNN классификатор (веса найдены автоматически или через -gnn-model)
			}
			if len(result.MachineCodeReports) > 0 {
				extraXP += 50 // Нативный машинный код (--scan-native)
			}
			if len(result.ArtifactFindings) > 0 {
				extraXP += 40 // APKiD / Exodus / Native scan
			}
			if len(result.RuleMatches) > 0 {
				extraXP += 45 // MobSF SAST rules
			}
		}

		breakdown.StaticXP = baseXP + sizeXP + extraXP
	}

	if isPatcher {
		baseXP := 30 // Base XP for patcher from user request

		complexityMultiplier := float64(complexity) / 10.0
		if complexityMultiplier < 0.5 {
			complexityMultiplier = 0.5
		}
		if complexityMultiplier > 3.0 {
			complexityMultiplier = 3.0
		}
		threatBonus := int(threatScore * complexityMultiplier)

		breakdown.PatcherXP = baseXP + threatBonus
	}

	if isFeedback {
		breakdown.FeedbackXP = 30 // Base XP for ML Feedback from user request
	}

	return breakdown
}

func (xp *DefaultXPSystem) AddXP(userID string, breakdown XPGainBreakdown) error {
	if xp.userData[userID] == nil {
		xp.userData[userID] = &XPData{
			TotalXP:      0,
			CurrentLevel: 1,
			XPThreshold:  DefaultLevelThresholds[1],
			LastUpdated:  time.Now().Format(time.RFC3339),

			StaticXP:        0,
			StaticLevel:     1,
			StaticThreshold: DefaultLevelThresholds[1],

			PatcherXP:        0,
			PatcherLevel:     1,
			PatcherThreshold: DefaultLevelThresholds[1],

			FeedbackXP:        0,
			FeedbackLevel:     1,
			FeedbackThreshold: DefaultLevelThresholds[1],
		}
	}

	data := xp.userData[userID]

	// Migration check for existing users
	if data.StaticLevel == 0 {
		data.StaticLevel = 1
		data.StaticThreshold = xp.GetXPThreshold(1)
	}
	if data.PatcherLevel == 0 {
		data.PatcherLevel = 1
		data.PatcherThreshold = xp.GetXPThreshold(1)
	}
	if data.FeedbackLevel == 0 {
		data.FeedbackLevel = 1
		data.FeedbackThreshold = xp.GetXPThreshold(1)
	}

	// Add XP
	if breakdown.StaticXP > 0 {
		data.StaticXP += breakdown.StaticXP
		data.StaticLevel = xp.calculateLevel(data.StaticXP)
		data.StaticThreshold = xp.GetXPThreshold(data.StaticLevel)
	}
	if breakdown.PatcherXP > 0 {
		data.PatcherXP += breakdown.PatcherXP
		data.PatcherLevel = xp.calculateLevel(data.PatcherXP)
		data.PatcherThreshold = xp.GetXPThreshold(data.PatcherLevel)
	}
	if breakdown.FeedbackXP > 0 {
		data.FeedbackXP += breakdown.FeedbackXP
		data.FeedbackLevel = xp.calculateLevel(data.FeedbackXP)
		data.FeedbackThreshold = xp.GetXPThreshold(data.FeedbackLevel)
	}

	// Compatibility legacy fields
	data.TotalXP = data.StaticXP + data.PatcherXP + data.FeedbackXP
	data.CurrentLevel = xp.calculateLevel(data.TotalXP)
	data.XPThreshold = xp.GetXPThreshold(data.CurrentLevel)
	data.LastUpdated = time.Now().Format(time.RFC3339)

	return xp.PersistData()
}

func (xp *DefaultXPSystem) GetLevel(userID string) int {
	if data, exists := xp.userData[userID]; exists {
		return data.CurrentLevel
	}
	return 1 // Default level
}

func (xp *DefaultXPSystem) GetXPData(userID string) *XPData {
	if data, exists := xp.userData[userID]; exists {
		return data
	}
	return &XPData{
		TotalXP:           0,
		CurrentLevel:      1,
		XPThreshold:       DefaultLevelThresholds[1],
		StaticLevel:       1,
		StaticThreshold:   DefaultLevelThresholds[1],
		PatcherLevel:      1,
		PatcherThreshold:  DefaultLevelThresholds[1],
		FeedbackLevel:     1,
		FeedbackThreshold: DefaultLevelThresholds[1],
	}
}

func (xp *DefaultXPSystem) GetXPThreshold(level int) int {
	if level < len(DefaultLevelThresholds) {
		return DefaultLevelThresholds[level]
	}
	// For levels beyond our threshold table, use exponential growth
	return DefaultLevelThresholds[len(DefaultLevelThresholds)-1] + (level-len(DefaultLevelThresholds)+1)*1000
}

func (xp *DefaultXPSystem) calculateLevel(totalXP int) int {
	level := 1
	for i, threshold := range DefaultLevelThresholds {
		if totalXP >= threshold {
			level = i + 1
		} else {
			break
		}
	}
	return level
}

func (xp *DefaultXPSystem) PersistData() error {
	// Ensure directory exists
	dir := filepath.Dir(xp.dataFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}

	// Marshal data to JSON
	data, err := json.MarshalIndent(xp.userData, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal XP data: %w", err)
	}

	// Write to file
	if err := os.WriteFile(xp.dataFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write XP data: %w", err)
	}

	return nil
}

func (xp *DefaultXPSystem) LoadData() error {
	// Check if file exists
	if _, err := os.Stat(xp.dataFile); os.IsNotExist(err) {
		// File doesn't exist, start with empty data
		return nil
	}

	// Read file
	data, err := os.ReadFile(xp.dataFile)
	if err != nil {
		return fmt.Errorf("failed to read XP data: %w", err)
	}

	// Unmarshal JSON
	if err := json.Unmarshal(data, &xp.userData); err != nil {
		return fmt.Errorf("failed to unmarshal XP data: %w", err)
	}

	return nil
}
