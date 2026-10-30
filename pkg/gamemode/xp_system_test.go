package gamemode

import (
	"testing"

	"mega-analyzer/pkg/internal/types"
)

// TestXPSystemInterface verifies the interface is properly defined
func TestXPSystemInterface(t *testing.T) {
	// This test ensures the interface compiles and is usable
	var _ XPSystem = (*mockXPSystem)(nil)
}

// mockXPSystem is a mock implementation for testing
type mockXPSystem struct {
	data map[string]*XPData
}

func (m *mockXPSystem) CalculateXP(threatScore float64, complexity int, result *types.AnalysisResult, isStatic bool, isPatcher bool, isFeedback bool) XPGainBreakdown {
	return XPGainBreakdown{
		StaticXP:   100 + int(threatScore*float64(complexity)),
		PatcherXP:  0,
		FeedbackXP: 0,
	}
}

func (m *mockXPSystem) AddXP(userID string, breakdown XPGainBreakdown) error {
	if m.data == nil {
		m.data = make(map[string]*XPData)
	}
	if _, exists := m.data[userID]; !exists {
		m.data[userID] = &XPData{TotalXP: 0, CurrentLevel: 1}
	}
	m.data[userID].TotalXP += breakdown.StaticXP + breakdown.PatcherXP + breakdown.FeedbackXP
	return nil
}

func (m *mockXPSystem) GetLevel(userID string) int {
	if m.data == nil || m.data[userID] == nil {
		return 1
	}
	return m.data[userID].CurrentLevel
}

func (m *mockXPSystem) GetXPThreshold(level int) int {
	return level * 1000
}

func (m *mockXPSystem) GetXPData(userID string) *XPData {
	if m.data == nil || m.data[userID] == nil {
		return &XPData{TotalXP: 0, CurrentLevel: 1}
	}
	return m.data[userID]
}

func (m *mockXPSystem) PersistData() error {
	return nil
}

func (m *mockXPSystem) LoadData() error {
	return nil
}

// TestXPDataStructure verifies XPData structure
func TestXPDataStructure(t *testing.T) {
	xpData := XPData{
		TotalXP:      5000,
		CurrentLevel: 5,
		XPThreshold:  6000,
		LastUpdated:  "2026-04-18T12:00:00Z",
	}

	if xpData.TotalXP != 5000 {
		t.Errorf("Expected TotalXP 5000, got %d", xpData.TotalXP)
	}
	if xpData.CurrentLevel != 5 {
		t.Errorf("Expected CurrentLevel 5, got %d", xpData.CurrentLevel)
	}
	// Use LastUpdated to avoid unused field warning
	if xpData.LastUpdated != "2026-04-18T12:00:00Z" {
		t.Errorf("Expected LastUpdated timestamp, got %s", xpData.LastUpdated)
	}
	if xpData.XPThreshold != 6000 {
		t.Errorf("Expected XPThreshold 6000, got %d", xpData.XPThreshold)
	}
}

// TestXPCalculation verifies basic XP calculation
func TestXPCalculation(t *testing.T) {
	xpSys := &mockXPSystem{}

	breakdown := xpSys.CalculateXP(500.0, 2, nil, true, true, true)
	expected := 100 + int(500.0*2)
	if breakdown.StaticXP != expected {
		t.Errorf("Expected XP %d, got %d", expected, breakdown.StaticXP)
	}
}
