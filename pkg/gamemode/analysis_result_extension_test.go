package gamemode

import (
	"fmt"
	"testing"
	"time"

	"mega-analyzer/pkg/internal/types"
	"mega-analyzer/pkg/ml"
)

func TestNewEnhancedAnalysisResult(t *testing.T) {
	result := types.NewAnalysisResult("/tmp")
	enhanced := NewEnhancedAnalysisResult(result)
	if enhanced == nil {
		t.Fatal("expected non-nil")
	}
	if enhanced.AnalysisResult != result {
		t.Fatal("AnalysisResult not set")
	}
	if enhanced.GameData != nil {
		t.Fatal("GameData should be nil initially")
	}
}

func TestEnhancedAnalysisResult_SetGetGameData(t *testing.T) {
	result := types.NewAnalysisResult("/tmp")
	enhanced := NewEnhancedAnalysisResult(result)

	if enhanced.HasGameData() {
		t.Fatal("should not have game data initially")
	}

	gameData := &GameData{}
	enhanced.SetGameData(gameData)

	if !enhanced.HasGameData() {
		t.Fatal("should have game data after set")
	}
	if enhanced.GetGameData() != gameData {
		t.Fatal("GetGameData should return what was set")
	}
}

func TestNewGameModeManager(t *testing.T) {
	gmm := NewGameModeManager("user123")
	if gmm == nil {
		t.Fatal("expected non-nil")
	}
	if !gmm.IsEnabled() {
		t.Fatal("should be enabled by default")
	}
	if gmm.GetUserID() != "user123" {
		t.Fatalf("userID = %q, want 'user123'", gmm.GetUserID())
	}
}

func TestGameModeManager_Enable(t *testing.T) {
	gmm := NewGameModeManager("user")
	gmm.Enable(false)
	if gmm.IsEnabled() {
		t.Fatal("should be disabled")
	}
	gmm.Enable(true)
	if !gmm.IsEnabled() {
		t.Fatal("should be enabled")
	}
}

func TestGameModeManager_SetUserID(t *testing.T) {
	gmm := NewGameModeManager("old")
	gmm.SetUserID("new")
	if gmm.GetUserID() != "new" {
		t.Fatalf("userID = %q, want 'new'", gmm.GetUserID())
	}
}

func TestGameModeManager_ProcessAnalysis(t *testing.T) {
	uniqueUser := fmt.Sprintf("testuser-%d", time.Now().UnixNano())
	gmm := NewGameModeManager(uniqueUser)
	result := types.NewAnalysisResult("/tmp")

	patchPoints := []ml.PatchPoint{
		{MethodName: "isLicensed", Confidence: 0.9},
		{MethodName: "isPremium", Confidence: 0.8},
	}

	enhanced := gmm.ProcessAnalysis(result, patchPoints, true, true, true)
	if enhanced == nil {
		t.Fatal("expected non-nil enhanced result")
	}
	if !enhanced.HasGameData() {
		t.Fatal("should have game data after processing")
	}
	if enhanced.GameData.ThreatResult == nil {
		t.Fatal("ThreatResult should not be nil")
	}
	if len(enhanced.GameData.UnlockedBadges) == 0 {
		t.Fatal("expected at least one unlocked badge (first_blood)")
	}
	if enhanced.GameData.UnlockedBadges[0] != BadgeFirstBlood {
		t.Fatalf("expected first badge to be first_blood, got %v", enhanced.GameData.UnlockedBadges[0])
	}
}

func TestGameModeManager_ProcessAnalysis_Disabled(t *testing.T) {
	gmm := NewGameModeManager("testuser")
	gmm.Enable(false)
	result := types.NewAnalysisResult("/tmp")

	enhanced := gmm.ProcessAnalysis(result, nil, true, true, true)
	if enhanced == nil {
		t.Fatal("expected non-nil")
	}
	if enhanced.HasGameData() {
		t.Fatal("should not have game data when disabled")
	}
}

func TestGameModeManager_FormatResult_Disabled(t *testing.T) {
	gmm := NewGameModeManager("user")
	gmm.Enable(false)
	enhanced := NewEnhancedAnalysisResult(types.NewAnalysisResult("/tmp"))

	output := gmm.FormatResult(enhanced)
	if output != "" {
		t.Fatal("should return empty when disabled")
	}
}

func TestGameModeManager_FormatResult_NoGameData(t *testing.T) {
	gmm := NewGameModeManager("user")
	enhanced := NewEnhancedAnalysisResult(types.NewAnalysisResult("/tmp"))

	output := gmm.FormatResult(enhanced)
	if output != "" {
		t.Fatal("should return empty when no game data")
	}
}

func TestGameModeManager_FormatMarkdown_Disabled(t *testing.T) {
	gmm := NewGameModeManager("user")
	gmm.Enable(false)
	enhanced := NewEnhancedAnalysisResult(types.NewAnalysisResult("/tmp"))

	output := gmm.FormatMarkdown(enhanced)
	if output != "" {
		t.Fatal("should return empty when disabled")
	}
}

func TestGameModeManager_FormatJSON_Disabled(t *testing.T) {
	gmm := NewGameModeManager("user")
	gmm.Enable(false)
	enhanced := NewEnhancedAnalysisResult(types.NewAnalysisResult("/tmp"))

	data, err := gmm.FormatJSON(enhanced)
	if err != nil {
		t.Fatalf("FormatJSON: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("should return some JSON even when disabled")
	}
}

func TestGameModeManager_GetComponents(t *testing.T) {
	gmm := NewGameModeManager("user")
	tc, xp, rs, of := gmm.GetComponents()
	if tc == nil || xp == nil || rs == nil || of == nil {
		t.Fatal("all components should be non-nil")
	}
}

func TestGameModeManager_SetComponents_Nil(t *testing.T) {
	gmm := NewGameModeManager("user")
	tc, xp, rs, of := gmm.GetComponents()

	// Setting nil should not change components
	gmm.SetComponents(nil, nil, nil, nil)
	tc2, xp2, rs2, of2 := gmm.GetComponents()
	if tc != tc2 || xp != xp2 || rs != rs2 || of != of2 {
		t.Fatal("nil components should not replace existing ones")
	}
}
