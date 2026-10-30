package ml

import (
	"os"
	"path/filepath"
	"testing"
)

// TestPatternRepository_GetActivePatterns tests getting active patterns
func TestPatternRepository_GetActivePatterns(t *testing.T) {
	repo := NewPatternRepository()

	active := repo.GetActivePatterns()

	if len(active) == 0 {
		t.Error("Expected active patterns, got none")
	}

	// All patterns should have IDs
	for _, p := range active {
		if p.ID == "" {
			t.Error("Pattern missing ID")
		}
	}
}

// TestPatternRepository_DeprecatePattern tests pattern deprecation
func TestPatternRepository_DeprecatePattern(t *testing.T) {
	repo := NewPatternRepository()

	// Get initial counts
	initialActive := len(repo.GetActivePatterns())
	initialDeprecated := len(repo.GetDeprecatedPatterns())

	// Get first pattern ID
	if len(repo.activePatterns) == 0 {
		t.Fatal("No patterns to deprecate")
	}
	patternID := repo.activePatterns[0].ID

	// Deprecate pattern
	err := repo.DeprecatePattern(patternID, "Test deprecation", "")
	if err != nil {
		t.Fatalf("Failed to deprecate pattern: %v", err)
	}

	// Check counts changed
	finalActive := len(repo.GetActivePatterns())
	finalDeprecated := len(repo.GetDeprecatedPatterns())

	if finalActive != initialActive-1 {
		t.Errorf("Active count = %d, want %d", finalActive, initialActive-1)
	}

	if finalDeprecated != initialDeprecated+1 {
		t.Errorf("Deprecated count = %d, want %d", finalDeprecated, initialDeprecated+1)
	}

	// Try to deprecate non-existent pattern
	err = repo.DeprecatePattern("NON_EXISTENT", "Test", "")
	if err == nil {
		t.Error("Expected error for non-existent pattern")
	}
}

// TestPatternRepository_Metadata tests metadata management
func TestPatternRepository_Metadata(t *testing.T) {
	repo := NewPatternRepository()
	repo.InitializeMetadata()

	// Check metadata was created for all patterns
	for _, p := range repo.activePatterns {
		meta, ok := repo.GetMetadata(p.ID)
		if !ok {
			t.Errorf("No metadata for pattern %s", p.ID)
			continue
		}

		if meta.ID != p.ID {
			t.Errorf("Metadata ID mismatch: got %s, want %s", meta.ID, p.ID)
		}

		if meta.CreatedAt.IsZero() {
			t.Errorf("Pattern %s has zero CreatedAt", p.ID)
		}

		if meta.LastUpdated.IsZero() {
			t.Errorf("Pattern %s has zero LastUpdated", p.ID)
		}
	}
}

// TestPatternRepository_ExportImport tests export and import functionality
func TestPatternRepository_ExportImport(t *testing.T) {
	// Create temporary directory
	tmpDir := testTempDir(t)
	exportPath := filepath.Join(tmpDir, "patterns.json")

	// Create and populate repository
	repo1 := NewPatternRepository()
	repo1.InitializeMetadata()

	// Export
	err := repo1.ExportToJSON(exportPath)
	if err != nil {
		t.Fatalf("Export failed: %v", err)
	}

	// Check file exists
	if _, err := os.Stat(exportPath); os.IsNotExist(err) {
		t.Fatal("Export file not created")
	}

	// Create new repository and import
	repo2 := NewPatternRepository()
	repo2.activePatterns = []VulnerablePattern{} // Clear patterns

	err = repo2.ImportFromJSON(exportPath)
	if err != nil {
		t.Fatalf("Import failed: %v", err)
	}

	// Compare counts
	if len(repo2.activePatterns) != len(repo1.activePatterns) {
		t.Errorf("Pattern count mismatch: got %d, want %d",
			len(repo2.activePatterns), len(repo1.activePatterns))
	}

	// Compare metadata counts
	if len(repo2.metadata) != len(repo1.metadata) {
		t.Errorf("Metadata count mismatch: got %d, want %d",
			len(repo2.metadata), len(repo1.metadata))
	}
}

// TestPatternRepository_ValidatePatterns tests pattern validation
func TestPatternRepository_ValidatePatterns(t *testing.T) {
	repo := NewPatternRepository()

	tests := []struct {
		name    string
		pattern VulnerablePattern
		wantErr bool
	}{
		{
			name: "valid pattern",
			pattern: VulnerablePattern{
				ID:            "TEST_PATTERN",
				Category:      "test",
				Description:   "Test pattern",
				MethodNames:   []string{"test"},
				Weight:        1.0,
				MinMatchScore: 50,
			},
			wantErr: false,
		},
		{
			name: "missing ID",
			pattern: VulnerablePattern{
				Category:    "test",
				Description: "Test pattern",
				MethodNames: []string{"test"},
			},
			wantErr: true,
		},
		{
			name: "missing category",
			pattern: VulnerablePattern{
				ID:          "TEST_PATTERN",
				Description: "Test pattern",
				MethodNames: []string{"test"},
			},
			wantErr: true,
		},
		{
			name: "missing description",
			pattern: VulnerablePattern{
				ID:          "TEST_PATTERN",
				Category:    "test",
				MethodNames: []string{"test"},
			},
			wantErr: true,
		},
		{
			name: "no matching criteria",
			pattern: VulnerablePattern{
				ID:          "TEST_PATTERN",
				Category:    "test",
				Description: "Test pattern",
			},
			wantErr: true,
		},
		{
			name: "negative weight",
			pattern: VulnerablePattern{
				ID:          "TEST_PATTERN",
				Category:    "test",
				Description: "Test pattern",
				MethodNames: []string{"test"},
				Weight:      -1.0,
			},
			wantErr: true,
		},
		{
			name: "invalid min match score",
			pattern: VulnerablePattern{
				ID:            "TEST_PATTERN",
				Category:      "test",
				Description:   "Test pattern",
				MethodNames:   []string{"test"},
				MinMatchScore: 150,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := repo.validatePatterns([]VulnerablePattern{tt.pattern})
			if (err != nil) != tt.wantErr {
				t.Errorf("validatePatterns() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestPatternRepository_GetPatternsByTier tests filtering by tier
func TestPatternRepository_GetPatternsByTier(t *testing.T) {
	repo := NewPatternRepository()
	repo.InitializeMetadata()

	// Count total metadata entries
	totalEntries := len(repo.metadata)
	if totalEntries < 9 {
		t.Skipf("Skipping: need at least 9 metadata entries, have %d", totalEntries)
	}

	// Set some patterns to different tiers
	ids := make([]string, 0, len(repo.metadata))
	for id := range repo.metadata {
		ids = append(ids, id)
	}

	// Set first 3 to IMBA, next 3 to Normal, next 3 to Trash
	// All others keep their original tier
	for i := 0; i < 3 && i < len(ids); i++ {
		repo.metadata[ids[i]].Tier = TierIMBA
	}
	for i := 3; i < 6 && i < len(ids); i++ {
		repo.metadata[ids[i]].Tier = TierNormal
	}
	for i := 6; i < 9 && i < len(ids); i++ {
		repo.metadata[ids[i]].Tier = TierTrash
	}

	// Get patterns by tier
	imbaPatterns := repo.GetPatternsByTier(TierIMBA)
	normalPatterns := repo.GetPatternsByTier(TierNormal)
	trashPatterns := repo.GetPatternsByTier(TierTrash)

	// Verify we got at least the patterns we set
	if len(imbaPatterns) < 3 {
		t.Errorf("IMBA patterns = %d, want at least 3", len(imbaPatterns))
	}

	if len(normalPatterns) < 3 {
		t.Errorf("Normal patterns = %d, want at least 3", len(normalPatterns))
	}

	if len(trashPatterns) < 3 {
		t.Errorf("Trash patterns = %d, want at least 3", len(trashPatterns))
	}
}

// TestPatternRepository_UpdateMetadataFromEffectiveness tests updating metadata
func TestPatternRepository_UpdateMetadataFromEffectiveness(t *testing.T) {
	repo := NewPatternRepository()
	repo.InitializeMetadata()

	// Create effectiveness data
	effectiveness := map[string]*PatternEffectiveness{
		"LICENSE_BOOL_CHECK": {
			PatternID:         "LICENSE_BOOL_CHECK",
			TruePositiveRate:  0.95,
			FalsePositiveRate: 0.05,
			Tier:              TierIMBA,
			TierReason:        "High effectiveness",
		},
	}

	// Update metadata
	repo.UpdateMetadataFromEffectiveness(effectiveness)

	// Check metadata was updated
	meta, ok := repo.GetMetadata("LICENSE_BOOL_CHECK")
	if !ok {
		t.Fatal("Metadata not found")
	}

	if meta.Effectiveness == nil {
		t.Error("Effectiveness not set")
	}

	if meta.Tier != TierIMBA {
		t.Errorf("Tier = %s, want %s", meta.Tier, TierIMBA)
	}

	if meta.LastUpdated.IsZero() {
		t.Error("LastUpdated not set")
	}
}

// TestPatternRepository_ConflictDetection tests conflict detection
func TestPatternRepository_ConflictDetection(t *testing.T) {
	repo := NewPatternRepository()

	// Create patterns with conflicting IDs
	imported := []VulnerablePattern{
		{
			ID:          repo.activePatterns[0].ID, // Use existing ID
			Category:    "test",
			Description: "Test pattern",
			MethodNames: []string{"test"},
		},
	}

	conflicts := repo.detectConflicts(imported)

	if len(conflicts) == 0 {
		t.Error("Expected conflicts, got none")
	}

	if conflicts[0] != repo.activePatterns[0].ID {
		t.Errorf("Conflict ID = %s, want %s", conflicts[0], repo.activePatterns[0].ID)
	}
}
