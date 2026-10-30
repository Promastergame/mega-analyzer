package ml

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
// PATTERN METADATA AND REPOSITORY MANAGEMENT (Task 15)
// Requirements: 14.1-14.5, 20.1-20.5
// ═══════════════════════════════════════════════════════════════════════════════

// PatternMetadata contains metadata about a vulnerability pattern
type PatternMetadata struct {
	ID            string                `json:"id"`
	Effectiveness *PatternEffectiveness `json:"effectiveness,omitempty"`
	Tier          PatternTier           `json:"tier"`
	LastUpdated   time.Time             `json:"last_updated"`
	CreatedAt     time.Time             `json:"created_at"`
	DeprecatedAt  *time.Time            `json:"deprecated_at,omitempty"`
	ReplacedBy    string                `json:"replaced_by,omitempty"`
	Notes         string                `json:"notes,omitempty"`
}

// PatternRepository manages pattern lifecycle, metadata, and deprecation
type PatternRepository struct {
	activePatterns     []VulnerablePattern
	deprecatedPatterns []DeprecatedPattern
	metadata           map[string]*PatternMetadata
}

// DeprecatedPattern represents a pattern that has been deprecated
type DeprecatedPattern struct {
	Pattern      VulnerablePattern `json:"pattern"`
	Reason       string            `json:"reason"`
	DeprecatedAt time.Time         `json:"deprecated_at"`
	ReplacedBy   string            `json:"replaced_by,omitempty"`
}

// NewPatternRepository creates a new pattern repository
func NewPatternRepository() *PatternRepository {
	return &PatternRepository{
		activePatterns:     GetAllPatterns(),
		deprecatedPatterns: []DeprecatedPattern{},
		metadata:           make(map[string]*PatternMetadata),
	}
}

// GetActivePatterns returns only active (non-deprecated) patterns
func (pr *PatternRepository) GetActivePatterns() []VulnerablePattern {
	return pr.activePatterns
}

// GetDeprecatedPatterns returns all deprecated patterns
func (pr *PatternRepository) GetDeprecatedPatterns() []DeprecatedPattern {
	return pr.deprecatedPatterns
}

// GetMetadata returns metadata for a specific pattern
func (pr *PatternRepository) GetMetadata(id string) (*PatternMetadata, bool) {
	meta, ok := pr.metadata[id]
	return meta, ok
}

// SetMetadata sets metadata for a pattern
func (pr *PatternRepository) SetMetadata(id string, meta *PatternMetadata) {
	pr.metadata[id] = meta
}

// DeprecatePattern marks a pattern as deprecated
func (pr *PatternRepository) DeprecatePattern(id string, reason string, replacedBy string) error {
	// Find the pattern in active patterns
	var foundPattern *VulnerablePattern
	var foundIndex int

	for i, p := range pr.activePatterns {
		if p.ID == id {
			foundPattern = &p
			foundIndex = i
			break
		}
	}

	if foundPattern == nil {
		return fmt.Errorf("pattern not found: %s", id)
	}

	// Create deprecated pattern entry
	now := time.Now()
	deprecated := DeprecatedPattern{
		Pattern:      *foundPattern,
		Reason:       reason,
		DeprecatedAt: now,
		ReplacedBy:   replacedBy,
	}

	// Add to deprecated list
	pr.deprecatedPatterns = append(pr.deprecatedPatterns, deprecated)

	// Remove from active patterns
	pr.activePatterns = append(pr.activePatterns[:foundIndex], pr.activePatterns[foundIndex+1:]...)

	// Update metadata
	if meta, ok := pr.metadata[id]; ok {
		meta.DeprecatedAt = &now
		meta.ReplacedBy = replacedBy
	}

	return nil
}

// ExportToJSON exports patterns and metadata to JSON file
func (pr *PatternRepository) ExportToJSON(path string) error {
	// Create export structure
	export := struct {
		ActivePatterns     []VulnerablePattern         `json:"active_patterns"`
		DeprecatedPatterns []DeprecatedPattern         `json:"deprecated_patterns"`
		Metadata           map[string]*PatternMetadata `json:"metadata"`
		ExportedAt         time.Time                   `json:"exported_at"`
		Version            string                      `json:"version"`
	}{
		ActivePatterns:     pr.activePatterns,
		DeprecatedPatterns: pr.deprecatedPatterns,
		Metadata:           pr.metadata,
		ExportedAt:         time.Now(),
		Version:            "1.0",
	}

	// Marshal to JSON with indentation
	data, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal patterns: %w", err)
	}

	// Write to file
	err = os.WriteFile(path, data, 0644)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// ImportFromJSON imports patterns and metadata from JSON file
func (pr *PatternRepository) ImportFromJSON(path string) error {
	// Read file
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Parse JSON
	var imported struct {
		ActivePatterns     []VulnerablePattern         `json:"active_patterns"`
		DeprecatedPatterns []DeprecatedPattern         `json:"deprecated_patterns"`
		Metadata           map[string]*PatternMetadata `json:"metadata"`
		ExportedAt         time.Time                   `json:"exported_at"`
		Version            string                      `json:"version"`
	}

	err = json.Unmarshal(data, &imported)
	if err != nil {
		return fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	// Validate patterns
	err = pr.validatePatterns(imported.ActivePatterns)
	if err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	// Detect and resolve conflicts
	conflicts := pr.detectConflicts(imported.ActivePatterns)
	if len(conflicts) > 0 {
		return fmt.Errorf("conflicts detected: %v", conflicts)
	}

	// Import patterns
	pr.activePatterns = imported.ActivePatterns
	pr.deprecatedPatterns = imported.DeprecatedPatterns
	pr.metadata = imported.Metadata

	return nil
}

// validatePatterns validates imported patterns for correctness
func (pr *PatternRepository) validatePatterns(patterns []VulnerablePattern) error {
	for _, p := range patterns {
		// Check required fields
		if p.ID == "" {
			return fmt.Errorf("pattern missing ID")
		}
		if p.Category == "" {
			return fmt.Errorf("pattern %s missing category", p.ID)
		}
		if p.Description == "" {
			return fmt.Errorf("pattern %s missing description", p.ID)
		}

		// Check that at least one matching criterion exists
		if len(p.MethodNames) == 0 && len(p.ClassPatterns) == 0 &&
			len(p.RequiredCalls) == 0 && len(p.StringPatterns) == 0 {
			return fmt.Errorf("pattern %s has no matching criteria", p.ID)
		}

		// Validate weight
		if p.Weight < 0 {
			return fmt.Errorf("pattern %s has negative weight", p.ID)
		}

		// Validate min match score
		if p.MinMatchScore < 0 || p.MinMatchScore > 100 {
			return fmt.Errorf("pattern %s has invalid min match score", p.ID)
		}
	}

	return nil
}

// detectConflicts detects ID conflicts between existing and imported patterns
func (pr *PatternRepository) detectConflicts(imported []VulnerablePattern) []string {
	conflicts := []string{}

	// Build map of existing pattern IDs
	existing := make(map[string]bool)
	for _, p := range pr.activePatterns {
		existing[p.ID] = true
	}

	// Check for conflicts
	for _, p := range imported {
		if existing[p.ID] {
			conflicts = append(conflicts, p.ID)
		}
	}

	return conflicts
}

// InitializeMetadata initializes metadata for all active patterns
func (pr *PatternRepository) InitializeMetadata() {
	now := time.Now()

	for _, p := range pr.activePatterns {
		if _, exists := pr.metadata[p.ID]; !exists {
			// Create default metadata
			meta := &PatternMetadata{
				ID:          p.ID,
				Tier:        TierNormal, // Default tier
				CreatedAt:   now,
				LastUpdated: now,
			}

			// If pattern has effectiveness data, use it
			if p.Effectiveness != nil {
				meta.Effectiveness = p.Effectiveness
				meta.Tier = p.Effectiveness.Tier
			}

			pr.metadata[p.ID] = meta
		}
	}
}

// UpdateMetadataFromEffectiveness updates metadata based on effectiveness analysis
func (pr *PatternRepository) UpdateMetadataFromEffectiveness(effectiveness map[string]*PatternEffectiveness) {
	now := time.Now()

	for id, eff := range effectiveness {
		meta, exists := pr.metadata[id]
		if !exists {
			meta = &PatternMetadata{
				ID:        id,
				CreatedAt: now,
			}
			pr.metadata[id] = meta
		}

		meta.Effectiveness = eff
		meta.Tier = eff.Tier
		meta.LastUpdated = now
	}
}

// GetPatternCount returns the count of active and deprecated patterns
func (pr *PatternRepository) GetPatternCount() (active int, deprecated int) {
	return len(pr.activePatterns), len(pr.deprecatedPatterns)
}

// GetPatternsByTier returns patterns filtered by tier
func (pr *PatternRepository) GetPatternsByTier(tier PatternTier) []VulnerablePattern {
	result := []VulnerablePattern{}

	for _, p := range pr.activePatterns {
		meta, ok := pr.metadata[p.ID]
		if ok && meta.Tier == tier {
			result = append(result, p)
		}
	}

	return result
}
