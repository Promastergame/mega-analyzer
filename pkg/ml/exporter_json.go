package ml

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
// JSON EXPORTER — exports patches with complete metadata
//
// Features:
//   - Export patches with mode, explanation, confidence breakdown
//   - Include original code, patched code, and diff view
//   - Add timestamp and version metadata
//   - Validate JSON structure before writing
// ═══════════════════════════════════════════════════════════════════════════════

// JSONExporter exports patches to JSON format
type JSONExporter struct {
	version string
}

// NewJSONExporter creates a new JSON exporter
func NewJSONExporter() *JSONExporter {
	return &JSONExporter{
		version: "2.0.0", // Smart patch bridge schema
	}
}

// JSONExport represents the complete JSON export structure
type JSONExport struct {
	SchemaVersion string   `json:"schema_version"`
	Capabilities  []string `json:"capabilities,omitempty"`
	// Metadata
	Version   string    `json:"version"`
	Timestamp time.Time `json:"timestamp"`
	Generator string    `json:"generator"`

	// Patches
	Patches   []JSONPatch     `json:"patches"`
	Artifacts []PatchArtifact `json:"artifacts,omitempty"`

	// Summary
	Summary JSONSummary `json:"summary"`
}

// JSONPatch represents a single patch in JSON format
type JSONPatch struct {
	PatchID       string `json:"patch_id"`
	SchemaVersion string `json:"schema_version"`
	// Location
	FilePath        string `json:"file_path"`
	ClassName       string `json:"class_name"`
	MethodName      string `json:"method_name"`
	MethodSignature string `json:"method_signature"`

	// Code
	OriginalCode string `json:"original_code"`
	PatchedCode  string `json:"patched_code"`
	DiffView     string `json:"diff_view"`
	UnifiedDiff  string `json:"unified_diff,omitempty"`
	OriginalHash string `json:"original_hash,omitempty"`
	PatchedHash  string `json:"patched_hash,omitempty"`

	// Patch metadata
	PatchType   PatchType `json:"patch_type"`
	Description string    `json:"description"`
	Mode        PatchMode `json:"mode"`

	// Explanation
	Explanation PatchExplanation `json:"explanation"`

	// Confidence
	Confidence          float64                      `json:"confidence"`
	ConfidenceBreakdown *ConfidenceBreakdown         `json:"confidence_breakdown,omitempty"`
	CategoryConfidence  *CategoryConformalConfidence `json:"category_confidence,omitempty"`
	ValidatorErrors     []ValidationError            `json:"validator_errors,omitempty"`
	ApplySafe           bool                         `json:"apply_safe"`
	ApplySafetyLevel    string                       `json:"apply_safety_level,omitempty"`
	SafetyReasons       []string                     `json:"safety_reasons,omitempty"`

	// Flattened apply plan is intentionally duplicated from Artifacts so the
	// dependency-free Zig IDE can consume it without parsing nested objects.
	BlockStartLine    int    `json:"block_start_line,omitempty"`
	BlockEndLine      int    `json:"block_end_line,omitempty"`
	BlockOriginalCode string `json:"block_original_code,omitempty"`
	BlockPatchedCode  string `json:"block_patched_code,omitempty"`
	BlockOriginalHash string `json:"block_original_hash,omitempty"`
	BlockPatchedHash  string `json:"block_patched_hash,omitempty"`

	// Risk
	RiskScore float64   `json:"risk_score"`
	RiskLevel RiskClass `json:"risk_level"`

	// Category
	Category     PatchCategory `json:"category"`
	CategoryName string        `json:"category_name"`
}

// JSONSummary provides summary statistics
type JSONSummary struct {
	TotalPatches     int            `json:"total_patches"`
	ByMode           map[string]int `json:"by_mode"`
	ByRiskLevel      map[string]int `json:"by_risk_level"`
	ByCategory       map[string]int `json:"by_category"`
	AvgConfidence    float64        `json:"avg_confidence"`
	HighConfidence   int            `json:"high_confidence_count"`   // >= 0.8
	MediumConfidence int            `json:"medium_confidence_count"` // 0.5-0.8
	LowConfidence    int            `json:"low_confidence_count"`    // < 0.5
}

// ExportToFile exports patches to a JSON file
func (je *JSONExporter) ExportToFile(patches []*GeneratedPatch, points []PatchPoint, filepath string) error {
	// Build export structure
	export := je.buildExport(patches, points)

	// Validate structure
	if err := je.validate(export); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	// Marshal to JSON with indentation
	data, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	// Write to file
	if err := os.WriteFile(filepath, data, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// ExportToFileWithThreshold exports patches with confidence >= threshold to a JSON file
func (je *JSONExporter) ExportToFileWithThreshold(patches []*GeneratedPatch, points []PatchPoint, filepath string, threshold float64) error {
	// Filter patches and points by confidence threshold
	filteredPatches, filteredPoints := je.filterByConfidence(patches, points, threshold)

	// Use standard export with filtered data
	return je.ExportToFile(filteredPatches, filteredPoints, filepath)
}

// ExportToString exports patches to a JSON string
func (je *JSONExporter) ExportToString(patches []*GeneratedPatch, points []PatchPoint) (string, error) {
	// Build export structure
	export := je.buildExport(patches, points)

	// Validate structure
	if err := je.validate(export); err != nil {
		return "", fmt.Errorf("validation failed: %w", err)
	}

	// Marshal to JSON with indentation
	data, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON: %w", err)
	}

	return string(data), nil
}

// ExportToStringWithThreshold exports patches with confidence >= threshold to a JSON string
func (je *JSONExporter) ExportToStringWithThreshold(patches []*GeneratedPatch, points []PatchPoint, threshold float64) (string, error) {
	// Filter patches and points by confidence threshold
	filteredPatches, filteredPoints := je.filterByConfidence(patches, points, threshold)

	// Use standard export with filtered data
	return je.ExportToString(filteredPatches, filteredPoints)
}

// buildExport constructs the JSONExport structure
func (je *JSONExporter) buildExport(patches []*GeneratedPatch, points []PatchPoint) *JSONExport {
	export := &JSONExport{
		SchemaVersion: "2.0.0",
		Capabilities:  []string{"stable_patch_id", "signature_identity", "apply_safety", "block_patch", "independent_revert"},
		Version:       je.version,
		Timestamp:     time.Now().UTC(),
		Generator:     "ML Patcher",
		Patches:       make([]JSONPatch, 0, len(patches)),
	}

	// Build patch map for quick lookup
	patchMap := make(map[string]*GeneratedPatch)
	for _, patch := range patches {
		if patch != nil {
			key := patchLookupKey(patch.FilePath, patch.MethodName, patch.MethodSignature)
			patchMap[key] = patch
		}
	}

	// Convert patches with corresponding points
	for _, point := range points {
		key := patchLookupKey(point.FilePath, point.MethodName, point.MethodSignature)
		patch := patchMap[key]
		if patch == nil {
			patch = patchMap[legacyPatchLookupKey(point.FilePath, point.MethodName)]
		}

		if patch == nil {
			// Create minimal patch from point if patch not found
			patch = &GeneratedPatch{
				MethodName:  point.MethodName,
				FilePath:    point.FilePath,
				PatchType:   point.SuggestedPatch,
				Description: point.PatchDesc,
				Confidence:  point.Confidence,
			}
		}

		jsonPatch := JSONPatch{
			SchemaVersion: "2.0.0",
			PatchID:       stablePatchID(point.FilePath, point.MethodName, point.MethodSignature, ""),
			// Location
			FilePath:        point.FilePath,
			ClassName:       point.ClassName,
			MethodName:      point.MethodName,
			MethodSignature: point.MethodSignature,

			// Code
			OriginalCode: patch.OriginalCode,
			PatchedCode:  patch.PatchedCode,
			DiffView:     patch.DiffView,
			UnifiedDiff:  "",

			// Patch metadata
			PatchType:   patch.PatchType,
			Description: patch.Description,
			Mode:        patch.Mode,

			// Explanation
			Explanation: patch.Explanation,

			// Confidence
			Confidence:          patch.Confidence,
			ConfidenceBreakdown: patch.ConfidenceBreakdown,
			CategoryConfidence:  point.CategoryConfidence,
			ApplySafe:           false,
			ApplySafetyLevel:    "blocked",
			SafetyReasons:       []string{"validated patch artifact is unavailable"},

			// Risk
			RiskScore: point.RiskScore,
			RiskLevel: point.RiskLevel,

			// Category
			Category:     point.Category,
			CategoryName: point.CategoryName,
		}
		if patch.Artifact != nil {
			// The artifact carries the FULL, canonicalized method body (not the
			// report-truncated OriginalCode). This is what a downstream applier
			// must match against on disk, so prefer it for the apply fields.
			if patch.Artifact.OriginalCode != "" {
				jsonPatch.OriginalCode = patch.Artifact.OriginalCode
			}
			if patch.Artifact.PatchedCode != "" {
				jsonPatch.PatchedCode = patch.Artifact.PatchedCode
			}
			jsonPatch.UnifiedDiff = patch.Artifact.UnifiedDiff
			jsonPatch.OriginalHash = patch.Artifact.OriginalHash
			jsonPatch.PatchedHash = patch.Artifact.PatchedHash
			if patch.Artifact.PatchID != "" {
				jsonPatch.PatchID = patch.Artifact.PatchID
			}
			if patch.Artifact.SchemaVersion != "" {
				jsonPatch.SchemaVersion = patch.Artifact.SchemaVersion
			}
			jsonPatch.ValidatorErrors = patch.Artifact.Validation.Errors
			jsonPatch.ApplySafe = patch.Artifact.ApplySafety.CanWrite
			jsonPatch.ApplySafetyLevel = patch.Artifact.ApplySafety.Level
			jsonPatch.SafetyReasons = append([]string(nil), patch.Artifact.ApplySafety.Reasons...)
			if jsonPatch.ApplySafe {
				if _, _, err := patch.Artifact.ValidatedBodies(); err != nil {
					jsonPatch.ApplySafe = false
					jsonPatch.ApplySafetyLevel = "blocked"
					jsonPatch.SafetyReasons = append(jsonPatch.SafetyReasons, err.Error())
				}
			}
			if bp := patch.Artifact.BlockPatch; bp != nil {
				jsonPatch.BlockStartLine = bp.StartLine
				jsonPatch.BlockEndLine = bp.EndLine
				jsonPatch.BlockOriginalCode = strings.Join(bp.OriginalLines, "\n")
				jsonPatch.BlockPatchedCode = strings.Join(bp.PatchedLines, "\n")
				jsonPatch.BlockOriginalHash = bp.OriginalHash
				jsonPatch.BlockPatchedHash = bp.PatchedHash
			}
			exportedArtifact := *patch.Artifact
			exportedArtifact.ApplySafety = ApplySafety{
				Safe:     patch.Artifact.ApplySafety.Safe && jsonPatch.ApplySafe,
				CanWrite: jsonPatch.ApplySafe,
				Level:    jsonPatch.ApplySafetyLevel,
				Reasons:  append([]string(nil), jsonPatch.SafetyReasons...),
			}
			export.Artifacts = append(export.Artifacts, exportedArtifact)
		}

		export.Patches = append(export.Patches, jsonPatch)
	}

	// Build summary
	export.Summary = je.buildSummary(export.Patches)

	return export
}

// buildSummary calculates summary statistics
func (je *JSONExporter) buildSummary(patches []JSONPatch) JSONSummary {
	summary := JSONSummary{
		TotalPatches: len(patches),
		ByMode:       make(map[string]int),
		ByRiskLevel:  make(map[string]int),
		ByCategory:   make(map[string]int),
	}

	if len(patches) == 0 {
		return summary
	}

	totalConfidence := 0.0

	for _, patch := range patches {
		// Count by mode
		if patch.Mode != "" {
			summary.ByMode[string(patch.Mode)]++
		}

		// Count by risk level
		summary.ByRiskLevel[string(patch.RiskLevel)]++

		// Count by category
		summary.ByCategory[string(patch.Category)]++

		// Accumulate confidence
		totalConfidence += patch.Confidence

		// Count confidence tiers
		if patch.Confidence >= 0.8 {
			summary.HighConfidence++
		} else if patch.Confidence >= 0.5 {
			summary.MediumConfidence++
		} else {
			summary.LowConfidence++
		}
	}

	// Calculate average confidence
	summary.AvgConfidence = totalConfidence / float64(len(patches))

	return summary
}

// validate checks the JSON structure before writing
func (je *JSONExporter) validate(export *JSONExport) error {
	if export == nil {
		return fmt.Errorf("export is nil")
	}

	// Validate metadata
	if export.Version == "" {
		return fmt.Errorf("version is empty")
	}

	if export.Timestamp.IsZero() {
		return fmt.Errorf("timestamp is zero")
	}

	if export.Generator == "" {
		return fmt.Errorf("generator is empty")
	}

	// Validate patches
	if export.Patches == nil {
		return fmt.Errorf("patches array is nil")
	}

	for i, patch := range export.Patches {
		if err := je.validatePatch(&patch, i); err != nil {
			return fmt.Errorf("patch %d: %w", i, err)
		}
	}

	// Validate summary
	if err := je.validateSummary(&export.Summary, len(export.Patches)); err != nil {
		return fmt.Errorf("summary: %w", err)
	}

	return nil
}

// validatePatch validates a single patch
func (je *JSONExporter) validatePatch(patch *JSONPatch, _ int) error {
	// Required fields
	if patch.FilePath == "" {
		return fmt.Errorf("file_path is empty")
	}

	if patch.MethodName == "" {
		return fmt.Errorf("method_name is empty")
	}

	if patch.PatchType == "" {
		return fmt.Errorf("patch_type is empty")
	}

	// Validate confidence range
	if patch.Confidence < 0.0 || patch.Confidence > 1.0 {
		return fmt.Errorf("confidence %f out of range [0.0, 1.0]", patch.Confidence)
	}

	// Validate risk score range
	if patch.RiskScore < 0.0 || patch.RiskScore > 100.0 {
		return fmt.Errorf("risk_score %f out of range [0.0, 100.0]", patch.RiskScore)
	}

	return nil
}

// validateSummary validates the summary section
func (je *JSONExporter) validateSummary(summary *JSONSummary, patchCount int) error {
	if summary.TotalPatches != patchCount {
		return fmt.Errorf("total_patches %d does not match actual count %d",
			summary.TotalPatches, patchCount)
	}

	// Validate confidence tier counts sum to total
	confidenceSum := summary.HighConfidence + summary.MediumConfidence + summary.LowConfidence
	if confidenceSum != patchCount {
		return fmt.Errorf("confidence tier counts %d do not sum to total %d",
			confidenceSum, patchCount)
	}

	// Validate average confidence range
	if patchCount > 0 {
		if summary.AvgConfidence < 0.0 || summary.AvgConfidence > 1.0 {
			return fmt.Errorf("avg_confidence %f out of range [0.0, 1.0]",
				summary.AvgConfidence)
		}
	}

	return nil
}

// filterByConfidence filters patches and points by confidence threshold
func (je *JSONExporter) filterByConfidence(patches []*GeneratedPatch, points []PatchPoint, threshold float64) ([]*GeneratedPatch, []PatchPoint) {
	// Build patch map for quick lookup
	patchMap := make(map[string]*GeneratedPatch)
	for _, patch := range patches {
		if patch != nil {
			key := patchLookupKey(patch.FilePath, patch.MethodName, patch.MethodSignature)
			patchMap[key] = patch
		}
	}

	// Filter points by confidence
	filteredPoints := []PatchPoint{}
	for _, point := range points {
		if point.Confidence >= threshold {
			filteredPoints = append(filteredPoints, point)
		}
	}

	// Filter patches to match filtered points
	filteredPatches := []*GeneratedPatch{}
	for _, point := range filteredPoints {
		key := patchLookupKey(point.FilePath, point.MethodName, point.MethodSignature)
		patch, exists := patchMap[key]
		if !exists {
			patch, exists = patchMap[legacyPatchLookupKey(point.FilePath, point.MethodName)]
		}
		if exists {
			filteredPatches = append(filteredPatches, patch)
		}
	}

	return filteredPatches, filteredPoints
}
