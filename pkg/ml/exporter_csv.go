package ml

import (
	"encoding/csv"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
// CSV EXPORTER — exports patches in spreadsheet-compatible format
//
// Features:
//   - Export patches with key fields for data analysis
//   - Include file path, class, method, signature
//   - Include patch type, mode, confidence, risk score, risk level
//   - Include category and description
//   - Add timestamp and version metadata in header comments
//   - Handle special characters, commas, quotes properly
// ═══════════════════════════════════════════════════════════════════════════════

// CSVExporter exports patches to CSV format
type CSVExporter struct {
	version string
}

// NewCSVExporter creates a new CSV exporter
func NewCSVExporter() *CSVExporter {
	return &CSVExporter{
		version: "1.0.0", // ML Patcher version
	}
}

// ExportToFile exports patches to a CSV file
func (ce *CSVExporter) ExportToFile(patches []*GeneratedPatch, points []PatchPoint, filepath string) error {
	// Generate CSV content
	content, err := ce.ExportToString(patches, points)
	if err != nil {
		return fmt.Errorf("failed to generate CSV: %w", err)
	}

	// Write to file
	if err := os.WriteFile(filepath, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// ExportToFileWithThreshold exports patches with confidence >= threshold to a CSV file
func (ce *CSVExporter) ExportToFileWithThreshold(patches []*GeneratedPatch, points []PatchPoint, filepath string, threshold float64) error {
	// Filter patches and points by confidence threshold
	filteredPatches, filteredPoints := ce.filterByConfidence(patches, points, threshold)

	// Use standard export with filtered data
	return ce.ExportToFile(filteredPatches, filteredPoints, filepath)
}

// ExportToString exports patches to a CSV string
func (ce *CSVExporter) ExportToString(patches []*GeneratedPatch, points []PatchPoint) (string, error) {
	var b strings.Builder
	writer := csv.NewWriter(&b)

	// Write header comments with metadata
	timestamp := time.Now().UTC().Format(time.RFC3339)
	b.WriteString("# ML Patcher CSV Export\n")
	b.WriteString(fmt.Sprintf("# Version: %s\n", ce.version))
	b.WriteString(fmt.Sprintf("# Timestamp: %s\n", timestamp))
	b.WriteString("# Generator: ML Patcher\n")
	b.WriteString(fmt.Sprintf("# Total Patches: %d\n", len(points)))
	b.WriteString("#\n")

	// Write CSV header row
	header := []string{
		"File Path",
		"Class Name",
		"Method Name",
		"Method Signature",
		"Patch Type",
		"Mode",
		"Confidence",
		"Risk Score",
		"Risk Level",
		"Category",
		"Description",
	}

	if err := writer.Write(header); err != nil {
		return "", fmt.Errorf("failed to write header: %w", err)
	}

	// Build patch map for quick lookup
	patchMap := make(map[string]*GeneratedPatch)
	for _, patch := range patches {
		if patch != nil {
			key := patchLookupKey(patch.FilePath, patch.MethodName, patch.MethodSignature)
			patchMap[key] = patch
		}
	}

	// Write data rows
	for _, point := range points {
		key := patchLookupKey(point.FilePath, point.MethodName, point.MethodSignature)
		patch := patchMap[key]
		if patch == nil {
			patch = patchMap[legacyPatchLookupKey(point.FilePath, point.MethodName)]
		}

		// Get mode from patch or default to empty
		mode := ""
		if patch != nil && patch.Mode != "" {
			mode = string(patch.Mode)
		}

		// Get description from patch or point
		description := ""
		if patch != nil && patch.Description != "" {
			description = patch.Description
		} else if point.PatchDesc != "" {
			description = point.PatchDesc
		}

		// Build row
		row := []string{
			ce.sanitize(point.FilePath),
			ce.sanitize(point.ClassName),
			ce.sanitize(point.MethodName),
			ce.sanitize(point.MethodSignature),
			ce.sanitize(string(point.SuggestedPatch)),
			ce.sanitize(mode),
			ce.formatFloat(point.Confidence),
			ce.formatFloat(point.RiskScore),
			ce.sanitize(string(point.RiskLevel)),
			ce.sanitize(string(point.Category)),
			ce.sanitize(description),
		}

		if err := writer.Write(row); err != nil {
			return "", fmt.Errorf("failed to write row: %w", err)
		}
	}

	// Flush writer
	writer.Flush()
	if err := writer.Error(); err != nil {
		return "", fmt.Errorf("CSV writer error: %w", err)
	}

	return b.String(), nil
}

// ExportToStringWithThreshold exports patches with confidence >= threshold to a CSV string
func (ce *CSVExporter) ExportToStringWithThreshold(patches []*GeneratedPatch, points []PatchPoint, threshold float64) (string, error) {
	// Filter patches and points by confidence threshold
	filteredPatches, filteredPoints := ce.filterByConfidence(patches, points, threshold)

	// Use standard export with filtered data
	return ce.ExportToString(filteredPatches, filteredPoints)
}

// sanitize prepares a string for CSV output
// Handles special characters, newlines, and ensures proper escaping
func (ce *CSVExporter) sanitize(s string) string {
	// Replace newlines with spaces
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")

	// Trim whitespace
	s = strings.TrimSpace(s)

	// The csv.Writer will handle quotes and commas automatically
	return s
}

// formatFloat formats a float64 to a string with 2 decimal places
func (ce *CSVExporter) formatFloat(f float64) string {
	return strconv.FormatFloat(f, 'f', 2, 64)
}

// filterByConfidence filters patches and points by confidence threshold
func (ce *CSVExporter) filterByConfidence(patches []*GeneratedPatch, points []PatchPoint, threshold float64) ([]*GeneratedPatch, []PatchPoint) {
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
