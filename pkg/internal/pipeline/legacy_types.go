//go:build legacy_pipeline
// +build legacy_pipeline

package pipeline

import (
	"errors"
	"os"
	"sync"

	"mega-analyzer/pkg/internal/parser"
	"mega-analyzer/pkg/internal/types"
)

// Severity is a legacy alias used by legacy_pipeline analyzers.
// Map it to ThreatSeverity to avoid name conflicts with existing constants.
type Severity = ThreatSeverity

// SeverityInfo is not present in ThreatSeverity; map it to the lowest level.
const SeverityInfo Severity = SeverityLow

// Category aliases the core types.Category enum for legacy analyzers.
type Category = types.Category

const (
	CategoryAds       Category = types.CategoryAdNetwork
	CategoryAnalytics Category = types.CategoryAnalytics
)

// FileType aliases core file types for legacy analyzers.
type FileType = types.FileType

const (
	FileTypeUnknown FileType = types.FileTypeUnknown
	FileTypeSmali   FileType = types.FileTypeSmali
	FileTypeXML     FileType = types.FileTypeXML
)

// AnalysisPhase is a legacy analyzer phase marker.
type AnalysisPhase uint8

const (
	PhaseQuickScan AnalysisPhase = iota
)

// Location describes where a finding was detected.
type Location struct {
	Path       string
	Line       int
	Column     int
	ClassName  string
	MethodName string
}

// LegacyFinding is a legacy finding representation used only by legacy analyzers.
type LegacyFinding struct {
	ID          string
	Title       string
	Description string
	Location    Location
	Severity    Severity
	Category    Category
	Confidence  float64
}

// CategoryResult groups findings for a category.
type CategoryResult struct {
	Category   Category
	Score      float64
	Confidence float64
	MatchCount int
	Severity   Severity
	Findings   []LegacyFinding
}

// AnalysisResult is a minimal legacy result used by legacy analyzers.
type AnalysisResult struct {
	File        *FileData
	ParseResult *ParseResult
	Categories  map[Category]CategoryResult
}

// ParseResult aliases the parser result for legacy analyzers.
type ParseResult = parser.ParseResult

// FileData is a minimal legacy file wrapper used by legacy analyzers.
type FileData struct {
	Path         string
	RelativePath string
	Type         FileType
	ContentBytes []byte

	contentOnce sync.Once
	contentErr  error
}

// Content returns file bytes, reading from disk if needed.
func (f *FileData) Content() ([]byte, error) {
	if f == nil {
		return nil, errors.New("file data is nil")
	}
	if f.ContentBytes != nil {
		return f.ContentBytes, nil
	}
	f.contentOnce.Do(func() {
		if f.Path == "" {
			f.contentErr = errors.New("file path is empty")
			return
		}
		f.ContentBytes, f.contentErr = os.ReadFile(f.Path)
	})
	return f.ContentBytes, f.contentErr
}
