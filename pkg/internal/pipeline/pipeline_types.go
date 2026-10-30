package pipeline

import (
	"strings"
	"unicode"

	"mega-analyzer/pkg/internal/types"
)

// ═══════════════════════════════════════════════════════════════════════════════
// CONFIDENCE
// ═══════════════════════════════════════════════════════════════════════════════

// Confidence represents how certain a finding is correct (0.0–1.0 scale).
type Confidence float64

const (
	ConfidenceWeak       Confidence = 0.2
	ConfidenceLow        Confidence = 0.4
	ConfidenceMedium     Confidence = 0.6
	ConfidenceHigh       Confidence = 0.8
	ConfidenceDefinitive Confidence = 1.0
)

func clampConfidence(confidence Confidence) Confidence {
	switch {
	case confidence < 0:
		return 0
	case confidence > 1:
		return 1
	default:
		return confidence
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// SOURCE KIND
// ═══════════════════════════════════════════════════════════════════════════════

// SourceKind describes the origin of the analysed content.
type SourceKind uint8

const (
	SourceKindUnknown SourceKind = iota
	SourceKindSmali
	SourceKindXML
	SourceKindNative
	SourceKindAsset
	SourceKindResource
	SourceKindConfig
)

func (sk SourceKind) String() string {
	switch sk {
	case SourceKindSmali:
		return "smali"
	case SourceKindXML:
		return "xml"
	case SourceKindNative:
		return "native"
	case SourceKindAsset:
		return "asset"
	case SourceKindResource:
		return "resource"
	case SourceKindConfig:
		return "config"
	default:
		return "unknown"
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// FINDING
// ═══════════════════════════════════════════════════════════════════════════════

// Finding represents a single security analysis result.
type Finding struct {
	Category   types.Category
	File       string
	Offset     int64
	Line       int
	SourceKind SourceKind
	Pattern    string
	Snippet    string
	Severity   types.Severity
	Confidence Confidence
	Score      float64
	IsCritical bool
}

// newBinaryFinding creates a Finding from a binary/text pattern match.
func newBinaryFinding(
	category types.Category,
	file string,
	offset int64,
	sourceKind SourceKind,
	label string,
	snippet string,
	severity types.Severity,
	confidence Confidence,
) Finding {
	confidence = clampConfidence(confidence)

	return Finding{
		Category:   category,
		File:       file,
		Offset:     offset,
		SourceKind: sourceKind,
		Pattern:    label,
		Snippet:    snippet,
		Severity:   severity,
		Confidence: confidence,
		Score:      baseScore(severity, confidence),
	}
}

// newFinding creates a Finding with explicit line information.
func newFinding(
	category types.Category,
	file string,
	offset int64,
	line int,
	sourceKind SourceKind,
	severity types.Severity,
	confidence Confidence,
	label string,
	snippet string,
	isCritical bool,
) Finding {
	confidence = clampConfidence(confidence)

	return Finding{
		Category:   category,
		File:       file,
		Offset:     offset,
		Line:       line,
		SourceKind: sourceKind,
		Pattern:    label,
		Snippet:    snippet,
		Severity:   severity,
		Confidence: confidence,
		Score:      baseScore(severity, confidence),
		IsCritical: isCritical,
	}
}

// baseScore computes the initial score from severity and confidence.
func baseScore(severity types.Severity, confidence Confidence) float64 {
	sevScore := float64(severity)
	if sevScore < 0 {
		sevScore = 0
	}
	return sevScore * 2.0 * float64(clampConfidence(confidence))
}

// safeSnippetStr returns a display-safe substring of content (string version).
// The pipeline also has safeSnippet([]byte, int, int) in accessibility_detector.go
// — this is the string overload used by security_heuristics.
func safeSnippetStr(content string, maxLen int) string {
	if maxLen <= 0 || content == "" {
		return ""
	}

	var b strings.Builder
	truncated := false
	runesWritten := 0
	lastWasSpace := true

	for _, r := range content {
		if runesWritten >= maxLen {
			truncated = true
			break
		}

		switch {
		case unicode.IsSpace(r):
			if lastWasSpace || b.Len() == 0 {
				continue
			}
			b.WriteByte(' ')
			runesWritten++
			lastWasSpace = true
		case unicode.IsPrint(r):
			b.WriteRune(r)
			runesWritten++
			lastWasSpace = false
		}
	}

	out := strings.TrimSpace(b.String())
	if truncated && out != "" {
		out += "…"
	}
	return out
}
