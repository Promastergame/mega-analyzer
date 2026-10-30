// Package piracy — limits.go
// Hard safety limits to keep analysis bounded.
package piracy

const (
	// MaxFindingsPerFile bounds the number of findings produced per file.
	// Prevents pathological cases where a file matches thousands of patterns.
	MaxFindingsPerFile = 500

	// MaxRegexMatchesPerPattern bounds regex scanning work if we ever iterate.
	// (Currently we only record the first match per regex.)
	MaxRegexMatchesPerPattern = 100

	// MaxFileSize is an internal guardrail for single-file analysis.
	// Note: Detector.Analyze also truncates content to MaxAnalysisSize.
	MaxFileSize = 50 * 1024 * 1024 // 50MB
)
