package apkloader

import (
	"strings"
	"sync"
)

// ═══════════════════════════════════════════════════════════════════════════════
// NAME QUALITY IMPROVEMENT: Enhanced Variable and Method Naming
// ═══════════════════════════════════════════════════════════════════════════════

// NameQualityAnalyzer analyzes and improves name quality.
type NameQualityAnalyzer struct {
	mu sync.RWMutex

	// API patterns database
	apiPatterns map[string][]string

	// String patterns for naming
	stringPatterns map[string][]string

	// Naming heuristics
	heuristics []NamingHeuristic

	// Statistics
	analyzedNames int
	improvedNames int
	confidenceSum float64
}

// NamingHeuristic represents a naming heuristic.
type NamingHeuristic struct {
	Name        string
	Pattern     string
	Replacement string
	Confidence  float64
}

// NewNameQualityAnalyzer creates a new name quality analyzer.
func NewNameQualityAnalyzer() *NameQualityAnalyzer {
	analyzer := &NameQualityAnalyzer{
		apiPatterns:    make(map[string][]string),
		stringPatterns: make(map[string][]string),
		heuristics:     make([]NamingHeuristic, 0),
	}

	analyzer.initializePatterns()
	analyzer.initializeHeuristics()

	return analyzer
}

// initializePatterns initializes API and string patterns.
func (nqa *NameQualityAnalyzer) initializePatterns() {
	// Android API patterns
	nqa.apiPatterns["Intent"] = []string{
		"putExtra", "getExtra", "setAction", "setData", "setType",
		"setClass", "setComponent", "setFlags", "addFlags",
	}

	nqa.apiPatterns["SharedPreferences"] = []string{
		"getSharedPreferences", "edit", "putString", "putInt", "putBoolean",
		"getString", "getInt", "getBoolean", "remove", "clear",
	}

	nqa.apiPatterns["Cipher"] = []string{
		"getInstance", "init", "doFinal", "update", "getBlockSize",
	}

	nqa.apiPatterns["MessageDigest"] = []string{
		"getInstance", "digest", "update", "reset",
	}

	nqa.apiPatterns["File"] = []string{
		"exists", "isFile", "isDirectory", "length", "delete",
		"mkdir", "mkdirs", "listFiles", "getAbsolutePath",
	}

	// String patterns for naming
	nqa.stringPatterns["crypto"] = []string{
		"encrypt", "decrypt", "cipher", "hash", "digest", "key", "secret",
		"aes", "rsa", "md5", "sha", "hmac",
	}

	nqa.stringPatterns["license"] = []string{
		"license", "verify", "check", "validate", "expired", "valid",
		"activation", "serial", "key",
	}

	nqa.stringPatterns["network"] = []string{
		"http", "https", "socket", "connect", "send", "receive",
		"request", "response", "url", "host", "port",
	}

	nqa.stringPatterns["file"] = []string{
		"file", "read", "write", "open", "close", "path", "directory",
		"save", "load", "delete", "exists",
	}

	nqa.stringPatterns["logging"] = []string{
		"log", "debug", "info", "warn", "error", "trace", "print",
		"logger", "message", "level",
	}
}

// initializeHeuristics initializes naming heuristics.
func (nqa *NameQualityAnalyzer) initializeHeuristics() {
	nqa.heuristics = []NamingHeuristic{
		{
			Name:        "CamelCaseDetection",
			Pattern:     "^[a-z]+([A-Z][a-z]+)*$",
			Replacement: "CamelCase",
			Confidence:  0.9,
		},
		{
			Name:        "SnakeCaseDetection",
			Pattern:     "^[a-z]+(_[a-z]+)*$",
			Replacement: "snake_case",
			Confidence:  0.85,
		},
		{
			Name:        "PrefixDetection",
			Pattern:     "^(m|s|_)[A-Z]",
			Replacement: "HasPrefix",
			Confidence:  0.8,
		},
		{
			Name:        "AbbreviationDetection",
			Pattern:     "^[A-Z]{2,}$",
			Replacement: "Abbreviation",
			Confidence:  0.75,
		},
	}
}

// AnalyzeName analyzes a single name and returns quality metrics.
func (nqa *NameQualityAnalyzer) AnalyzeName(name string) NameQualityMetrics {
	nqa.mu.Lock()
	nqa.analyzedNames++
	nqa.mu.Unlock()

	metrics := NameQualityMetrics{
		OriginalName:      name,
		Length:            len(name),
		IsReadable:        nqa.isReadable(name),
		HasMeaningfulPart: nqa.hasMeaningfulPart(name),
		ConfidenceScore:   0.5,
	}

	// Check for meaningful parts
	if nqa.hasMeaningfulPart(name) {
		metrics.ConfidenceScore += 0.2
	}

	// Check readability
	if metrics.IsReadable {
		metrics.ConfidenceScore += 0.15
	}

	// Check length
	if metrics.Length > 3 && metrics.Length < 50 {
		metrics.ConfidenceScore += 0.15
	}

	return metrics
}

// isReadable checks if a name is readable.
func (nqa *NameQualityAnalyzer) isReadable(name string) bool {
	if len(name) < 2 {
		return false
	}

	// Check for camelCase or snake_case
	hasCamelCase := strings.ContainsAny(name, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	hasSnakeCase := strings.Contains(name, "_")

	return hasCamelCase || hasSnakeCase
}

// hasMeaningfulPart checks if name contains meaningful parts.
func (nqa *NameQualityAnalyzer) hasMeaningfulPart(name string) bool {
	lowerName := strings.ToLower(name)

	for _, patterns := range nqa.stringPatterns {
		for _, pattern := range patterns {
			if strings.Contains(lowerName, pattern) {
				return true
			}
		}
	}

	return false
}

// GetAPIPatterns returns API patterns for a category.
func (nqa *NameQualityAnalyzer) GetAPIPatterns(category string) []string {
	nqa.mu.RLock()
	defer nqa.mu.RUnlock()

	return nqa.apiPatterns[category]
}

// AddAPIPattern adds a new API pattern.
func (nqa *NameQualityAnalyzer) AddAPIPattern(category string, pattern string) {
	nqa.mu.Lock()
	defer nqa.mu.Unlock()

	if _, exists := nqa.apiPatterns[category]; !exists {
		nqa.apiPatterns[category] = make([]string, 0)
	}

	nqa.apiPatterns[category] = append(nqa.apiPatterns[category], pattern)
}

// GetStringPatterns returns string patterns for a category.
func (nqa *NameQualityAnalyzer) GetStringPatterns(category string) []string {
	nqa.mu.RLock()
	defer nqa.mu.RUnlock()

	return nqa.stringPatterns[category]
}

// AddStringPattern adds a new string pattern.
func (nqa *NameQualityAnalyzer) AddStringPattern(category string, pattern string) {
	nqa.mu.Lock()
	defer nqa.mu.Unlock()

	if _, exists := nqa.stringPatterns[category]; !exists {
		nqa.stringPatterns[category] = make([]string, 0)
	}

	nqa.stringPatterns[category] = append(nqa.stringPatterns[category], pattern)
}

// GetHeuristics returns all naming heuristics.
func (nqa *NameQualityAnalyzer) GetHeuristics() []NamingHeuristic {
	nqa.mu.RLock()
	defer nqa.mu.RUnlock()

	return nqa.heuristics
}

// GetStatistics returns analysis statistics.
func (nqa *NameQualityAnalyzer) GetStatistics() NameQualityStatistics {
	nqa.mu.RLock()
	defer nqa.mu.RUnlock()

	avgConfidence := 0.0
	if nqa.analyzedNames > 0 {
		avgConfidence = nqa.confidenceSum / float64(nqa.analyzedNames)
	}

	return NameQualityStatistics{
		AnalyzedNames:     nqa.analyzedNames,
		ImprovedNames:     nqa.improvedNames,
		AverageConfidence: avgConfidence,
	}
}

// NameQualityMetrics holds metrics for a single name.
type NameQualityMetrics struct {
	OriginalName      string
	Length            int
	IsReadable        bool
	HasMeaningfulPart bool
	ConfidenceScore   float64
}

// NameQualityStatistics holds overall statistics.
type NameQualityStatistics struct {
	AnalyzedNames     int
	ImprovedNames     int
	AverageConfidence float64
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONFIDENCE SCORING CALIBRATION
// ═══════════════════════════════════════════════════════════════════════════════

// ConfidenceCalibratorator calibrates confidence scores.
type ConfidenceCalibrator struct {
	mu sync.RWMutex

	// Calibration data
	predictions []float64
	actuals     []float64

	// Calibration metrics
	meanError         float64
	stdDeviation      float64
	calibrationFactor float64
}

// NewConfidenceCalibrator creates a new confidence calibrator.
func NewConfidenceCalibrator() *ConfidenceCalibrator {
	return &ConfidenceCalibrator{
		predictions:       make([]float64, 0),
		actuals:           make([]float64, 0),
		calibrationFactor: 1.0,
	}
}

// RecordPrediction records a prediction and actual value.
func (cc *ConfidenceCalibrator) RecordPrediction(predicted, actual float64) {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	cc.predictions = append(cc.predictions, predicted)
	cc.actuals = append(cc.actuals, actual)
}

// CalibrateScore calibrates a confidence score.
func (cc *ConfidenceCalibrator) CalibrateScore(score float64) float64 {
	cc.mu.RLock()
	defer cc.mu.RUnlock()

	calibrated := score * cc.calibrationFactor
	if calibrated > 1.0 {
		calibrated = 1.0
	}
	if calibrated < 0.0 {
		calibrated = 0.0
	}

	return calibrated
}

// GetCalibrationMetrics returns calibration metrics.
func (cc *ConfidenceCalibrator) GetCalibrationMetrics() (meanError, stdDev, factor float64) {
	cc.mu.RLock()
	defer cc.mu.RUnlock()

	return cc.meanError, cc.stdDeviation, cc.calibrationFactor
}

// ═══════════════════════════════════════════════════════════════════════════════
// NAME FILTERING AND RANKING
// ═══════════════════════════════════════════════════════════════════════════════

// NameFilter filters names based on criteria.
type NameFilter struct {
	minLength       int
	maxLength       int
	minConfidence   float64
	requireReadable bool
}

// NewNameFilter creates a new name filter.
func NewNameFilter() *NameFilter {
	return &NameFilter{
		minLength:       2,
		maxLength:       100,
		minConfidence:   0.5,
		requireReadable: true,
	}
}

// SetMinLength sets minimum name length.
func (nf *NameFilter) SetMinLength(length int) {
	nf.minLength = length
}

// SetMaxLength sets maximum name length.
func (nf *NameFilter) SetMaxLength(length int) {
	nf.maxLength = length
}

// SetMinConfidence sets minimum confidence threshold.
func (nf *NameFilter) SetMinConfidence(confidence float64) {
	nf.minConfidence = confidence
}

// SetRequireReadable sets whether readable names are required.
func (nf *NameFilter) SetRequireReadable(require bool) {
	nf.requireReadable = require
}

// Filter filters a list of names.
func (nf *NameFilter) Filter(names []NameQualityMetrics) []NameQualityMetrics {
	var filtered []NameQualityMetrics

	for _, name := range names {
		if nf.matches(name) {
			filtered = append(filtered, name)
		}
	}

	return filtered
}

// matches checks if a name matches filter criteria.
func (nf *NameFilter) matches(name NameQualityMetrics) bool {
	if name.Length < nf.minLength || name.Length > nf.maxLength {
		return false
	}

	if name.ConfidenceScore < nf.minConfidence {
		return false
	}

	if nf.requireReadable && !name.IsReadable {
		return false
	}

	return true
}

// NameRanker ranks names by quality.
type NameRanker struct {
	weights map[string]float64
}

// NewNameRanker creates a new name ranker.
func NewNameRanker() *NameRanker {
	return &NameRanker{
		weights: map[string]float64{
			"confidence":     0.4,
			"readability":    0.3,
			"meaningfulness": 0.2,
			"length":         0.1,
		},
	}
}

// Rank ranks a name and returns a score.
func (nr *NameRanker) Rank(name NameQualityMetrics) float64 {
	score := 0.0

	// Confidence score
	score += name.ConfidenceScore * nr.weights["confidence"]

	// Readability score
	readabilityScore := 0.0
	if name.IsReadable {
		readabilityScore = 1.0
	}
	score += readabilityScore * nr.weights["readability"]

	// Meaningfulness score
	meaningfulnessScore := 0.0
	if name.HasMeaningfulPart {
		meaningfulnessScore = 1.0
	}
	score += meaningfulnessScore * nr.weights["meaningfulness"]

	// Length score (prefer names between 5-20 chars)
	lengthScore := 0.0
	if name.Length >= 5 && name.Length <= 20 {
		lengthScore = 1.0
	} else if name.Length >= 3 && name.Length <= 30 {
		lengthScore = 0.7
	}
	score += lengthScore * nr.weights["length"]

	return score
}

// RankNames ranks a list of names.
func (nr *NameRanker) RankNames(names []NameQualityMetrics) []NameQualityMetrics {
	// Create a copy to avoid modifying original
	ranked := make([]NameQualityMetrics, len(names))
	copy(ranked, names)

	// Sort by rank (simple bubble sort for small lists)
	for i := 0; i < len(ranked); i++ {
		for j := i + 1; j < len(ranked); j++ {
			if nr.Rank(ranked[j]) > nr.Rank(ranked[i]) {
				ranked[i], ranked[j] = ranked[j], ranked[i]
			}
		}
	}

	return ranked
}
