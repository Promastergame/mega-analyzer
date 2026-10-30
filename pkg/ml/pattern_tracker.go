package ml

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
// PATTERN TRACKER — Phase 4: Pattern Effectiveness Tracking
// ═══════════════════════════════════════════════════════════════════════════════
//
// This module implements pattern effectiveness tracking for the ML Patcher
// Improvements spec (Requirements 8.1, 8.2, 8.3, 8.4).
//
// PatternTracker records pattern outcomes (true positives, false positives,
// false negatives), calculates metrics (precision, recall, F1), and identifies
// low-performing patterns.

// OutcomeType represents the outcome of a pattern match
type OutcomeType string

const (
	OutcomeTruePositive  OutcomeType = "true_positive"
	OutcomeFalsePositive OutcomeType = "false_positive"
	OutcomeFalseNegative OutcomeType = "false_negative"
)

// PatternTracker manages pattern effectiveness metrics
type PatternTracker struct {
	metrics map[string]*PatternMetrics
	mu      sync.RWMutex
}

// NewPatternTracker creates a new PatternTracker instance
func NewPatternTracker() *PatternTracker {
	return &PatternTracker{
		metrics: make(map[string]*PatternMetrics),
	}
}

// RecordOutcome records a pattern match outcome and updates metrics
func (pt *PatternTracker) RecordOutcome(patternID string, outcome OutcomeType) {
	if patternID == "" {
		return
	}
	switch outcome {
	case OutcomeTruePositive, OutcomeFalsePositive, OutcomeFalseNegative:
	default:
		return
	}

	pt.mu.Lock()
	defer pt.mu.Unlock()

	// Get or create metrics for this pattern
	if _, exists := pt.metrics[patternID]; !exists {
		pt.metrics[patternID] = &PatternMetrics{
			PatternID: patternID,
		}
	}

	m := pt.metrics[patternID]

	// Update counts based on outcome
	switch outcome {
	case OutcomeTruePositive:
		m.TruePositives++
	case OutcomeFalsePositive:
		m.FalsePositives++
	case OutcomeFalseNegative:
		m.FalseNegatives++
	}

	// Update total matches and timestamp
	m.TotalMatches = m.TruePositives + m.FalsePositives
	m.LastUpdated = time.Now()

	// Recalculate metrics
	pt.calculateMetrics(m)
}

// calculateMetrics calculates precision, recall, and F1 score for a pattern
func (pt *PatternTracker) calculateMetrics(m *PatternMetrics) {
	// Precision = TP / (TP + FP)
	if m.TotalMatches > 0 {
		m.Precision = float64(m.TruePositives) / float64(m.TotalMatches)
	} else {
		m.Precision = 0.0
	}

	// Recall = TP / (TP + FN)
	totalRelevant := m.TruePositives + m.FalseNegatives
	if totalRelevant > 0 {
		m.Recall = float64(m.TruePositives) / float64(totalRelevant)
	} else {
		m.Recall = 0.0
	}

	// F1 = 2 * (Precision * Recall) / (Precision + Recall)
	if m.Precision+m.Recall > 0 {
		m.F1Score = 2 * (m.Precision * m.Recall) / (m.Precision + m.Recall)
	} else {
		m.F1Score = 0.0
	}
}

// GetLowPerformingPatterns returns patterns with precision below the threshold
// Only considers patterns with at least 10 total matches
func (pt *PatternTracker) GetLowPerformingPatterns(threshold float64) []string {
	pt.mu.RLock()
	defer pt.mu.RUnlock()

	lowPerforming := []string{}
	for patternID, m := range pt.metrics {
		if m.TotalMatches >= 10 && m.Precision < threshold {
			lowPerforming = append(lowPerforming, patternID)
		}
	}

	return lowPerforming
}

// GetMetrics returns the metrics for a specific pattern (thread-safe)
func (pt *PatternTracker) GetMetrics(patternID string) *PatternMetrics {
	pt.mu.RLock()
	defer pt.mu.RUnlock()

	if m, exists := pt.metrics[patternID]; exists {
		// Return a copy to prevent external modification
		metricsCopy := *m
		return &metricsCopy
	}

	return nil
}

// GetAllMetrics returns all pattern metrics (thread-safe)
func (pt *PatternTracker) GetAllMetrics() map[string]*PatternMetrics {
	pt.mu.RLock()
	defer pt.mu.RUnlock()

	// Return a copy of the metrics map
	result := make(map[string]*PatternMetrics, len(pt.metrics))
	for patternID, m := range pt.metrics {
		metricsCopy := *m
		result[patternID] = &metricsCopy
	}

	return result
}

// SaveToFile persists pattern metrics to a JSON file
func (pt *PatternTracker) SaveToFile(path string) error {
	pt.mu.RLock()
	data, err := json.MarshalIndent(pt.metrics, "", "  ")
	pt.mu.RUnlock()
	if err != nil {
		return fmt.Errorf("failed to marshal metrics: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("failed to create metrics directory: %w", err)
	}
	tmpPath := fmt.Sprintf("%s.%d.tmp", path, time.Now().UnixNano())
	defer os.Remove(tmpPath)
	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open temporary metrics file: %w", err)
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return fmt.Errorf("failed to write metrics file: %w", err)
	}
	if closeErr != nil {
		return fmt.Errorf("failed to close metrics file: %w", closeErr)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("failed to replace metrics file: %w", err)
	}

	return nil
}

// LoadFromFile loads pattern metrics from a JSON file
func (pt *PatternTracker) LoadFromFile(path string) error {
	// Read file
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist yet, not an error
			return nil
		}
		return fmt.Errorf("failed to read metrics file: %w", err)
	}

	// Unmarshal JSON
	var loadedMetrics map[string]*PatternMetrics
	err = json.Unmarshal(data, &loadedMetrics)
	if err != nil {
		return fmt.Errorf("failed to unmarshal metrics: %w", err)
	}

	if loadedMetrics == nil {
		loadedMetrics = make(map[string]*PatternMetrics)
	}
	// Persisted precision/recall values are derived data. Recalculate them from
	// counts so hand-edited, old, or partially written files cannot inject stale
	// model quality metrics.
	for patternID, metrics := range loadedMetrics {
		if metrics == nil {
			metrics = &PatternMetrics{PatternID: patternID}
			loadedMetrics[patternID] = metrics
		}
		if metrics.PatternID == "" {
			metrics.PatternID = patternID
		}
		metrics.TotalMatches = metrics.TruePositives + metrics.FalsePositives
		pt.calculateMetrics(metrics)
	}

	// Update metrics map
	pt.mu.Lock()
	defer pt.mu.Unlock()

	pt.metrics = loadedMetrics

	return nil
}
