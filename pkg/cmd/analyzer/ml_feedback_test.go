package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"mega-analyzer/pkg/ml"
)

func TestMLRunner_ImportFeedback(t *testing.T) {
	// Create temporary directory for test
	tempDir := t.TempDir()

	// Create a test feedback file
	feedbackFile := filepath.Join(tempDir, "feedback.json")
	feedback := []map[string]string{
		{"pattern_id": "test_pattern_1", "outcome": "true_positive"},
		{"pattern_id": "test_pattern_2", "outcome": "false_positive"},
		{"pattern_id": "test_pattern_3", "outcome": "false_negative"},
	}

	data, err := json.MarshalIndent(feedback, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal feedback: %v", err)
	}

	if err := os.WriteFile(feedbackFile, data, 0644); err != nil {
		t.Fatalf("Failed to write feedback file: %v", err)
	}

	// Create test history directory
	historyDir := filepath.Join(tempDir, ".omnisec")
	if err := os.MkdirAll(historyDir, 0755); err != nil {
		t.Fatalf("Failed to create history dir: %v", err)
	}

	// Create empty history file
	historyFile := filepath.Join(historyDir, "history.json")
	emptyHistory, err := ml.LoadHistory(historyFile)
	if err != nil {
		t.Fatalf("Failed to create history: %v", err)
	}
	if err := emptyHistory.Save(); err != nil {
		t.Fatalf("Failed to save history file: %v", err)
	}

	// Create options with feedback file
	opts := &CLIOptions{
		FeedbackFile: feedbackFile,
		Quiet:        true,
	}

	// Override default paths for testing
	originalHome := os.Getenv("HOME")
	if originalHome == "" {
		originalHome = os.Getenv("USERPROFILE")
	}
	os.Setenv("HOME", tempDir)
	os.Setenv("USERPROFILE", tempDir)
	defer func() {
		os.Setenv("HOME", originalHome)
		os.Setenv("USERPROFILE", originalHome)
	}()

	// Create ML runner
	runner, err := NewMLRunner(opts)
	if err != nil {
		t.Fatalf("Failed to create ML runner: %v", err)
	}

	// Import feedback
	if err := runner.importFeedback(); err != nil {
		t.Fatalf("importFeedback() failed: %v", err)
	}

	// Get the actual metrics path that was used
	metricsPath, err := ml.DefaultPatternMetricsPath()
	if err != nil {
		t.Fatalf("Failed to get metrics path: %v", err)
	}

	// Verify metrics were saved
	if _, err := os.Stat(metricsPath); os.IsNotExist(err) {
		t.Errorf("Pattern metrics file was not created at %s", metricsPath)
	}

	// Load and verify metrics
	tracker := ml.NewPatternTracker()
	if err := tracker.LoadFromFile(metricsPath); err != nil {
		t.Fatalf("Failed to load metrics: %v", err)
	}

	// Check that patterns were recorded
	metrics := tracker.GetAllMetrics()
	if len(metrics) != 3 {
		t.Errorf("Expected 3 patterns, got %d", len(metrics))
	}

	// Verify specific pattern metrics
	pattern1 := tracker.GetMetrics("test_pattern_1")
	if pattern1 == nil {
		t.Error("Pattern test_pattern_1 not found")
	} else {
		if pattern1.TruePositives != 1 {
			t.Errorf("Pattern test_pattern_1: expected 1 true positive, got %d", pattern1.TruePositives)
		}
	}

	pattern2 := tracker.GetMetrics("test_pattern_2")
	if pattern2 == nil {
		t.Error("Pattern test_pattern_2 not found")
	} else {
		if pattern2.FalsePositives != 1 {
			t.Errorf("Pattern test_pattern_2: expected 1 false positive, got %d", pattern2.FalsePositives)
		}
	}

	pattern3 := tracker.GetMetrics("test_pattern_3")
	if pattern3 == nil {
		t.Error("Pattern test_pattern_3 not found")
	} else {
		if pattern3.FalseNegatives != 1 {
			t.Errorf("Pattern test_pattern_3: expected 1 false negative, got %d", pattern3.FalseNegatives)
		}
	}

	// False-negative feedback means the signal was missed and must be boosted,
	// not suppressed as noise in the direct override layer.
	decision, ok := ml.FindUserOverrideDecision(runner.history.Snapshot(), "test_pattern_3", true)
	if !ok || decision.Action != ml.FeedbackRelevant {
		t.Fatalf("false negative must create a relevant override, got %+v (found=%v)", decision, ok)
	}
}

func TestMLRunner_ImportFeedback_InvalidFile(t *testing.T) {
	tempDir := t.TempDir()

	opts := &CLIOptions{
		FeedbackFile: filepath.Join(tempDir, "nonexistent.json"),
		Quiet:        true,
	}

	// Create test history
	historyDir := filepath.Join(tempDir, ".omnisec")
	if err := os.MkdirAll(historyDir, 0755); err != nil {
		t.Fatalf("Failed to create history dir: %v", err)
	}

	historyFile := filepath.Join(historyDir, "history.json")
	emptyHistory, err := ml.LoadHistory(historyFile)
	if err != nil {
		t.Fatalf("Failed to create history: %v", err)
	}
	if err := emptyHistory.Save(); err != nil {
		t.Fatalf("Failed to save history file: %v", err)
	}

	// Override paths
	originalHome := os.Getenv("HOME")
	if originalHome == "" {
		originalHome = os.Getenv("USERPROFILE")
	}
	os.Setenv("HOME", tempDir)
	os.Setenv("USERPROFILE", tempDir)
	defer func() {
		os.Setenv("HOME", originalHome)
		os.Setenv("USERPROFILE", originalHome)
	}()

	runner, err := NewMLRunner(opts)
	if err != nil {
		t.Fatalf("Failed to create ML runner: %v", err)
	}

	// Should fail with file not found
	err = runner.importFeedback()
	if err == nil {
		t.Error("Expected error for nonexistent file, got nil")
	}
}

func TestMLRunner_ImportFeedback_InvalidJSON(t *testing.T) {
	tempDir := t.TempDir()

	// Create invalid JSON file
	feedbackFile := filepath.Join(tempDir, "invalid.json")
	if err := os.WriteFile(feedbackFile, []byte("not valid json"), 0644); err != nil {
		t.Fatalf("Failed to write invalid JSON: %v", err)
	}

	opts := &CLIOptions{
		FeedbackFile: feedbackFile,
		Quiet:        true,
	}

	// Create test history
	historyDir := filepath.Join(tempDir, ".omnisec")
	if err := os.MkdirAll(historyDir, 0755); err != nil {
		t.Fatalf("Failed to create history dir: %v", err)
	}

	historyFile := filepath.Join(historyDir, "history.json")
	emptyHistory, err := ml.LoadHistory(historyFile)
	if err != nil {
		t.Fatalf("Failed to create history: %v", err)
	}
	if err := emptyHistory.Save(); err != nil {
		t.Fatalf("Failed to save history file: %v", err)
	}

	// Override paths
	originalHome := os.Getenv("HOME")
	if originalHome == "" {
		originalHome = os.Getenv("USERPROFILE")
	}
	os.Setenv("HOME", tempDir)
	os.Setenv("USERPROFILE", tempDir)
	defer func() {
		os.Setenv("HOME", originalHome)
		os.Setenv("USERPROFILE", originalHome)
	}()

	runner, err := NewMLRunner(opts)
	if err != nil {
		t.Fatalf("Failed to create ML runner: %v", err)
	}

	// Should fail with JSON parse error
	err = runner.importFeedback()
	if err == nil {
		t.Error("Expected error for invalid JSON, got nil")
	}
}
