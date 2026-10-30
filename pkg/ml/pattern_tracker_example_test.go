package ml_test

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"mega-analyzer/pkg/ml"
)

// Example demonstrates saving and loading pattern metrics
func Example_patternTrackerPersistence() {
	// Create a temporary directory for the example
	tmpDir, err := os.MkdirTemp("", "pattern_tracker_example")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	metricsFile := filepath.Join(tmpDir, "pattern_metrics.json")

	// Create a pattern tracker and record some outcomes
	tracker := ml.NewPatternTracker()

	// Record outcomes for pattern1
	tracker.RecordOutcome("root_detection_pattern", ml.OutcomeTruePositive)
	tracker.RecordOutcome("root_detection_pattern", ml.OutcomeTruePositive)
	tracker.RecordOutcome("root_detection_pattern", ml.OutcomeFalsePositive)

	// Record outcomes for pattern2
	tracker.RecordOutcome("premium_check_pattern", ml.OutcomeTruePositive)
	tracker.RecordOutcome("premium_check_pattern", ml.OutcomeTruePositive)
	tracker.RecordOutcome("premium_check_pattern", ml.OutcomeTruePositive)
	tracker.RecordOutcome("premium_check_pattern", ml.OutcomeTruePositive)

	// Save metrics to file
	err = tracker.SaveToFile(metricsFile)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Metrics saved successfully")

	// Create a new tracker and load the metrics
	newTracker := ml.NewPatternTracker()
	err = newTracker.LoadFromFile(metricsFile)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Metrics loaded successfully")

	// Retrieve and display metrics
	metrics := newTracker.GetMetrics("root_detection_pattern")
	if metrics != nil {
		fmt.Printf("Pattern: %s\n", metrics.PatternID)
		fmt.Printf("True Positives: %d\n", metrics.TruePositives)
		fmt.Printf("False Positives: %d\n", metrics.FalsePositives)
		fmt.Printf("Precision: %.2f\n", metrics.Precision)
	}

	// Output:
	// Metrics saved successfully
	// Metrics loaded successfully
	// Pattern: root_detection_pattern
	// True Positives: 2
	// False Positives: 1
	// Precision: 0.67
}
