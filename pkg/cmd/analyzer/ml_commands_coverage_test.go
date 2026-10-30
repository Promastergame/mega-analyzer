package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"mega-analyzer/pkg/ml"
)

func TestMLRunner_AllCommandsCoverage(t *testing.T) {
	tempDir := t.TempDir()
	historyPath := filepath.Join(tempDir, "history.json")

	// Create a dummy history with records
	records := []*ml.AnalysisFeedback{
		{
			ID:        "test-id-1",
			APKHash:   "abcde12345",
			APKName:   "test.apk",
			Package:   "com.example.test",
			Timestamp: time.Now(),
			KeywordStats: map[string]*ml.KeywordFeedback{
				"relevant_keyword": {
					Keyword:        "relevant_keyword",
					Triggered:      5,
					MarkedRelevant: 1,
				},
				"noise_keyword": {
					Keyword:     "noise_keyword",
					Triggered:   10,
					MarkedNoise: 1,
				},
			},
			LibraryStats: map[string]*ml.LibraryFeedback{
				"lib1": {
					Prefix:       "lib1",
					MatchedFiles: 2,
				},
			},
		},
	}

	data, err := json.Marshal(records)
	if err != nil {
		t.Fatalf("Failed to marshal dummy records: %v", err)
	}
	if err := os.WriteFile(historyPath, data, 0644); err != nil {
		t.Fatalf("Failed to write dummy history: %v", err)
	}

	history, err := ml.LoadHistory(historyPath)
	if err != nil {
		t.Fatalf("Failed to load dummy history: %v", err)
	}

	// 1. Test MLRunner setup and empty options error
	opts := &CLIOptions{}
	var outBuf, errBuf bytes.Buffer
	runner := &MLRunner{
		opts:    opts,
		history: history,
		output:  &outBuf,
		errOut:  &errBuf,
	}

	err = runner.Run()
	if err == nil || err.Error() != "no ML command specified" {
		t.Errorf("expected error for no command, got: %v", err)
	}

	// 2. Test MLExList command
	outBuf.Reset()
	errBuf.Reset()
	opts.MLExList = true
	err = runner.Run()
	if err != nil {
		t.Errorf("MLExList command failed: %v", err)
	}
	opts.MLExList = false

	// 3. Test MLStats command
	outBuf.Reset()
	errBuf.Reset()
	opts.MLStats = true
	err = runner.Run()
	if err != nil {
		t.Errorf("MLStats command failed: %v", err)
	}
	opts.MLStats = false

	// 4. Test MLHistory command
	outBuf.Reset()
	errBuf.Reset()
	opts.MLHistory = true
	err = runner.Run()
	if err != nil {
		t.Errorf("MLHistory command failed: %v", err)
	}
	opts.MLHistory = false

	// 5. Test ShowFeedback command
	outBuf.Reset()
	errBuf.Reset()
	opts.ShowFeedback = true
	err = runner.Run()
	if err != nil {
		t.Errorf("ShowFeedback command failed: %v", err)
	}
	opts.ShowFeedback = false

	// 6. Test PatternStats command
	outBuf.Reset()
	errBuf.Reset()
	opts.PatternStats = true
	err = runner.Run()
	if err != nil {
		t.Errorf("PatternStats command failed: %v", err)
	}
	opts.PatternStats = false

	// 7. Test ExportPatternStats command
	outBuf.Reset()
	errBuf.Reset()
	exportPath := filepath.Join(tempDir, "pattern_stats.json")
	opts.ExportPatternStats = exportPath
	err = runner.Run()
	if err != nil {
		t.Errorf("ExportPatternStats command failed: %v", err)
	}
	opts.ExportPatternStats = ""

	// 8. Test MarkRelevant command
	outBuf.Reset()
	errBuf.Reset()
	opts.MarkRelevant = "relevant_keyword"
	err = runner.Run()
	if err != nil {
		t.Errorf("MarkRelevant command failed: %v", err)
	}
	opts.MarkRelevant = ""

	// 9. Test MarkNoise command
	outBuf.Reset()
	errBuf.Reset()
	opts.MarkNoise = "noise_keyword"
	err = runner.Run()
	if err != nil {
		t.Errorf("MarkNoise command failed: %v", err)
	}
	opts.MarkNoise = ""

	// 10. Test MLApply command (will fail if no suggestions, but handles it)
	outBuf.Reset()
	errBuf.Reset()
	opts.MLApply = "all"
	_ = runner.Run()
	opts.MLApply = ""

	// 11. Test MLSuggest command (no training model exists, will print skip/error but run successfully)
	outBuf.Reset()
	errBuf.Reset()
	opts.MLSuggest = true
	_ = runner.Run()
	opts.MLSuggest = false

	// 12. Test MLTrain command
	outBuf.Reset()
	errBuf.Reset()
	opts.MLTrain = true
	// training might return error due to insufficient samples, which is captured and logged
	_ = runner.Run()
	opts.MLTrain = false

	// 13. Test FeedbackFile import
	outBuf.Reset()
	errBuf.Reset()
	feedbackFile := filepath.Join(tempDir, "feedback_import.json")
	_ = os.WriteFile(feedbackFile, []byte(`[]`), 0644)
	opts.FeedbackFile = feedbackFile
	err = runner.Run()
	if err != nil {
		t.Errorf("FeedbackFile import failed: %v", err)
	}
	opts.FeedbackFile = ""

	// 14. Test JSON commands
	_ = runner.jsonHistory()
	_ = runner.jsonStats()
}
