package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/config"
	"mega-analyzer/pkg/internal/types"
)

func TestCoreRunMetadataMarksPartialAndDoesNotRecordSecrets(t *testing.T) {
	opts := &CLIOptions{Timeout: 42, DecisionAIURL: "http://localhost:9999/private"}
	cfg := &config.Config{Workers: 2, MaxFileSizeMB: 16, LogFile: "private-path.log"}
	result := &types.AnalysisResult{}
	for _, tc := range []struct {
		err    error
		reason string
	}{
		{context.Canceled, "cancelled"}, {context.DeadlineExceeded, "timeout"},
	} {
		run := coreRunMetadata(opts, cfg, result, tc.err)
		if run.Status != "incomplete" || run.StopReason != tc.reason {
			t.Fatalf("partial scan marked complete: %+v", run)
		}
		data, err := json.Marshal(run)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "private") {
			t.Fatalf("run metadata included a private option: %s", data)
		}
		if run.CoreSettings["max_file_size_mb"] != 16 || run.TimeoutSeconds != 42 {
			t.Fatal("effective scan limits were lost")
		}
	}
	result.Coverage.ParseFailed = 1
	if coreRunMetadata(opts, cfg, result, nil).Status != "incomplete" {
		t.Fatal("parser failures marked complete")
	}
}
