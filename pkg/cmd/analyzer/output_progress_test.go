package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// Redirected (non-TTY) progress must be rare newline-terminated lines, not
// \r repaints: a long run redirected to a file appended megabytes of nearly
// identical bar snapshots (subwaysurf 4MB run log).
func TestPrintProgress_PlainModeThrottlesSpam(t *testing.T) {
	var buf bytes.Buffer
	o := NewOutputWithWriter(NoColorTheme(), false, &buf)

	// 200 rapid updates within the same percent bucket.
	for i := 0; i < 200; i++ {
		o.PrintProgress("scan_and_analyze", 5606+i, 65376)
	}
	lines := strings.Count(buf.String(), "\n")
	if lines > 3 {
		t.Fatalf("expected throttled plain progress (<=3 lines), got %d:\n%s", lines, buf.String())
	}
	if strings.Contains(buf.String(), "\r") {
		t.Fatal("plain progress must not contain carriage returns")
	}
	if !strings.Contains(buf.String(), "scan_and_analyze") {
		t.Fatal("expected stage name in plain progress output")
	}
}

// Stalled workers (same counters, only elapsed-seconds status changing)
// must stay silent in plain mode.
func TestPrintProgressStatus_PlainModeSilencesStall(t *testing.T) {
	var buf bytes.Buffer
	o := NewOutputWithWriter(NoColorTheme(), false, &buf)

	for sec := 33; sec < 90; sec++ {
		o.PrintProgressStatus("scan_and_analyze", 5606, 65376,
			fmt.Sprintf("analyzing classes2.dex · 1719/8311 · %ds · +3 active", sec))
	}
	lines := strings.Count(buf.String(), "\n")
	if lines > 3 {
		t.Fatalf("expected stalled progress to stay silent (<=3 lines), got %d", lines)
	}
}

// Completion must always print, even right after throttled updates.
func TestPrintProgress_PlainModeAlwaysCompletes(t *testing.T) {
	var buf bytes.Buffer
	o := NewOutputWithWriter(NoColorTheme(), false, &buf)

	o.PrintProgress("scan_and_analyze", 5606, 65376)
	buf.Reset()
	o.PrintProgress("scan_and_analyze", 65376, 65376)
	if !strings.Contains(buf.String(), "100%") {
		t.Fatalf("expected completion line with 100%%, got %q", buf.String())
	}
}

func TestClearProgress_PlainModeWritesNothing(t *testing.T) {
	var buf bytes.Buffer
	o := NewOutputWithWriter(NoColorTheme(), false, &buf)

	o.ClearProgress()
	if buf.Len() != 0 {
		t.Fatalf("expected no output from ClearProgress in plain mode, got %q", buf.String())
	}
}
