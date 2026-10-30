package web

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestManagedProxyStopHelper(t *testing.T) {
	path := os.Getenv("MEGA_TEST_MANAGED_PROXY_CAPTURE")
	if path == "" {
		return
	}
	f, err := os.Create(path)
	if err != nil {
		os.Exit(2)
	}
	w := bufio.NewWriter(f)
	_, _ = w.WriteString("pending capture record\n")
	fmt.Println("proxy ready")
	_, _ = io.Copy(io.Discard, os.Stdin)
	if w.Flush() != nil || f.Close() != nil {
		os.Exit(3)
	}
	fmt.Println("capture flushed")
	os.Exit(0)
}

func TestManagedProxyStopFlushesCapture(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.jsonl")
	t.Setenv("MEGA_TEST_MANAGED_PROXY_CAPTURE", path)
	j := newScanJob("managed-proxy", "", "")
	j.mode = "intercept"
	done := make(chan struct{})
	go func() {
		runAnalysis(os.Args[0], j, []string{"-test.run=^TestManagedProxyStopHelper$"})
		close(done)
	}()
	defer j.stop()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	for {
		lines, _, finished, _, updated := j.read(0)
		if strings.Contains(strings.Join(lines, "\n"), "proxy ready") {
			break
		}
		if finished {
			t.Fatalf("helper exited before startup: %v", lines)
		}
		select {
		case <-updated:
		case <-deadline.C:
			t.Fatal("helper did not start")
		}
	}
	j.stop()
	j.stop() // repeated clicks must not interrupt graceful shutdown
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("managed proxy did not exit after stdin closed")
	}
	lines, _, finished, code, _ := j.read(0)
	if !finished || code != 0 || !strings.Contains(strings.Join(lines, "\n"), "capture flushed") {
		t.Fatalf("proxy was killed before flushing: code=%d logs=%v", code, lines)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "pending capture record\n" {
		t.Fatalf("buffered capture lost: %q, %v", data, err)
	}
}

func TestAnalysisLongOutputHelper(t *testing.T) {
	stream := os.Getenv("MEGA_TEST_LONG_OUTPUT_STREAM")
	if stream == "" {
		return
	}
	line := strings.Repeat("x", 4<<20) + "\n"
	if stream == "stdout" || stream == "both" {
		fmt.Fprint(os.Stdout, line)
	}
	if stream == "stderr" || stream == "both" {
		fmt.Fprint(os.Stderr, line)
	}
	os.Exit(0)
}

func TestRunAnalysisDrainsOversizedOutput(t *testing.T) {
	for _, stream := range []string{"stdout", "stderr", "both"} {
		t.Run(stream, func(t *testing.T) {
			t.Setenv("MEGA_TEST_LONG_OUTPUT_STREAM", stream)
			j := newScanJob("long-output", "", "")
			done := make(chan struct{})
			go func() {
				runAnalysis(os.Args[0], j, []string{"-test.run=^TestAnalysisLongOutputHelper$"})
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(15 * time.Second):
				j.stop()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("helper did not stop")
				}
				t.Fatal("analysis blocked after an oversized output line")
			}
			lines, _, finished, code, _ := j.read(0)
			if !finished || code != 0 {
				t.Fatalf("finished=%v exit=%d logs=%v", finished, code, lines)
			}
			if !strings.Contains(strings.Join(lines, "\n"), "log stream truncated") {
				t.Fatalf("missing truncation warning: %v", lines)
			}
		})
	}
}
