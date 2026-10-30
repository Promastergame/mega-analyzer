// Moved out of the monolithic web_ui.go. See doc.go for the package map.

package web

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

func runAnalysis(exe string, job *scanJob, args []string) {
	defer job.cleanupUpload()
	// This runs on its own goroutine: an unrecovered panic here used to take
	// the whole analyzer process down, browser session included.
	defer func() {
		if rec := recover(); rec != nil {
			job.broadcast(fmt.Sprintf("[error] internal panic: %v", rec))
			job.finish(2)
		}
	}()
	cmd := exec.Command(exe, args...)
	cmd.Env = os.Environ()
	var stopInput io.WriteCloser
	if job.mode == "intercept" {
		var err error
		stopInput, err = cmd.StdinPipe()
		if err != nil {
			job.broadcast("[error] failed to create proxy control pipe: " + err.Error())
			job.finish(1)
			return
		}
		defer stopInput.Close()
	}
	processDone := make(chan struct{})
	defer close(processDone)
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	// Serialize Start with stop, so cancellation cannot miss a new process.
	job.mu.Lock()
	if job.stopped {
		job.mu.Unlock()
		job.finish(130)
		return
	}
	job.cmd = cmd
	job.stopInput = stopInput
	job.processDone = processDone
	err := cmd.Start()
	job.mu.Unlock()
	if err != nil {
		job.broadcast("[error] failed to start: " + err.Error())
		job.finish(1)
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)
	pipe := func(r io.Reader) {
		defer wg.Done()
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		sc.Split(scanLinesAnyBreak)

		// A progress bar repaints far faster than anyone can read. Hold the most
		// recent redraw and emit at most one per progressThrottle, always
		// flushing before a real log line so ordering is preserved and never
		// dropping the final state.
		var pending string
		var lastEmit time.Time
		flush := func() {
			if pending != "" {
				job.broadcast(pending)
				pending = ""
			}
		}
		for sc.Scan() {
			line := stripANSI(sc.Text())
			if strings.TrimSpace(line) == "" {
				continue
			}
			if isProgressLine(line) {
				pending = line
				if time.Since(lastEmit) >= progressThrottle {
					flush()
					lastEmit = time.Now()
				}
				continue
			}
			flush()
			job.broadcast(line)
		}
		flush()
		if err := sc.Err(); err != nil {
			job.broadcast("[warn] log stream truncated: " + err.Error())
			// Keep draining after a long line stops Scanner. Otherwise the child
			// blocks on a full pipe and never exits, leaving wg.Wait stuck too.
			_, _ = io.Copy(io.Discard, r)
		}
	}
	go pipe(stdout)
	go pipe(stderr)
	wg.Wait()

	code := 0
	if err := cmd.Wait(); err != nil {
		if ex, ok := err.(*exec.ExitError); ok {
			code = ex.ExitCode()
		} else {
			code = 1
		}
	}
	job.finish(code)

}
