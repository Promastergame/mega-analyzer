// Moved out of the monolithic web_ui.go. See doc.go for the package map.

package web

import (
	"context"
	"encoding/json"
	"io"
	"mega-analyzer/pkg/internal/androidsdk"
	"mega-analyzer/pkg/internal/vmware"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// jobTrimBatch is how many lines are dropped at once when the buffer is full.
const jobTrimBatch = 4096

type scanJob struct {
	onFinish       func(*scanJob) error
	id             string
	tmpDir         string
	outDir         string
	filename       string
	mode           string
	sandboxSession string
	deviceSerial   string
	vmwareScreen   func(context.Context) ([]byte, error) // bound to the active guest; never accepts a client VM path
	vmwareConsole  *vmware.Console

	mu            sync.Mutex
	lines         []string // log buffer, trimmed to maxJobLines
	base          int      // absolute index of lines[0]
	lineBytes     int
	logFile       *os.File // opened by the workspace; written as output arrives
	logDir        string
	logBytes      int
	logTruncated  bool
	liveTruncated bool
	logErr        error
	done          bool
	state         string
	stopped       bool
	exitCode      int
	// uploadBytes holds this job's web-upload temp bytes for the aggregate
	// budget gauge. Set once before the job is submitted; released exactly
	// once by cleanupUpload, which is the single choke point for temp-dir
	// lifetime (runAnalysis defer, queue cancel, shutdown path via stop+run
	// return). Guarded by the queue mutex happens-before, not j.mu.
	uploadBytes int64
	cmd         *exec.Cmd          // set for subprocess-backed modes
	stopInput   io.WriteCloser     // EOF asks a managed MITM child to stop and flush
	processDone <-chan struct{}    // closes after subprocess output has drained
	cancel      context.CancelFunc // set for in-process modes (sandbox)
	updated     chan struct{}      // closed + replaced whenever state changes
	started     time.Time
}

// newScanJob builds a job with its notification channel ready. Always use this
// instead of a bare &scanJob{} literal: a nil `updated` channel would park every
// reader forever.
func newScanJob(id, tmpDir, outDir string) *scanJob {
	return &scanJob{
		id:      id,
		tmpDir:  tmpDir,
		outDir:  outDir,
		started: time.Now(),
		updated: make(chan struct{}),
		state:   "running",
	}
}

// wakeLocked releases every reader parked on `updated`. Caller must hold mu.
func (j *scanJob) wakeLocked() {
	close(j.updated)
	j.updated = make(chan struct{})
}

// broadcast appends a line and wakes all readers.
//
// This must never block on a consumer. The previous implementation pushed each
// line into per-listener bounded channels and, worse, replayed the backlog into
// a 512-slot channel while holding j.mu — so any job that produced more than 512
// lines deadlocked the mutex, which in turn blocked broadcast() and finish()
// forever. Readers now pull from the shared slice by cursor instead.
func (j *scanJob) broadcast(line string) {
	j.mu.Lock()
	if j.logDir != "" && !j.done && j.logFile == nil && j.logErr == nil {
		root, err := os.OpenRoot(j.logDir)
		if err == nil {
			j.logFile, err = root.OpenFile("scan.log", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			root.Close()
		}
		j.logErr = err
	}
	// Disk captures the original line before the bounded live preview is made.
	if j.logFile != nil && j.logErr == nil {
		if len(line)+1 > maxWorkspaceLog-j.logBytes {
			j.logTruncated = true
		} else {
			var n int
			n, j.logErr = io.WriteString(j.logFile, line+"\n")
			j.logBytes += n
		}
	}
	if len(line) > maxJobLineBytes {
		const suffix = " [live line truncated; see scan.log]"
		end := maxJobLineBytes - len(suffix)
		for end > 0 && !utf8.RuneStart(line[end]) {
			end--
		}
		line = strings.Clone(line[:end]) + suffix
		j.liveTruncated = true
	}
	var event struct {
		Type    string `json:"type"`
		Details string `json:"details"`
	}
	if json.Unmarshal([]byte(line), &event) == nil && event.Type == "report" && validSandboxSession(event.Details) {
		j.sandboxSession = event.Details
	}
	if event.Type == "device" && androidsdk.ValidDeviceSerial(event.Details) {
		j.deviceSerial = event.Details
	}
	j.lines = append(j.lines, line)
	j.lineBytes += len(line) + 1
	if len(j.lines) > maxJobLines || j.lineBytes > maxJobLogBytes {
		// Trim in batches: dropping exactly one line per append re-copied the
		// whole 200k-entry buffer on every single log line (O(n) per line).
		drop := 0
		for drop < len(j.lines)-1 && (len(j.lines)-drop > maxJobLines-jobTrimBatch || j.lineBytes > maxJobLogBytes*3/4) {
			j.lineBytes -= len(j.lines[drop]) + 1
			drop++
		}
		copy(j.lines, j.lines[drop:])
		for i := len(j.lines) - drop; i < len(j.lines); i++ {
			j.lines[i] = ""
		}
		j.lines = j.lines[:len(j.lines)-drop]
		j.base += drop
	}
	j.wakeLocked()
	j.mu.Unlock()
}

// read returns every line at or after absolute index `from`, the next cursor,
// the terminal state, and the channel to wait on for more. It never blocks.
func (j *scanJob) read(from int) (lines []string, next int, done bool, code int, wait <-chan struct{}) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if from < j.base {
		from = j.base
	}
	if idx := from - j.base; idx >= 0 && idx < len(j.lines) {
		lines = append(lines, j.lines[idx:]...)
	}
	return lines, j.base + len(j.lines), j.done, j.exitCode, j.updated
}

func (j *scanJob) finish(code int) {
	j.mu.Lock()
	first := !j.done
	if first {
		if j.logFile != nil {
			if err := j.logFile.Close(); j.logErr == nil {
				j.logErr = err
			}
			j.logFile = nil
		}
		j.done = true
		j.exitCode = code
		j.state = "completed"
		if code != 0 {
			j.state = "failed"
		}
		if j.stopped {
			j.state = "stopped"
		}
	}
	callback := j.onFinish
	j.mu.Unlock()
	if first && callback != nil {
		if err := callback(j); err != nil {
			j.broadcast("[warn] cannot persist scan: " + workspaceError(err))
		}
	}
	j.mu.Lock()
	j.wakeLocked()
	j.mu.Unlock()
}

// isDone reports whether the job reached a terminal state.
func (j *scanJob) isDone() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.done
}

// stop closes managed MITM input to let it flush the capture, with a bounded
// kill fallback. Other subprocesses and in-process modes retain their cleanup.
func (j *scanJob) stop() {
	j.mu.Lock()
	if j.done || j.stopped {
		j.mu.Unlock()
		return
	}
	c, cancel := j.cmd, j.cancel
	input, processDone := j.stopInput, j.processDone
	j.stopped = true
	if input == nil && c != nil && c.Process != nil {
		_ = c.Process.Kill()
	}
	j.mu.Unlock()
	if input != nil {
		_ = input.Close()
		if c != nil && c.Process != nil {
			go func() {
				timer := time.NewTimer(5 * time.Second)
				defer timer.Stop()
				select {
				case <-processDone:
				case <-timer.C:
					_ = c.Process.Kill()
				}
			}()
		}
	}
	if cancel != nil {
		cancel()
	}
}

func (j *scanJob) status() string {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.state
}

func (j *scanJob) cleanupUpload() {
	if j.tmpDir != "" {
		_ = os.RemoveAll(j.tmpDir)
	}
	if n := j.uploadBytes; n > 0 {
		j.uploadBytes = 0
		uploadInflightBytes.Add(-n)
	}
}

func validSandboxSession(id string) bool {
	if id == "" || len(id) > 160 || strings.ContainsAny(id, "/\\.") {
		return false
	}
	for _, r := range id {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-') {
			return false
		}
	}
	return true
}
