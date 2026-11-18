package scanjobs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

type CommandRunner struct {
	executable string
	maxOutput  int
	// maxMemoryBytes caps the child analyzer's GC heap via GOMEMLIMIT.
	// Non-positive means unlimited (legacy behaviour).
	maxMemoryBytes int64
}

func NewCommandRunner(executable string, maxOutput int) (*CommandRunner, error) {
	return NewCommandRunnerWithLimits(executable, maxOutput, 0)
}

// NewCommandRunnerWithLimits additionally budgets the child process memory.
// maxMemoryBytes <= 0 leaves the child unlimited. The budget is enforced
// through GOMEMLIMIT: the spawned analyzer is our own Go binary, so the Go
// runtime keeps the heap under the limit with aggressive GC instead of
// growing until the host OOM-killer steps in. This is stdlib-only and
// cross-platform; a hard OS cap (cgroups, Job Objects) is intentionally not
// attempted here — it needs privileges and per-OS facilities, while a soft
// GC budget degrades gracefully: the job fails with a clear Go OOM message
// (surfaced as "job memory limit exceeded", see Manager.run) instead of
// taking down neighbouring jobs.
func NewCommandRunnerWithLimits(executable string, maxOutput int, maxMemoryBytes int64) (*CommandRunner, error) {
	if executable == "" {
		var err error
		executable, err = os.Executable()
		if err != nil {
			return nil, fmt.Errorf("resolve analyzer executable: %w", err)
		}
	}
	abs, err := filepath.Abs(executable)
	if err != nil {
		return nil, fmt.Errorf("resolve analyzer executable: %w", err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("stat analyzer executable: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("analyzer executable is not a regular file")
	}
	if maxOutput <= 0 {
		maxOutput = 256 << 10
	}
	return &CommandRunner{executable: abs, maxOutput: maxOutput, maxMemoryBytes: maxMemoryBytes}, nil
}

// buildCmd assembles the child command (seam for tests asserting the
// memory budget without spawning a process).
func (r *CommandRunner) buildCmd(ctx context.Context, request Request, outputDir string) *exec.Cmd {
	args := []string{"--target", request.Target, "--output", outputDir, "--quiet", "--no-color"}
	if request.EnableMedia {
		args = append(args, "--enable-media")
	}
	if request.ExtractPS1 {
		args = append(args, "--extract-ps1")
	}

	cmd := exec.CommandContext(ctx, r.executable, args...)
	if r.maxMemoryBytes > 0 {
		cmd.Env = append(os.Environ(), "GOMEMLIMIT="+strconv.FormatInt(r.maxMemoryBytes, 10))
	}
	return cmd
}

func (r *CommandRunner) Run(ctx context.Context, request Request, outputDir string) (RunResult, error) {
	output := &boundedBuffer{limit: r.maxOutput}
	cmd := r.buildCmd(ctx, request, outputDir)
	// The analyzer may spawn children (aapt2, apksigner, adb). Without these
	// two lines a timed-out child holding stdout/stderr kept cmd.Run() alive
	// forever and orphaned the rest of the tree.
	cmd.WaitDelay = 5 * time.Second
	killProcessTree(cmd)
	cmd.Stdout = output
	cmd.Stderr = output
	err := cmd.Run()
	return RunResult{Output: output.String(), OutputTruncated: output.Truncated()}, err
}

type boundedBuffer struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	written := len(p)
	remaining := b.limit - b.buf.Len()
	if remaining <= 0 {
		b.truncated = true
		return written, nil
	}
	if len(p) > remaining {
		_, _ = b.buf.Write(p[:remaining])
		b.truncated = true
		return written, nil
	}
	_, _ = b.buf.Write(p)
	return written, nil
}

func (b *boundedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *boundedBuffer) Truncated() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.truncated
}
