// Package scanjobs owns the lifecycle of asynchronous analyzer runs.
//
// The package deliberately does not depend on the HTTP API. This keeps job
// isolation, cancellation and resource limits reusable by CLI, API and future
// distributed workers.
package scanjobs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type State string

const (
	StateQueued    State = "queued"
	StateRunning   State = "running"
	StateSucceeded State = "succeeded"
	StateFailed    State = "failed"
	StateCanceled  State = "canceled"
)

var (
	ErrQueueFull     = errors.New("scan queue is full")
	ErrJobNotFound   = errors.New("scan job not found")
	ErrJobNotReady   = errors.New("scan job is not complete")
	ErrInvalidReport = errors.New("invalid report name")
)

type Request struct {
	Target      string `json:"-"`
	ArtifactID  string `json:"artifact_id,omitempty"`
	EnableMedia bool   `json:"enable_media,omitempty"`
	ExtractPS1  bool   `json:"extract_ps1,omitempty"`
}

type RunResult struct {
	Output          string
	OutputTruncated bool
}

// Runner executes a single scan. Implementations must honor ctx cancellation
// and write reports only inside outputDir.
type Runner interface {
	Run(ctx context.Context, request Request, outputDir string) (RunResult, error)
}

type Config struct {
	RootDir        string
	MaxConcurrent  int
	QueueSize      int
	Timeout        time.Duration
	MaxOutputBytes int
	MaxUploadBytes int64
	Runner         Runner

	// MaxJobMemoryBytes budgets one job's child-process heap (see
	// NewCommandRunnerWithLimits). Non-positive means unlimited. The manager
	// itself does not enforce the budget — the runner passes it to the
	// child — but when set, a Go out-of-memory signature in a failed job's
	// output is reported as "job memory limit exceeded" instead of a bare
	// exit error, so operators can tell a budgeted kill from a real crash.
	MaxJobMemoryBytes int64

	// Retention: how many terminal (succeeded/failed/canceled) jobs stay in
	// memory and on disk before the janitor prunes them, and how long
	// uploaded artifacts live. Zero selects the defaults; negative disables
	// the janitor entirely.
	MaxFinishedJobs int
	ArtifactTTL     time.Duration
}

type Snapshot struct {
	ID              string    `json:"id"`
	State           State     `json:"state"`
	ArtifactID      string    `json:"artifact_id,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	StartedAt       time.Time `json:"started_at,omitempty"`
	FinishedAt      time.Time `json:"finished_at,omitempty"`
	Error           string    `json:"error,omitempty"`
	Output          string    `json:"output,omitempty"`
	OutputTruncated bool      `json:"output_truncated,omitempty"`
	Reports         []string  `json:"reports,omitempty"`
}

type job struct {
	snapshot  Snapshot
	request   Request
	outputDir string
	ctx       context.Context
	cancel    context.CancelFunc
	done      chan struct{}
	doneOnce  sync.Once
}

type Manager struct {
	cfg    Config
	root   string
	ctx    context.Context
	cancel context.CancelFunc

	mu    sync.RWMutex
	jobs  map[string]*job
	queue chan string
	start sync.Once
	wg    sync.WaitGroup
	close sync.Once
}

func NewManager(cfg Config) (*Manager, error) {
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = 2
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 32
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Minute
	}
	if cfg.MaxOutputBytes <= 0 {
		cfg.MaxOutputBytes = 256 << 10
	}
	if cfg.MaxUploadBytes <= 0 {
		cfg.MaxUploadBytes = 1 << 30
	}
	if cfg.Runner == nil {
		return nil, errors.New("scan runner is required")
	}
	if cfg.MaxFinishedJobs == 0 {
		cfg.MaxFinishedJobs = 100
	}
	if cfg.ArtifactTTL == 0 {
		cfg.ArtifactTTL = 24 * time.Hour
	}

	root := strings.TrimSpace(cfg.RootDir)
	if root == "" {
		cacheDir, err := os.UserCacheDir()
		if err != nil {
			return nil, fmt.Errorf("resolve user cache directory: %w", err)
		}
		root = filepath.Join(cacheDir, "mega-analyzer", "api")
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve scan root: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(absRoot, "jobs"), 0o700); err != nil {
		return nil, fmt.Errorf("create jobs directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(absRoot, "artifacts"), 0o700); err != nil {
		return nil, fmt.Errorf("create artifacts directory: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &Manager{
		cfg:    cfg,
		root:   absRoot,
		ctx:    ctx,
		cancel: cancel,
		jobs:   make(map[string]*job),
		queue:  make(chan string, cfg.QueueSize),
	}, nil
}

func (m *Manager) RootDir() string       { return m.root }
func (m *Manager) MaxUploadBytes() int64 { return m.cfg.MaxUploadBytes }

func (m *Manager) startWorkers() {
	m.start.Do(func() {
		for i := 0; i < m.cfg.MaxConcurrent; i++ {
			m.wg.Add(1)
			go m.worker()
		}
		if m.cfg.MaxFinishedJobs > 0 && m.cfg.ArtifactTTL > 0 {
			m.wg.Add(1)
			go m.janitor()
		}
	})
}

// janitor bounds memory and disk growth: the jobs map used to retain every
// job (with up to MaxOutputBytes of output each) forever, and uploaded
// artifacts were never deleted. Runs until Close().
func (m *Manager) janitor() {
	defer m.wg.Done()
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.prune()
		}
	}
}

func (m *Manager) prune() {
	now := time.Now().UTC()

	m.mu.Lock()
	terminal := make([]*job, 0, len(m.jobs))
	for _, j := range m.jobs {
		if isTerminal(j.snapshot.State) {
			terminal = append(terminal, j)
		}
	}
	sort.Slice(terminal, func(i, k int) bool {
		return terminal[i].snapshot.FinishedAt.After(terminal[k].snapshot.FinishedAt)
	})
	var doomed []string
	if len(terminal) > m.cfg.MaxFinishedJobs {
		for _, j := range terminal[m.cfg.MaxFinishedJobs:] {
			delete(m.jobs, j.snapshot.ID)
			if j.outputDir != "" {
				doomed = append(doomed, j.outputDir)
			}
		}
	}
	m.mu.Unlock()
	for _, dir := range doomed {
		_ = os.RemoveAll(dir)
	}

	// Artifact retention.
	entries, err := os.ReadDir(filepath.Join(m.root, "artifacts"))
	if err != nil {
		return
	}
	for _, entry := range entries {
		info, statErr := entry.Info()
		if statErr != nil || !entry.Type().IsRegular() {
			continue
		}
		if now.Sub(info.ModTime()) > m.cfg.ArtifactTTL {
			_ = os.Remove(filepath.Join(m.root, "artifacts", entry.Name()))
		}
	}
}

func (m *Manager) Submit(request Request) (Snapshot, error) {
	if strings.TrimSpace(request.Target) == "" {
		return Snapshot{}, errors.New("scan target is required")
	}
	id, err := randomID()
	if err != nil {
		return Snapshot{}, err
	}
	outputDir := filepath.Join(m.root, "jobs", id)
	if err := os.Mkdir(outputDir, 0o700); err != nil {
		return Snapshot{}, fmt.Errorf("create job directory: %w", err)
	}

	jobCtx, cancel := context.WithCancel(m.ctx)
	j := &job{
		snapshot: Snapshot{
			ID:         id,
			State:      StateQueued,
			ArtifactID: request.ArtifactID,
			CreatedAt:  time.Now().UTC(),
		},
		request:   request,
		outputDir: outputDir,
		ctx:       jobCtx,
		cancel:    cancel,
		done:      make(chan struct{}),
	}

	m.mu.Lock()
	m.jobs[id] = j
	submitted := cloneSnapshot(j.snapshot)
	m.mu.Unlock()
	m.startWorkers()

	select {
	case m.queue <- id:
		return submitted, nil
	default:
		cancel()
		m.mu.Lock()
		delete(m.jobs, id)
		m.mu.Unlock()
		_ = os.Remove(outputDir)
		return Snapshot{}, ErrQueueFull
	}
}

func (m *Manager) worker() {
	defer m.wg.Done()
	for {
		select {
		case <-m.ctx.Done():
			return
		case id := <-m.queue:
			m.run(id)
		}
	}
}

func (m *Manager) run(id string) {
	m.mu.Lock()
	j, ok := m.jobs[id]
	if !ok || isTerminal(j.snapshot.State) {
		m.mu.Unlock()
		return
	}
	j.snapshot.State = StateRunning
	j.snapshot.StartedAt = time.Now().UTC()
	m.mu.Unlock()

	runCtx, timeoutCancel := context.WithTimeout(j.ctx, m.cfg.Timeout)
	result, err := m.cfg.Runner.Run(runCtx, j.request, j.outputDir)
	ctxErr := runCtx.Err()
	timeoutCancel()

	m.mu.Lock()
	j.snapshot.FinishedAt = time.Now().UTC()
	j.snapshot.Output = result.Output
	j.snapshot.OutputTruncated = result.OutputTruncated
	j.snapshot.Reports = reportNames(j.outputDir)
	switch {
	case errors.Is(ctxErr, context.Canceled), errors.Is(j.ctx.Err(), context.Canceled):
		j.snapshot.State = StateCanceled
		j.snapshot.Error = "scan canceled"
	case errors.Is(ctxErr, context.DeadlineExceeded):
		j.snapshot.State = StateFailed
		j.snapshot.Error = "scan deadline exceeded"
	case err != nil:
		j.snapshot.State = StateFailed
		j.snapshot.Error = err.Error()
		if m.cfg.MaxJobMemoryBytes > 0 && looksLikeOOM(result.Output) {
			j.snapshot.Error += fmt.Sprintf(" (job memory limit %d bytes exceeded)", m.cfg.MaxJobMemoryBytes)
		}
	case !containsReport(j.snapshot.Reports, "analysis.json"):
		j.snapshot.State = StateFailed
		j.snapshot.Error = "analyzer completed without analysis.json"
	default:
		j.snapshot.State = StateSucceeded
	}
	m.mu.Unlock()
	j.doneOnce.Do(func() { close(j.done) })
}

func (m *Manager) Get(id string) (Snapshot, error) {
	m.mu.RLock()
	j, ok := m.jobs[id]
	if !ok {
		m.mu.RUnlock()
		return Snapshot{}, ErrJobNotFound
	}
	snapshot := cloneSnapshot(j.snapshot)
	m.mu.RUnlock()
	return snapshot, nil
}

func (m *Manager) Wait(ctx context.Context, id string) (Snapshot, error) {
	m.mu.RLock()
	j, ok := m.jobs[id]
	if !ok {
		m.mu.RUnlock()
		return Snapshot{}, ErrJobNotFound
	}
	done := j.done
	m.mu.RUnlock()
	select {
	case <-ctx.Done():
		return Snapshot{}, ctx.Err()
	case <-done:
		return m.Get(id)
	}
}

func (m *Manager) Cancel(id string) (Snapshot, error) {
	m.mu.Lock()
	j, ok := m.jobs[id]
	if !ok {
		m.mu.Unlock()
		return Snapshot{}, ErrJobNotFound
	}
	if isTerminal(j.snapshot.State) {
		snapshot := cloneSnapshot(j.snapshot)
		m.mu.Unlock()
		return snapshot, nil
	}
	queued := j.snapshot.State == StateQueued
	j.cancel()
	if queued {
		j.snapshot.State = StateCanceled
		j.snapshot.Error = "scan canceled"
		j.snapshot.FinishedAt = time.Now().UTC()
	}
	snapshot := cloneSnapshot(j.snapshot)
	m.mu.Unlock()
	if queued {
		j.doneOnce.Do(func() { close(j.done) })
	}
	return snapshot, nil
}

func (m *Manager) ReportPath(id, name string) (string, error) {
	if filepath.Base(name) != name || !validReportName(name) {
		return "", ErrInvalidReport
	}
	snapshot, err := m.Get(id)
	if err != nil {
		return "", err
	}
	if snapshot.State != StateSucceeded && snapshot.State != StateFailed {
		return "", ErrJobNotReady
	}
	if !containsReport(snapshot.Reports, name) {
		return "", os.ErrNotExist
	}
	path := filepath.Join(m.root, "jobs", id, name)
	if !pathWithin(filepath.Join(m.root, "jobs", id), path) {
		return "", ErrInvalidReport
	}
	return path, nil
}

func (m *Manager) Close() {
	m.close.Do(func() {
		m.cancel()
		m.mu.Lock()
		for _, j := range m.jobs {
			if !isTerminal(j.snapshot.State) {
				j.cancel()
			}
		}
		m.mu.Unlock()
		m.wg.Wait()
	})
}

func cloneSnapshot(in Snapshot) Snapshot {
	out := in
	out.Reports = append([]string(nil), in.Reports...)
	return out
}

func randomID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate job ID: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
}

func reportNames(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	result := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Type().IsRegular() && validReportName(entry.Name()) {
			result = append(result, entry.Name())
		}
	}
	sort.Strings(result)
	return result
}

func validReportName(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".json", ".html", ".md", ".sarif", ".txt", ".csv":
		return name != ""
	default:
		return false
	}
}

func containsReport(reports []string, name string) bool {
	for _, report := range reports {
		if report == name {
			return true
		}
	}
	return false
}

func isTerminal(state State) bool {
	return state == StateSucceeded || state == StateFailed || state == StateCanceled
}

// looksLikeOOM reports whether child output carries a Go runtime
// out-of-memory signature. Matched only when the operator set
// MaxJobMemoryBytes, so an unrelated crash mentioning "memory" is never
// relabelled.
func looksLikeOOM(output string) bool {
	for _, marker := range []string{
		"fatal error: out of memory",
		"runtime: out of memory",
		"out of memory: cannot allocate",
	} {
		if strings.Contains(output, marker) {
			return true
		}
	}
	return false
}

func pathWithin(root, candidate string) bool {
	rel, err := filepath.Rel(root, candidate)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}
