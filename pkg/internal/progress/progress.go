package progress

import (
	"fmt"
	"math"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════
// PROGRESS BAR — красивый прогресс бар с ETA
// ═══════════════════════════════════════════════════════════════════════════

// ProgressBar displays scanning progress with ETA
type ProgressBar struct {
	mu         sync.Mutex
	total      int64
	current    int64
	startTime  time.Time
	lastUpdate time.Time
	width      int
	label      string
	showETA    bool
	showSpeed  bool
	disabled   bool // for CI/non-terminal environments
}

// NewProgressBar creates a new progress bar
func NewProgressBar(total int, label string) *ProgressBar {
	disabled := !isTerminal()

	pb := &ProgressBar{
		total:      int64(total),
		label:      label,
		width:      50,
		showETA:    true,
		showSpeed:  true,
		disabled:   disabled,
		startTime:  time.Now(),
		lastUpdate: time.Now(),
	}

	if !disabled && total > 0 {
		pb.render()
	}

	return pb
}

// SetTotal updates total count
func (pb *ProgressBar) SetTotal(total int) {
	atomic.StoreInt64(&pb.total, int64(total))
}

// Increment advances the progress by 1
func (pb *ProgressBar) Increment() {
	atomic.AddInt64(&pb.current, 1)
	pb.maybeRender()
}

// Advance advances the progress by n
func (pb *ProgressBar) Advance(n int) {
	atomic.AddInt64(&pb.current, int64(n))
	pb.maybeRender()
}

// Set sets the current progress to n
func (pb *ProgressBar) Set(n int) {
	atomic.StoreInt64(&pb.current, int64(n))
	pb.maybeRender()
}

// Finish completes the progress bar
func (pb *ProgressBar) Finish() {
	if pb.disabled {
		return
	}

	pb.mu.Lock()
	defer pb.mu.Unlock()

	current := atomic.LoadInt64(&pb.current)
	total := atomic.LoadInt64(&pb.total)
	if current < total {
		atomic.StoreInt64(&pb.current, total)
	}

	pb.renderFinal()
}

func (pb *ProgressBar) maybeRender() {
	if pb.disabled {
		return
	}

	pb.mu.Lock()
	defer pb.mu.Unlock()

	now := time.Now()
	// Throttle rendering to ~10 FPS
	if now.Sub(pb.lastUpdate) < 100*time.Millisecond {
		return
	}

	pb.lastUpdate = now
	pb.render()
}

func (pb *ProgressBar) render() {
	current := atomic.LoadInt64(&pb.current)
	total := atomic.LoadInt64(&pb.total)

	if total <= 0 {
		return
	}
	// Clamp display values: callers may overshoot (Set past total) or pass
	// garbage (negative Advance). An unclamped negative fraction panics in
	// strings.Repeat below; an overshoot prints a negative ETA.
	if current < 0 {
		current = 0
	}
	if current > total {
		current = total
	}

	fraction := float64(current) / float64(total)

	// Build progress bar
	filled := int(fraction * float64(pb.width))
	empty := pb.width - filled

	bar := strings.Repeat("█", filled) + strings.Repeat("░", empty)

	// Calculate speed
	elapsed := time.Since(pb.startTime).Seconds()
	if elapsed <= 0 {
		elapsed = 0.001
	}
	speed := float64(current) / elapsed

	// Format output
	var parts []string
	parts = append(parts, fmt.Sprintf("\r%s [%s] %3.0f%%", pb.label, bar, fraction*100))
	parts = append(parts, fmt.Sprintf("(%d/%d)", current, total))

	if pb.showSpeed {
		parts = append(parts, formatSpeed(speed))
	}

	// No ETA without movement: at current==0 speed is 0 and the division
	// yields +Inf, which formats as garbage (float→int conversion of +Inf
	// is platform-defined). The first frame simply shows no ETA.
	if pb.showETA && current < total && speed > 0 {
		remaining := float64(total-current) / speed
		eta := time.Duration(remaining) * time.Second
		parts = append(parts, formatDuration(eta))
	}

	fmt.Print(strings.Join(parts, " "))
}

func (pb *ProgressBar) renderFinal() {
	current := atomic.LoadInt64(&pb.current)
	total := atomic.LoadInt64(&pb.total)
	elapsed := time.Since(pb.startTime)
	secs := elapsed.Seconds()
	if secs <= 0 {
		secs = 0.001
	}
	speed := float64(current) / secs

	filled := pb.width
	bar := strings.Repeat("█", filled)

	fmt.Printf("\r%s [%s] 100%% (%d/%d) %s %s\n",
		pb.label, bar, current, total,
		formatSpeed(speed),
		formatDuration(elapsed))
}

// GetProgress returns current progress
func (pb *ProgressBar) GetProgress() (current int, total int) {
	return int(atomic.LoadInt64(&pb.current)), int(atomic.LoadInt64(&pb.total))
}

// ═══════════════════════════════════════════════════════════════════════════
// LIVE STATS — статистика в реальном времени
// ═══════════════════════════════════════════════════════════════════════════

// LiveStats tracks real-time scanning statistics
type LiveStats struct {
	mu sync.Mutex

	FilesScanned    int64
	MatchesFound    int64
	CategoriesFound int64
	BytesProcessed  int64
	MemoryUsageMB   float64

	// Timing
	startTime time.Time
	lastStats time.Time
	lastFiles int64

	// Categories
	categories map[string]int64

	// Callback for live updates
	onUpdate func(stats *LiveStatsSnapshot)

	stopChan chan struct{}
	stopOnce sync.Once
	disabled bool
}

// LiveStatsSnapshot is a point-in-time snapshot of stats
type LiveStatsSnapshot struct {
	FilesScanned    int64
	MatchesFound    int64
	CategoriesFound int64
	BytesProcessed  int64
	MemoryUsageMB   float64

	Elapsed     time.Duration
	FilesPerSec float64
	BytesPerSec float64
	ETA         time.Duration

	Categories map[string]int64
}

// NewLiveStats creates a new live stats tracker
func NewLiveStats(onUpdate func(*LiveStatsSnapshot)) *LiveStats {
	ls := &LiveStats{
		startTime:  time.Now(),
		lastStats:  time.Now(),
		categories: make(map[string]int64),
		onUpdate:   onUpdate,
		stopChan:   make(chan struct{}),
		disabled:   !isTerminal(),
	}

	if !ls.disabled {
		go ls.runUpdateLoop()
	}

	return ls
}

func (ls *LiveStats) runUpdateLoop() {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			snapshot := ls.Snapshot()
			if ls.onUpdate != nil {
				ls.onUpdate(snapshot)
			}
		case <-ls.stopChan:
			return
		}
	}
}

// Stop stops the live stats update loop. Safe to call multiple times and
// on a disabled instance (closing an already-closed channel panics, so the
// close runs exactly once).
func (ls *LiveStats) Stop() {
	if ls.disabled {
		return
	}
	ls.stopOnce.Do(func() { close(ls.stopChan) })
}

// RecordFile records that a file was scanned
func (ls *LiveStats) RecordFile(size int64, category string) {
	atomic.AddInt64(&ls.FilesScanned, 1)
	atomic.AddInt64(&ls.BytesProcessed, size)

	ls.mu.Lock()
	if category != "" {
		ls.categories[category]++
		if ls.categories[category] == 1 {
			atomic.AddInt64(&ls.CategoriesFound, 1)
		}
	}
	ls.mu.Unlock()
}

// RecordMatch records a match was found
func (ls *LiveStats) RecordMatch() {
	atomic.AddInt64(&ls.MatchesFound, 1)
}

// SetMemoryUsage updates current memory usage
func (ls *LiveStats) SetMemoryUsage(mb float64) {
	ls.mu.Lock()
	ls.MemoryUsageMB = mb
	ls.mu.Unlock()
}

// Snapshot returns a point-in-time snapshot
func (ls *LiveStats) Snapshot() *LiveStatsSnapshot {
	ls.mu.Lock()
	defer ls.mu.Unlock()

	files := atomic.LoadInt64(&ls.FilesScanned)
	bytes := atomic.LoadInt64(&ls.BytesProcessed)
	elapsed := time.Since(ls.startTime)

	// Calculate rates
	filesPerSec := float64(files) / elapsed.Seconds()
	bytesPerSec := float64(bytes) / elapsed.Seconds()

	// Estimate ETA (based on files)
	// This would need total files to be set separately
	eta := time.Duration(0)

	// Copy categories
	cats := make(map[string]int64, len(ls.categories))
	for k, v := range ls.categories {
		cats[k] = v
	}

	return &LiveStatsSnapshot{
		FilesScanned:    files,
		MatchesFound:    atomic.LoadInt64(&ls.MatchesFound),
		CategoriesFound: atomic.LoadInt64(&ls.CategoriesFound),
		BytesProcessed:  bytes,
		MemoryUsageMB:   math.Round(ls.MemoryUsageMB*100) / 100,
		Elapsed:         elapsed,
		FilesPerSec:     math.Round(filesPerSec*10) / 10,
		BytesPerSec:     bytesPerSec,
		ETA:             eta,
		Categories:      cats,
	}
}

// PrintFinal prints final statistics
func (ls *LiveStats) PrintFinal() {
	if ls.disabled {
		return
	}

	snapshot := ls.Snapshot()
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════╗")
	fmt.Println("║         📊 SCANNING STATISTICS              ║")
	fmt.Println("╠══════════════════════════════════════════════╣")
	fmt.Printf("║  Files scanned:    %6d                      ║\n", snapshot.FilesScanned)
	fmt.Printf("║  Matches found:    %6d                      ║\n", snapshot.MatchesFound)
	fmt.Printf("║  Categories:       %6d                      ║\n", snapshot.CategoriesFound)
	fmt.Printf("║  Data processed:   %6.2f MB                  ║\n", float64(snapshot.BytesProcessed)/1024/1024)
	fmt.Printf("║  Speed:            %6.0f files/sec           ║\n", snapshot.FilesPerSec)
	fmt.Printf("║  Time elapsed:     %6s                ║\n", formatDuration(snapshot.Elapsed))
	fmt.Println("╚══════════════════════════════════════════════╝")
}

// ═══════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════

func formatSpeed(filesPerSec float64) string {
	return fmt.Sprintf("%.0f files/s", filesPerSec)
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}

	minutes := int(d.Minutes())
	seconds := int(d.Seconds()) % 60
	return fmt.Sprintf("%dm%ds", minutes, seconds)
}

// isTerminal reports whether stdout is a character device (a real
// terminal) rather than a redirect. Non-terminal output disables live
// rendering so logs stay clean.
func isTerminal() bool {
	fileInfo, err := os.Stdout.Stat()
	if err != nil || fileInfo == nil {
		return false
	}
	return (fileInfo.Mode() & os.ModeCharDevice) != 0
}
