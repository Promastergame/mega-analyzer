// Package scheduler — Adaptive Worker Scheduler
//
// Dynamic worker pool that tunes itself based on:
//   - CPU pressure (goroutine scheduling latency)
//   - Heap pressure (GC overhead, allocation rate)
//   - Queue depth (backpressure signal)
//   - GC pause time (stop-the-world impact)
//   - Memory locality (NUMA-aware batching)
//
// Static workers = NumCPU()*2 often kills memory locality.
// This scheduler adapts in real-time for optimal throughput.
package scheduler

import (
	"context"
	"math"
	"runtime"
	"runtime/metrics"
	"sync"
	"sync/atomic"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
// SCHEDULER CONFIG
// ═══════════════════════════════════════════════════════════════════════════════

// Config controls the adaptive scheduler behavior.
type Config struct {
	MinWorkers     int           // minimum worker count (default: 2)
	MaxWorkers     int           // maximum worker count (default: NumCPU*2)
	InitialWorkers int           // starting worker count (default: NumCPU)
	ProbeInterval  time.Duration // how often to check pressure (default: 100ms)

	// Thresholds
	CPUHighThreshold    float64       // scale down above this (default: 0.85)
	CPULowThreshold     float64       // scale up below this (default: 0.50)
	HeapHighThreshold   float64       // scale down above this ratio (default: 0.80)
	QueueDepthThreshold int           // scale up if queue > this (default: 32)
	GCPauseThreshold    time.Duration // scale down if GC pause > this (default: 5ms)

	// Scaling
	ScaleUpStep   int           // workers to add per scale-up (default: 1)
	ScaleDownStep int           // workers to remove per scale-down (default: 1)
	CooldownTime  time.Duration // min time between scaling decisions (default: 500ms)
}

// DefaultConfig returns production defaults.
func DefaultConfig() Config {
	numCPU := runtime.NumCPU()
	return Config{
		MinWorkers:          2,
		MaxWorkers:          numCPU * 2,
		InitialWorkers:      numCPU,
		ProbeInterval:       100 * time.Millisecond,
		CPUHighThreshold:    0.85,
		CPULowThreshold:     0.50,
		HeapHighThreshold:   0.80,
		QueueDepthThreshold: 32,
		GCPauseThreshold:    5 * time.Millisecond,
		ScaleUpStep:         1,
		ScaleDownStep:       1,
		CooldownTime:        500 * time.Millisecond,
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// PRESSURE METRICS
// ═══════════════════════════════════════════════════════════════════════════════

// Pressure represents current system pressure metrics.
type Pressure struct {
	CPUUtilization float64 // 0.0 - 1.0 (estimated from goroutine scheduling)
	HeapRatio      float64 // heap_inuse / heap_sys
	QueueDepth     int     // current job queue depth
	GCPauseNs      uint64  // last GC pause in nanoseconds
	GCFrequency    float64 // GC cycles per second
	AllocRate      float64 // bytes allocated per second
	Goroutines     int     // active goroutine count
	Timestamp      time.Time
}

// ScaleDecision is the scheduler's decision.
type ScaleDecision int

const (
	ScaleHold ScaleDecision = iota
	ScaleUp
	ScaleDown
)

func (d ScaleDecision) String() string {
	return [...]string{"hold", "up", "down"}[d]
}

// ═══════════════════════════════════════════════════════════════════════════════
// ADAPTIVE SCHEDULER
// ═══════════════════════════════════════════════════════════════════════════════

// Scheduler manages a dynamic worker pool.
type Scheduler[T any, R any] struct {
	config Config

	// Worker management
	activeWorkers atomic.Int32
	targetWorkers atomic.Int32
	workerFn      WorkerFunc[T, R]

	// Channels
	jobs    chan T
	results chan R

	// Control
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Pressure monitoring
	pressure    atomic.Value // *Pressure
	lastScale   atomic.Value // time.Time
	probeCancel context.CancelFunc
	monitorDone chan struct{} // closed when the pressure monitor has exited

	// Stats
	stats schedulerStats
}

// WorkerFunc is the function each worker executes.
type WorkerFunc[T any, R any] func(ctx context.Context, job T) R

// SchedulerStats tracks scheduler performance.
type SchedulerStats struct {
	TotalJobs      int64
	CompletedJobs  int64
	ScaleUpCount   int64
	ScaleDownCount int64
	PeakWorkers    int32
	MinWorkers     int32
	TotalGCPauseNs uint64
}

// schedulerStats tracks scheduler performance using atomic operations.
type schedulerStats struct {
	TotalJobs      atomic.Int64
	CompletedJobs  atomic.Int64
	ScaleUpCount   atomic.Int64
	ScaleDownCount atomic.Int64
	PeakWorkers    atomic.Int32
	MinWorkers     atomic.Int32
	TotalGCPauseNs atomic.Uint64
}

// NewScheduler creates an adaptive scheduler.
func NewScheduler[T any, R any](cfg Config, fn WorkerFunc[T, R]) *Scheduler[T, R] {
	if cfg.MinWorkers <= 0 {
		cfg.MinWorkers = 2
	}
	if cfg.MaxWorkers <= 0 {
		cfg.MaxWorkers = runtime.NumCPU() * 2
	}
	if cfg.InitialWorkers <= 0 {
		cfg.InitialWorkers = runtime.NumCPU()
	}
	if cfg.InitialWorkers > cfg.MaxWorkers {
		cfg.InitialWorkers = cfg.MaxWorkers
	}
	if cfg.InitialWorkers < cfg.MinWorkers {
		cfg.InitialWorkers = cfg.MinWorkers
	}

	ctx, cancel := context.WithCancel(context.Background())

	s := &Scheduler[T, R]{
		config:   cfg,
		workerFn: fn,
		jobs:     make(chan T, cfg.MaxWorkers*4),
		results:  make(chan R, cfg.MaxWorkers*4),
		ctx:      ctx,
		cancel:   cancel,
	}

	s.targetWorkers.Store(int32(cfg.InitialWorkers))
	s.stats.MinWorkers.Store(int32(cfg.InitialWorkers))
	s.lastScale.Store(time.Now())

	return s
}

// Start begins the scheduler with pressure monitoring.
func (s *Scheduler[T, R]) Start() {
	// Start initial workers
	target := int(s.targetWorkers.Load())
	for i := 0; i < target; i++ {
		s.spawnWorker()
	}

	// Start pressure monitor. Stop() must be able to wait for it to finish
	// BEFORE wg.Wait(): a spawnWorker (wg.Add) racing with Wait used to be
	// a WaitGroup misuse panic.
	probeCtx, probeCancel := context.WithCancel(s.ctx)
	s.probeCancel = probeCancel
	s.monitorDone = make(chan struct{})
	go func() {
		defer close(s.monitorDone)
		s.pressureMonitor(probeCtx)
	}()
}

// Submit submits a job to the scheduler.
func (s *Scheduler[T, R]) Submit(job T) {
	defer func() {
		_ = recover() // ignore panic if s.jobs is closed
	}()
	s.stats.TotalJobs.Add(1)
	select {
	case s.jobs <- job:
	case <-s.ctx.Done():
	}
}

// Results returns the results channel.
func (s *Scheduler[T, R]) Results() <-chan R {
	return s.results
}

// Stop gracefully shuts down the scheduler.
func (s *Scheduler[T, R]) Stop() {
	if s.probeCancel != nil {
		s.probeCancel()
	}
	// The monitor is the only component calling spawnWorker (wg.Add); join
	// it before waiting on the worker WaitGroup.
	if s.monitorDone != nil {
		<-s.monitorDone
	}
	close(s.jobs)
	s.wg.Wait()
	close(s.results)
	s.cancel()
}

// ActiveWorkers returns current active worker count.
func (s *Scheduler[T, R]) ActiveWorkers() int {
	return int(s.activeWorkers.Load())
}

// CurrentPressure returns the latest pressure reading.
func (s *Scheduler[T, R]) CurrentPressure() *Pressure {
	if v := s.pressure.Load(); v != nil {
		return v.(*Pressure)
	}
	return nil
}

// GetStats returns scheduler statistics.
func (s *Scheduler[T, R]) GetStats() SchedulerStats {
	return SchedulerStats{
		TotalJobs:      s.stats.TotalJobs.Load(),
		CompletedJobs:  s.stats.CompletedJobs.Load(),
		ScaleUpCount:   s.stats.ScaleUpCount.Load(),
		ScaleDownCount: s.stats.ScaleDownCount.Load(),
		PeakWorkers:    s.stats.PeakWorkers.Load(),
		MinWorkers:     s.stats.MinWorkers.Load(),
		TotalGCPauseNs: s.stats.TotalGCPauseNs.Load(),
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// WORKER LIFECYCLE
// ═══════════════════════════════════════════════════════════════════════════════

func (s *Scheduler[T, R]) spawnWorker() {
	s.wg.Add(1)
	s.activeWorkers.Add(1)

	current := s.activeWorkers.Load()
	if current > s.stats.PeakWorkers.Load() {
		s.stats.PeakWorkers.Store(current)
	}

	go func() {
		selfExited := false
		defer func() {
			// The CAS self-exit path below already decremented the counter
			// before claiming its slot.
			if !selfExited {
				s.activeWorkers.Add(-1)
			}
			s.wg.Done()
		}()

		for job := range s.jobs {
			select {
			case <-s.ctx.Done():
				return
			default:
			}

			result := s.workerFn(s.ctx, job)
			s.stats.CompletedJobs.Add(1)

			select {
			case s.results <- result:
			case <-s.ctx.Done():
				return
			}

			// Check if we should self-terminate (scale down). Claim the
			// exit with a CAS on the active counter so workers seeing the
			// same surplus concurrently cannot all quit at once — that
			// used to drop the pool below target and even below MinWorkers.
			for {
				active := s.activeWorkers.Load()
				if active <= s.targetWorkers.Load() {
					break // no surplus left: keep working
				}
				if s.activeWorkers.CompareAndSwap(active, active-1) {
					selfExited = true
					return
				}
			}
		}
	}()
}

// ═══════════════════════════════════════════════════════════════════════════════
// PRESSURE MONITOR
// ═══════════════════════════════════════════════════════════════════════════════

func (s *Scheduler[T, R]) pressureMonitor(ctx context.Context) {
	ticker := time.NewTicker(s.config.ProbeInterval)
	defer ticker.Stop()

	var lastGCStats runtime.MemStats
	var lastProbeTime time.Time
	var lastTotalAlloc uint64
	var lastSched schedWindow

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pressure := s.probe(&lastGCStats, &lastProbeTime, &lastTotalAlloc, &lastSched)
			s.pressure.Store(pressure)
			s.makeScaleDecision(pressure)
		}
	}
}

func (s *Scheduler[T, R]) probe(lastStats *runtime.MemStats, lastTime *time.Time, lastAlloc *uint64, lastSched *schedWindow) *Pressure {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	now := time.Now()
	elapsed := now.Sub(*lastTime).Seconds()
	if elapsed <= 0 {
		elapsed = 0.1
	}

	p := &Pressure{
		Timestamp:  now,
		Goroutines: runtime.NumGoroutine(),
		QueueDepth: len(s.jobs),
	}

	// Heap pressure
	if m.HeapSys > 0 {
		p.HeapRatio = float64(m.HeapInuse) / float64(m.HeapSys)
	}

	// GC pause (last pause)
	if m.NumGC > 0 {
		p.GCPauseNs = m.PauseNs[(m.NumGC+255)%256]
		s.stats.TotalGCPauseNs.Add(p.GCPauseNs)
	}

	// GC frequency
	if lastStats.NumGC > 0 && elapsed > 0 {
		gcCycles := float64(m.NumGC - lastStats.NumGC)
		p.GCFrequency = gcCycles / elapsed
	}

	// Allocation rate
	if *lastAlloc > 0 && elapsed > 0 {
		p.AllocRate = float64(m.TotalAlloc-*lastAlloc) / elapsed
	}

	// CPU utilization from real scheduler latency. The old proxy
	// (NumGoroutine / GOMAXPROCS / 2) read >0.85 in any process with a few
	// hundred blocked goroutines, driving a perpetual scale-down to
	// MinWorkers. The mean /sched/latencies:seconds sample of THIS probe
	// interval measures how long goroutines actually waited for a P:
	// ~0 when the process is idle regardless of goroutine count.
	p.CPUUtilization = cpuUtilization(lastSched, now, *lastTime)

	// Save for next probe
	*lastStats = m
	*lastTime = now
	*lastAlloc = m.TotalAlloc

	return p
}

// schedWindow accumulates the /sched/latencies:seconds histogram between
// probes so a per-interval mean can be derived.
type schedWindow struct {
	sum   float64
	count uint64
}

// cpuUtilization maps the mean goroutine scheduling wait of the interval to
// a 0..1 utilization value. An average wait of 50 ms or more is treated as
// fully saturated.
func cpuUtilization(prev *schedWindow, now, lastTime time.Time) float64 {
	var sample [1]metrics.Sample
	sample[0].Name = "/sched/latencies:seconds"
	metrics.Read(sample[:])
	if sample[0].Value.Kind() != metrics.KindFloat64Histogram {
		return 0
	}
	h := sample[0].Value.Float64Histogram()
	var sum float64
	var count uint64
	for _, c := range h.Counts {
		count += uint64(c)
	}
	for i, c := range h.Counts {
		if c > 0 {
			sum += float64(c) * h.Buckets[i]
		}
	}
	cur := schedWindow{sum: sum, count: count}
	mean := 0.0
	if dCount := cur.count - prev.count; dCount > 0 {
		mean = (cur.sum - prev.sum) / float64(dCount)
	}
	*prev = cur
	_ = now
	_ = lastTime
	if math.IsNaN(mean) || mean < 0 {
		return 0
	}
	return math.Min(mean/0.050, 1.0)
}

// ═══════════════════════════════════════════════════════════════════════════════
// SCALE DECISION
// ═══════════════════════════════════════════════════════════════════════════════

func (s *Scheduler[T, R]) makeScaleDecision(p *Pressure) {
	// Cooldown check
	if lastScale, ok := s.lastScale.Load().(time.Time); ok {
		if time.Since(lastScale) < s.config.CooldownTime {
			return
		}
	}

	decision := s.evaluate(p)

	switch decision {
	case ScaleUp:
		s.scaleUp()
	case ScaleDown:
		s.scaleDown()
	}
}

func (s *Scheduler[T, R]) evaluate(p *Pressure) ScaleDecision {
	current := int(s.activeWorkers.Load())

	// Scale DOWN signals (any one triggers)
	if p.CPUUtilization > s.config.CPUHighThreshold && current > s.config.MinWorkers {
		return ScaleDown
	}
	if p.HeapRatio > s.config.HeapHighThreshold && current > s.config.MinWorkers {
		return ScaleDown
	}
	if p.GCPauseNs > uint64(s.config.GCPauseThreshold) && current > s.config.MinWorkers {
		return ScaleDown
	}

	// Scale UP signals (need multiple)
	upSignals := 0
	if p.CPUUtilization < s.config.CPULowThreshold {
		upSignals++
	}
	if p.QueueDepth > s.config.QueueDepthThreshold {
		upSignals++
	}
	if p.HeapRatio < s.config.HeapHighThreshold*0.7 {
		upSignals++
	}

	if upSignals >= 2 && current < s.config.MaxWorkers {
		return ScaleUp
	}

	return ScaleHold
}

func (s *Scheduler[T, R]) scaleUp() {
	newTarget := int(s.targetWorkers.Load()) + s.config.ScaleUpStep
	if newTarget > s.config.MaxWorkers {
		newTarget = s.config.MaxWorkers
	}
	s.targetWorkers.Store(int32(newTarget))

	// Spawn additional workers
	current := int(s.activeWorkers.Load())
	for i := current; i < newTarget; i++ {
		s.spawnWorker()
	}

	s.stats.ScaleUpCount.Add(1)
	s.lastScale.Store(time.Now())
}

func (s *Scheduler[T, R]) scaleDown() {
	newTarget := int(s.targetWorkers.Load()) - s.config.ScaleDownStep
	if newTarget < s.config.MinWorkers {
		newTarget = s.config.MinWorkers
	}
	s.targetWorkers.Store(int32(newTarget))

	// Workers will self-terminate when they see target < active
	s.stats.ScaleDownCount.Add(1)
	s.lastScale.Store(time.Now())

	current := s.activeWorkers.Load()
	if current < s.stats.MinWorkers.Load() {
		s.stats.MinWorkers.Store(current)
	}
}
