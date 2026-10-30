package scheduler

import (
	"context"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	numCPU := runtime.NumCPU()

	if cfg.MinWorkers != 2 {
		t.Fatalf("MinWorkers = %d, want 2", cfg.MinWorkers)
	}
	if cfg.MaxWorkers != numCPU*2 {
		t.Fatalf("MaxWorkers = %d, want %d", cfg.MaxWorkers, numCPU*2)
	}
	if cfg.InitialWorkers != numCPU {
		t.Fatalf("InitialWorkers = %d, want %d", cfg.InitialWorkers, numCPU)
	}
	if cfg.ProbeInterval != 100*time.Millisecond {
		t.Fatalf("ProbeInterval = %v", cfg.ProbeInterval)
	}
	if cfg.CPUHighThreshold != 0.85 {
		t.Fatalf("CPUHighThreshold = %f", cfg.CPUHighThreshold)
	}
	if cfg.CPULowThreshold != 0.50 {
		t.Fatalf("CPULowThreshold = %f", cfg.CPULowThreshold)
	}
	if cfg.HeapHighThreshold != 0.80 {
		t.Fatalf("HeapHighThreshold = %f", cfg.HeapHighThreshold)
	}
	if cfg.QueueDepthThreshold != 32 {
		t.Fatalf("QueueDepthThreshold = %d", cfg.QueueDepthThreshold)
	}
	if cfg.GCPauseThreshold != 5*time.Millisecond {
		t.Fatalf("GCPauseThreshold = %v", cfg.GCPauseThreshold)
	}
	if cfg.ScaleUpStep != 1 {
		t.Fatalf("ScaleUpStep = %d", cfg.ScaleUpStep)
	}
	if cfg.ScaleDownStep != 1 {
		t.Fatalf("ScaleDownStep = %d", cfg.ScaleDownStep)
	}
	if cfg.CooldownTime != 500*time.Millisecond {
		t.Fatalf("CooldownTime = %v", cfg.CooldownTime)
	}
}

func TestScaleDecision_String(t *testing.T) {
	tests := []struct {
		d    ScaleDecision
		want string
	}{
		{ScaleHold, "hold"},
		{ScaleUp, "up"},
		{ScaleDown, "down"},
	}
	for _, tt := range tests {
		if got := tt.d.String(); got != tt.want {
			t.Fatalf("ScaleDecision(%d).String() = %q, want %q", tt.d, got, tt.want)
		}
	}
}

func TestNewScheduler_DefaultsApplied(t *testing.T) {
	cfg := Config{} // all zeros
	fn := func(ctx context.Context, job int) int { return job * 2 }
	s := NewScheduler(cfg, fn)

	if s.config.MinWorkers != 2 {
		t.Fatalf("MinWorkers should default to 2, got %d", s.config.MinWorkers)
	}
	if s.config.MaxWorkers <= 0 {
		t.Fatalf("MaxWorkers should be positive, got %d", s.config.MaxWorkers)
	}
	if s.config.InitialWorkers < s.config.MinWorkers {
		t.Fatalf("InitialWorkers (%d) < MinWorkers (%d)", s.config.InitialWorkers, s.config.MinWorkers)
	}
	if s.config.InitialWorkers > s.config.MaxWorkers {
		t.Fatalf("InitialWorkers (%d) > MaxWorkers (%d)", s.config.InitialWorkers, s.config.MaxWorkers)
	}
}

func TestNewScheduler_InitialClamped(t *testing.T) {
	cfg := Config{
		MinWorkers:     3,
		MaxWorkers:     5,
		InitialWorkers: 10, // above max
	}
	fn := func(ctx context.Context, job int) int { return job }
	s := NewScheduler(cfg, fn)

	if s.config.InitialWorkers != 5 {
		t.Fatalf("InitialWorkers should be clamped to MaxWorkers=5, got %d", s.config.InitialWorkers)
	}
}

func TestNewScheduler_InitialBelowMin(t *testing.T) {
	cfg := Config{
		MinWorkers:     4,
		MaxWorkers:     8,
		InitialWorkers: 1, // below min
	}
	fn := func(ctx context.Context, job int) int { return job }
	s := NewScheduler(cfg, fn)

	if s.config.InitialWorkers != 4 {
		t.Fatalf("InitialWorkers should be clamped to MinWorkers=4, got %d", s.config.InitialWorkers)
	}
}

func TestScheduler_StartAndStop(t *testing.T) {
	cfg := Config{
		MinWorkers:     2,
		MaxWorkers:     4,
		InitialWorkers: 2,
		ProbeInterval:  50 * time.Millisecond,
		CooldownTime:   100 * time.Millisecond,
	}
	fn := func(ctx context.Context, job int) int { return job * 2 }
	s := NewScheduler(cfg, fn)

	s.Start()
	time.Sleep(20 * time.Millisecond)

	active := s.ActiveWorkers()
	if active < 1 {
		t.Fatalf("expected at least 1 active worker, got %d", active)
	}

	s.Stop()
}

func TestScheduler_SubmitAndResults(t *testing.T) {
	cfg := Config{
		MinWorkers:     2,
		MaxWorkers:     4,
		InitialWorkers: 2,
		ProbeInterval:  50 * time.Millisecond,
		CooldownTime:   100 * time.Millisecond,
	}
	var processed atomic.Int64
	fn := func(ctx context.Context, job int) int {
		processed.Add(1)
		return job * 3
	}
	s := NewScheduler(cfg, fn)
	s.Start()

	const numJobs = 10
	for i := 0; i < numJobs; i++ {
		s.Submit(i)
	}

	// Collect results
	results := make([]int, 0, numJobs)
	timeout := time.After(5 * time.Second)
	for len(results) < numJobs {
		select {
		case r := <-s.Results():
			results = append(results, r)
		case <-timeout:
			t.Fatalf("timed out waiting for results, got %d/%d", len(results), numJobs)
		}
	}

	s.Stop()

	if len(results) != numJobs {
		t.Fatalf("expected %d results, got %d", numJobs, len(results))
	}
	if processed.Load() != numJobs {
		t.Fatalf("expected %d processed, got %d", numJobs, processed.Load())
	}
}

func TestScheduler_CurrentPressure_InitiallyNil(t *testing.T) {
	cfg := Config{
		MinWorkers:     2,
		MaxWorkers:     4,
		InitialWorkers: 2,
		ProbeInterval:  1 * time.Second, // long interval so it won't fire
		CooldownTime:   100 * time.Millisecond,
	}
	fn := func(ctx context.Context, job int) int { return job }
	s := NewScheduler(cfg, fn)

	if p := s.CurrentPressure(); p != nil {
		t.Fatalf("expected nil pressure before start, got %+v", p)
	}
}

func TestScheduler_GetStats(t *testing.T) {
	cfg := Config{
		MinWorkers:     2,
		MaxWorkers:     4,
		InitialWorkers: 2,
		ProbeInterval:  50 * time.Millisecond,
		CooldownTime:   100 * time.Millisecond,
	}
	fn := func(ctx context.Context, job string) string { return job + "_done" }
	s := NewScheduler(cfg, fn)
	s.Start()

	s.Submit("task1")
	s.Submit("task2")

	// Wait for results
	timeout := time.After(2 * time.Second)
	for i := 0; i < 2; i++ {
		select {
		case <-s.Results():
		case <-timeout:
			t.Fatal("timed out")
		}
	}

	s.Stop()

	stats := s.GetStats()
	if stats.TotalJobs != 2 {
		t.Fatalf("TotalJobs = %d, want 2", stats.TotalJobs)
	}
	if stats.CompletedJobs != 2 {
		t.Fatalf("CompletedJobs = %d, want 2", stats.CompletedJobs)
	}
}

func TestScheduler_Evaluate_ScaleDown_HighCPU(t *testing.T) {
	cfg := Config{
		MinWorkers:       2,
		MaxWorkers:       8,
		InitialWorkers:   4,
		CPUHighThreshold: 0.85,
		CPULowThreshold:  0.50,
		CooldownTime:     100 * time.Millisecond,
	}
	fn := func(ctx context.Context, job int) int { return job }
	s := NewScheduler(cfg, fn)
	s.activeWorkers.Store(4)

	p := &Pressure{CPUUtilization: 0.90} // above high threshold
	decision := s.evaluate(p)
	if decision != ScaleDown {
		t.Fatalf("expected ScaleDown for high CPU, got %s", decision)
	}
}

func TestScheduler_Evaluate_ScaleDown_HighHeap(t *testing.T) {
	cfg := Config{
		MinWorkers:        2,
		MaxWorkers:        8,
		InitialWorkers:    4,
		HeapHighThreshold: 0.80,
		CooldownTime:      100 * time.Millisecond,
	}
	fn := func(ctx context.Context, job int) int { return job }
	s := NewScheduler(cfg, fn)
	s.activeWorkers.Store(4)

	p := &Pressure{HeapRatio: 0.90}
	decision := s.evaluate(p)
	if decision != ScaleDown {
		t.Fatalf("expected ScaleDown for high heap, got %s", decision)
	}
}

func TestScheduler_Evaluate_ScaleDown_HighGCPause(t *testing.T) {
	cfg := Config{
		MinWorkers:       2,
		MaxWorkers:       8,
		InitialWorkers:   4,
		GCPauseThreshold: 5 * time.Millisecond,
		CooldownTime:     100 * time.Millisecond,
	}
	fn := func(ctx context.Context, job int) int { return job }
	s := NewScheduler(cfg, fn)
	s.activeWorkers.Store(4)

	p := &Pressure{GCPauseNs: uint64(10 * time.Millisecond)}
	decision := s.evaluate(p)
	if decision != ScaleDown {
		t.Fatalf("expected ScaleDown for high GC pause, got %s", decision)
	}
}

func TestScheduler_Evaluate_ScaleUp(t *testing.T) {
	cfg := Config{
		MinWorkers:          2,
		MaxWorkers:          8,
		InitialWorkers:      4,
		CPUHighThreshold:    0.85,
		CPULowThreshold:     0.50,
		HeapHighThreshold:   0.80,
		QueueDepthThreshold: 32,
		GCPauseThreshold:    5 * time.Millisecond,
		CooldownTime:        100 * time.Millisecond,
	}
	fn := func(ctx context.Context, job int) int { return job }
	s := NewScheduler(cfg, fn)
	s.activeWorkers.Store(4)

	// Low CPU + high queue depth + low heap = 3 up signals, no down signals
	p := &Pressure{
		CPUUtilization: 0.30,                         // below CPULowThreshold → up signal
		QueueDepth:     50,                           // above QueueDepthThreshold → up signal
		HeapRatio:      0.40,                         // below 0.80*0.7=0.56 → up signal; below HeapHigh → no down
		GCPauseNs:      uint64(1 * time.Millisecond), // below GCPauseThreshold → no down
	}
	decision := s.evaluate(p)
	if decision != ScaleUp {
		t.Fatalf("expected ScaleUp, got %s", decision)
	}
}

func TestScheduler_Evaluate_Hold(t *testing.T) {
	cfg := Config{
		MinWorkers:          2,
		MaxWorkers:          8,
		InitialWorkers:      4,
		CPUHighThreshold:    0.85,
		CPULowThreshold:     0.50,
		HeapHighThreshold:   0.80,
		QueueDepthThreshold: 32,
		GCPauseThreshold:    5 * time.Millisecond,
		CooldownTime:        100 * time.Millisecond,
	}
	fn := func(ctx context.Context, job int) int { return job }
	s := NewScheduler(cfg, fn)
	s.activeWorkers.Store(4)

	// Middle-of-the-road pressure → hold
	p := &Pressure{
		CPUUtilization: 0.60,
		HeapRatio:      0.50,
		QueueDepth:     10,
		GCPauseNs:      uint64(1 * time.Millisecond),
	}
	decision := s.evaluate(p)
	if decision != ScaleHold {
		t.Fatalf("expected ScaleHold, got %s", decision)
	}
}

func TestScheduler_Evaluate_AtMinWorkers_NoScaleDown(t *testing.T) {
	cfg := Config{
		MinWorkers:       2,
		MaxWorkers:       8,
		InitialWorkers:   2,
		CPUHighThreshold: 0.85,
		CooldownTime:     100 * time.Millisecond,
	}
	fn := func(ctx context.Context, job int) int { return job }
	s := NewScheduler(cfg, fn)
	s.activeWorkers.Store(2) // at minimum

	p := &Pressure{CPUUtilization: 0.95}
	decision := s.evaluate(p)
	if decision != ScaleHold {
		t.Fatalf("at min workers, should hold even with high CPU, got %s", decision)
	}
}

func TestScheduler_Evaluate_AtMaxWorkers_NoScaleUp(t *testing.T) {
	cfg := Config{
		MinWorkers:          2,
		MaxWorkers:          4,
		InitialWorkers:      4,
		CPUHighThreshold:    0.85,
		CPULowThreshold:     0.50,
		HeapHighThreshold:   0.80,
		QueueDepthThreshold: 32,
		GCPauseThreshold:    5 * time.Millisecond,
		CooldownTime:        100 * time.Millisecond,
	}
	fn := func(ctx context.Context, job int) int { return job }
	s := NewScheduler(cfg, fn)
	s.activeWorkers.Store(4) // at maximum

	// All signals point to scale-up, no down triggers
	p := &Pressure{
		CPUUtilization: 0.20,
		QueueDepth:     100,
		HeapRatio:      0.30,
		GCPauseNs:      uint64(1 * time.Millisecond),
	}
	decision := s.evaluate(p)
	if decision != ScaleHold {
		t.Fatalf("at max workers, should hold even with scale-up signals, got %s", decision)
	}
}

func TestScheduler_ScaleUp(t *testing.T) {
	cfg := Config{
		MinWorkers:     2,
		MaxWorkers:     6,
		InitialWorkers: 3,
		ProbeInterval:  50 * time.Millisecond,
		CooldownTime:   10 * time.Millisecond,
		ScaleUpStep:    2,
	}
	fn := func(ctx context.Context, job int) int { return job }
	s := NewScheduler(cfg, fn)
	s.Start()
	time.Sleep(30 * time.Millisecond)

	// Force scale up
	s.scaleUp()
	time.Sleep(20 * time.Millisecond)

	target := s.targetWorkers.Load()
	if target != 5 { // 3 + 2 (ScaleUpStep)
		t.Fatalf("target after scaleUp = %d, want 5", target)
	}

	stats := s.GetStats()
	if stats.ScaleUpCount != 1 {
		t.Fatalf("ScaleUpCount = %d, want 1", stats.ScaleUpCount)
	}

	s.Stop()
}

func TestScheduler_ScaleDown(t *testing.T) {
	cfg := Config{
		MinWorkers:     2,
		MaxWorkers:     6,
		InitialWorkers: 4,
		ProbeInterval:  50 * time.Millisecond,
		CooldownTime:   10 * time.Millisecond,
		ScaleDownStep:  1,
	}
	fn := func(ctx context.Context, job int) int { return job }
	s := NewScheduler(cfg, fn)
	// Do not call s.Start() to prevent the background loop from scaling down automatically.
	// We just want to test the manual scaleDown logic.

	s.scaleDown()

	target := s.targetWorkers.Load()
	if target != 3 { // 4 - 1
		t.Fatalf("target after scaleDown = %d, want 3", target)
	}

	stats := s.GetStats()
	if stats.ScaleDownCount != 1 {
		t.Fatalf("ScaleDownCount = %d, want 1", stats.ScaleDownCount)
	}

	s.Stop()
}

func TestScheduler_ScaleUp_CappedAtMax(t *testing.T) {
	cfg := Config{
		MinWorkers:     2,
		MaxWorkers:     4,
		InitialWorkers: 4,
		ProbeInterval:  50 * time.Millisecond,
		CooldownTime:   10 * time.Millisecond,
		ScaleUpStep:    5,
	}
	fn := func(ctx context.Context, job int) int { return job }
	s := NewScheduler(cfg, fn)

	s.scaleUp()
	target := s.targetWorkers.Load()
	if target != 4 { // capped at MaxWorkers
		t.Fatalf("target = %d, want 4 (capped at max)", target)
	}
}

func TestScheduler_ScaleDown_CappedAtMin(t *testing.T) {
	cfg := Config{
		MinWorkers:     3,
		MaxWorkers:     8,
		InitialWorkers: 3,
		ProbeInterval:  50 * time.Millisecond,
		CooldownTime:   10 * time.Millisecond,
		ScaleDownStep:  5,
	}
	fn := func(ctx context.Context, job int) int { return job }
	s := NewScheduler(cfg, fn)

	s.scaleDown()
	target := s.targetWorkers.Load()
	if target != 3 { // capped at MinWorkers
		t.Fatalf("target = %d, want 3 (capped at min)", target)
	}
}

func TestScheduler_PressureMonitor_ProducesReading(t *testing.T) {
	cfg := Config{
		MinWorkers:     2,
		MaxWorkers:     4,
		InitialWorkers: 2,
		ProbeInterval:  20 * time.Millisecond,
		CooldownTime:   500 * time.Millisecond,
	}
	fn := func(ctx context.Context, job int) int { return job }
	s := NewScheduler(cfg, fn)
	s.Start()

	// Wait for at least one probe
	time.Sleep(100 * time.Millisecond)

	p := s.CurrentPressure()
	if p == nil {
		t.Fatal("expected non-nil pressure after probe interval")
	}
	if p.Goroutines <= 0 {
		t.Fatalf("Goroutines = %d, should be > 0", p.Goroutines)
	}
	if p.Timestamp.IsZero() {
		t.Fatal("Timestamp should not be zero")
	}

	s.Stop()
}

func TestScheduler_MakeScaleDecision_Cooldown(t *testing.T) {
	cfg := Config{
		MinWorkers:       2,
		MaxWorkers:       8,
		InitialWorkers:   4,
		CPUHighThreshold: 0.85,
		GCPauseThreshold: 5 * time.Millisecond,
		CooldownTime:     1 * time.Second, // long cooldown
	}
	fn := func(ctx context.Context, job int) int { return job }
	s := NewScheduler(cfg, fn)
	s.activeWorkers.Store(4)
	s.lastScale.Store(time.Now()) // just scaled

	// Even with high pressure, cooldown should prevent scaling
	p := &Pressure{CPUUtilization: 0.95}
	s.makeScaleDecision(p)

	// Target should not have changed
	if s.targetWorkers.Load() != int32(cfg.InitialWorkers) {
		t.Fatal("should not scale during cooldown")
	}
}
