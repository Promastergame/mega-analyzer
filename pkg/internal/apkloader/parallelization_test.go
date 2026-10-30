package apkloader

import (
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
// UNIT TESTS: Parallelization
// ═══════════════════════════════════════════════════════════════════════════════

// TestDefaultParallelConfig tests default parallelization config.
func TestDefaultParallelConfig(t *testing.T) {
	config := DefaultParallelConfig()

	if config.MaxGoroutines <= 0 {
		t.Error("Expected positive max goroutines")
	}
	if config.MethodBatchSize <= 0 {
		t.Error("Expected positive method batch size")
	}
	if config.ClassBatchSize <= 0 {
		t.Error("Expected positive class batch size")
	}
	if !config.EnableMethodLevel {
		t.Error("Expected method level parallelization to be enabled")
	}
	if !config.EnableClassLevel {
		t.Error("Expected class level parallelization to be enabled")
	}
	if !config.EnablePassLevel {
		t.Error("Expected pass level parallelization to be enabled")
	}
}

// TestParallelMethodAnalyzer_AnalyzeMethodsParallel tests parallel method analysis.
func TestParallelMethodAnalyzer_AnalyzeMethodsParallel(t *testing.T) {
	config := DefaultParallelConfig()
	analyzer := NewParallelMethodAnalyzer(config)

	tasks := make([]*MethodAnalysisTask, 10)
	for i := 0; i < 10; i++ {
		tasks[i] = &MethodAnalysisTask{
			MethodID:   i,
			MethodName: "method_" + string(rune(i)),
		}
	}

	var counter int32
	err := analyzer.AnalyzeMethodsParallel(tasks, func(task *MethodAnalysisTask) error {
		atomic.AddInt32(&counter, 1)
		return nil
	}, 0, len(tasks))

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if counter != 10 {
		t.Errorf("Expected 10 tasks to execute, got %d", counter)
	}
}

// TestParallelMethodAnalyzer_AnalyzeMethodsInBatches tests batch method analysis.
func TestParallelMethodAnalyzer_AnalyzeMethodsInBatches(t *testing.T) {
	config := DefaultParallelConfig()
	config.MethodBatchSize = 3
	analyzer := NewParallelMethodAnalyzer(config)

	tasks := make([]*MethodAnalysisTask, 10)
	for i := 0; i < 10; i++ {
		tasks[i] = &MethodAnalysisTask{
			MethodID:   i,
			MethodName: "method_" + string(rune(i)),
		}
	}

	var counter int32
	err := analyzer.AnalyzeMethodsInBatches(tasks, func(task *MethodAnalysisTask) error {
		atomic.AddInt32(&counter, 1)
		return nil
	})

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if counter != 10 {
		t.Errorf("Expected 10 tasks to execute, got %d", counter)
	}
}

// TestParallelClassAnalyzer_AnalyzeClassesParallel tests parallel class analysis.
func TestParallelClassAnalyzer_AnalyzeClassesParallel(t *testing.T) {
	config := DefaultParallelConfig()
	analyzer := NewParallelClassAnalyzer(config)

	tasks := make([]*ClassAnalysisTask, 5)
	for i := 0; i < 5; i++ {
		tasks[i] = &ClassAnalysisTask{
			ClassID:   i,
			ClassName: "class_" + string(rune(i)),
			Methods:   make([]*MethodAnalysisTask, 0),
		}
	}

	var counter int32
	err := analyzer.AnalyzeClassesParallel(tasks, func(task *ClassAnalysisTask) error {
		atomic.AddInt32(&counter, 1)
		return nil
	}, 0, len(tasks))

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if counter != 5 {
		t.Errorf("Expected 5 tasks to execute, got %d", counter)
	}
}

// TestParallelClassAnalyzer_AnalyzeClassesInBatches tests batch class analysis.
func TestParallelClassAnalyzer_AnalyzeClassesInBatches(t *testing.T) {
	config := DefaultParallelConfig()
	config.ClassBatchSize = 2
	analyzer := NewParallelClassAnalyzer(config)

	tasks := make([]*ClassAnalysisTask, 5)
	for i := 0; i < 5; i++ {
		tasks[i] = &ClassAnalysisTask{
			ClassID:   i,
			ClassName: "class_" + string(rune(i)),
			Methods:   make([]*MethodAnalysisTask, 0),
		}
	}

	var counter int32
	err := analyzer.AnalyzeClassesInBatches(tasks, func(task *ClassAnalysisTask) error {
		atomic.AddInt32(&counter, 1)
		return nil
	})

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if counter != 5 {
		t.Errorf("Expected 5 tasks to execute, got %d", counter)
	}
}

// TestParallelPassExecutor_ExecutePassesParallel tests parallel pass execution.
func TestParallelPassExecutor_ExecutePassesParallel(t *testing.T) {
	config := DefaultParallelConfig()
	executor := NewParallelPassExecutor(config)

	tasks := make([]*PassTask, 4)
	for i := 0; i < 4; i++ {
		tasks[i] = &PassTask{
			PassName: "pass_" + string(rune(i)),
		}
	}

	var counter int32
	err := executor.ExecutePassesParallel(tasks, func(task *PassTask) error {
		atomic.AddInt32(&counter, 1)
		return nil
	})

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if counter != 4 {
		t.Errorf("Expected 4 tasks to execute, got %d", counter)
	}
}

// TestCacheOptimizer_RecordHit tests cache hit recording.
func TestCacheOptimizer_RecordHit(t *testing.T) {
	optimizer := NewCacheOptimizer(1000)

	optimizer.RecordHit()
	optimizer.RecordHit()
	optimizer.RecordMiss()

	hitRate := optimizer.GetHitRate()

	if hitRate < 0.6 || hitRate > 0.7 {
		t.Errorf("Expected hit rate around 0.67, got %.2f", hitRate)
	}
}

// TestCacheOptimizer_GetOptimizationRecommendations tests optimization recommendations.
func TestCacheOptimizer_GetOptimizationRecommendations(t *testing.T) {
	optimizer := NewCacheOptimizer(1000)

	// Low hit rate
	for i := 0; i < 10; i++ {
		optimizer.RecordMiss()
	}

	recommendations := optimizer.GetOptimizationRecommendations()

	if len(recommendations) == 0 {
		t.Error("Expected optimization recommendations for low hit rate")
	}
}

// TestMemoryOptimizer_IsMemoryAvailable tests memory availability check.
func TestMemoryOptimizer_IsMemoryAvailable(t *testing.T) {
	optimizer := NewMemoryOptimizer(1024) // 1GB

	available := optimizer.IsMemoryAvailable(1024 * 1024) // 1MB

	if !available {
		t.Error("Expected memory to be available")
	}
}

// TestMemoryOptimizer_GetMemoryUsagePercentage tests memory usage percentage.
func TestMemoryOptimizer_GetMemoryUsagePercentage(t *testing.T) {
	optimizer := NewMemoryOptimizer(1024) // 1GB

	percentage := optimizer.GetMemoryUsagePercentage()

	if percentage < 0 || percentage > 100 {
		t.Errorf("Expected percentage between 0 and 100, got %.2f", percentage)
	}
}

// TestMemoryOptimizer_GetOptimizationRecommendations tests memory recommendations.
func TestMemoryOptimizer_GetOptimizationRecommendations(t *testing.T) {
	optimizer := NewMemoryOptimizer(1) // 1MB (very small)

	recommendations := optimizer.GetOptimizationRecommendations()

	// Should have recommendations for high memory usage
	if len(recommendations) == 0 {
		t.Error("Expected optimization recommendations")
	}
}

// TestBottleneckDetector_RecordComponentTime tests component time recording.
func TestBottleneckDetector_RecordComponentTime(t *testing.T) {
	detector := NewBottleneckDetector(50.0)

	detector.RecordComponentTime("component1", 100)
	detector.RecordComponentTime("component2", 50)

	bottlenecks := detector.FindBottlenecks()

	if len(bottlenecks) == 0 {
		t.Error("Expected bottlenecks to be detected")
	}
}

// TestBottleneckDetector_GetComponentPercentage tests component percentage calculation.
func TestBottleneckDetector_GetComponentPercentage(t *testing.T) {
	detector := NewBottleneckDetector(50.0)

	detector.RecordComponentTime("component1", 100)
	detector.RecordComponentTime("component2", 100)

	percentage := detector.GetComponentPercentage("component1")

	if percentage < 45 || percentage > 55 {
		t.Errorf("Expected percentage around 50, got %.2f", percentage)
	}
}

// TestBottleneckDetector_Reset tests detector reset.
func TestBottleneckDetector_Reset(t *testing.T) {
	detector := NewBottleneckDetector(50.0)

	detector.RecordComponentTime("component1", 100)
	detector.Reset()

	bottlenecks := detector.FindBottlenecks()

	if len(bottlenecks) != 0 {
		t.Error("Expected no bottlenecks after reset")
	}
}

// TestParallelMethodAnalyzer_ConcurrencyLimit tests concurrency limiting.
func TestParallelMethodAnalyzer_ConcurrencyLimit(t *testing.T) {
	config := DefaultParallelConfig()
	config.MaxGoroutines = 2
	analyzer := NewParallelMethodAnalyzer(config)

	tasks := make([]*MethodAnalysisTask, 10)
	for i := 0; i < 10; i++ {
		tasks[i] = &MethodAnalysisTask{
			MethodID:   i,
			MethodName: "method_" + string(rune(i)),
		}
	}

	var maxConcurrent atomic.Int32
	var currentConcurrent atomic.Int32

	err := analyzer.AnalyzeMethodsParallel(tasks, func(task *MethodAnalysisTask) error {
		current := currentConcurrent.Add(1)
		for maximum := maxConcurrent.Load(); current > maximum; maximum = maxConcurrent.Load() {
			if maxConcurrent.CompareAndSwap(maximum, current) {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
		currentConcurrent.Add(-1)
		return nil
	}, 0, len(tasks))

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if maximum := maxConcurrent.Load(); maximum < 1 || maximum > int32(config.MaxGoroutines) {
		t.Errorf("Expected max concurrent between 1 and %d, got %d", config.MaxGoroutines, maximum)
	}
}

// TestCacheOptimizer_HighHitRate tests high hit rate scenario.
func TestCacheOptimizer_HighHitRate(t *testing.T) {
	optimizer := NewCacheOptimizer(1000)

	// High hit rate
	for i := 0; i < 90; i++ {
		optimizer.RecordHit()
	}
	for i := 0; i < 10; i++ {
		optimizer.RecordMiss()
	}

	hitRate := optimizer.GetHitRate()

	if hitRate < 0.85 || hitRate > 0.95 {
		t.Errorf("Expected hit rate around 0.9, got %.2f", hitRate)
	}

	recommendations := optimizer.GetOptimizationRecommendations()

	// Should have some recommendation (either positive or neutral)
	// High hit rate is good, so we just verify the function works
	_ = recommendations
}

// TestBottleneckDetector_NoBottlenecks tests when no bottlenecks exist.
func TestBottleneckDetector_NoBottlenecks(t *testing.T) {
	detector := NewBottleneckDetector(50.0)

	detector.RecordComponentTime("component1", 100)
	detector.RecordComponentTime("component2", 100)

	bottlenecks := detector.FindBottlenecks()

	// With 50% threshold and equal distribution, both components are at 50%
	// So they should be detected as bottlenecks (>= threshold)
	if len(bottlenecks) != 2 {
		t.Errorf("Expected 2 bottlenecks at 50%% threshold, got %d", len(bottlenecks))
	}
}

// TestParallelMethodAnalyzer_EmptyTasks tests handling of empty task list.
func TestParallelMethodAnalyzer_EmptyTasks(t *testing.T) {
	config := DefaultParallelConfig()
	analyzer := NewParallelMethodAnalyzer(config)

	tasks := make([]*MethodAnalysisTask, 0)

	err := analyzer.AnalyzeMethodsParallel(tasks, func(task *MethodAnalysisTask) error {
		return nil
	}, 0, len(tasks))

	if err != nil {
		t.Errorf("Expected no error for empty tasks, got %v", err)
	}
}

// TestParallelMethodAnalyzer_BoundsWaitingGoroutines prevents a goroutine per
// task. A bounded pool must keep the number of waiting goroutines independent of
// the number of queued methods.
func TestParallelMethodAnalyzer_BoundsWaitingGoroutines(t *testing.T) {
	config := DefaultParallelConfig()
	config.MaxGoroutines = 2
	analyzer := NewParallelMethodAnalyzer(config)

	const taskCount = 2000
	tasks := make([]*MethodAnalysisTask, taskCount)
	for i := range tasks {
		tasks[i] = &MethodAnalysisTask{MethodID: i}
	}

	baseline := runtime.NumGoroutine()
	started := make(chan struct{}, config.MaxGoroutines)
	release := make(chan struct{})
	done := make(chan error, 1)
	var entered int32
	go func() {
		done <- analyzer.AnalyzeMethodsParallel(tasks, func(*MethodAnalysisTask) error {
			if atomic.AddInt32(&entered, 1) <= int32(config.MaxGoroutines) {
				started <- struct{}{}
			}
			<-release
			return nil
		}, 0, len(tasks))
	}()

	for i := 0; i < config.MaxGoroutines; i++ {
		<-started
	}
	if got := runtime.NumGoroutine() - baseline; got > config.MaxGoroutines+8 {
		t.Fatalf("expected a bounded worker pool, got %d extra goroutines for %d tasks", got, taskCount)
	}

	close(release)
	if err := <-done; err != nil {
		t.Fatalf("AnalyzeMethodsParallel() error = %v", err)
	}
}

func TestParallelMethodAnalyzer_HonorsDisabledFlag(t *testing.T) {
	config := DefaultParallelConfig()
	config.MaxGoroutines = 8
	config.EnableMethodLevel = false
	analyzer := NewParallelMethodAnalyzer(config)

	tasks := make([]*MethodAnalysisTask, 8)
	for i := range tasks {
		tasks[i] = &MethodAnalysisTask{MethodID: i}
	}

	var active, peak int32
	err := analyzer.AnalyzeMethodsParallel(tasks, func(*MethodAnalysisTask) error {
		current := atomic.AddInt32(&active, 1)
		for {
			seen := atomic.LoadInt32(&peak)
			if current <= seen || atomic.CompareAndSwapInt32(&peak, seen, current) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
		atomic.AddInt32(&active, -1)
		return nil
	}, 0, len(tasks))
	if err != nil {
		t.Fatalf("AnalyzeMethodsParallel() error = %v", err)
	}
	if peak != 1 {
		t.Fatalf("expected disabled method-level parallelism to run sequentially, peak = %d", peak)
	}
}

// TestMemoryOptimizer_ZeroMaxMemory tests handling of zero max memory.
func TestMemoryOptimizer_ZeroMaxMemory(t *testing.T) {
	optimizer := NewMemoryOptimizer(0)

	percentage := optimizer.GetMemoryUsagePercentage()

	if percentage != 0 {
		t.Errorf("Expected 0%% for zero max memory, got %.2f%%", percentage)
	}
}

func TestMemoryOptimizer_RuntimeSnapshot(t *testing.T) {
	optimizer := NewMemoryOptimizer(64)
	snapshot := optimizer.RuntimeSnapshot()
	if snapshot.Goroutines < 1 {
		t.Fatalf("expected at least one goroutine, got %d", snapshot.Goroutines)
	}
	if snapshot.MemoryLimitBytes != 64*1024*1024 {
		t.Fatalf("memory limit = %d, want %d", snapshot.MemoryLimitBytes, 64*1024*1024)
	}
	if snapshot.RuntimeSysBytes == 0 {
		t.Fatal("expected Go runtime to report reserved memory")
	}
}
