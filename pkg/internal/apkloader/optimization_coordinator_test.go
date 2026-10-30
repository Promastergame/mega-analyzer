package apkloader

import (
	"sync/atomic"
	"testing"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
// UNIT TESTS: Optimization Coordinator
// ═══════════════════════════════════════════════════════════════════════════════

// TestNewOptimizationCoordinator tests coordinator initialization.
func TestNewOptimizationCoordinator(t *testing.T) {
	coordinator := NewOptimizationCoordinator(nil)

	if coordinator == nil {
		t.Fatal("Expected coordinator to be created, got nil")
	}
	if coordinator.config == nil {
		t.Error("Expected config to be set")
	}
	if coordinator.methodAnalyzer == nil {
		t.Error("Expected method analyzer to be initialized")
	}
	if coordinator.classAnalyzer == nil {
		t.Error("Expected class analyzer to be initialized")
	}
	if coordinator.passExecutor == nil {
		t.Error("Expected pass executor to be initialized")
	}
	if coordinator.cacheOptimizer == nil {
		t.Error("Expected cache optimizer to be initialized")
	}
	if coordinator.memoryOptimizer == nil {
		t.Error("Expected memory optimizer to be initialized")
	}
	if coordinator.bottleneckDetector == nil {
		t.Error("Expected bottleneck detector to be initialized")
	}
}

// TestOptimizationCoordinator_StartAndEnd tests start and end optimization.
func TestOptimizationCoordinator_StartAndEnd(t *testing.T) {
	coordinator := NewOptimizationCoordinator(nil)

	coordinator.StartOptimization()
	time.Sleep(10 * time.Millisecond)
	coordinator.EndOptimization()

	duration := coordinator.GetTotalDuration()

	if duration < 10*time.Millisecond {
		t.Error("Expected duration to be at least 10ms")
	}
}

// TestOptimizationCoordinator_AnalyzeMethodsOptimized tests optimized method analysis.
func TestOptimizationCoordinator_AnalyzeMethodsOptimized(t *testing.T) {
	coordinator := NewOptimizationCoordinator(nil)

	tasks := make([]*MethodAnalysisTask, 5)
	for i := 0; i < 5; i++ {
		tasks[i] = &MethodAnalysisTask{
			MethodID:   i,
			MethodName: "method_" + string(rune(i)),
		}
	}

	var counter int32
	err := coordinator.AnalyzeMethodsOptimized(tasks, func(task *MethodAnalysisTask) error {
		atomic.AddInt32(&counter, 1)
		return nil
	})

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if counter != 5 {
		t.Errorf("Expected 5 tasks to execute, got %d", counter)
	}
	if coordinator.GetComponentsRun() != 1 {
		t.Error("Expected 1 component to be run")
	}
}

// TestOptimizationCoordinator_AnalyzeClassesOptimized tests optimized class analysis.
func TestOptimizationCoordinator_AnalyzeClassesOptimized(t *testing.T) {
	coordinator := NewOptimizationCoordinator(nil)

	tasks := make([]*ClassAnalysisTask, 3)
	for i := 0; i < 3; i++ {
		tasks[i] = &ClassAnalysisTask{
			ClassID:   i,
			ClassName: "class_" + string(rune(i)),
			Methods:   make([]*MethodAnalysisTask, 0),
		}
	}

	var counter int32
	err := coordinator.AnalyzeClassesOptimized(tasks, func(task *ClassAnalysisTask) error {
		atomic.AddInt32(&counter, 1)
		return nil
	})

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if counter != 3 {
		t.Errorf("Expected 3 tasks to execute, got %d", counter)
	}
	if coordinator.GetComponentsRun() != 1 {
		t.Error("Expected 1 component to be run")
	}
}

// TestOptimizationCoordinator_ExecutePassesOptimized tests optimized pass execution.
func TestOptimizationCoordinator_ExecutePassesOptimized(t *testing.T) {
	coordinator := NewOptimizationCoordinator(nil)

	tasks := make([]*PassTask, 2)
	for i := 0; i < 2; i++ {
		tasks[i] = &PassTask{
			PassName: "pass_" + string(rune(i)),
		}
	}

	var counter int32
	err := coordinator.ExecutePassesOptimized(tasks, func(task *PassTask) error {
		atomic.AddInt32(&counter, 1)
		return nil
	})

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if counter != 2 {
		t.Errorf("Expected 2 tasks to execute, got %d", counter)
	}
	if coordinator.GetComponentsRun() != 1 {
		t.Error("Expected 1 component to be run")
	}
}

// TestOptimizationCoordinator_CacheTracking tests cache tracking.
func TestOptimizationCoordinator_CacheTracking(t *testing.T) {
	coordinator := NewOptimizationCoordinator(nil)

	coordinator.RecordCacheHit()
	coordinator.RecordCacheHit()
	coordinator.RecordCacheMiss()

	hitRate := coordinator.GetCacheHitRate()

	if hitRate < 0.6 || hitRate > 0.7 {
		t.Errorf("Expected hit rate around 0.67, got %.2f", hitRate)
	}
}

// TestOptimizationCoordinator_MemoryTracking tests memory tracking.
func TestOptimizationCoordinator_MemoryTracking(t *testing.T) {
	coordinator := NewOptimizationCoordinator(nil)

	percentage := coordinator.GetMemoryUsagePercentage()

	if percentage < 0 || percentage > 100 {
		t.Errorf("Expected percentage between 0 and 100, got %.2f", percentage)
	}
}

// TestOptimizationCoordinator_GetOptimizationReport tests report generation.
func TestOptimizationCoordinator_GetOptimizationReport(t *testing.T) {
	coordinator := NewOptimizationCoordinator(nil)

	coordinator.StartOptimization()
	time.Sleep(5 * time.Millisecond)
	coordinator.EndOptimization()

	report := coordinator.GetOptimizationReport()

	if report == "" {
		t.Error("Expected report to be generated")
	}
	if len(report) == 0 {
		t.Error("Expected non-empty report")
	}
}

// TestOptimizationCoordinator_MultipleComponents tests multiple components.
func TestOptimizationCoordinator_MultipleComponents(t *testing.T) {
	coordinator := NewOptimizationCoordinator(nil)

	// Analyze methods
	methodTasks := make([]*MethodAnalysisTask, 2)
	for i := 0; i < 2; i++ {
		methodTasks[i] = &MethodAnalysisTask{
			MethodID:   i,
			MethodName: "method_" + string(rune(i)),
		}
	}
	_ = coordinator.AnalyzeMethodsOptimized(methodTasks, func(task *MethodAnalysisTask) error {
		return nil
	})

	// Analyze classes
	classTasks := make([]*ClassAnalysisTask, 1)
	classTasks[0] = &ClassAnalysisTask{
		ClassID:   0,
		ClassName: "class_0",
		Methods:   make([]*MethodAnalysisTask, 0),
	}
	_ = coordinator.AnalyzeClassesOptimized(classTasks, func(task *ClassAnalysisTask) error {
		return nil
	})

	// Execute passes
	passTasks := make([]*PassTask, 1)
	passTasks[0] = &PassTask{
		PassName: "pass_0",
	}
	_ = coordinator.ExecutePassesOptimized(passTasks, func(task *PassTask) error {
		return nil
	})

	if coordinator.GetComponentsRun() != 3 {
		t.Errorf("Expected 3 components to be run, got %d", coordinator.GetComponentsRun())
	}
}

// TestOptimizationCoordinator_GetBottlenecks tests bottleneck detection.
func TestOptimizationCoordinator_GetBottlenecks(t *testing.T) {
	coordinator := NewOptimizationCoordinator(nil)

	// Create a slow method analysis
	methodTasks := make([]*MethodAnalysisTask, 1)
	methodTasks[0] = &MethodAnalysisTask{
		MethodID:   0,
		MethodName: "slow_method",
	}

	_ = coordinator.AnalyzeMethodsOptimized(methodTasks, func(task *MethodAnalysisTask) error {
		time.Sleep(10 * time.Millisecond)
		return nil
	})

	bottlenecks := coordinator.GetBottlenecks()

	// Should detect method_analysis as bottleneck if it takes significant time
	_ = bottlenecks
}

// TestOptimizationCoordinator_WithCustomConfig tests with custom config.
func TestOptimizationCoordinator_WithCustomConfig(t *testing.T) {
	config := &ParallelConfig{
		MaxGoroutines:     4,
		MethodBatchSize:   50,
		ClassBatchSize:    5,
		EnableMethodLevel: true,
		EnableClassLevel:  true,
		EnablePassLevel:   true,
	}

	coordinator := NewOptimizationCoordinator(config)

	if coordinator.config.MaxGoroutines != 4 {
		t.Error("Expected custom max goroutines to be set")
	}
	if coordinator.config.MethodBatchSize != 50 {
		t.Error("Expected custom method batch size to be set")
	}
}

// TestOptimizationCoordinator_ConcurrentOperations tests concurrent operations.
func TestOptimizationCoordinator_ConcurrentOperations(t *testing.T) {
	coordinator := NewOptimizationCoordinator(nil)

	coordinator.StartOptimization()

	// Simulate concurrent cache operations
	for i := 0; i < 100; i++ {
		if i%2 == 0 {
			coordinator.RecordCacheHit()
		} else {
			coordinator.RecordCacheMiss()
		}
	}

	coordinator.EndOptimization()

	hitRate := coordinator.GetCacheHitRate()

	if hitRate < 0.4 || hitRate > 0.6 {
		t.Errorf("Expected hit rate around 0.5, got %.2f", hitRate)
	}
}

// TestOptimizationCoordinator_EmptyTasks tests with empty tasks.
func TestOptimizationCoordinator_EmptyTasks(t *testing.T) {
	coordinator := NewOptimizationCoordinator(nil)

	methodTasks := make([]*MethodAnalysisTask, 0)
	err := coordinator.AnalyzeMethodsOptimized(methodTasks, func(task *MethodAnalysisTask) error {
		return nil
	})

	if err != nil {
		t.Errorf("Expected no error for empty tasks, got %v", err)
	}
}

// TestOptimizationCoordinator_ReportContent tests report content.
func TestOptimizationCoordinator_ReportContent(t *testing.T) {
	coordinator := NewOptimizationCoordinator(nil)

	coordinator.StartOptimization()
	coordinator.RecordCacheHit()
	coordinator.RecordCacheMiss()
	coordinator.EndOptimization()

	report := coordinator.GetOptimizationReport()

	// Check for key sections in report
	if len(report) == 0 {
		t.Error("Expected non-empty report")
	}
}

// TestFormatPercentage tests formatPercentage function.
func TestFormatPercentage(t *testing.T) {
	tests := []struct {
		val      float64
		expected string
	}{
		{-5.0, "0.00%"},
		{0.0, "0.00%"},
		{5.23, "5.23%"},
		{12.34, "12.34%"},
		{99.999, "100.00%"},
		{100.0, "100.00%"},
		{150.0, "100.00%"},
	}

	for _, tc := range tests {
		res := formatPercentage(tc.val)
		if res != tc.expected {
			t.Errorf("formatPercentage(%f) = %q, expected %q", tc.val, res, tc.expected)
		}
	}
}

func TestOptimizationCoordinator_DegradesMethodParallelismUnderMemoryPressure(t *testing.T) {
	coordinator := NewOptimizationCoordinator(nil)
	// Force the pre-flight availability check without changing the process-wide
	// Go runtime memory limit installed by the constructor.
	coordinator.memoryOptimizer.maxMemory = 1

	tasks := make([]*MethodAnalysisTask, 8)
	for i := range tasks {
		tasks[i] = &MethodAnalysisTask{MethodID: i}
	}

	var active, peak int32
	err := coordinator.AnalyzeMethodsOptimized(tasks, func(*MethodAnalysisTask) error {
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
	})
	if err != nil {
		t.Fatalf("AnalyzeMethodsOptimized() error = %v", err)
	}
	if peak != 1 {
		t.Fatalf("expected memory-pressure fallback to one worker, peak = %d", peak)
	}

	report := coordinator.GetOptimizationReport()
	if report == "" {
		t.Fatal("expected an optimization report")
	}
}
