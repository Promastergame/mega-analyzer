package apkloader

import (
	"strconv"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
// OPTIMIZATION COORDINATOR: Unified Performance Management
// ═══════════════════════════════════════════════════════════════════════════════

// OptimizationCoordinator coordinates all optimization strategies.
type OptimizationCoordinator struct {
	mu sync.RWMutex

	// Configuration
	config *ParallelConfig

	// Optimization components
	methodAnalyzer     *ParallelMethodAnalyzer
	classAnalyzer      *ParallelClassAnalyzer
	passExecutor       *ParallelPassExecutor
	cacheOptimizer     *CacheOptimizer
	memoryOptimizer    *MemoryOptimizer
	bottleneckDetector *BottleneckDetector

	// Metrics
	startTime     time.Time
	totalDuration time.Duration
	componentsRun int
	optimizations []string
}

// NewOptimizationCoordinator creates a new optimization coordinator.
func NewOptimizationCoordinator(config *ParallelConfig) *OptimizationCoordinator {
	if config == nil {
		config = DefaultParallelConfig()
	}

	memoryOptimizer := NewMemoryOptimizer(config.MemoryLimitMB)
	memoryOptimizer.ApplyRuntimeLimit()

	return &OptimizationCoordinator{
		config:             config,
		methodAnalyzer:     NewParallelMethodAnalyzer(config),
		classAnalyzer:      NewParallelClassAnalyzer(config),
		passExecutor:       NewParallelPassExecutor(config),
		cacheOptimizer:     NewCacheOptimizer(10000),
		memoryOptimizer:    memoryOptimizer,
		bottleneckDetector: NewBottleneckDetector(20.0), // 20% threshold
		optimizations:      make([]string, 0),
	}
}

// StartOptimization marks the start of optimization.
func (oc *OptimizationCoordinator) StartOptimization() {
	oc.mu.Lock()
	defer oc.mu.Unlock()

	oc.startTime = time.Now()
	oc.componentsRun = 0
	oc.optimizations = make([]string, 0)
}

// EndOptimization marks the end of optimization and calculates metrics.
func (oc *OptimizationCoordinator) EndOptimization() {
	oc.mu.Lock()
	defer oc.mu.Unlock()

	oc.totalDuration = time.Since(oc.startTime)
}

// AnalyzeMethodsOptimized analyzes methods with optimization.
func (oc *OptimizationCoordinator) AnalyzeMethodsOptimized(
	tasks []*MethodAnalysisTask,
	analyzeFunc func(*MethodAnalysisTask) error,
) error {
	oc.mu.Lock()
	oc.componentsRun++
	oc.mu.Unlock()

	analyzer := oc.methodAnalyzer
	if !oc.memoryOptimizer.IsMemoryAvailable(32 * 1024 * 1024) {
		// Do not start another parallel batch when the heap is already under
		// pressure. This keeps the pipeline productive instead of multiplying
		// CFG/SSA allocations across workers close to the memory limit.
		degradedConfig := *oc.config
		degradedConfig.MaxGoroutines = 1
		degradedConfig.MethodBatchSize = 16
		degradedConfig.EnableMethodLevel = false
		analyzer = NewParallelMethodAnalyzer(&degradedConfig)
		analyzer.ProgressCallback = oc.methodAnalyzer.ProgressCallback

		oc.mu.Lock()
		oc.optimizations = append(oc.optimizations, "Memory pressure detected - method analysis switched to a single worker with batches of 16")
		oc.mu.Unlock()
	}

	start := time.Now()
	err := analyzer.AnalyzeMethodsInBatches(tasks, analyzeFunc)
	duration := time.Since(start)

	oc.bottleneckDetector.RecordComponentTime("method_analysis", duration.Nanoseconds())

	if err != nil {
		return err
	}

	// Record if the completed batch left the process near its memory budget.
	if !oc.memoryOptimizer.IsMemoryAvailable(32 * 1024 * 1024) {
		oc.mu.Lock()
		oc.optimizations = append(oc.optimizations, "Memory pressure remains after method analysis - the next batch will stay degraded")
		oc.mu.Unlock()
	}

	return nil
}

// AnalyzeClassesOptimized analyzes classes with optimization.
func (oc *OptimizationCoordinator) AnalyzeClassesOptimized(
	tasks []*ClassAnalysisTask,
	analyzeFunc func(*ClassAnalysisTask) error,
) error {
	oc.mu.Lock()
	oc.componentsRun++
	oc.mu.Unlock()

	start := time.Now()
	err := oc.classAnalyzer.AnalyzeClassesInBatches(tasks, analyzeFunc)
	duration := time.Since(start)

	oc.bottleneckDetector.RecordComponentTime("class_analysis", duration.Nanoseconds())

	if err != nil {
		return err
	}

	return nil
}

// ExecutePassesOptimized executes passes with optimization.
func (oc *OptimizationCoordinator) ExecutePassesOptimized(
	tasks []*PassTask,
	executeFunc func(*PassTask) error,
) error {
	oc.mu.Lock()
	oc.componentsRun++
	oc.mu.Unlock()

	start := time.Now()
	err := oc.passExecutor.ExecutePassesParallel(tasks, executeFunc)
	duration := time.Since(start)

	oc.bottleneckDetector.RecordComponentTime("pass_execution", duration.Nanoseconds())

	if err != nil {
		return err
	}

	return nil
}

// RecordCacheHit records a cache hit for optimization tracking.
func (oc *OptimizationCoordinator) RecordCacheHit() {
	oc.cacheOptimizer.RecordHit()
}

// RecordCacheMiss records a cache miss for optimization tracking.
func (oc *OptimizationCoordinator) RecordCacheMiss() {
	oc.cacheOptimizer.RecordMiss()
}

// GetOptimizationReport returns a comprehensive optimization report.
func (oc *OptimizationCoordinator) GetOptimizationReport() string {
	oc.mu.RLock()
	defer oc.mu.RUnlock()

	report := "═══════════════════════════════════════════════════════════════════════════════\n"
	report += "OPTIMIZATION REPORT\n"
	report += "═══════════════════════════════════════════════════════════════════════════════\n\n"

	report += "EXECUTION METRICS\n"
	report += "─────────────────────────────────────────────────────────────────────────────\n"
	report += "Total Duration: " + oc.totalDuration.String() + "\n"
	report += "Components Run: " + strconv.Itoa(oc.componentsRun) + "\n"
	report += "Max Goroutines: " + strconv.Itoa(oc.config.MaxGoroutines) + "\n"
	report += "Memory Limit: " + strconv.FormatUint(oc.config.MemoryLimitMB, 10) + " MB\n\n"

	report += "CACHE OPTIMIZATION\n"
	report += "─────────────────────────────────────────────────────────────────────────────\n"
	cacheStats := oc.cacheOptimizer.GetHitRate()
	report += "Cache Hit Rate: " + formatPercentage(cacheStats) + "\n"
	cacheRecommendations := oc.cacheOptimizer.GetOptimizationRecommendations()
	for _, rec := range cacheRecommendations {
		report += "  • " + rec + "\n"
	}
	report += "\n"

	report += "MEMORY OPTIMIZATION\n"
	report += "─────────────────────────────────────────────────────────────────────────────\n"
	snapshot := oc.memoryOptimizer.RuntimeSnapshot()
	memUsage := oc.memoryOptimizer.GetMemoryUsagePercentage()
	report += "Memory Usage: " + formatPercentage(memUsage) + "\n"
	report += "Heap Alloc: " + formatMiB(snapshot.HeapAllocBytes) + "\n"
	report += "Heap In Use: " + formatMiB(snapshot.HeapInUseBytes) + "\n"
	report += "Runtime Sys: " + formatMiB(snapshot.RuntimeSysBytes) + "\n"
	report += "Heap Objects: " + strconv.FormatUint(snapshot.HeapObjects, 10) + "\n"
	report += "Goroutines: " + strconv.Itoa(snapshot.Goroutines) + "\n"
	memRecommendations := oc.memoryOptimizer.GetOptimizationRecommendations()
	for _, rec := range memRecommendations {
		report += "  • " + rec + "\n"
	}
	report += "\n"

	report += "BOTTLENECK ANALYSIS\n"
	report += "─────────────────────────────────────────────────────────────────────────────\n"
	bottlenecks := oc.bottleneckDetector.FindBottlenecks()
	if len(bottlenecks) > 0 {
		report += "Detected Bottlenecks:\n"
		for _, bottleneck := range bottlenecks {
			report += "  • " + bottleneck + "\n"
		}
	} else {
		report += "No significant bottlenecks detected\n"
	}
	report += "\n"

	report += "OPTIMIZATION ACTIONS\n"
	report += "─────────────────────────────────────────────────────────────────────────────\n"
	if len(oc.optimizations) > 0 {
		for _, opt := range oc.optimizations {
			report += "  • " + opt + "\n"
		}
	} else {
		report += "No optimization actions needed\n"
	}
	report += "\n"

	report += "═══════════════════════════════════════════════════════════════════════════════\n"

	return report
}

// formatPercentage formats a percentage value.
func formatMiB(bytes uint64) string {
	const mib = 1024 * 1024
	whole := bytes / mib
	fraction := (bytes % mib) * 100 / mib
	return strconv.FormatUint(whole, 10) + "." + strconv.FormatUint(fraction, 10) + " MiB"
}

func formatPercentage(value float64) string {
	if value < 0 {
		return "0.00%"
	}
	if value >= 100 {
		return "100.00%"
	}
	// Simple formatting without fmt package
	intPart := int(value)
	fracPart := int((value-float64(intPart))*100 + 0.5)
	if fracPart >= 100 {
		intPart++
		fracPart -= 100
		if intPart >= 100 {
			return "100.00%"
		}
	}

	var intStr string
	if intPart < 10 {
		intStr = string(rune(intPart + 48))
	} else {
		intStr = string(rune(intPart/10+48)) + string(rune(intPart%10+48))
	}

	return intStr + "." + string(rune(fracPart/10+48)) + string(rune(fracPart%10+48)) + "%"
}

// GetBottlenecks returns detected bottlenecks.
func (oc *OptimizationCoordinator) GetBottlenecks() []string {
	oc.mu.RLock()
	defer oc.mu.RUnlock()

	return oc.bottleneckDetector.FindBottlenecks()
}

// GetCacheHitRate returns the cache hit rate.
func (oc *OptimizationCoordinator) GetCacheHitRate() float64 {
	oc.mu.RLock()
	defer oc.mu.RUnlock()

	return oc.cacheOptimizer.GetHitRate()
}

// GetMemoryUsagePercentage returns memory usage percentage.
func (oc *OptimizationCoordinator) GetMemoryUsagePercentage() float64 {
	oc.mu.RLock()
	defer oc.mu.RUnlock()

	return oc.memoryOptimizer.GetMemoryUsagePercentage()
}

// GetTotalDuration returns total optimization duration.
func (oc *OptimizationCoordinator) GetTotalDuration() time.Duration {
	oc.mu.RLock()
	defer oc.mu.RUnlock()

	return oc.totalDuration
}

// GetComponentsRun returns number of components run.
func (oc *OptimizationCoordinator) GetComponentsRun() int {
	oc.mu.RLock()
	defer oc.mu.RUnlock()

	return oc.componentsRun
}
