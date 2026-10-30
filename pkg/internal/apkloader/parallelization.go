package apkloader

import (
	"os"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
)

// ═══════════════════════════════════════════════════════════════════════════════
// PARALLELIZATION: Per-Method, Per-Class, and Per-Pass Analysis
// ═══════════════════════════════════════════════════════════════════════════════

// ParallelConfig holds parallelization configuration.
type ParallelConfig struct {
	// MaxGoroutines is a shared upper bound for concurrent heavy analyses.
	// Values <= 0 use the safe default derived from GOMAXPROCS.
	MaxGoroutines int
	// MemoryLimitMB is a Go runtime soft heap limit. Zero disables this guard.
	// Native allocations remain outside this budget, so a conservative default is used.
	MemoryLimitMB     uint64
	MethodBatchSize   int
	ClassBatchSize    int
	EnableMethodLevel bool
	EnableClassLevel  bool
	EnablePassLevel   bool
}

// DefaultParallelConfig returns default parallelization configuration.
const (
	defaultMaxParallelWorkers = 8
	defaultMemoryLimitMB      = 1024
)

func DefaultParallelConfig() *ParallelConfig {
	return &ParallelConfig{
		MaxGoroutines:     defaultWorkerCount(),
		MemoryLimitMB:     defaultMemoryLimitMB,
		MethodBatchSize:   100,
		ClassBatchSize:    10,
		EnableMethodLevel: true,
		EnableClassLevel:  true,
		EnablePassLevel:   true,
	}
}

func defaultWorkerCount() int {
	workers := runtime.GOMAXPROCS(0)
	if workers < 1 {
		return 1
	}
	if workers > defaultMaxParallelWorkers {
		return defaultMaxParallelWorkers
	}
	return workers
}

func boundedWorkerCount(config *ParallelConfig, taskCount int, enabled bool) int {
	if taskCount <= 0 || !enabled {
		return 1
	}
	workers := config.MaxGoroutines
	if workers <= 0 {
		workers = defaultWorkerCount()
	}
	if workers > taskCount {
		workers = taskCount
	}
	if workers < 1 {
		return 1
	}
	return workers
}

// MethodAnalysisTask represents a single method analysis task.
type MethodAnalysisTask struct {
	MethodID    int
	MethodName  string
	ClassName   string
	Method      *EncodedMethod
	CFG         *CFG
	SSA         *SSAForm
	StringTable map[uint32]string
	Result      interface{}
	Error       error
}

// ClassAnalysisTask represents a single class analysis task.
type ClassAnalysisTask struct {
	ClassID   int
	ClassName string
	Methods   []*MethodAnalysisTask
	Result    interface{}
	Error     error
}

// ProgressCallback is a function called when a task is completed.
type ProgressCallback func(completed, total int)

// ParallelMethodAnalyzer analyzes methods in parallel.
type ParallelMethodAnalyzer struct {
	config           *ParallelConfig
	ProgressCallback ProgressCallback
}

// NewParallelMethodAnalyzer creates a new parallel method analyzer.
func NewParallelMethodAnalyzer(config *ParallelConfig) *ParallelMethodAnalyzer {
	if config == nil {
		config = DefaultParallelConfig()
	}
	return &ParallelMethodAnalyzer{config: config}
}

// AnalyzeMethodsParallel analyzes multiple methods in parallel.
func (pma *ParallelMethodAnalyzer) AnalyzeMethodsParallel(
	tasks []*MethodAnalysisTask,
	analyzeFunc func(*MethodAnalysisTask) error,
	completedOffset int,
	globalTotal int,
) error {
	if len(tasks) == 0 {
		return nil
	}

	workers := boundedWorkerCount(pma.config, len(tasks), pma.config.EnableMethodLevel)
	jobs := make(chan *MethodAnalysisTask, workers)
	errChan := make(chan error, workers)
	completed := int32(0)
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for task := range jobs {
			task.Error = analyzeFunc(task)
			if task.Error != nil {
				select {
				case errChan <- task.Error:
				default:
				}
			}
			if pma.ProgressCallback != nil {
				count := atomic.AddInt32(&completed, 1)
				pma.ProgressCallback(completedOffset+int(count), globalTotal)
			}
		}
	}

	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go worker()
	}
	for _, task := range tasks {
		jobs <- task
	}
	close(jobs)
	wg.Wait()
	close(errChan)

	for err := range errChan {
		return err
	}
	return nil
}

// AnalyzeMethodsInBatches analyzes methods in batches for better cache locality.
func (pma *ParallelMethodAnalyzer) AnalyzeMethodsInBatches(
	tasks []*MethodAnalysisTask,
	analyzeFunc func(*MethodAnalysisTask) error,
) error {
	batchSize := pma.config.MethodBatchSize
	if batchSize <= 0 {
		batchSize = 100
	}

	for i := 0; i < len(tasks); i += batchSize {
		end := i + batchSize
		if end > len(tasks) {
			end = len(tasks)
		}

		batch := tasks[i:end]
		if err := pma.AnalyzeMethodsParallel(batch, analyzeFunc, i, len(tasks)); err != nil {
			return err
		}
	}

	return nil
}

// ParallelClassAnalyzer analyzes classes in parallel.
type ParallelClassAnalyzer struct {
	config           *ParallelConfig
	ProgressCallback ProgressCallback
}

// NewParallelClassAnalyzer creates a new parallel class analyzer.
func NewParallelClassAnalyzer(config *ParallelConfig) *ParallelClassAnalyzer {
	if config == nil {
		config = DefaultParallelConfig()
	}
	return &ParallelClassAnalyzer{config: config}
}

// AnalyzeClassesParallel analyzes multiple classes in parallel.
func (pca *ParallelClassAnalyzer) AnalyzeClassesParallel(
	tasks []*ClassAnalysisTask,
	analyzeFunc func(*ClassAnalysisTask) error,
	completedOffset int,
	globalTotal int,
) error {
	if len(tasks) == 0 {
		return nil
	}

	workers := boundedWorkerCount(pca.config, len(tasks), pca.config.EnableClassLevel)
	jobs := make(chan *ClassAnalysisTask, workers)
	errChan := make(chan error, workers)
	completed := int32(0)
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for task := range jobs {
			task.Error = analyzeFunc(task)
			if task.Error != nil {
				select {
				case errChan <- task.Error:
				default:
				}
			}
			if pca.ProgressCallback != nil {
				count := atomic.AddInt32(&completed, 1)
				pca.ProgressCallback(completedOffset+int(count), globalTotal)
			}
		}
	}

	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go worker()
	}
	for _, task := range tasks {
		jobs <- task
	}
	close(jobs)
	wg.Wait()
	close(errChan)

	for err := range errChan {
		return err
	}
	return nil
}

// AnalyzeClassesInBatches analyzes classes in batches.
func (pca *ParallelClassAnalyzer) AnalyzeClassesInBatches(
	tasks []*ClassAnalysisTask,
	analyzeFunc func(*ClassAnalysisTask) error,
) error {
	batchSize := pca.config.ClassBatchSize
	if batchSize <= 0 {
		batchSize = 10
	}

	for i := 0; i < len(tasks); i += batchSize {
		end := i + batchSize
		if end > len(tasks) {
			end = len(tasks)
		}

		batch := tasks[i:end]
		if err := pca.AnalyzeClassesParallel(batch, analyzeFunc, i, len(tasks)); err != nil {
			return err
		}
	}

	return nil
}

// ParallelPassExecutor executes independent analysis passes in parallel.
type ParallelPassExecutor struct {
	config *ParallelConfig
}

// NewParallelPassExecutor creates a new parallel pass executor.
func NewParallelPassExecutor(config *ParallelConfig) *ParallelPassExecutor {
	if config == nil {
		config = DefaultParallelConfig()
	}
	return &ParallelPassExecutor{config: config}
}

// PassTask represents a single analysis pass task.
type PassTask struct {
	PassName string
	CFG      *CFG
	SSA      *SSAForm
	Result   interface{}
	Error    error
}

// ExecutePassesParallel executes multiple independent passes in parallel.
func (ppe *ParallelPassExecutor) ExecutePassesParallel(
	tasks []*PassTask,
	executeFunc func(*PassTask) error,
) error {
	if len(tasks) == 0 {
		return nil
	}

	workers := boundedWorkerCount(ppe.config, len(tasks), ppe.config.EnablePassLevel)
	jobs := make(chan *PassTask, workers)
	errChan := make(chan error, workers)
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for task := range jobs {
			task.Error = executeFunc(task)
			if task.Error != nil {
				select {
				case errChan <- task.Error:
				default:
				}
			}
		}
	}

	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go worker()
	}
	for _, task := range tasks {
		jobs <- task
	}
	close(jobs)
	wg.Wait()
	close(errChan)

	for err := range errChan {
		return err
	}
	return nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// CACHE OPTIMIZATION
// ═══════════════════════════════════════════════════════════════════════════════

// CacheOptimizer provides cache optimization utilities.
type CacheOptimizer struct {
	mu              sync.RWMutex
	hits            int64
	misses          int64
	evictions       int64
	maxSize         int
	currentSize     int
	hitRate         float64
	recommendedSize int
}

// NewCacheOptimizer creates a new cache optimizer.
func NewCacheOptimizer(maxSize int) *CacheOptimizer {
	return &CacheOptimizer{
		maxSize:         maxSize,
		currentSize:     0,
		recommendedSize: maxSize,
	}
}

// RecordHit records a cache hit.
func (co *CacheOptimizer) RecordHit() {
	co.mu.Lock()
	defer co.mu.Unlock()

	co.hits++
	co.updateHitRate()
}

// RecordMiss records a cache miss.
func (co *CacheOptimizer) RecordMiss() {
	co.mu.Lock()
	defer co.mu.Unlock()

	co.misses++
	co.updateHitRate()
}

// RecordEviction records a cache eviction.
func (co *CacheOptimizer) RecordEviction() {
	co.mu.Lock()
	defer co.mu.Unlock()

	co.evictions++
}

// updateHitRate updates the hit rate (must be called with lock held).
func (co *CacheOptimizer) updateHitRate() {
	total := co.hits + co.misses
	if total > 0 {
		co.hitRate = float64(co.hits) / float64(total)
	}
}

// GetHitRate returns the current hit rate.
func (co *CacheOptimizer) GetHitRate() float64 {
	co.mu.RLock()
	defer co.mu.RUnlock()

	return co.hitRate
}

// GetOptimizationRecommendations returns cache optimization recommendations.
func (co *CacheOptimizer) GetOptimizationRecommendations() []string {
	co.mu.RLock()
	defer co.mu.RUnlock()

	var recommendations []string

	if co.hitRate < 0.5 {
		recommendations = append(recommendations, "Low cache hit rate (<50%) - consider increasing cache size")
		co.recommendedSize = co.maxSize * 2
	} else if co.hitRate < 0.7 {
		recommendations = append(recommendations, "Moderate cache hit rate (<70%) - consider increasing cache size by 50%")
		co.recommendedSize = co.maxSize * 3 / 2
	} else if co.hitRate > 0.9 {
		recommendations = append(recommendations, "Excellent cache hit rate (>90%) - cache is well-tuned")
	}

	if co.evictions > co.hits {
		recommendations = append(recommendations, "High eviction rate - consider increasing cache capacity")
	}

	return recommendations
}

// ═══════════════════════════════════════════════════════════════════════════════
// MEMORY OPTIMIZATION
// ═══════════════════════════════════════════════════════════════════════════════

// MemoryOptimizer provides memory optimization utilities.
type MemoryOptimizer struct {
	mu        sync.RWMutex
	maxMemory uint64
	threshold float64
}

// RuntimeResourceSnapshot provides a cheap, allocation-free view of the Go
// runtime at a pipeline boundary. It intentionally distinguishes live heap from
// runtime-reserved memory so reports do not confuse the two.
type RuntimeResourceSnapshot struct {
	HeapAllocBytes   uint64
	HeapInUseBytes   uint64
	RuntimeSysBytes  uint64
	HeapObjects      uint64
	Goroutines       int
	MemoryLimitBytes uint64
}

// NewMemoryOptimizer creates a new memory optimizer.
func NewMemoryOptimizer(maxMemoryMB uint64) *MemoryOptimizer {
	return &MemoryOptimizer{
		maxMemory: maxMemoryMB * 1024 * 1024,
		threshold: 0.8, // Start backpressure before the runtime reaches its hard ceiling.
	}
}

// ApplyRuntimeLimit configures the Go runtime's soft memory limit for this process.
// It is intentionally a soft limit: the runtime can exceed it briefly to preserve
// correctness, while starting collection sooner and reducing heap growth.
func (mo *MemoryOptimizer) ApplyRuntimeLimit() {
	mo.mu.RLock()
	limit := mo.maxMemory
	mo.mu.RUnlock()
	if limit > 0 {
		// Let operators override the conservative project default without a rebuild.
		if _, userConfigured := os.LookupEnv("GOMEMLIMIT"); !userConfigured {
			debug.SetMemoryLimit(int64(limit))
		}
	}
}

// GetCurrentMemory returns current memory usage.
func (mo *MemoryOptimizer) GetCurrentMemory() uint64 {
	return mo.RuntimeSnapshot().HeapAllocBytes
}

// RuntimeSnapshot captures current Go heap and scheduler state for reports and
// pressure decisions. It does not report native DLL, mmap, or OS file-cache use.
func (mo *MemoryOptimizer) RuntimeSnapshot() RuntimeResourceSnapshot {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	mo.mu.RLock()
	limit := mo.maxMemory
	mo.mu.RUnlock()
	return RuntimeResourceSnapshot{
		HeapAllocBytes:   m.HeapAlloc,
		HeapInUseBytes:   m.HeapInuse,
		RuntimeSysBytes:  m.Sys,
		HeapObjects:      m.HeapObjects,
		Goroutines:       runtime.NumGoroutine(),
		MemoryLimitBytes: limit,
	}
}

// IsMemoryAvailable checks if memory is available.
func (mo *MemoryOptimizer) IsMemoryAvailable(requiredBytes uint64) bool {
	snapshot := mo.RuntimeSnapshot()
	if snapshot.MemoryLimitBytes == 0 {
		return true
	}
	mo.mu.RLock()
	threshold := uint64(float64(snapshot.MemoryLimitBytes) * mo.threshold)
	mo.mu.RUnlock()
	return snapshot.HeapAllocBytes+requiredBytes <= threshold
}

// GetMemoryUsagePercentage returns memory usage as percentage.
func (mo *MemoryOptimizer) GetMemoryUsagePercentage() float64 {
	snapshot := mo.RuntimeSnapshot()
	if snapshot.MemoryLimitBytes == 0 {
		return 0
	}
	return float64(snapshot.HeapAllocBytes) / float64(snapshot.MemoryLimitBytes) * 100
}

// GetOptimizationRecommendations returns memory optimization recommendations.
func (mo *MemoryOptimizer) GetOptimizationRecommendations() []string {
	usage := mo.GetMemoryUsagePercentage()

	var recommendations []string

	if usage > 90 {
		recommendations = append(recommendations, "Critical: Memory usage >90% - reduce batch sizes immediately")
	} else if usage > 75 {
		recommendations = append(recommendations, "Warning: Memory usage >75% - consider reducing batch sizes")
	} else if usage < 30 {
		recommendations = append(recommendations, "Opportunity: Memory usage <30% - can increase batch sizes for better throughput")
	}

	return recommendations
}

// ═══════════════════════════════════════════════════════════════════════════════
// BOTTLENECK DETECTION
// ═══════════════════════════════════════════════════════════════════════════════

// BottleneckDetector identifies performance bottlenecks.
type BottleneckDetector struct {
	mu         sync.RWMutex
	components map[string]int64 // component name -> duration in nanoseconds
	threshold  float64          // percentage threshold
}

// NewBottleneckDetector creates a new bottleneck detector.
func NewBottleneckDetector(threshold float64) *BottleneckDetector {
	return &BottleneckDetector{
		components: make(map[string]int64),
		threshold:  threshold,
	}
}

// RecordComponentTime records the execution time of a component.
func (bd *BottleneckDetector) RecordComponentTime(name string, durationNs int64) {
	bd.mu.Lock()
	defer bd.mu.Unlock()

	bd.components[name] = durationNs
}

// FindBottlenecks identifies components that exceed the threshold.
func (bd *BottleneckDetector) FindBottlenecks() []string {
	bd.mu.RLock()
	defer bd.mu.RUnlock()

	totalDuration := int64(0)
	for _, duration := range bd.components {
		totalDuration += duration
	}

	if totalDuration == 0 {
		return []string{}
	}

	var bottlenecks []string
	for name, duration := range bd.components {
		percentage := float64(duration) / float64(totalDuration) * 100
		if percentage >= bd.threshold {
			bottlenecks = append(bottlenecks, name)
		}
	}

	return bottlenecks
}

// GetComponentPercentage returns the percentage of total time for a component.
func (bd *BottleneckDetector) GetComponentPercentage(name string) float64 {
	bd.mu.RLock()
	defer bd.mu.RUnlock()

	totalDuration := int64(0)
	for _, duration := range bd.components {
		totalDuration += duration
	}

	if totalDuration == 0 {
		return 0
	}

	duration, exists := bd.components[name]
	if !exists {
		return 0
	}

	return float64(duration) / float64(totalDuration) * 100
}

// Reset clears all recorded times.
func (bd *BottleneckDetector) Reset() {
	bd.mu.Lock()
	defer bd.mu.Unlock()

	bd.components = make(map[string]int64)
}
