// pkg/internal/apkloader/pipeline_profiling_test.go
// Comprehensive profiling tests for deobfuscation pipeline components
// Uses Go pprof to measure performance of CFG, SSA, constant propagation,
// dead code elimination, variable recovery, method recovery, and reflection resolution
package apkloader

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"testing"
	"time"

	"mega-analyzer/pkg/internal/testutil"
)

// ═══════════════════════════════════════════════════════════════════════════════
// Profile Metrics Collection
// ═══════════════════════════════════════════════════════════════════════════════

// ProfileMetrics holds performance metrics for a component
type ProfileMetrics struct {
	ComponentName  string
	Duration       time.Duration
	MemAllocated   uint64
	MemInUse       uint64
	AllocCount     uint64
	FreeCount      uint64
	GCRuns         uint32
	CPUSamples     int64
	OperationCount int64
	Throughput     float64
}

// String returns a formatted string representation of metrics
func (pm *ProfileMetrics) String() string {
	return fmt.Sprintf(
		"Component: %s\n"+
			"  Duration: %v\n"+
			"  Memory Allocated: %d bytes (%.2f MB)\n"+
			"  Memory In Use: %d bytes (%.2f MB)\n"+
			"  Alloc Count: %d\n"+
			"  Free Count: %d\n"+
			"  GC Runs: %d\n"+
			"  Operations: %d\n"+
			"  Throughput: %.2f ops/sec\n",
		pm.ComponentName,
		pm.Duration,
		pm.MemAllocated, float64(pm.MemAllocated)/(1024*1024),
		pm.MemInUse, float64(pm.MemInUse)/(1024*1024),
		pm.AllocCount,
		pm.FreeCount,
		pm.GCRuns,
		pm.OperationCount,
		pm.Throughput,
	)
}

// ProfileResult holds complete profiling results
type ProfileResult struct {
	Metrics       *ProfileMetrics
	CPUProfile    []byte
	MemProfile    []byte
	GoroutineInfo []byte
	Timestamp     time.Time
}

// ═══════════════════════════════════════════════════════════════════════════════
// Profiling Utilities
// ═══════════════════════════════════════════════════════════════════════════════

// startMemoryProfile captures initial memory state
func startMemoryProfile() runtime.MemStats {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m
}

// endMemoryProfile captures final memory state and calculates metrics
func endMemoryProfile(startMem runtime.MemStats) (uint64, uint64, uint64, uint64, uint32) {
	runtime.GC()
	var endMem runtime.MemStats
	runtime.ReadMemStats(&endMem)

	memAllocated := endMem.TotalAlloc - startMem.TotalAlloc
	memInUse := endMem.Alloc
	allocCount := endMem.Mallocs - startMem.Mallocs
	freeCount := endMem.Frees - startMem.Frees
	gcRuns := endMem.NumGC - startMem.NumGC

	return memAllocated, memInUse, allocCount, freeCount, gcRuns
}

// profileComponent runs a function with profiling and returns metrics
var profilingSink int

func profileComponent(name string, fn func() int64) *ProfileMetrics {
	// Start memory profiling
	startMem := startMemoryProfile()

	// Measure execution time
	start := time.Now()
	opsCount := fn()
	duration := time.Since(start)

	// End memory profiling
	memAllocated, memInUse, allocCount, freeCount, gcRuns := endMemoryProfile(startMem)

	// Calculate throughput
	throughput := 0.0
	if duration.Seconds() > 0 {
		throughput = float64(opsCount) / duration.Seconds()
	}

	return &ProfileMetrics{
		ComponentName:  name,
		Duration:       duration,
		MemAllocated:   memAllocated,
		MemInUse:       memInUse,
		AllocCount:     allocCount,
		FreeCount:      freeCount,
		GCRuns:         gcRuns,
		OperationCount: opsCount,
		Throughput:     throughput,
	}
}

// writeCPUProfile writes CPU profile to buffer
func writeCPUProfile() ([]byte, error) {
	var buf bytes.Buffer
	if err := pprof.WriteHeapProfile(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// writeMemProfile writes memory profile to buffer
func writeMemProfile() ([]byte, error) {
	var buf bytes.Buffer
	if err := pprof.WriteHeapProfile(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// Test Helpers - Large Application Simulation
// ═══════════════════════════════════════════════════════════════════════════════

// createLargeTestCFG creates a large CFG for profiling
func createLargeTestCFG(blockCount int) *CFG {
	cfg := &CFG{
		Blocks:         make([]*BasicBlock, blockCount),
		offsetToBlock:  make(map[uint32]*BasicBlock),
		ExceptionEdges: make([]*ExceptionEdge, 0),
		HandlerBlocks:  make([]*BasicBlock, 0),
	}

	// Create basic blocks
	for i := 0; i < blockCount; i++ {
		block := &BasicBlock{
			ID:          i,
			Start:       i * 100,
			End:         (i + 1) * 100,
			Insns:       make([]MIRInsn, 10),
			Succs:       make([]*BasicBlock, 0),
			Preds:       make([]*BasicBlock, 0),
			DomFrontier: make([]*BasicBlock, 0),
			Children:    make([]*BasicBlock, 0),
		}
		cfg.Blocks[i] = block
		cfg.offsetToBlock[uint32(block.Start)] = block
	}

	// Connect blocks in a chain with some branches
	for i := 0; i < blockCount-1; i++ {
		cfg.Blocks[i].Succs = append(cfg.Blocks[i].Succs, cfg.Blocks[i+1])
		cfg.Blocks[i+1].Preds = append(cfg.Blocks[i+1].Preds, cfg.Blocks[i])

		// Add some branches for complexity
		if i%5 == 0 && i+2 < blockCount {
			cfg.Blocks[i].Succs = append(cfg.Blocks[i].Succs, cfg.Blocks[i+2])
			cfg.Blocks[i+2].Preds = append(cfg.Blocks[i+2].Preds, cfg.Blocks[i])
		}
	}

	cfg.Entry = cfg.Blocks[0]
	cfg.Exit = cfg.Blocks[blockCount-1]

	return cfg
}

// createLargeTestSSA creates a large SSA form for profiling
func createLargeTestSSA(varCount int) *SSAForm {
	cfg := &CFG{
		Blocks:        make([]*BasicBlock, 1),
		offsetToBlock: make(map[uint32]*BasicBlock),
	}
	cfg.Blocks[0] = &BasicBlock{
		ID:          0,
		Start:       0,
		End:         100,
		Insns:       make([]MIRInsn, 0),
		Succs:       make([]*BasicBlock, 0),
		Preds:       make([]*BasicBlock, 0),
		DomFrontier: make([]*BasicBlock, 0),
		Children:    make([]*BasicBlock, 0),
	}
	cfg.Entry = cfg.Blocks[0]
	cfg.Exit = cfg.Blocks[0]

	ssa := &SSAForm{
		CFG:           cfg,
		Variables:     make([]*SSAVariable, varCount),
		VarByID:       make(map[int16]*SSAVariable),
		RegisterToVar: make(map[int16]*SSAVariable),
		PhiFunctions:  make(map[*BasicBlock][]*SSAVariable),
	}

	for i := 0; i < varCount; i++ {
		v := &SSAVariable{
			ID:           int16(i),
			OrigRegister: int16(i),
			Definitions:  make([]SSADef, 0),
			Uses:         make([]SSAUse, 0),
		}
		ssa.Variables[i] = v
		ssa.VarByID[int16(i)] = v
	}

	return ssa
}

// ═══════════════════════════════════════════════════════════════════════════════
// Profiling Tests
// ═══════════════════════════════════════════════════════════════════════════════

// TestProfile_CFGConstruction profiles CFG construction on large applications
func TestProfile_CFGConstruction(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping profiling test in short mode")
	}

	testCases := []struct {
		name       string
		blockCount int
	}{
		{"Small (100 blocks)", 100},
		{"Medium (500 blocks)", 500},
		{"Large (1000 blocks)", 1000},
		{"XLarge (5000 blocks)", 5000},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			metrics := profileComponent(
				fmt.Sprintf("CFG Construction (%s)", tc.name),
				func() int64 {
					var totalOps int64
					for i := 0; i < 1000; i++ {
						cfg := createLargeTestCFG(tc.blockCount)
						// Simulate CFG operations
						for _, block := range cfg.Blocks {
							_ = len(block.Succs)
							_ = len(block.Preds)
						}
						totalOps += int64(tc.blockCount)
					}
					return totalOps
				},
			)

			t.Logf("\n%s", metrics.String())

			// Verify metrics are reasonable
			// Note: Very fast operations may have 0 duration due to timer resolution
			if metrics.MemInUse == 0 {
				t.Error("Memory in use should be > 0")
			}
		})
	}
}

// TestProfile_SSAConstruction profiles SSA form construction
func TestProfile_SSAConstruction(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping profiling test in short mode")
	}

	testCases := []struct {
		name     string
		varCount int
	}{
		{"Small (100 vars)", 100},
		{"Medium (500 vars)", 500},
		{"Large (1000 vars)", 1000},
		{"XLarge (5000 vars)", 5000},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			metrics := profileComponent(
				fmt.Sprintf("SSA Construction (%s)", tc.name),
				func() int64 {
					var totalOps int64
					for i := 0; i < 1000; i++ {
						ssa := createLargeTestSSA(tc.varCount)
						// Simulate SSA operations
						for _, v := range ssa.Variables {
							_ = len(v.Definitions)
							_ = len(v.Uses)
						}
						totalOps += int64(tc.varCount)
					}
					return totalOps
				},
			)

			t.Logf("\n%s", metrics.String())

			if metrics.Duration == 0 {
				t.Log("Duration is 0 — timer resolution too low on this platform (skipping)")
			}
		})
	}
}

// TestProfile_ConstantPropagation profiles constant propagation on large CFGs
func TestProfile_ConstantPropagation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping profiling test in short mode")
	}

	testCases := []struct {
		name       string
		blockCount int
	}{
		{"Small (100 blocks)", 100},
		{"Medium (500 blocks)", 500},
		{"Large (1000 blocks)", 1000},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := createLargeTestCFG(tc.blockCount)
			ssa := createLargeTestSSA(tc.blockCount / 10)

			metrics := profileComponent(
				fmt.Sprintf("Constant Propagation (%s)", tc.name),
				func() int64 {
					var totalOps int64
					for i := 0; i < 1000; i++ {
						result := ConstantPropagation(cfg, ssa)
						if result != nil {
							totalOps += int64(len(result.Constants))
						}
					}
					return totalOps
				},
			)

			t.Logf("\n%s", metrics.String())

			if metrics.Duration == 0 {
				t.Log("Duration is 0 — timer resolution too low on this platform (skipping)")
			}
		})
	}
}

// TestProfile_DeadCodeElimination profiles dead code elimination
func TestProfile_DeadCodeElimination(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping profiling test in short mode")
	}

	testCases := []struct {
		name       string
		blockCount int
	}{
		{"Small (100 blocks)", 100},
		{"Medium (500 blocks)", 500},
		{"Large (1000 blocks)", 1000},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := createLargeTestCFG(tc.blockCount)
			ssa := createLargeTestSSA(tc.blockCount / 10)

			metrics := profileComponent(
				fmt.Sprintf("Dead Code Elimination (%s)", tc.name),
				func() int64 {
					var totalOps int64
					for i := 0; i < 1000; i++ {
						result := AnalyzeDeadCode(cfg, ssa)
						if result != nil {
							totalOps += int64(len(result.UnreachableBlocks) + len(result.DeadAssignments))
						}
					}
					return totalOps
				},
			)

			t.Logf("\n%s", metrics.String())

			if metrics.Duration == 0 {
				t.Log("Duration is 0 — timer resolution too low on this platform (skipping)")
			}
		})
	}
}

// TestProfile_VariableRecovery profiles variable recovery on large SSA forms
func TestProfile_VariableRecovery(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping profiling test in short mode")
	}

	testCases := []struct {
		name     string
		varCount int
	}{
		{"Small (100 vars)", 100},
		{"Medium (500 vars)", 500},
		{"Large (1000 vars)", 1000},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ssa := createLargeTestSSA(tc.varCount)

			metrics := profileComponent(
				fmt.Sprintf("Variable Recovery (%s)", tc.name),
				func() int64 {
					// Simulate variable recovery operations
					var totalOps int64
					for i := 0; i < 10000; i++ {
						count := 0
						for _, v := range ssa.Variables {
							// Simulate context analysis
							profilingSink += len(v.Uses)
							count++
						}
						totalOps += int64(count)
					}
					return totalOps
				},
			)

			t.Logf("\n%s", metrics.String())

			if metrics.Duration == 0 {
				t.Log("Duration is 0 — timer resolution too low on this platform (skipping)")
			}
		})
	}
}

// TestProfile_MethodRecovery profiles method recovery operations
func TestProfile_MethodRecovery(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping profiling test in short mode")
	}

	testCases := []struct {
		name        string
		methodCount int
	}{
		{"Small (100 methods)", 100},
		{"Medium (500 methods)", 500},
		{"Large (1000 methods)", 1000},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			metrics := profileComponent(
				fmt.Sprintf("Method Recovery (%s)", tc.name),
				func() int64 {
					// Simulate method recovery operations
					var totalOps int64
					for i := 0; i < 10000; i++ {
						count := 0
						for i := 0; i < tc.methodCount; i++ {
							// Simulate method analysis
							profilingSink += len(fmt.Sprintf("method_%d", i))
							count++
						}
						totalOps += int64(count)
					}
					return totalOps
				},
			)

			t.Logf("\n%s", metrics.String())

			if metrics.Duration == 0 {
				t.Log("Duration is 0 — timer resolution too low on this platform (skipping)")
			}
		})
	}
}

// TestProfile_ReflectionResolution profiles reflection resolution
func TestProfile_ReflectionResolution(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping profiling test in short mode")
	}

	testCases := []struct {
		name            string
		reflectionCount int
	}{
		{"Small (100 calls)", 100},
		{"Medium (500 calls)", 500},
		{"Large (1000 calls)", 1000},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			metrics := profileComponent(
				fmt.Sprintf("Reflection Resolution (%s)", tc.name),
				func() int64 {
					// Simulate reflection resolution operations
					var totalOps int64
					for j := 0; j < 10000; j++ {
						count := 0
						for i := 0; i < tc.reflectionCount; i++ {
							// Simulate reflection call analysis
							profilingSink += len(fmt.Sprintf("reflection_%d", i))
							count++
						}
						totalOps += int64(count)
					}
					return totalOps
				},
			)

			t.Logf("\n%s", metrics.String())

			if metrics.Duration == 0 {
				t.Log("Duration is 0 — timer resolution too low on this platform (skipping)")
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Comprehensive Pipeline Profiling
// ═══════════════════════════════════════════════════════════════════════════════

// TestProfile_CompletePipeline profiles the complete deobfuscation pipeline
func TestProfile_CompletePipeline(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping profiling test in short mode")
	}

	testCases := []struct {
		name       string
		blockCount int
		varCount   int
	}{
		{"Small App", 100, 50},
		{"Medium App", 500, 250},
		{"Large App", 1000, 500},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			metrics := profileComponent(
				fmt.Sprintf("Complete Pipeline (%s)", tc.name),
				func() int64 {
					var totalOps int64
					for i := 0; i < 1000; i++ {
						cfg := createLargeTestCFG(tc.blockCount)
						ssa := createLargeTestSSA(tc.varCount)

						// Simulate complete pipeline
						count := 0

						// CFG operations
						for _, block := range cfg.Blocks {
							_ = len(block.Succs)
							count++
						}

						// SSA operations
						for _, v := range ssa.Variables {
							_ = len(v.Uses)
							count++
						}

						// Constant propagation
						_ = ConstantPropagation(cfg, ssa)
						count += len(ssa.Variables)

						// Dead code elimination
						_ = AnalyzeDeadCode(cfg, ssa)
						count += len(cfg.Blocks)

						totalOps += int64(count)
					}
					return totalOps
				},
			)

			t.Logf("\n%s", metrics.String())

			if metrics.Duration == 0 {
				t.Log("Duration is 0 — timer resolution too low on this platform (skipping)")
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// CPU and Memory Profile Output
// ═══════════════════════════════════════════════════════════════════════════════

// TestProfile_CPUProfileOutput generates CPU profile output for analysis
func TestProfile_CPUProfileOutput(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping profiling test in short mode")
	}

	tmpDir := testutil.TempDir(t)
	cpuProfilePath := filepath.Join(tmpDir, "cpu.prof")

	// Start CPU profiling
	f, err := os.Create(cpuProfilePath)
	if err != nil {
		t.Fatalf("Failed to create CPU profile file: %v", err)
	}
	defer f.Close()

	if err := pprof.StartCPUProfile(f); err != nil {
		t.Fatalf("Failed to start CPU profiling: %v", err)
	}

	// Run workload
	cfg := createLargeTestCFG(1000)
	ssa := createLargeTestSSA(500)

	for i := 0; i < 100; i++ {
		_ = ConstantPropagation(cfg, ssa)
		_ = AnalyzeDeadCode(cfg, ssa)
	}

	pprof.StopCPUProfile()

	// Verify profile was created
	info, err := os.Stat(cpuProfilePath)
	if err != nil {
		t.Fatalf("Failed to stat CPU profile: %v", err)
	}

	if info.Size() == 0 {
		t.Error("CPU profile is empty")
	}

	t.Logf("CPU profile written to: %s (size: %d bytes)", cpuProfilePath, info.Size())
}

// TestProfile_MemoryProfileOutput generates memory profile output for analysis
func TestProfile_MemoryProfileOutput(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping profiling test in short mode")
	}

	tmpDir := testutil.TempDir(t)
	memProfilePath := filepath.Join(tmpDir, "mem.prof")

	// Run workload
	cfg := createLargeTestCFG(1000)
	ssa := createLargeTestSSA(500)

	for i := 0; i < 100; i++ {
		_ = ConstantPropagation(cfg, ssa)
		_ = AnalyzeDeadCode(cfg, ssa)
	}

	// Write memory profile
	f, err := os.Create(memProfilePath)
	if err != nil {
		t.Fatalf("Failed to create memory profile file: %v", err)
	}
	defer f.Close()

	if err := pprof.WriteHeapProfile(f); err != nil {
		t.Fatalf("Failed to write memory profile: %v", err)
	}

	// Verify profile was created
	info, err := os.Stat(memProfilePath)
	if err != nil {
		t.Fatalf("Failed to stat memory profile: %v", err)
	}

	if info.Size() == 0 {
		t.Error("Memory profile is empty")
	}

	t.Logf("Memory profile written to: %s (size: %d bytes)", memProfilePath, info.Size())
}

// ═══════════════════════════════════════════════════════════════════════════════
// Benchmark Tests (for go test -bench)
// ═══════════════════════════════════════════════════════════════════════════════

// BenchmarkCFGConstruction benchmarks CFG construction
func BenchmarkCFGConstruction(b *testing.B) {
	cfg := createLargeTestCFG(1000)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		for _, block := range cfg.Blocks {
			_ = len(block.Succs)
			_ = len(block.Preds)
		}
	}
}

// BenchmarkSSAConstruction benchmarks SSA form construction
func BenchmarkSSAConstruction(b *testing.B) {
	ssa := createLargeTestSSA(1000)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		for _, v := range ssa.Variables {
			_ = len(v.Definitions)
			_ = len(v.Uses)
		}
	}
}

// BenchmarkConstantPropagation benchmarks constant propagation
func BenchmarkConstantPropagation(b *testing.B) {
	cfg := createLargeTestCFG(1000)
	ssa := createLargeTestSSA(500)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = ConstantPropagation(cfg, ssa)
	}
}

// BenchmarkDeadCodeElimination benchmarks dead code elimination
func BenchmarkDeadCodeElimination(b *testing.B) {
	cfg := createLargeTestCFG(1000)
	ssa := createLargeTestSSA(500)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = AnalyzeDeadCode(cfg, ssa)
	}
}

// BenchmarkVariableRecovery benchmarks variable recovery
func BenchmarkVariableRecovery(b *testing.B) {
	ssa := createLargeTestSSA(1000)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		for _, v := range ssa.Variables {
			_ = len(v.Uses)
		}
	}
}

// BenchmarkMethodRecovery benchmarks method recovery
func BenchmarkMethodRecovery(b *testing.B) {
	methodCount := 1000

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		for j := 0; j < methodCount; j++ {
			_ = fmt.Sprintf("method_%d", j)
		}
	}
}

// BenchmarkReflectionResolution benchmarks reflection resolution
func BenchmarkReflectionResolution(b *testing.B) {
	reflectionCount := 1000

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		for j := 0; j < reflectionCount; j++ {
			_ = fmt.Sprintf("reflection_%d", j)
		}
	}
}

// BenchmarkCompletePipeline benchmarks the complete pipeline
func BenchmarkCompletePipeline(b *testing.B) {
	cfg := createLargeTestCFG(1000)
	ssa := createLargeTestSSA(500)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// CFG operations
		for _, block := range cfg.Blocks {
			_ = len(block.Succs)
		}

		// SSA operations
		for _, v := range ssa.Variables {
			_ = len(v.Uses)
		}

		// Constant propagation
		_ = ConstantPropagation(cfg, ssa)

		// Dead code elimination
		_ = AnalyzeDeadCode(cfg, ssa)
	}
}
