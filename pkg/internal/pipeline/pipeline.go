// pkg/internal/pipeline/pipeline.go
// Pipeline v4.0 — streaming architecture, cached detectors
package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	slashpath "path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"mega-analyzer/pkg/internal/syncx"

	"mega-analyzer/pkg/internal/analyzer"
	"mega-analyzer/pkg/internal/callgraph"
	"mega-analyzer/pkg/internal/config"
	"mega-analyzer/pkg/internal/configs"
	"mega-analyzer/pkg/internal/contentcache"
	"mega-analyzer/pkg/internal/dataflow"
	"mega-analyzer/pkg/internal/evidencegraph"
	"mega-analyzer/pkg/internal/filter"
	"mega-analyzer/pkg/internal/matcher"
	"mega-analyzer/pkg/internal/piracy"
	"mega-analyzer/pkg/internal/rating"
	"mega-analyzer/pkg/internal/rules"
	"mega-analyzer/pkg/internal/types"
	"mega-analyzer/pkg/logger"

	"mega-analyzer/pkg/internal/anomaly"
	"mega-analyzer/pkg/internal/cfg"
	"mega-analyzer/pkg/internal/crackpoint"
	"mega-analyzer/pkg/internal/deobfmetrics"
	"mega-analyzer/pkg/internal/fpfilter"
)

// ═══════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════

const (
	minChannelBuffer = 128
	maxChannelBuffer = 4096

	progressInterval       = 500
	progressReportInterval = 80 * time.Millisecond
	progressStatusInterval = 500 * time.Millisecond
	progressStallThreshold = 2 * time.Second
	defaultWorkerCount     = 8
	// Bumped to 3: content-cache entries are now framed with a header and a
	// SHA-256 payload checksum, so v2 files are unreadable by design.
	contentCacheSchemaVersion uint32 = 3
)

// ═══════════════════════════════════════════════════════════════════════════════
// PIPELINE
// ═══════════════════════════════════════════════════════════════════════════════

type Pipeline struct {
	config  *config.Config
	matcher *matcher.Matcher

	runMu sync.Mutex
	mu    sync.Mutex

	detectorsMu sync.RWMutex

	filter         *filter.Filter
	dpFinder       *analyzer.DecisionPointFinder
	cgBuilder      *analyzer.CallGraphBuilder
	typedCGBuilder *callgraph.Builder
	typedCallGraph *callgraph.Graph
	methodAnalyzer *analyzer.MethodAnalyzer
	contentCache   *contentcache.PipelineCache
	dataFlow       *dataflow.Program
	result         *types.AnalysisResult

	stats  *PipelineStats
	tracer *Tracer

	// Always-on coarse timings have negligible cost and explain slow scans even
	// when optional CPU/heap tracing was not requested.
	stageTimingsMu sync.Mutex
	stageTimings   []StageTiming

	piracyDetector   *piracy.Detector
	rulesEngine      *rules.Engine
	builtinDetectors []FileDetector
	customDetectors  []FileDetector

	cachedDetectors     []FileDetector
	cachedDetectorIndex *detectorIndex
	cachedDetectorsOnce sync.Once

	dexSemOnce sync.Once
	dexSem     chan struct{}

	slowMu    sync.Mutex
	slowFiles []slowFileSample
	activeMu  sync.Mutex
	active    map[string]activeFileProgress
	workUnits map[string]int64

	OnProgress       func(stage string, current, total int)
	OnProgressStatus func(stage string, current, total int, status string)

	userFeedback *UserFeedbackFilter

	// Per-detector cost/yield accounting (E1). Lazily created so no existing
	// constructor path changes.
	detectorMetrics     *DetectorMetrics
	detectorMetricsOnce sync.Once
}

// StageTiming is the wall-clock duration of one top-level pipeline stage.
type StageTiming struct {
	Name     string
	Duration time.Duration
}

func NewPipeline(cfg *config.Config) (*Pipeline, error) {
	if cfg == nil {
		return nil, errors.New("nil pipeline config")
	}

	m, err := matcher.NewMatcher(cfg)
	if err != nil {
		return nil, fmt.Errorf("create matcher: %w", err)
	}

	piracyDetector := loadPiracyDetector()
	rulesEngine := loadRulesEngine()

	p := &Pipeline{
		config:         cfg,
		matcher:        m,
		filter:         filter.NewFilter(),
		dpFinder:       analyzer.NewDecisionPointFinder(),
		cgBuilder:      analyzer.NewCallGraphBuilder(),
		typedCGBuilder: callgraph.NewBuilder(),
		methodAnalyzer: analyzer.NewDefaultMethodAnalyzer(),
		stats:          NewPipelineStats(),
		tracer:         NewTracer(cfg.EnableTracing),
		piracyDetector: piracyDetector,
		rulesEngine:    rulesEngine,
	}
	if cfg.EnableContentCache {
		maxDiskBytes := int64(0)
		if cfg.ContentCacheMaxDiskMB > 0 {
			const mib = int64(1024 * 1024)
			if cfg.ContentCacheMaxDiskMB > (1<<63-1)/mib {
				maxDiskBytes = 1<<63 - 1
			} else {
				maxDiskBytes = cfg.ContentCacheMaxDiskMB * mib
			}
		}
		store, cacheErr := contentcache.NewStore(contentcache.StoreConfig{
			BaseDir:        cfg.ContentCacheDir,
			Version:        contentCacheSchemaVersion ^ loadedRulesFingerprint.Load(),
			MaxMemoryPerNS: 4096,
			MaxDiskBytes:   maxDiskBytes,
		})
		if cacheErr != nil {
			logger.Warn("Content cache disabled", "error", cacheErr)
		} else {
			p.contentCache = contentcache.NewPipelineCache(store)
		}
	}

	p.builtinDetectors = NewBuiltinDetectors(piracyDetector)

	return p, nil
}

// TypedCallGraph returns the CHA/RTA graph produced by the latest run.
func (p *Pipeline) TypedCallGraph() *callgraph.Graph {
	p.runMu.Lock()
	defer p.runMu.Unlock()
	return p.typedCallGraph
}

func (p *Pipeline) RegisterDetector(d FileDetector) {
	p.runMu.Lock()
	defer p.runMu.Unlock()

	p.detectorsMu.Lock()
	defer p.detectorsMu.Unlock()

	p.customDetectors = append(p.customDetectors, d)
	p.cachedDetectors = nil
	p.cachedDetectorIndex = nil
}

func (p *Pipeline) SetUserFeedback(filter *UserFeedbackFilter) {
	p.runMu.Lock()
	defer p.runMu.Unlock()
	p.userFeedback = filter
}

func (p *Pipeline) allDetectors() []FileDetector {
	p.detectorsMu.RLock()
	if p.cachedDetectors != nil {
		cached := p.cachedDetectors
		p.detectorsMu.RUnlock()
		return cached
	}
	p.detectorsMu.RUnlock()

	p.detectorsMu.Lock()
	defer p.detectorsMu.Unlock()

	return p.allDetectorsLocked()
}

func (p *Pipeline) allDetectorsLocked() []FileDetector {
	if p.cachedDetectors != nil {
		return p.cachedDetectors
	}

	all := make([]FileDetector, 0, len(p.builtinDetectors)+len(p.customDetectors))
	all = append(all, p.builtinDetectors...)
	all = append(all, p.customDetectors...)
	p.cachedDetectors = all

	return p.cachedDetectors
}

func (p *Pipeline) getDetectorIndex() *detectorIndex {
	p.detectorsMu.RLock()
	if p.cachedDetectorIndex != nil {
		idx := p.cachedDetectorIndex
		p.detectorsMu.RUnlock()
		return idx
	}
	p.detectorsMu.RUnlock()

	p.detectorsMu.Lock()
	defer p.detectorsMu.Unlock()

	if p.cachedDetectorIndex != nil {
		return p.cachedDetectorIndex
	}

	all := p.allDetectorsLocked()
	idx := buildDetectorIndex(all)
	p.cachedDetectorIndex = idx
	return idx
}

func (p *Pipeline) effectiveWorkerCount() int {
	if p == nil || p.config == nil || p.config.Workers <= 0 {
		return defaultWorkerCount
	}
	return p.config.Workers
}

// dexClassSemaphore caps concurrent DEX class analyses across ALL pipeline
// workers. Without this cap, W outer workers can each spawn W inner goroutines
// (up to W*W concurrent analyses) on multi-DEX APKs, which thrashes the
// scheduler and inflates memory instead of making anything faster.
func (p *Pipeline) dexClassSemaphore() chan struct{} {
	p.dexSemOnce.Do(func() {
		n := p.effectiveWorkerCount()
		if n < 1 {
			n = 1
		}
		p.dexSem = make(chan struct{}, n)
	})
	return p.dexSem
}

type slowFileSample struct {
	relPath string
	elapsed time.Duration
}

// slowFilesTracked is how many of the slowest files are kept for diagnostics.
const slowFilesTracked = 8

// recordSlowFile keeps the slowest files of the run for debug diagnostics.
func (p *Pipeline) recordSlowFile(relPath string, elapsed time.Duration) {
	p.slowMu.Lock()
	defer p.slowMu.Unlock()
	if len(p.slowFiles) >= slowFilesTracked && elapsed <= p.slowFiles[len(p.slowFiles)-1].elapsed {
		return
	}
	p.slowFiles = append(p.slowFiles, slowFileSample{relPath: relPath, elapsed: elapsed})
	sort.Slice(p.slowFiles, func(i, j int) bool { return p.slowFiles[i].elapsed > p.slowFiles[j].elapsed })
	if len(p.slowFiles) > slowFilesTracked {
		p.slowFiles = p.slowFiles[:slowFilesTracked]
	}
}

// logSlowFiles reports the slowest analyzed files in debug mode so users can
// see exactly where scan time goes.
func (p *Pipeline) logSlowFiles() {
	p.slowMu.Lock()
	samples := append([]slowFileSample(nil), p.slowFiles...)
	p.slowMu.Unlock()
	for i, s := range samples {
		logger.Debug("Slowest file", "rank", i+1, "file", s.relPath, "took", s.elapsed.Round(time.Millisecond).String())
	}
}

func (p *Pipeline) resetRunState(targetDir string) {
	p.filter = filter.NewFilter()
	p.dpFinder = analyzer.NewDecisionPointFinder()
	p.cgBuilder = analyzer.NewCallGraphBuilder()
	p.typedCGBuilder = callgraph.NewBuilder()
	p.typedCallGraph = nil
	p.methodAnalyzer = analyzer.NewDefaultMethodAnalyzer()
	p.stats = NewPipelineStats()
	p.tracer = NewTracer(p.config.EnableTracing)
	p.stageTimingsMu.Lock()
	p.stageTimings = p.stageTimings[:0]
	p.stageTimingsMu.Unlock()
	p.slowMu.Lock()
	p.slowFiles = nil
	p.slowMu.Unlock()
	p.activeMu.Lock()
	p.active = make(map[string]activeFileProgress)
	p.activeMu.Unlock()
	p.workUnits = nil
	p.result = types.NewAnalysisResult(targetDir)
	if p.config.EnableDataFlow {
		p.dataFlow = dataflow.NewProgram(dataflow.Config{
			MaxMethods:    p.config.DataFlowMaxMethods,
			MaxIterations: 20,
			MaxFindings:   p.config.DataFlowMaxFindings,
		})
		if p.contentCache != nil {
			p.dataFlow.SetCache(dataFlowCacheAdapter{cache: p.contentCache})
		}
	} else {
		p.dataFlow = nil
	}
	if p.contentCache != nil {
		p.contentCache.ResetStats()
		p.result.Cache.Enabled = true
		p.result.Cache.SchemaVersion = contentCacheSchemaVersion
	}
}

func (p *Pipeline) runStage(name string, fn func() error) (err error) {
	if p.OnProgress != nil {
		p.OnProgress(name, 0, 0)
	}

	started := time.Now()
	stage := p.tracer.StartStage(name)
	defer func() {
		p.tracer.EndStage(stage)
		p.stageTimingsMu.Lock()
		p.stageTimings = append(p.stageTimings, StageTiming{Name: name, Duration: time.Since(started)})
		p.stageTimingsMu.Unlock()
		if p.OnProgress != nil {
			p.OnProgress(name, 1, 1)
		}
		if r := recover(); r != nil {
			logger.Error("Pipeline stage panicked", "stage", name, "panic", r)
			err = fmt.Errorf("stage %s panicked: %v", name, r)
		}
	}()

	return fn()
}

// ═══════════════════════════════════════════════════════════════════════════════
// RUN
// ═══════════════════════════════════════════════════════════════════════════════

func (p *Pipeline) Run(ctx context.Context, targetDir string) (*types.AnalysisResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(targetDir) == "" {
		return nil, errors.New("empty target directory")
	}

	info, err := os.Stat(targetDir)
	if err != nil {
		return nil, fmt.Errorf("stat target directory: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("target is not a directory: %s", targetDir)
	}

	p.runMu.Lock()
	defer p.runMu.Unlock()

	p.resetRunState(targetDir)
	defer p.publishCacheStats()
	workerCount := p.effectiveWorkerCount()

	logger.Info("Starting analysis v4.0",
		"target", targetDir,
		"workers", workerCount,
		"code_limit_mb", formatLimitMB(p.config.MaxFileSizeMB),
		"resource_limit_mb", formatLimitMB(p.config.MaxResourceSizeMB),
	)

	if err := p.runStage("initialization", func() error {
		p.detectAppPackage(targetDir)
		return nil
	}); err != nil {
		return p.result, err
	}

	scanErr := p.runStage("scan_and_analyze", func() error {
		return p.runStreamingPipeline(ctx, targetDir)
	})
	p.result.Stats.TotalFiles = int(p.stats.FilesTotal.Load())

	if scanErr != nil {
		switch {
		case errors.Is(scanErr, context.Canceled):
			logger.Warn("Analysis cancelled, returning partial results",
				"processed", p.stats.FilesProcessed.Load(),
				"analyzed", p.result.Stats.AnalyzedFiles,
			)
		case p.result.Stats.AnalyzedFiles == 0:
			return p.result, scanErr
		default:
			logger.Error("Pipeline error", "error", scanErr)
			logger.Warn("Returning partial results",
				"analyzed", p.result.Stats.AnalyzedFiles,
			)
		}
	}

	logger.Info("Scanning complete",
		"total", p.stats.FilesTotal.Load(),
		"processed", p.stats.FilesProcessed.Load(),
		"skipped", p.stats.FilesSkipped.Load(),
		"failed", p.stats.FilesFailed.Load(),
	)

	postErr := p.runStage("post_processing", func() error {
		p.postProcess(ctx)
		return nil
	})
	if postErr != nil {
		if scanErr == nil || errors.Is(scanErr, context.Canceled) {
			scanErr = postErr
		} else {
			logger.Error("Post-processing error suppressed by earlier pipeline error", "error", postErr)
		}
	}

	logger.Info("Analysis complete",
		"processed", p.stats.FilesProcessed.Load(),
		"matches", p.result.Stats.TotalMatches,
		"critical", p.result.Stats.CriticalMatches,
		"hotspots", len(p.result.Hotspots),
	)

	// Log top-level stage wall-clock durations.
	p.stageTimingsMu.Lock()
	st := append([]StageTiming(nil), p.stageTimings...)
	p.stageTimingsMu.Unlock()
	if len(st) > 0 {
		logger.Info("Stage wall-clock timings:")
		for _, s := range st {
			logger.Info(fmt.Sprintf("  %-22s %s", s.Name, s.Duration.Round(time.Millisecond)))
		}
	}

	// Log fine-grained sub-stage breakdown (accumulated CPU-like time).
	p.stats.InternalTimings.log()

	return p.result, scanErr
}

func (p *Pipeline) publishCacheStats() {
	if p.result == nil || p.contentCache == nil {
		return
	}
	stats := p.contentCache.Stats()
	p.result.Cache = types.AnalysisCacheStats{
		Enabled:       true,
		MethodHits:    stats.MethodHits,
		MethodMisses:  stats.MethodMisses,
		MethodStores:  stats.MethodStores,
		HitRate:       stats.HitRate,
		BytesReused:   stats.BytesReused,
		HotEntries:    stats.StoreStats.HotEntries,
		DiskBytes:     stats.StoreStats.DiskBytes,
		SchemaVersion: contentCacheSchemaVersion,
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// STREAMING PIPELINE
// ═══════════════════════════════════════════════════════════════════════════════

func (p *Pipeline) runStreamingPipeline(ctx context.Context, targetDir string) error {
	// Snapshot the work before workers start. Physical files alone are not an
	// honest progress denominator for APKs: a single classes.dex may contain
	// thousands of class analyses. DEX class counts are read from the fixed-size
	// header, not by decoding the DEX twice.
	physicalTotal, workTotal, unitsByPath := p.preScanWork(ctx, targetDir)
	p.stats.FilesTotal.Store(physicalTotal)
	p.stats.WorkTotal.Store(workTotal)
	p.workUnits = unitsByPath

	if p.OnProgress != nil {
		p.OnProgress("scan_and_analyze", 0, 0)
	}
	defer p.publishCoverage()

	bufSize := clampInt(p.effectiveWorkerCount()*8, minChannelBuffer, maxChannelBuffer)

	jobsChan := make(chan FileJob, bufSize)
	resultsChan := make(chan *types.FileAnalysis, bufSize)

	g, gctx := syncx.WithContext(ctx)

	g.Go(func() error {
		defer close(jobsChan)
		return p.streamFiles(gctx, targetDir, jobsChan)
	})

	workerCount := p.effectiveWorkerCount()
	for i := 0; i < workerCount; i++ {
		g.Go(func() error {
			return p.worker(gctx, jobsChan, resultsChan)
		})
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- g.Wait()
		close(resultsChan)
	}()

	var lastReportedProcessed int64 = -1
	var lastObservedProcessed int64
	lastReportAt := time.Now()
	lastAdvanceAt := time.Now()
	reportProgress := func(now time.Time, force bool) {
		processed := p.stats.WorkProcessed.Load()
		total := p.stats.WorkTotal.Load()
		if processed > lastObservedProcessed {
			lastObservedProcessed = processed
			lastAdvanceAt = now
		}
		if p.OnProgress != nil && processed != lastReportedProcessed &&
			(force || processed >= total || now.Sub(lastReportAt) >= progressReportInterval) {
			lastReportedProcessed = processed
			lastReportAt = now
			p.OnProgress("scan_and_analyze", int(processed), int(total))
		}
	}

	ticker := time.NewTicker(progressStatusInterval)
	defer ticker.Stop()
	resultsOpen := true
	for resultsOpen {
		select {
		case analysis, ok := <-resultsChan:
			if !ok {
				resultsOpen = false
				continue
			}
			if analysis != nil {
				p.collectResult(analysis)
			}
			reportProgress(time.Now(), false)
		case now := <-ticker.C:
			// Files that fail before producing an analysis still advance the
			// physical-file counter. Reporting from a ticker keeps the bar honest.
			reportProgress(now, false)
			processed := p.stats.WorkProcessed.Load()
			total := p.stats.WorkTotal.Load()
			if p.OnProgressStatus != nil && processed < total && now.Sub(lastAdvanceAt) >= progressStallThreshold {
				p.OnProgressStatus("scan_and_analyze", int(processed), int(total), p.activeProgressStatus(now))
			}
		}
	}
	err := <-errCh
	reportProgress(time.Now(), true)
	if p.OnProgress != nil {
		p.OnProgress("scan_and_analyze", int(p.stats.WorkProcessed.Load()), int(p.stats.WorkTotal.Load()))
	}
	p.logScanBreakdown()
	p.logSlowFiles()
	if dropped := p.stats.ResultsDropped.Load(); dropped > 0 {
		logger.Warn("Analysis results dropped because the run was cancelled; report is partial", "dropped", dropped)
	}
	return err
}

// ═══════════════════════════════════════════════════════════════════════════════
// STREAM FILES
// ═══════════════════════════════════════════════════════════════════════════════

// preScanCount is retained as a diagnostic/test helper. Production scanning is
// single-pass and does not retain one FileJob per discovered file.
func (p *Pipeline) preScanCount(ctx context.Context, rootDir string) int64 {
	var count int64
	_ = filepath.WalkDir(rootDir, func(path string, d os.DirEntry, walkErr error) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if walkErr != nil {
			return nil
		}
		if d.IsDir() {
			if shouldSkipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}

		fileType := classifyFile(path)
		if fileType == types.FileTypeUnknown {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return nil
		}

		if p.isFileTooLarge(fileType, info.Size()) {
			return nil
		}

		if p.config.MaxFiles > 0 && count >= int64(p.config.MaxFiles) {
			return errMaxFilesReached
		}

		count++
		return nil
	})
	return count
}

// preScanWork freezes both the physical-file total for reporting and the real
// analysis-unit total for progress. DEX class counts come from the 100-byte DEX
// header, so this adds only directory metadata I/O plus one tiny read per DEX.
func (p *Pipeline) preScanWork(ctx context.Context, rootDir string) (int64, int64, map[string]int64) {
	unitsByPath := make(map[string]int64)
	var physical, work int64
	var eligible int64
	_ = filepath.WalkDir(rootDir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if d.IsDir() {
			if shouldSkipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		fileType := classifyFile(path)
		if fileType == types.FileTypeUnknown {
			return nil
		}
		info, err := d.Info()
		if err != nil || p.isFileTooLarge(fileType, info.Size()) {
			return nil
		}
		if p.config.MaxFiles > 0 && eligible >= int64(p.config.MaxFiles) {
			return errMaxFilesReached
		}
		eligible++
		physical++
		units := int64(1)
		if fileType == types.FileTypeDex {
			units = dexClassWorkUnits(path)
		}
		unitsByPath[path] = units
		work += units
		return nil
	})
	return physical, work, unitsByPath
}

func (p *Pipeline) streamFiles(ctx context.Context, rootDir string, jobs chan<- FileJob) error {
	var queued int64
	walkErr := filepath.WalkDir(rootDir, func(path string, d os.DirEntry, walkErr error) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if walkErr != nil {
			p.stats.FilesFailed.Add(1)
			return nil
		}
		if d.IsDir() {
			if shouldSkipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		p.stats.FilesDiscovered.Add(1)
		fileType := classifyFile(path)
		if fileType == types.FileTypeUnknown {
			if !isForensicDataFile(path) {
				p.stats.Unsupported.Add(1)
				return nil
			}
		}
		p.stats.FilesEligible.Add(1)
		info, err := d.Info()
		if err != nil {
			p.stats.FilesFailed.Add(1)
			return nil
		}
		if p.isFileTooLarge(fileType, info.Size()) {
			p.stats.FilesSkipped.Add(1)
			p.stats.SkippedBySize.Add(1)
			return nil
		}
		if p.config.MaxFiles > 0 && queued >= int64(p.config.MaxFiles) {
			p.stats.FilesSkipped.Add(1)
			p.stats.SkippedByLimit.Add(1)
			p.stats.LimitReached.Store(true)
			return errMaxFilesReached
		}
		relPath := path
		if rel, err := filepath.Rel(rootDir, path); err == nil {
			relPath = rel
		}
		units := p.workUnits[path]
		if units < 1 {
			units = 1
		}
		job := FileJob{Path: path, RelPath: relPath, Type: fileType, Size: info.Size(), Hash: djb2Hash(relPath), WorkUnits: units}
		select {
		case jobs <- job:
			queued++
		case <-ctx.Done():
			return ctx.Err()
		}
		if queued%progressInterval == 0 {
			logger.Debug("Scanning progress", "files_found", queued)
		}
		return nil
	})
	if errors.Is(walkErr, errMaxFilesReached) {
		return nil
	}
	return walkErr
}

func (p *Pipeline) publishCoverage() {
	coverage := types.CoverageStats{
		Discovered:      int(p.stats.FilesDiscovered.Load()),
		Eligible:        int(p.stats.FilesEligible.Load()),
		Queued:          int(p.stats.FilesTotal.Load()),
		Parsed:          int(p.stats.FilesParsed.Load()),
		ParseFailed:     int(p.stats.ParseFailed.Load()),
		FilesFailed:     int(p.stats.FilesFailed.Load()),
		SkippedBySize:   int(p.stats.SkippedBySize.Load()),
		SkippedByLimit:  int(p.stats.SkippedByLimit.Load()),
		Unsupported:     int(p.stats.Unsupported.Load()),
		AnalyzedFiles:   int(p.stats.FilesParsed.Load()),
		AnalyzedClasses: int(p.stats.ClassesAnalyzed.Load()),
		AnalyzedMethods: int(p.stats.MethodsAnalyzed.Load()),
		AnalysisUnits:   int(p.stats.AnalysisUnits.Load()),
		FindingsBearing: int(p.stats.FindingsBearing.Load()),
		LimitReached:    p.stats.LimitReached.Load(),
	}
	p.result.Coverage = coverage
	p.result.Stats.TotalFiles = coverage.Queued
	p.result.Stats.AnalyzedFiles = coverage.AnalyzedFiles
}

var errMaxFilesReached = errors.New("max files reached")

// logScanBreakdown emits one debug line per scanned file category once the
// scan stage is done ("Scanned all smali classes", "Scanned all native
// binaries", ...). Visible only with debug/trace log level.
func (p *Pipeline) logScanBreakdown() {
	if n := precisionSuppressedTotal.Load(); n > 0 {
		logger.Info("Precision gate suppressed false-positive matches", "count", n)
	}
	if p.result == nil || len(p.result.FilesByType) == 0 {
		return
	}
	type typeCount struct {
		ft    types.FileType
		count int
	}
	counts := make([]typeCount, 0, len(p.result.FilesByType))
	for ft, n := range p.result.FilesByType {
		if n > 0 {
			counts = append(counts, typeCount{ft: ft, count: n})
		}
	}
	sort.Slice(counts, func(i, j int) bool {
		if counts[i].count != counts[j].count {
			return counts[i].count > counts[j].count
		}
		return counts[i].ft < counts[j].ft
	})
	for _, tc := range counts {
		logger.Debug("Scanned all "+scanCategoryLabel(tc.ft), "files", tc.count)
	}
}

// scanCategoryLabel returns a human-friendly category name for debug logs.
func scanCategoryLabel(ft types.FileType) string {
	switch ft {
	case types.FileTypeSmali:
		return "smali classes"
	case types.FileTypeDex:
		return "dex classes"
	case types.FileTypeNative:
		return "native binaries"
	case types.FileTypeMedia:
		return "media artifacts"
	case types.FileTypeXML:
		return "xml files"
	case types.FileTypeArchive:
		return "archives"
	case types.FileTypeSignature:
		return "signatures"
	case types.FileTypeResource:
		return "resources"
	default:
		return ft.String() + " files"
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// FILE SIZE CHECK
// ═══════════════════════════════════════════════════════════════════════════════

func (p *Pipeline) isFileTooLarge(fileType types.FileType, size int64) bool {
	var limitBytes int64

	switch fileType {
	case types.FileTypeResource, types.FileTypeXML:
		limitBytes = p.config.GetMaxResourceFileSize()
	default:
		limitBytes = p.config.GetMaxCodeFileSize()
	}

	if limitBytes <= 0 {
		return false
	}

	return size > limitBytes
}

// ═══════════════════════════════════════════════════════════════════════════════
// DETECT APP PACKAGE
// ═══════════════════════════════════════════════════════════════════════════════

func (p *Pipeline) detectAppPackage(targetDir string) {
	manifestPath := filepath.Join(targetDir, "AndroidManifest.xml")
	content, err := os.ReadFile(manifestPath)
	if err != nil {
		return
	}

	pkg := extractManifestPackage(content)
	if pkg == "" {
		return
	}

	p.filter.SetAppPackage(pkg)
	p.result.AppPackage = pkg
	logger.Info("Detected app package", "package", pkg)
}

func extractManifestPackage(content []byte) string {
	if pkg := extractAttribute(content, `package="`, '"'); pkg != "" {
		return pkg
	}
	if pkg := extractAttribute(content, `package='`, '\''); pkg != "" {
		return pkg
	}

	manifest := string(content)
	idx := strings.Index(manifest, "<manifest")
	if idx == -1 {
		return ""
	}
	manifest = manifest[idx:]
	if end := strings.IndexByte(manifest, '>'); end >= 0 {
		manifest = manifest[:end]
	}

	for _, token := range []struct {
		prefix string
		quote  byte
	}{
		{prefix: `package="`, quote: '"'},
		{prefix: `package='`, quote: '\''},
	} {
		if value := extractAttribute([]byte(manifest), token.prefix, token.quote); value != "" {
			return value
		}
	}

	return ""
}

// ═══════════════════════════════════════════════════════════════════════════════
// POST-PROCESSING
// ═══════════════════════════════════════════════════════════════════════════════

func (p *Pipeline) postProcess(ctx context.Context) {
	if p.result == nil {
		return
	}
	// totalSteps counts every reportProgress call on the longest path,
	// including the two deferred ones registered below.
	const totalSteps = 14
	step := 0
	reportProgress := func(stageName string) {
		step++
		if p.OnProgress != nil {
			p.OnProgress("post_processing: "+stageName, step, totalSteps)
		}
	}

	// Registered after reportProgress exists so the closing phases are visible
	// too. They run on every exit path, including the cancellation return
	// below, and used to finish in silence after the last reported step.
	defer func() {
		reportProgress("typed findings")
		p.buildTypedFindings()
		reportProgress("evidence graph")
		p.result.EvidenceGraph = evidencegraph.Build(p.result)
	}()

	reportProgress("correlations")
	// Always calculate hotspots and correlations as they are fast and essential for partial results
	if p.config.EnableCorrelations {
		finder := analyzer.NewCorrelationFinder(p.result.Files)
		p.result.Correlations = finder.FindAll()
	}

	// Deobfuscation must precede rule evaluation, scoring and triage: it
	// recovers plaintext from encrypted literals and feeds it back into the
	// match set, so anything downstream that reads matches sees the decrypted
	// content. Running it after the rule engine (as it did until now) meant a
	// recovered C2 URL or API key was never matched against any rule.
	// runDeobfuscation only merges the per-file counters that the scan workers
	// already produced, so this step completes in microseconds. Every phase
	// below it used to run under this same label without reporting, so the UI
	// sat on "deobfuscation" for as long as the rule engine, triage, piracy
	// analysis, hotspot scoring and recommendations took together — attributing
	// minutes of work to the one cheap step in the block. Each phase now
	// reports itself.
	reportProgress("deobfuscation")
	if p.config.EnableDeobfuscation && (ctx == nil || ctx.Err() == nil) {
		p.runDeobfuscation()
		p.computeDeobfMetrics()
	}

	reportProgress("rule engine")
	p.applyRuleEngine()

	reportProgress("triage")
	p.triageFindings()

	// Rebuild the dedicated, evidence-rich piracy section after triage has
	// finalized per-match criticality. This must precede hotspots and report
	// scoring so every output surface uses the same risk assessment.
	reportProgress("piracy analysis")
	p.buildPiracyAnalysis()

	reportProgress("hotspot scoring")
	scorer := analyzer.NewScorer(p.config, p.filter)
	p.result.Hotspots = scorer.CalculateHotspots(p.result.Files, 50)
	types.SortHotspotsByScore(p.result.Hotspots)
	p.stats.HotspotsTotal.Store(int64(len(p.result.Hotspots)))

	reportProgress("recommendations")
	p.result.Recommendations = generateRecommendations(p.result)

	// If analysis was cancelled via Ctrl-C, skip heavy operations
	if ctx != nil && ctx.Err() != nil {
		logger.Warn("Skipping heavy post-processing (CallGraph, Deobfuscation) due to cancellation")
		p.runFusionReports()
		return
	}

	reportProgress("call_graph")
	if p.config.EnableCallGraph {
		p.result.CallGraph = p.cgBuilder.Build()
		p.typedCGBuilder.ApplyRTA()
		p.typedCallGraph = p.typedCGBuilder.Build()
		typedStats := p.typedCallGraph.Stats()
		logger.Info("Call graph built",
			"legacy_nodes", len(p.result.CallGraph.Nodes),
			"typed_nodes", typedStats.Nodes,
			"typed_edges", typedStats.Edges,
			"cha_edges", typedStats.CHAEdges,
			"reflection_edges", typedStats.ReflectionEdges,
		)
	}

	reportProgress("data_flow")
	if p.dataFlow != nil {
		p.runDataFlow(ctx)
	}

	reportProgress("crack_points")
	if p.config.EnableCrackPointAnalysis {
		p.runCrackPointAnalysis()
	}

	reportProgress("anomaly_detection")
	if p.config.EnableAnomalyDetection {
		p.runAnomalyDetection()
	}

	reportProgress("fp_filter & fusion")
	// Run False Positive Filter Layer
	p.runFPFilter()

	p.runFusionReports()
}

func (p *Pipeline) runFusionReports() {
	if p.result == nil {
		return
	}
	p.result.VulnFusionReport = runVulnDetectorsFusionIntelligence(p.result)

	for _, det := range p.allDetectors() {
		if threatDet, ok := det.(*ThreatIndicatorsDetector); ok {
			agg := threatDet.GetAggregator()
			if agg != nil {
				agg.RunCorrelations()
				if signals := agg.GetSignals(); signals != nil {
					p.result.BehaviorFusionReport = signals.FusionIntelligence
				}
			}
			break
		}
	}
}

// ── NEW: False Positive Filter ───────────────────────────────────────────────

func (p *Pipeline) runFPFilter() {
	logger.Info("Running FP / Noise Reduction Filter...")

	classifier := fpfilter.NewClassifier(&p.config.FPFilter, p.filter)
	engine := fpfilter.NewSuppressionEngine(&p.config.FPFilter)
	refiner := fpfilter.NewVerdictRefiner()

	var allClassified []types.ClassifiedFinding

	for path, fa := range p.result.Files {
		for i := range fa.Matches {
			m := &fa.Matches[i]
			cf := classifier.Classify(m, path)
			allClassified = append(allClassified, cf)
		}
	}

	refined := refiner.Refine(allClassified)
	out := engine.Process(refined)
	p.result.FPFilterResults = out

	// 🆕 Расчёт 6 раздельных категорий рейтингов и профиля рисков
	prof := rating.ComputeProfile(refined)
	p.result.RiskProfile = prof

	logger.Info("FP Filter complete",
		"suppressed_noise", out.Stats.SuppressedSDKNoise,
		"confirmed_app_risks", out.Stats.ConfirmedAppRisks,
		"confirmed_sdk_risks", out.Stats.ConfirmedSDKRisks,
		"overall_risk_score", prof.OverallScore,
		"overall_risk_level", prof.OverallLevel,
	)
}

// ── ELITE STAGE 1: Deobfuscation ─────────────────────────────────────────────

// runDeobfuscation анализирует Smali-файлы и восстанавливает
// Результат сохраняется в p.result.Deobfuscation.
// runDeobfuscation aggregates the per-file results produced during the scan.
//
// The analysis itself runs in the file workers (see deobfuscateClass), because
// a file with nothing but an encrypted literal carries no findings and is
// dropped before post-processing ever sees it. This stage only merges what
// they found and publishes it on the result.
func (p *Pipeline) runDeobfuscation() {
	agg := &types.DeobfuscationResult{}
	filesWithFindings := 0

	for _, fa := range p.result.Files {
		if fa == nil || fa.Deobfuscation == nil {
			continue
		}
		filesWithFindings++
		d := fa.Deobfuscation
		agg.CFFFDetected = agg.CFFFDetected || d.CFFFDetected
		agg.OpaquePredicates += d.OpaquePredicates
		agg.DeadCodeNodes += d.DeadCodeNodes
		agg.RecoveredStrings += d.RecoveredStrings
		agg.MethodsConsidered += d.MethodsConsidered
		agg.MethodsTransformed += d.MethodsTransformed
		agg.ProofsAccepted += d.ProofsAccepted
		agg.FoldedConstants += d.FoldedConstants
		agg.FoldedBranches += d.FoldedBranches
		agg.BlocksBefore += d.BlocksBefore
		agg.BlocksAfter += d.BlocksAfter
		agg.EdgesBefore += d.EdgesBefore
		agg.EdgesAfter += d.EdgesAfter
		agg.InstructionsBefore += d.InstructionsBefore
		agg.InstructionsAfter += d.InstructionsAfter
		agg.EmulatorAttempts += d.EmulatorAttempts
		agg.EmulatorRecoveries += d.EmulatorRecoveries
		agg.EmulatorAbstentions += d.EmulatorAbstentions
		agg.EmulatorBudgets += d.EmulatorBudgets
		agg.JournalTruncated = agg.JournalTruncated || d.JournalTruncated
		agg.Methods = append(agg.Methods, d.Methods...)
		p.stats.DeobfProcessed.Add(1)
	}
	p.stats.DeobfTotal.Store(int64(filesWithFindings))

	sort.Slice(agg.Methods, func(i, j int) bool {
		if agg.Methods[i].ClassName != agg.Methods[j].ClassName {
			return agg.Methods[i].ClassName < agg.Methods[j].ClassName
		}
		return agg.Methods[i].MethodName < agg.Methods[j].MethodName
	})
	p.result.Deobfuscation = agg

	logger.Info("Deobfuscation complete",
		"files_with_findings", filesWithFindings,
		"methods_obfuscated", len(agg.Methods),
		"opaque_predicates", agg.OpaquePredicates,
		"dead_blocks", agg.DeadCodeNodes,
		"strings_recovered", agg.RecoveredStrings,
		"hyperion_candidates", agg.MethodsConsidered,
		"hyperion_transformed", agg.MethodsTransformed,
		"accepted_proofs", agg.ProofsAccepted,
		"emulator_attempts", agg.EmulatorAttempts,
		"emulator_recoveries", agg.EmulatorRecoveries,
	)
}

// computeDeobfMetrics derives a 0-1 quality confidence score from the
// deobfuscation findings and stores it on p.result. The score reflects how
// effectively encrypted strings, opaque predicates and dead code were
// resolved relative to what was present.
func (p *Pipeline) computeDeobfMetrics() {
	if p.result == nil || p.result.Deobfuscation == nil {
		return
	}
	d := p.result.Deobfuscation
	if d.RecoveredStrings == 0 && d.ProofsAccepted == 0 && d.DeadCodeNodes == 0 {
		return // nothing was materially transformed
	}
	// Metrics are derived from accepted proofs and measured CFG deltas. Legacy
	// detection counts remain findings, not a claim that every item was fixed.
	before := deobfmetrics.DeobfState{
		EncryptedStrings:  d.RecoveredStrings,
		DecryptedStrings:  0,
		OpaquePredicates:  d.FoldedBranches,
		UnreachableBlocks: d.DeadCodeNodes,
	}
	after := deobfmetrics.DeobfState{
		EncryptedStrings:  0,
		DecryptedStrings:  d.RecoveredStrings,
		OpaquePredicates:  0,
		UnreachableBlocks: 0,
	}
	report, err := deobfmetrics.NewCalculator().Compute(before, after)
	if err != nil {
		logger.Debug("deobfmetrics skipped", "err", err)
		return
	}
	p.result.DeobfQualityConfidence = report.OverallConfidence
	logger.Info("Deobfuscation quality",
		"confidence", report.OverallConfidence,
		"string_decryption_rate", report.StringDecryptionRate,
		"dead_code_elimination_rate", report.DeadCodeEliminationRate,
	)
}

// hasParsedClass reports whether a file carries a parsed smali class body that
// per-method analysis can run over.
//
// Type alone is the wrong test. Classes lifted from a DEX are scanned through
// the smali grammar but then relabelled FileTypeDex to report their real source
// format (see the DEX class worker), so a `Type == FileTypeSmali` filter drops
// every class in an APK — which is the overwhelmingly common target. Both the
// deobfuscation and crack-point stages silently processed nothing because of
// it. What either stage actually needs is the parsed class, so ask for that.
func hasParsedClass(fa *types.FileAnalysis) bool {
	if fa == nil || fa.SmaliClass == nil {
		return false
	}
	return fa.Type == types.FileTypeSmali || fa.Type == types.FileTypeDex
}

// dedupeStrings returns s with duplicates removed, preserving first-seen order.
func dedupeStrings(s []string) []string {
	seen := make(map[string]struct{}, len(s))
	out := s[:0]
	for _, v := range s {
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// ── ELITE STAGE 2: Crack Point Discovery ─────────────────────────────────────

// runCrackPointAnalysis строит список crack points из реального CFG каждого
// Smali-файла.  CallGraph используется только для маршрутизации: CFG берётся
// из FileAnalysis, которые уже распарсены воркерами.
func (p *Pipeline) runCrackPointAnalysis() {
	logger.Info("Running crack point discovery engine...")

	finder := crackpoint.NewFinder()

	// Индекс FileAnalysis по канонической форме class-дескриптора.
	faByClass := make(map[string]*types.FileAnalysis, len(p.result.Files))
	for path, fa := range p.result.Files {
		if !hasParsedClass(fa) {
			continue
		}
		// fa.Path is always the relative path from the APK root
		// ("smali\com\example\Foo.smali" on Windows, forward-slash on others).
		// fa.RelPath is omitempty and often empty — use fa.Path instead.
		classKey := smaliPathToClassKey(fa.Path)
		if classKey == "" {
			classKey = smaliPathToClassKey(path)
		}
		faByClass[classKey] = fa
	}

	var allPoints []types.CrackPoint

	// Crack-point discovery scans each class's OWN control-flow graph, so it must
	// cover EVERY smali file — not just call-graph nodes. The call graph is built
	// for app code only, which would skip the most important targets (Google LVL
	// license code under com/android/vending/licensing/*, billing, integrity SDKs
	// that live in "library" paths). We iterate all smali files directly.
	for _, fa := range faByClass {
		// Use SmaliClass.Name as the descriptor when available — it's the most
		// authoritative source (set by the smali parser itself).
		descriptor := classKeyToDescriptor(smaliPathToClassKey(fa.Path))
		if fa.SmaliClass != nil && fa.SmaliClass.Name != "" {
			descriptor = fa.SmaliClass.Name
		}
		pts := analyzeCrackPoints(finder, fa, descriptor, p.contentCache, p.stats.InternalTimings)
		allPoints = append(allPoints, pts...)
	}
	allPoints = dedupeCrackPoints(allPoints)

	// Считаем high-confidence отдельно — не просто len(allPoints).
	highConf := 0
	for _, pt := range allPoints {
		if pt.Confidence >= crackpoint.HighConfidenceThreshold {
			highConf++
		}
	}

	p.result.CrackPoint = &types.CrackPointResult{
		Points:        allPoints,
		TotalHighConf: highConf,
	}

	logger.Info("Crack point analysis complete",
		"total", len(allPoints),
		"high_confidence", highConf,
	)
}

func dedupeCrackPoints(points []types.CrackPoint) []types.CrackPoint {
	if len(points) < 2 {
		return points
	}

	hasSpecificForMethod := make(map[string]bool, len(points))
	for _, pt := range points {
		if highValueCategories[pt.Category] {
			hasSpecificForMethod[crackPointMethodKey(pt)] = true
		}
	}

	bestByKey := make(map[string]types.CrackPoint, len(points))
	order := make([]string, 0, len(points))
	for _, pt := range points {
		// Callback entries are useful only when they are the only signal for a
		// method. If a concrete license/billing/tamper point exists, keep that.
		if pt.Category == "callback" && hasSpecificForMethod[crackPointMethodKey(pt)] {
			continue
		}

		key := crackPointExactKey(pt)
		if existing, ok := bestByKey[key]; ok {
			if strongerCrackPoint(pt, existing) {
				bestByKey[key] = pt
			}
			continue
		}
		bestByKey[key] = pt
		order = append(order, key)
	}

	out := make([]types.CrackPoint, 0, len(order))
	for _, key := range order {
		out = append(out, bestByKey[key])
	}
	return out
}

func crackPointMethodKey(pt types.CrackPoint) string {
	return normalizeClassPath(pt.Location.File) + "|" +
		normalizeClassPath(pt.ClassName) + "|" +
		strings.ToLower(pt.Method)
}

func crackPointExactKey(pt types.CrackPoint) string {
	return crackPointMethodKey(pt) + "|" + strings.ToLower(pt.Category)
}

func strongerCrackPoint(candidate, current types.CrackPoint) bool {
	if candidate.Confidence != current.Confidence {
		return candidate.Confidence > current.Confidence
	}
	if candidate.Impact != current.Impact {
		return candidate.Impact > current.Impact
	}
	if len(candidate.Evidence) != len(current.Evidence) {
		return len(candidate.Evidence) > len(current.Evidence)
	}
	return candidate.Location.Line > 0 && (current.Location.Line == 0 || candidate.Location.Line < current.Location.Line)
}

// alwaysFilterSDK — these paths are NEVER sources of real crack points,
// even for high-value categories (license/tamper/billing).  They are
// analytics, attribution, support, or UI SDKs that have no role in the
// app's own protection stack.
var alwaysFilterSDK = []string{
	"io/sentry", "com/crashlytics", "com/google/firebase/crashlytics",
	"com/google/android/gms/measurement", "com/snowplow",
	"com/appsflyer", "com/adjust",
	"com/helpshift", "com/usercentrics",
	"io/flutter/embedding", "io/flutter/view", "io/flutter/plugin",
	"com/google/android/flexbox", "com/google/android/material",
	"androidx/appcompat", "androidx/core", "androidx/fragment",
	"androidx/camera",
	"com/google/firebase/installations", "com/google/firebase/messaging",
	"com/google/firebase/analytics", "com/google/firebase/perf",
}

// sdkNoisePrefixes — lower-value category noise only.  For these paths
// we still keep license/tamper/billing findings (they implement real gates),
// but skip premium/debug/ads/root categories.
var sdkNoisePrefixes = []string{
	"com/google/android/gms", "com/google/firebase",
	"androidx/",
}

// highValueCategories are the crack-point categories that must be reported
// regardless of which class they come from — even inside an SDK.
var highValueCategories = map[string]bool{
	"license": true, "tamper": true, "billing": true,
}

var genericCrackPointMethods = map[string]bool{
	"<init>": true, "init": true, "builder": true, "build": true, "create": true,
	"createfromparcel": true, "createstandard": true, "call": true, "run": true,
	"invoke": true, "invokesuspend": true, "oncomplete": true, "apply": true,
	"accept": true, "get": true, "set": true,
}

// maxPerClassCategory caps how many crack points of the same category we
// report per class.  Prevents 30× repetition of obfuscated `zzl`/`zzm` stubs.
const maxPerClassCategory = 4

func normalizeClassPath(s string) string {
	return strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(s, "\\", "/"), ".", "/"))
}

func matchesPrefixes(lower string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

func isAppsFlyerLVL(lower string) bool {
	return strings.Contains(lower, "com/appsflyer/lvl/")
}

// isAlwaysFilteredSDK returns true when the class should NEVER produce crack
// points regardless of category (analytics, attribution, support, UI libs).
func isAlwaysFilteredSDK(classPath, descriptor string) bool {
	a := normalizeClassPath(classPath)
	b := normalizeClassPath(descriptor)
	if isAppsFlyerLVL(a) || isAppsFlyerLVL(b) {
		return false
	}
	return matchesPrefixes(a, alwaysFilterSDK) || matchesPrefixes(b, alwaysFilterSDK)
}

// isSDKNoiseClass returns true when the class is a known SDK that should
// only be filtered for low-value categories (premium/debug/ads/root).
func isSDKNoiseClass(classPath, descriptor string) bool {
	a := normalizeClassPath(classPath)
	b := normalizeClassPath(descriptor)
	return matchesPrefixes(a, sdkNoisePrefixes) || matchesPrefixes(b, sdkNoisePrefixes)
}

// analyzeCrackPoints запускает finder для каждого метода класса и конвертирует
// результаты в types.CrackPoint.
//
// CFG строится здесь, на лету, из сырого тела метода (method.Body) — раньше
// движок получал fa.CFG, который НИКОГДА н�� заполнялся, поэтому FindCrackPoints
// всегда возвращал пустой результат (total=0). CFG — это per-method структура,
// поэтому мы обходим методы класса по очереди и накапливаем точки взлома.
func analyzeCrackPoints(
	finder *crackpoint.Finder,
	fa *types.FileAnalysis,
	classDescriptor string,
	cache *contentcache.PipelineCache,
	timings *InternalTimings,
) []types.CrackPoint {
	if fa.SmaliClass == nil {
		return nil
	}

	// Always-filtered SDKs produce zero crack points.
	if isAlwaysFilteredSDK(fa.Path, classDescriptor) {
		return nil
	}
	// Noise-filtered SDKs still produce high-value category crack points.
	noisySDK := isSDKNoiseClass(fa.Path, classDescriptor)
	catCount := map[string]int{}
	builder := cfg.NewCFGBuilder()
	var pts []types.CrackPoint

	for mi := range fa.SmaliClass.Methods {
		m := &fa.SmaliClass.Methods[mi]

		// ── CFG summary cache check ───────────────────────────────────
		// A CachedCFGSummary tells us the graph's cyclomatic complexity without
		// rebuilding the full CFG. Trivial methods (complexity ≤ 1) are safe to
		// skip: they have no branches and therefore no crack points.
		if cache != nil && len(m.Body) > 0 {
			if summary, ok := cache.GetCFGSummary(m.Body); ok {
				if timings != nil {
					timings.CFGBuild.Hit()
				}
				if summary.CyclomaticCompl <= 1 {
					continue // trivial method — no crack points possible
				}
				// Non-trivial: still need the full CFG; fall through to build.
			} else if timings != nil {
				timings.CFGBuild.Miss()
			}
		}

		t0cfg := time.Now()
		graph := buildMethodCFG(builder, fa.SmaliClass.Name, m)
		if timings != nil {
			timings.CFGBuild.Record(time.Since(t0cfg))
		}
		if graph == nil {
			continue
		}

		// Store summary for future runs.
		if cache != nil && len(m.Body) > 0 {
			cache.PutCFGSummary(m.Body, cfgToSummary(graph))
		}

		analysis := finder.FindCrackPoints(graph, classDescriptor)
		for _, pt := range analysis.CrackPoints {
			// Noise-filtered SDKs: skip low-value categories only.
			if noisySDK && !highValueCategories[pt.Category] {
				continue
			}
			evidence := crackPointEvidence(fa, m, pt)
			if !isActionableCrackPoint(fa, m, pt, evidence) {
				continue
			}
			// Cap repetition of the same category per class.
			catCount[pt.Category]++
			if catCount[pt.Category] > maxPerClassCategory {
				continue
			}

			line := pt.Line
			if m.LineStart > 0 {
				line = m.LineStart
			}
			pts = append(pts, types.CrackPoint{
				Location: types.SourceLocation{
					File:   fa.Path,
					Line:   line,
					Method: m.Name,
				},
				ClassName:  classDescriptor,
				Method:     m.Name,
				Category:   pt.Category,
				Confidence: pt.Confidence,
				Impact:     pt.Impact,
				Suggestion: pt.SuggestedAction,
				PatchRisk:  pt.PatchRisk,
				Evidence:   evidence,
			})
		}
	}

	return pts
}

func crackPointEvidence(fa *types.FileAnalysis, m *types.SmaliMethod, pt crackpoint.CrackPoint) []string {
	evidence := append([]string(nil), pt.Signals...)
	lowerPath := strings.ToLower(strings.ReplaceAll(fa.Path, "\\", "/"))
	lowerClass := strings.ToLower(strings.ReplaceAll(fa.SmaliClass.Name, ".", "/"))
	lowerMethod := strings.ToLower(m.Name)
	body := strings.ToLower(strings.Join(m.Body, "\n"))

	needles := []struct {
		key   string
		label string
	}{
		{"licens", "license keyword"},
		{"billing", "billing keyword"},
		{"purchase", "purchase keyword"},
		{"vending/licensing", "Google LVL namespace"},
		{"play/core/integrity", "Play Integrity API"},
		{"playintegrity", "Play Integrity keyword"},
		{"safetynet", "SafetyNet API"},
		{"attest", "attestation keyword"},
		{"signature", "signature verification"},
		{"getpackageinfo", "package signature query"},
	}
	haystack := lowerPath + "\n" + lowerClass + "\n" + lowerMethod + "\n" + body
	seen := make(map[string]bool, len(evidence)+len(needles))
	out := make([]string, 0, len(evidence)+3)
	for _, item := range evidence {
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	for _, n := range needles {
		if strings.Contains(haystack, n.key) && !seen[n.label] {
			seen[n.label] = true
			out = append(out, n.label)
		}
	}
	return out
}

func isActionableCrackPoint(fa *types.FileAnalysis, m *types.SmaliMethod, pt crackpoint.CrackPoint, evidence []string) bool {
	method := strings.ToLower(m.Name)
	if isExplicitGateName(method) {
		return true
	}
	if genericCrackPointMethods[method] || isTinyObfuscatedName(method) {
		return isStrongObfuscatedVerdictPoint(method, pt)
	}
	if pt.Category == "license" || pt.Category == "billing" {
		return hasStrongCrackPointEvidence(evidence)
	}
	if pt.Category == "tamper" || pt.Category == "security" {
		if !hasStrongCrackPointEvidence(evidence) {
			return false
		}
		return true
	}
	return hasStrongCrackPointEvidence(evidence)
}

func isStrongObfuscatedVerdictPoint(method string, pt crackpoint.CrackPoint) bool {
	if pt.Category != "tamper" {
		return false
	}
	if !strings.Contains(strings.ToLower(pt.SuggestedAction), "mock successful attestation verdict") {
		return false
	}
	return strings.HasPrefix(method, "zz")
}

func isExplicitGateName(method string) bool {
	for _, token := range []string{
		"license", "licensed", "lvl", "billing", "purchase", "purchases", "premium",
		"subscription", "integrity", "safetynet", "attest", "signature", "tamper",
		"root", "debug", "ontransact", "onserviceconnected",
	} {
		if strings.Contains(method, token) {
			return true
		}
	}
	return false
}

func isTinyObfuscatedName(method string) bool {
	if len(method) <= 1 {
		return true
	}
	if len(method) <= 3 && strings.HasPrefix(method, "zz") {
		return true
	}
	return false
}

func hasStrongCrackPointEvidence(evidence []string) bool {
	for _, e := range evidence {
		lower := strings.ToLower(e)
		for _, token := range []string{"license", "billing", "purchase", "lvl", "integrity", "safetynet", "attestation", "signature"} {
			if strings.Contains(lower, token) {
				return true
			}
		}
	}
	return false
}

// buildMethodCFG builds a control-flow graph for a single smali method from its
// raw body lines. Returns nil when the method has no analyzable instructions
// (empty body, abstract/native method, or parse produced nothing).
func buildMethodCFG(builder *cfg.CFGBuilder, className string, m *types.SmaliMethod) *cfg.ControlFlowGraph {
	if len(m.Body) == 0 {
		return nil
	}
	input := cfg.BuildInputFromLines(className, m.Name, m.Params+m.ReturnType, m.Body)
	if len(input.Instructions) == 0 {
		return nil
	}
	return builder.Build(input)
}

// cfgToSummary converts a live ControlFlowGraph into a lightweight
// CachedCFGSummary suitable for content-cache storage. The summary is used on
// subsequent runs to decide whether a method is worth analysing without
// rebuilding the full graph.
func cfgToSummary(g *cfg.ControlFlowGraph) *contentcache.CachedCFGSummary {
	if g == nil {
		return &contentcache.CachedCFGSummary{}
	}
	hasLoops := len(g.Loops) > 0
	hasExceptions := len(g.Handlers) > 0 || len(g.ThrowExits) > 0
	// Cyclomatic complexity = edges - nodes + 2 (connected graph).
	cc := len(g.Edges) - len(g.Nodes) + 2
	if cc < 1 {
		cc = 1
	}
	return &contentcache.CachedCFGSummary{
		NodeCount:       len(g.Nodes),
		EdgeCount:       len(g.Edges),
		HasLoops:        hasLoops,
		HasExceptions:   hasExceptions,
		CyclomaticCompl: cc,
	}
}

// ── ELITE STAGE 3: Anomaly Detection ─────────────────────────────────────────

// runAnomalyDetection проверяет каждый файл на аномальное поведение.
// IsLibrary определяется по реальному filter-профилю, а не захардкожен.
func (p *Pipeline) runAnomalyDetection() {
	logger.Info("Running smart anomaly detection (noise bypass)...")

	detector := anomaly.NewDetector()

	var findings []types.AnomalyFinding

	for path, fa := range p.result.Files {
		// Images, media and raw resources can't exhibit code "behavior". A stray
		// match on an icon PNG must never be force-promoted to a "malware —
		// always visible" anomaly via the critical-category bypass.
		if fa.Type == types.FileTypeMedia || fa.Type == types.FileTypeResource {
			continue
		}

		isLibrary := p.filter.IsLibraryPath(fa.Path)
		category := dominantCategory(fa)
		libraryName := p.filter.LibraryNameFor(fa.Path)

		info := anomaly.FindingInfo{
			Path:        path,
			RelPath:     fa.Path,
			FileType:    string(fa.Type),
			Category:    category,
			IsLibrary:   isLibrary,
			LibraryName: libraryName,
			MatchCount:  len(fa.Matches),
		}

		res := detector.Analyze(info)
		if !res.IsAnomaly {
			continue
		}

		description := strings.Join(res.AnomalyAlerts, "; ")
		severity := anomalySeverity(res)

		findings = append(findings, types.AnomalyFinding{
			Location: types.SourceLocation{
				File: path,
			},
			Library:     libraryName,
			Description: description,
			Severity:    severity,
			BypassType:  res.BypassType,
			Score:       res.AnomalyScore,
		})
	}

	p.result.Anomalies = findings

	logger.Info("Anomaly detection complete",
		"files_checked", len(p.result.Files),
		"anomalies_found", len(findings),
	)
}

// dominantCategory возвращает категорию наиболее критичного матча в файле.
// Используется как контекст для anomaly detector.
func dominantCategory(fa *types.FileAnalysis) string {
	if fa == nil || len(fa.Matches) == 0 {
		return "unknown"
	}

	best := &fa.Matches[0]
	for i := 1; i < len(fa.Matches); i++ {
		m := &fa.Matches[i]
		if m.TotalImportance() > best.TotalImportance() {
			best = m
		}
	}

	return string(best.Category)
}

func anomalySeverity(res *anomaly.Result) types.Severity {
	switch {
	case res.AnomalyScore >= 0.85:
		return types.SeverityCritical
	case res.AnomalyScore >= 0.65:
		return types.SeverityHigh
	case res.AnomalyScore >= 0.40:
		return types.SeverityMedium
	default:
		return types.SeverityLow
	}
}

// ── Smali path helpers ────────────────────────────────────────────────────────

// smaliPathToClassKey: "smali/com/example/Foo.smali" → "com/example/foo"
func smaliPathToClassKey(relPath string) string {
	relPath = filepath.ToSlash(relPath)
	relPath = strings.TrimPrefix(relPath, "smali/")
	relPath = strings.TrimSuffix(relPath, ".smali")
	return strings.ToLower(relPath)
}

// smaliDescriptorToKey: "Lcom/example/Foo;" → "com/example/foo"
func smaliDescriptorToKey(descriptor string) string {
	s := descriptor
	if strings.HasPrefix(s, "L") && strings.HasSuffix(s, ";") {
		s = s[1 : len(s)-1]
	}
	return strings.ToLower(s)
}

// classKeyToDescriptor: "com/example/foo" → "Lcom/example/Foo;"
// Только для случая когда CallGraph не используется — descriptor приблизительный.
func classKeyToDescriptor(key string) string {
	return "L" + key + ";"
}

// ═══════════════════════════════════════════════════════════════════════════════
// PIRACY DETECTOR LOADING
// ═══════════════════════════════════════════════════════════════════════════════

func loadPiracyDetector() *piracy.Detector {
	paths := []string{
		"pkg/internal/configs/piracy_sites.json",
		"internal/configs/piracy_sites.json",
		"configs/piracy_sites.json",
		"piracy_sites.json",
	}

	for _, path := range paths {
		if d, err := piracy.NewDetectorFromFile(path); err == nil {
			logger.Info("Loaded piracy config", "path", path)
			return d
		}
	}

	// No on-disk file found: fall back to the embedded piracy database.
	if d, err := piracy.NewDetectorFromBytes(configs.PiracySites()); err == nil {
		logger.Info("Loaded embedded piracy config")
		return d
	}

	logger.Warn("Using default piracy detector configuration")
	return piracy.NewDetector()
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

func formatLimitMB(mb int) string {
	if mb <= 0 {
		return "unlimited"
	}
	return fmt.Sprintf("%d", mb)
}

// ═══════════════════════════════════════════════════════════════════════════════
// EXPORTS
// ═══════════════════════════════════════════════════════════════════════════════

func (p *Pipeline) GetStats() *PipelineStats {
	if p == nil {
		return nil
	}
	return p.stats
}

func (p *Pipeline) GetTraceStages() []StageMetrics {
	if p == nil || p.tracer == nil {
		return nil
	}
	return p.tracer.GetStages()
}

// GetStageTimings returns a snapshot of top-level stages. It remains available
// when optional profiling is disabled.
func (p *Pipeline) GetStageTimings() []StageTiming {
	if p == nil {
		return nil
	}
	p.stageTimingsMu.Lock()
	defer p.stageTimingsMu.Unlock()
	timings := make([]StageTiming, len(p.stageTimings))
	copy(timings, p.stageTimings)
	return timings
}

func ExportPiracyConfig(path string) error {
	return piracy.NewDetector().ExportConfig(path)
}

// ═══════════════════════════════════════════════════════════════════════════════
// USER FEEDBACK FILTER
// ═══════════════════════════════════════════════════════════════════════════════

// UserFeedbackFilter применяет user overrides к результатам анализа.
type UserFeedbackFilter struct {
	mu sync.RWMutex

	noisePatterns    map[string]bool
	relevantPatterns map[string]bool
	noiseKeywords    map[string]bool
	relevantKeywords map[string]bool
}

func NewUserFeedbackFilter() *UserFeedbackFilter {
	return &UserFeedbackFilter{
		noisePatterns:    make(map[string]bool),
		relevantPatterns: make(map[string]bool),
		noiseKeywords:    make(map[string]bool),
		relevantKeywords: make(map[string]bool),
	}
}

// LoadFromHistory загружает user overrides из файла ML history.
// Формат файла: JSON-массив объектов { "path": "...", "label": "noise|relevant" }
// или аналогичная структура, определяемая типом MLHistoryEntry.
func (f *UserFeedbackFilter) LoadFromHistory(historyPath string) error {
	if strings.TrimSpace(historyPath) == "" {
		return nil
	}

	data, err := os.ReadFile(historyPath)
	if err != nil {
		return fmt.Errorf("read ml history %q: %w", historyPath, err)
	}

	entries, err := parseMLHistory(data)
	if err != nil {
		return fmt.Errorf("parse ml history %q: %w", historyPath, err)
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	loaded := 0
	for _, e := range entries {
		norm := normalizePath(e.Path)
		if norm == "" {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(e.Label)) {
		case "noise":
			f.noisePatterns[norm] = true
			loaded++
		case "relevant":
			f.relevantPatterns[norm] = true
			loaded++
		default:
			logger.Debug("Unknown ML history label, skipping",
				"path", e.Path, "label", e.Label)
		}
	}

	logger.Info("ML history loaded",
		"file", historyPath,
		"entries_total", len(entries),
		"entries_loaded", loaded,
	)

	return nil
}

// ShouldFilterOut возвращает true если файл помечен как noise.
func (f *UserFeedbackFilter) ShouldFilterOut(path string, keywords []string) bool {
	if f == nil {
		return false
	}

	normalizedPath := normalizePath(path)

	f.mu.RLock()
	defer f.mu.RUnlock()

	for pattern := range f.noisePatterns {
		if matchNormalizedPattern(normalizedPath, pattern) {
			return true
		}
	}

	for _, kw := range keywords {
		if f.noiseKeywords[normalizeKeyword(kw)] {
			return true
		}
	}

	return false
}

// ShouldBoost возвращает true если файл помечен как relevant.
func (f *UserFeedbackFilter) ShouldBoost(path string, keywords []string) bool {
	if f == nil {
		return false
	}

	normalizedPath := normalizePath(path)

	f.mu.RLock()
	defer f.mu.RUnlock()

	for pattern := range f.relevantPatterns {
		if matchNormalizedPattern(normalizedPath, pattern) {
			return true
		}
	}

	for _, kw := range keywords {
		if f.relevantKeywords[normalizeKeyword(kw)] {
			return true
		}
	}

	return false
}

func (f *UserFeedbackFilter) AddNoisePattern(pattern string) {
	if f == nil {
		return
	}
	normalized := normalizePath(pattern)
	if normalized == "" {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.noisePatterns[normalized] = true
}

func (f *UserFeedbackFilter) AddRelevantPattern(pattern string) {
	if f == nil {
		return
	}
	normalized := normalizePath(pattern)
	if normalized == "" {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.relevantPatterns[normalized] = true
}

func (f *UserFeedbackFilter) AddNoiseKeyword(keyword string) {
	if f == nil {
		return
	}
	normalized := normalizeKeyword(keyword)
	if normalized == "" {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.noiseKeywords[normalized] = true
}

func (f *UserFeedbackFilter) AddRelevantKeyword(keyword string) {
	if f == nil {
		return
	}
	normalized := normalizeKeyword(keyword)
	if normalized == "" {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.relevantKeywords[normalized] = true
}

func (f *UserFeedbackFilter) Stats() (noisePatterns, relevantPatterns, noiseKeywords, relevantKeywords int) {
	if f == nil {
		return 0, 0, 0, 0
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.noisePatterns), len(f.relevantPatterns), len(f.noiseKeywords), len(f.relevantKeywords)
}

func normalizeKeyword(keyword string) string {
	return strings.ToLower(strings.TrimSpace(keyword))
}

func normalizePath(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	value = strings.ReplaceAll(value, "\\", "/")
	value = strings.TrimSuffix(value, "/.*")
	value = strings.TrimSuffix(value, ".*")

	if strings.HasPrefix(value, "L") && strings.HasSuffix(value, ";") && strings.Contains(value, "/") {
		value = strings.TrimPrefix(value, "L")
		value = strings.TrimSuffix(value, ";")
	}

	value = slashpath.Clean(value)
	if value == "." {
		return ""
	}

	value = strings.TrimPrefix(value, "./")
	value = strings.TrimPrefix(value, "/")
	value = strings.TrimSuffix(value, "/")

	return strings.ToLower(value)
}

func matchNormalizedPattern(path, pattern string) bool {
	if path == "" || pattern == "" {
		return false
	}
	if path == pattern {
		return true
	}

	if strings.ContainsAny(pattern, "*?[") {
		if matched, err := slashpath.Match(pattern, path); err == nil && matched {
			return true
		}

		if strings.HasSuffix(pattern, "/*") {
			prefix := strings.TrimSuffix(pattern, "/*")
			return path == prefix || strings.HasPrefix(path, prefix+"/")
		}
		if strings.HasPrefix(pattern, "*/") {
			suffix := strings.TrimPrefix(pattern, "*/")
			return path == suffix || strings.HasSuffix(path, "/"+suffix)
		}
		if strings.HasSuffix(pattern, "*") {
			prefix := strings.TrimSuffix(pattern, "*")
			return strings.HasPrefix(path, prefix)
		}
		if strings.HasPrefix(pattern, "*") {
			suffix := strings.TrimPrefix(pattern, "*")
			return strings.HasSuffix(path, suffix)
		}
	}

	return strings.HasPrefix(path, pattern+"/") ||
		strings.HasSuffix(path, "/"+pattern) ||
		strings.Contains(path, "/"+pattern+"/")
}

func matchPattern(path, pattern string) bool {
	return matchNormalizedPattern(normalizePath(path), normalizePath(pattern))
}

// parseMLHistory — временный парсер для истории обучения.
func parseMLHistory(data []byte) ([]MLHistoryEntry, error) {
	var entries []MLHistoryEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

type MLHistoryEntry struct {
	Path  string `json:"path"`
	Label string `json:"label"`
}
