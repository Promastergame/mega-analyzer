package ml

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"mega-analyzer/pkg/internal/cfg"
	"mega-analyzer/pkg/internal/types"
	"mega-analyzer/pkg/ml/stringutils"
)

// ═══════════════════════════════════════════════════════════════════════════════
// PREDICTOR
// ═══════════════════════════════════════════════════════════════════════════════

type PatchPredictor struct {
	// Prediction runs are serialized: feedback mutates this predictor's index.
	// Configure injected models/call graphs before starting concurrent callers.
	predictionOnce     sync.Once
	predictionGate     chan struct{}
	analyzer           *PatchAnalyzer
	scorer             *PatchScorer
	output             io.Writer
	config             PredictorConfig
	history            *AnalysisHistory
	patternTracker     *PatternTracker
	feedbackIntegrator *FeedbackIntegrator

	// 🔥 NEW: Сочные компоненты
	interestingScorer      InterestingScorer
	noiseFilter            NoiseFilter
	entryPointDetector     EntryPointDetector
	enableNoiseFilter      bool
	enableInterestingScore bool

	// DFG: кеш CFG (кешируем именно CFG, DFG считается поверх)
	cfgCache *cfg.CFGCache

	// 🔥 PHASE 4: Gate Detector для фильтрации equals/hashCode/toString
	gateDetector *GateDetector

	// v2: Semantic gate (CFG/DFG-aware, path-sensitive) — параллельно с v1, мощнее
	semanticGateDetector *SemanticGateDetector
	// Adaptive pipeline + feature registry (v2 observability)
	mlPipeline *MLPipeline
	// Replay buffer for incremental learning (capacity 256)
	replayBuffer *ReplayBuffer

	// CFG crack-point index from pipeline (boosts confirmed gates)
	crackPointIndex *CrackPointIndex

	// Trained risk model (nil until a caller injects one via
	// SetTrainedRiskScorer, e.g. training.EnsembleModelScorer). Optional —
	// ApplyEnsembleBoost falls back to pure heuristics when absent.
	trainedRiskScorer TrainedRiskScorer
}

type PredictorConfig struct {
	MaxHighRisk      int
	MaxMediumRisk    int
	MaxLowRisk       int
	MaxLibraryRisk   int // 🆕 сколько показывать в LIBRARY секции
	MaxAuditFindings int
	MinScore         float64
	IncludeLibraries bool
	Mode             PatchMode
	MaxSmaliFileSize int64

	// 🔥 NEW: Feature flags
	EnableDecoyDetection bool
	EnableVulnSignals    bool
	EnableGateDetection  bool // Phase 4: фильтрация data class methods

	// EnableEnsembleBoost re-ranks scored methods with the ensemble package's
	// structural/entropy/taint feature blend (see ApplyEnsembleBoost). Additive
	// on top of the legacy heuristic score — safe to leave on by default.
	EnableEnsembleBoost bool
	EnsembleMix         BoostMix

	// EnableConfidenceCalibration включает дефолтный conformal review-гейт на
	// скорере (DefaultReviewGate): патчи с низкой уверенностью помечаются
	// needs_review. Значение Confidence не искажается (scaler=nil).
	EnableConfidenceCalibration bool

	// EnableCategoryThresholds включает категорийные пороги риска
	// (RiskLevelForCategory): ниже для доверенных категорий (recall up),
	// выше для шумных (precision up). Off => глобальные 65/45/30.
	EnableCategoryThresholds bool

	// CFG cache is intentionally bounded: CFG nodes retain instruction IR and
	// can be substantially larger than the source text. TTL prevents a long
	// lived predictor from retaining graphs from old APKs indefinitely.
	CFGCacheCapacity int
	CFGCacheTTL      time.Duration
}

func DefaultPredictorConfig() PredictorConfig {
	return PredictorConfig{
		MaxHighRisk:      MaxHighRiskResults,
		MaxMediumRisk:    MaxMediumRiskResults,
		MaxLowRisk:       MaxLowRiskResults,
		MaxLibraryRisk:   8, // 🆕 не больше 8 библиотечных
		MaxAuditFindings: 32,
		MinScore:         MinPatchScore,
		IncludeLibraries: false, // 🆕 по умолчанию фильтруем библиотеки
		Mode:             "",
		MaxSmaliFileSize: 8 * 1024 * 1024,

		EnableDecoyDetection: true,
		EnableVulnSignals:    true,
		EnableGateDetection:  true, // Phase 4: включаем gate detection

		EnableEnsembleBoost: true,
		EnsembleMix:         DefaultBoostMix(),

		EnableConfidenceCalibration: true,
		EnableCategoryThresholds:    true,
		CFGCacheCapacity:            128,
		CFGCacheTTL:                 5 * time.Minute,
	}
}

// Validate performs validation on the PredictorConfig and returns an error if invalid.
func (pc *PredictorConfig) Validate() error {
	if pc.MaxHighRisk < 0 {
		return fmt.Errorf("MaxHighRisk must be non-negative, got %d", pc.MaxHighRisk)
	}
	if pc.MaxMediumRisk < 0 {
		return fmt.Errorf("MaxMediumRisk must be non-negative, got %d", pc.MaxMediumRisk)
	}
	if pc.MaxLowRisk < 0 {
		return fmt.Errorf("MaxLowRisk must be non-negative, got %d", pc.MaxLowRisk)
	}
	if pc.MaxLibraryRisk < 0 {
		return fmt.Errorf("MaxLibraryRisk must be non-negative, got %d", pc.MaxLibraryRisk)
	}
	if pc.MaxAuditFindings < 0 {
		return fmt.Errorf("MaxAuditFindings must be non-negative, got %d", pc.MaxAuditFindings)
	}
	if pc.MinScore < 0 || pc.MinScore > 100 {
		return fmt.Errorf("MinScore must be between 0 and 100, got %f", pc.MinScore)
	}
	if pc.MaxSmaliFileSize < 0 {
		return fmt.Errorf("MaxSmaliFileSize must be non-negative, got %d", pc.MaxSmaliFileSize)
	}
	if pc.CFGCacheCapacity < 0 {
		return fmt.Errorf("CFGCacheCapacity must be non-negative, got %d", pc.CFGCacheCapacity)
	}
	if pc.CFGCacheTTL < 0 {
		return fmt.Errorf("CFGCacheTTL must be non-negative, got %v", pc.CFGCacheTTL)
	}

	// Validate ensemble mix if enabled
	if pc.EnableEnsembleBoost {
		if err := pc.EnsembleMix.Validate(); err != nil {
			return fmt.Errorf("invalid EnsembleMix: %w", err)
		}
	}

	return nil
}

// classifyRisk выбирает уровень риска с учётом категории, когда включены
// категорийные пороги (config.EnableCategoryThresholds). Иначе — глобальные
// пороги через RiskLevelFromScore (полная обратная совместимость).
func (pp *PatchPredictor) classifyRisk(cat PatchCategory, score float64) RiskClass {
	if pp != nil && pp.config.EnableCategoryThresholds {
		return RiskLevelForCategory(cat, score)
	}
	return RiskLevelFromScore(score)
}

func NewPatchPredictor(output io.Writer) *PatchPredictor {
	return NewPatchPredictorWithConfig(output, DefaultPredictorConfig())
}

func NewPatchPredictorWithConfig(output io.Writer, config PredictorConfig) *PatchPredictor {
	// 🆕 Validate configuration before creating predictor
	if err := config.Validate(); err != nil {
		panic(fmt.Sprintf("invalid PredictorConfig: %v", err))
	}

	if config.MaxSmaliFileSize == 0 {
		config.MaxSmaliFileSize = 8 * 1024 * 1024
	}
	if config.CFGCacheCapacity <= 0 {
		config.CFGCacheCapacity = 128
	}
	if config.CFGCacheTTL < 0 {
		config.CFGCacheTTL = 0
	}
	analyzer := NewPatchAnalyzer()
	history, _ := LoadHistoryDefault()

	patternTracker := NewPatternTracker()
	feedbackIntegrator := NewFeedbackIntegrator(patternTracker)

	if metricsPath, err := DefaultPatternMetricsPath(); err == nil {
		_ = patternTracker.LoadFromFile(metricsPath)
	}

	// Калибровка «по умолчанию»: консервативный review-гейт на скорере. Скалер nil
	// ⇒ значения Confidence не меняются, добавляется лишь решение needs_review.
	scorer := NewPatchScorer(analyzer)
	if config.EnableConfidenceCalibration {
		scorer.EnableDefaultCalibration()
	}

	return &PatchPredictor{
		analyzer:           analyzer,
		scorer:             scorer,
		output:             output,
		config:             config,
		history:            history,
		patternTracker:     patternTracker,
		feedbackIntegrator: feedbackIntegrator,

		// 🔥 NEW: Инициализация сочных компонентов
		interestingScorer:      NewInterestingScorer(),
		noiseFilter:            NewNoiseFilter(),
		entryPointDetector:     NewEntryPointDetector(),
		enableNoiseFilter:      true, // Включено по умолчанию
		enableInterestingScore: true, // Включено по умолчанию

		// DFG: bounded CFG cache. Entries retain typed instruction IR, so an
		// unbounded/no-TTL cache would keep old APK graphs alive unnecessarily.
		cfgCache: cfg.NewCFGCacheWithConfig(cfg.CacheConfig{
			Capacity: config.CFGCacheCapacity,
			TTL:      config.CFGCacheTTL,
		}),

		// Phase 4: GateDetector (nil until CallGraph is built)
		gateDetector: nil, // Will be set if CallGraph available

		// v2 powerful components — zero-cost lazy init
		semanticGateDetector: NewSemanticGateDetector(),
		mlPipeline:           nil, // Constructed with the real stages for each prediction run.
		replayBuffer:         NewReplayBuffer(256),
	}
}

// CFGCacheStats exposes bounded-cache memory telemetry for callers that want
// to tune analysis under a process memory budget.
func (pp *PatchPredictor) CFGCacheStats() cfg.CacheStats {
	if pp == nil || pp.cfgCache == nil {
		return cfg.CacheStats{}
	}
	return pp.cfgCache.Stats()
}

// ClearCFGCache releases retained CFG/IR graphs between APK analyses.
func (pp *PatchPredictor) ClearCFGCache() {
	if pp != nil && pp.cfgCache != nil {
		pp.cfgCache.Clear()
	}
}

func (pp *PatchPredictor) Config() PredictorConfig { return pp.config }

// SetCallGraph подключает CallGraph к predictor'у (для GateDetector)
// Должен быть вызван до PredictFromDirectory/PredictFromCandidates.
func (pp *PatchPredictor) SetCallGraph(cg *types.CallGraph) {
	if cg != nil && pp.config.EnableGateDetection {
		pp.gateDetector = NewGateDetector(cg)
	}
}

// SetCrackPoints feeds CFG-confirmed crack points into patch scoring.
func (pp *PatchPredictor) SetCrackPoints(points []types.CrackPoint) {
	pp.crackPointIndex = BuildCrackPointIndex(points)
}

// SetTrainedRiskScorer injects a learned model that refines the ensemble
// boost's heuristic blend (see ApplyEnsembleBoost). Optional — pass nil (the
// zero value) to fall back to pure heuristics, which is also what happens
// automatically when the scorer reports IsLoaded()==false.
func (pp *PatchPredictor) SetTrainedRiskScorer(s TrainedRiskScorer) {
	pp.trainedRiskScorer = s
}

// SetPartialResults помечает результат как частичный (вызвать при timeout)
func (pp *PatchPredictor) SetPartialResults(prediction *PatchPrediction, partial bool) {
	if prediction != nil {
		prediction.PartialResults = partial
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// PREDICT
// ═══════════════════════════════════════════════════════════════════════════════

// directoryPredictionBatchSize bounds how many parsed ClassInfo values may be
// retained by the patch predictor at once. Large decompiled applications often
// have tens of thousands of Smali files; keeping every candidate's RawBody and
// extracted strings until scoring completes can consume gigabytes of memory.
const directoryPredictionBatchSize = 64

func (pp *PatchPredictor) PredictFromDirectory(targetDir string) (*PatchPrediction, error) {
	return pp.PredictFromDirectoryContext(context.Background(), targetDir)
}

// PredictFromDirectoryContext preserves completed batches and reports failures
// and cancellation instead of silently returning a complete-looking ranking.
func (pp *PatchPredictor) PredictFromDirectoryContext(ctx context.Context, targetDir string) (*PatchPrediction, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	prediction := pp.emptyPrediction()
	if err := ctx.Err(); err != nil {
		markPredictionPartial(prediction)
		return prediction, err
	}
	candidates, scanStats, err := pp.collectSmaliFilesContext(ctx, targetDir)
	if err != nil {
		if ctx.Err() != nil {
			applyFileScanStats(&prediction.Stats, scanStats)
			markPredictionPartial(prediction)
			return prediction, err
		}
		return nil, fmt.Errorf("failed to collect smali files: %w", err)
	}

	// Process directory candidates in bounded batches. PredictFromCandidates
	// allocates parsed methods, scores, and derived PatchPoint metadata; merging
	// only the ranked output buckets releases that working set between batches.
	var runErr error
	for start := 0; start < len(candidates); start += directoryPredictionBatchSize {
		end := start + directoryPredictionBatchSize
		if end > len(candidates) {
			end = len(candidates)
		}
		batch, batchErr := pp.PredictFromCandidatesContext(ctx, candidates[start:end])
		pp.mergeDirectoryPrediction(prediction, batch)
		runErr = errors.Join(runErr, batchErr)
		if ctx.Err() != nil {
			break
		}
	}
	applyFileScanStats(&prediction.Stats, scanStats)
	if len(scanStats.errors) > 0 {
		runErr = errors.Join(runErr, fmt.Errorf("Smali discovery incomplete; see scan_errors (%d diagnostics)", len(scanStats.errors)))
	}
	if prediction.PartialResults || runErr != nil {
		markPredictionPartial(prediction)
	}
	prediction.Stats.TopCategories = pp.buildTopCategories(prediction.Stats.ByCategory)
	prediction.MainFindings = pp.buildMainFindings(prediction)
	prediction.TopIssues = pp.buildTopIssues(prediction)
	pp.enrichMLHealth(prediction)
	return prediction, runErr
}

func (pp *PatchPredictor) mergeDirectoryPrediction(dst, src *PatchPrediction) {
	if dst == nil || src == nil {
		return
	}
	mergePredictionStats(&dst.Stats, src.Stats)
	dst.PartialResults = dst.PartialResults || src.PartialResults
	dst.HighRisk = retainTopPatchPoints(dst.HighRisk, src.HighRisk, pp.config.MaxHighRisk, patchValueOrFallback)
	dst.MediumRisk = retainTopPatchPoints(dst.MediumRisk, src.MediumRisk, pp.config.MaxMediumRisk, patchValueOrFallback)
	dst.LowRisk = retainTopPatchPoints(dst.LowRisk, src.LowRisk, pp.config.MaxLowRisk, patchValueOrFallback)
	dst.LibraryFindings = retainTopPatchPoints(dst.LibraryFindings, src.LibraryFindings, pp.config.MaxLibraryRisk, patchValueOrFallback)
	dst.MalwareIndicators = retainTopPatchPoints(dst.MalwareIndicators, src.MalwareIndicators, pp.config.MaxAuditFindings, auditValue)
	dst.AuditFindings = retainTopPatchPoints(dst.AuditFindings, src.AuditFindings, pp.config.MaxAuditFindings, auditValue)

	// The historical counters report retained findings, while PatchPointsFound
	// still records every scored app-code candidate across all batches.
	dst.Stats.HighRiskCount = len(dst.HighRisk)
	dst.Stats.MediumRiskCount = len(dst.MediumRisk)
	dst.Stats.LowRiskCount = len(dst.LowRisk)
	dst.Stats.LibraryFindingsCount = len(dst.LibraryFindings)
	dst.Stats.MalwareFindingsCount = len(dst.MalwareIndicators)
	dst.Stats.AuditFindingsCount = len(dst.AuditFindings)
}

func mergePredictionStats(dst *PredictionStats, src PredictionStats) {
	dst.FilesDiscovered += src.FilesDiscovered
	dst.FilesSkipped += src.FilesSkipped
	dst.FilesTooLarge += src.FilesTooLarge
	dst.FileReadErrors += src.FileReadErrors
	for _, message := range src.ScanErrors {
		if len(dst.ScanErrors) < 100 {
			dst.ScanErrors = append(dst.ScanErrors, message)
		}
	}
	dst.PipelineMetrics = mergePipelineMetrics(dst.PipelineMetrics, src.PipelineMetrics)
	previousPoints := dst.PatchPointsFound
	dst.TotalFilesScanned += src.TotalFilesScanned
	dst.TotalMethodsFound += src.TotalMethodsFound
	dst.MethodsAnalyzed += src.MethodsAnalyzed
	dst.MethodsSkipped += src.MethodsSkipped
	dst.FilteredMethods += src.FilteredMethods
	dst.PatchPointsFound += src.PatchPointsFound
	if dst.ByCategory == nil {
		dst.ByCategory = make(map[string]int)
	}
	for category, count := range src.ByCategory {
		dst.ByCategory[category] += count
	}
	if src.MaxScore > dst.MaxScore {
		dst.MaxScore = src.MaxScore
	}
	if dst.PatchPointsFound > 0 {
		dst.AvgScore = (dst.AvgScore*float64(previousPoints) + src.AvgScore*float64(src.PatchPointsFound)) / float64(dst.PatchPointsFound)
	}
}

func retainTopPatchPoints(current, incoming []PatchPoint, limit int, rank func(*PatchPoint) float64) []PatchPoint {
	retained := newRankedPatchPoints(limit, rank)
	for i := range current {
		retained.Add(&current[i])
	}
	for i := range incoming {
		retained.Add(&incoming[i])
	}
	return retained.Sorted()
}

func (pp *PatchPredictor) PredictFromCandidates(candidates []AnalysisCandidate) *PatchPrediction {
	prediction, _ := pp.PredictFromCandidatesContext(context.Background(), candidates)
	return prediction
}

// PredictFromCandidatesContext runs the real scoring/ranking path. It returns
// completed partial output together with the error on cancellation/failure.
// Cancellation is cooperative at file, method and bounded model-chunk boundaries.
func (pp *PatchPredictor) PredictFromCandidatesContext(ctx context.Context, candidates []AnalysisCandidate) (*PatchPrediction, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		p := pp.emptyPrediction()
		p.PartialResults = true
		return p, err
	}
	pp.predictionOnce.Do(func() { pp.predictionGate = make(chan struct{}, 1) })
	select {
	case pp.predictionGate <- struct{}{}:
		defer func() { <-pp.predictionGate }()
	case <-ctx.Done():
		p := pp.emptyPrediction()
		p.PartialResults = true
		return p, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		p := pp.emptyPrediction()
		p.PartialResults = true
		return p, err
	}
	if pp.feedbackIntegrator != nil {
		pp.feedbackIntegrator.AdjustIndexedPatternWeights(pp.analyzer.GetIndexedPatterns())
	}
	batch := pp.analyzer.batchAnalyzeContext(ctx, candidates, pp.config.MaxSmaliFileSize)
	scored, metrics := pp.runPredictionPipeline(ctx, batch)
	prediction := pp.buildPredictionContext(ctx, scored, batch)
	copied := copyPipelineMetrics(metrics)
	prediction.Stats.PipelineMetrics = &copied
	err := ctx.Err()
	if err == nil && len(metrics.Errors) > 0 {
		err = fmt.Errorf("ML pipeline incomplete: %s", strings.Join(metrics.Errors, "; "))
	}
	if err == nil && batch.FilesSkipped > 0 {
		err = fmt.Errorf("%d input files were skipped; see scan_errors", batch.FilesSkipped)
	}
	prediction.PartialResults = prediction.PartialResults || batch.Cancelled || err != nil
	if prediction.PartialResults {
		markPredictionPartial(prediction)
	}
	linkEconomyRelated(prediction)
	pp.enrichMLHealth(prediction)
	return prediction, err
}

func markPredictionPartial(prediction *PatchPrediction) {
	prediction.PartialResults = true
	for _, bucket := range [][]PatchPoint{prediction.HighRisk, prediction.MediumRisk, prediction.LowRisk, prediction.LibraryFindings, prediction.AuditFindings, prediction.MalwareIndicators} {
		for i := range bucket {
			if bucket[i].RuntimeDecision == "auto_patch" {
				bucket[i].RuntimeDecision = "needs_review"
				if bucket[i].RuntimeConfidence != nil {
					bucket[i].RuntimeConfidence.NeedsReview = true
					bucket[i].RuntimeConfidence.Reasons = append(bucket[i].RuntimeConfidence.Reasons, "partial prediction run")
				}
			}
		}
	}
}

type fileScanStats struct {
	discovered int
	skipped    int
	tooLarge   int
	readErrors int
	errors     []string
}

func (s *fileScanStats) addError(message string) {
	if len(s.errors) < 32 {
		s.errors = append(s.errors, message)
	}
}

func applyFileScanStats(stats *PredictionStats, scan fileScanStats) {
	if stats == nil {
		return
	}
	stats.FilesDiscovered = scan.discovered
	stats.FilesSkipped += scan.skipped
	stats.FilesTooLarge += scan.tooLarge
	stats.FileReadErrors += scan.readErrors
	stats.ScanErrors = append([]string(nil), scan.errors...)
}

func (pp *PatchPredictor) collectSmaliFiles(targetDir string) ([]AnalysisCandidate, fileScanStats, error) {
	return pp.collectSmaliFilesContext(context.Background(), targetDir)
}

func (pp *PatchPredictor) collectSmaliFilesContext(ctx context.Context, targetDir string) ([]AnalysisCandidate, fileScanStats, error) {
	// 🆕 Validate target directory before processing
	if err := pp.validateTargetDirectory(targetDir); err != nil {
		return nil, fileScanStats{}, fmt.Errorf("target directory validation failed: %w", err)
	}

	candidates := make([]AnalysisCandidate, 0, 256)
	var stats fileScanStats

	err := filepath.Walk(targetDir, func(path string, info os.FileInfo, err error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		// 🆕 Enhanced error handling with context
		if err != nil {
			stats.readErrors++
			stats.addError(fmt.Sprintf("%s: %v", path, err))
			// If target directory itself has an error, propagate it
			if filepath.Clean(path) == filepath.Clean(targetDir) {
				return fmt.Errorf("target directory error: %w", err)
			}
			// For subdirectories, log and continue
			return nil
		}

		// 🆕 Validate file info
		if info == nil {
			stats.skipped++
			stats.addError(fmt.Sprintf("%s: missing file metadata", path))
			return nil
		}

		// Skip directories and non-smali files
		if info.IsDir() || !strings.HasSuffix(strings.ToLower(path), ".smali") {
			return nil
		}

		stats.discovered++
		// Intentionally excluded SDKs do not make an application scan partial,
		// even when their generated marker classes are very small.
		if rel, relErr := filepath.Rel(targetDir, path); relErr == nil && !pp.config.IncludeLibraries {
			if IsLibraryPath(normalizePath(rel)) || IsKnownLibrary(rel) {
				return nil
			}
		}

		// 🆕 Enhanced file size validation with detailed error reporting
		if info.Size() < 100 {
			stats.skipped++
			stats.addError(fmt.Sprintf("%s: file too small (%d bytes < 100)", path, info.Size()))
			return nil
		}

		if pp.config.MaxSmaliFileSize > 0 && info.Size() > pp.config.MaxSmaliFileSize {
			stats.skipped++
			stats.tooLarge++
			stats.addError(fmt.Sprintf("%s: smali file exceeds size limit (%d bytes > %d bytes)",
				path, info.Size(), pp.config.MaxSmaliFileSize))
			return nil
		}

		// 🆕 Enhanced path validation and normalization
		relPath, relErr := filepath.Rel(targetDir, path)
		if relErr != nil {
			stats.addError(fmt.Sprintf("%s: relative path calculation failed: %v", path, relErr))
			relPath = path // Fallback to absolute path
		}
		if relPath == "" {
			relPath = path
		}

		// Validate relative path is not empty or just "."
		if relPath == "." || relPath == "" {
			stats.addError(fmt.Sprintf("%s: invalid relative path calculated", path))
			return nil
		}

		normalizedPath := normalizePath(relPath)
		// 🆕 Двойная проверка: старый детектор ИЛИ новая база известных libs
		isLibrary := IsLibraryPath(normalizedPath) || IsKnownLibrary(normalizedPath)

		// Если режим IncludeLibraries=false — фильтруем
		if !pp.config.IncludeLibraries && isLibrary {
			return nil
		}

		// 🆕 Validate candidate before adding
		if relPath == "" || path == "" {
			stats.addError(fmt.Sprintf("invalid candidate: relPath=%q, fullPath=%q", relPath, path))
			return nil
		}

		candidates = append(candidates, AnalysisCandidate{
			FilePath:  relPath,
			FullPath:  path,
			IsAppCode: !isLibrary,
		})
		return nil
	})

	// 🆕 Enhanced error reporting with context
	if err != nil {
		return candidates, stats, fmt.Errorf("file walk completed with errors: %w (discovered: %d, skipped: %d, errors: %d)",
			err, stats.discovered, stats.skipped, stats.readErrors)
	}

	// 🆕 Validate final results
	if stats.discovered == 0 {
		return candidates, stats, fmt.Errorf("no smali files discovered in target directory: %s", targetDir)
	}

	if len(candidates) == 0 && stats.discovered > 0 {
		return candidates, stats, fmt.Errorf("all discovered files were filtered (discovered: %d, skipped: %d)",
			stats.discovered, stats.skipped)
	}

	return candidates, stats, nil
}

// validateTargetDirectory performs pre-validation of the target directory
func (pp *PatchPredictor) validateTargetDirectory(targetDir string) error {
	if targetDir == "" {
		return fmt.Errorf("target directory path is empty")
	}

	// Check if directory exists
	info, err := os.Stat(targetDir)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("target directory does not exist: %s", targetDir)
		}
		return fmt.Errorf("failed to access target directory: %w", err)
	}

	// Check if it's actually a directory
	if !info.IsDir() {
		return fmt.Errorf("target path is not a directory: %s", targetDir)
	}

	// Check if directory is readable
	testFile := filepath.Join(targetDir, ".read_test")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err == nil {
		os.Remove(testFile)
	} else {
		// If we can't write, at least try to read
		entries, err := os.ReadDir(targetDir)
		if err != nil {
			return fmt.Errorf("target directory is not readable: %w", err)
		}
		if len(entries) == 0 {
			return fmt.Errorf("target directory is empty: %s", targetDir)
		}
	}

	return nil
}

func (pp *PatchPredictor) hasStrongPreFilterEvidence(sm *ScoredMethod) (bool, string) {
	if sm == nil {
		return false, ""
	}
	if vs := sm.Score.VulnerabilitySignals; vs != nil && vs.HasAny() {
		return true, "static vulnerability signal; review required"
	}
	if pp.crackPointIndex != nil {
		if _, ok := pp.crackPointIndex.Lookup(sm); ok {
			return true, "CFG crack-point confirmation"
		}
	}
	if sm.Method.HasSecurityAPI && sm.Score.Confidence >= 0.75 {
		return true, "high-confidence security API evidence"
	}
	return false, ""
}

// ═══════════════════════════════════════════════════════════════════════════════
// BUILD PREDICTION (с разделением app code / library code)
// ═══════════════════════════════════════════════════════════════════════════════

func (pp *PatchPredictor) buildPrediction(scored []ScoredMethod, batch *BatchAnalyzeResult) *PatchPrediction {
	return pp.buildPredictionContext(context.Background(), scored, batch)
}
func (pp *PatchPredictor) buildPredictionContext(ctx context.Context, scored []ScoredMethod, batch *BatchAnalyzeResult) *PatchPrediction {
	prediction := &PatchPrediction{
		HighRisk:          make([]PatchPoint, 0, pp.config.MaxHighRisk),
		MediumRisk:        make([]PatchPoint, 0, pp.config.MaxMediumRisk),
		LowRisk:           make([]PatchPoint, 0, pp.config.MaxLowRisk),
		LibraryFindings:   make([]PatchPoint, 0, pp.config.MaxLibraryRisk),
		MalwareIndicators: make([]PatchPoint, 0, 32),
		AuditFindings:     make([]PatchPoint, 0, pp.config.MaxAuditFindings),
		Mode:              pp.config.Mode,
		Stats: PredictionStats{
			TotalFilesScanned: batch.TotalFiles,
			TotalMethodsFound: batch.TotalMethods,
			MethodsAnalyzed:   batch.AnalyzedMethods,
			MethodsSkipped:    batch.SkippedMethods,
			ByCategory:        make(map[string]int),
			FilesDiscovered:   batch.InputFiles,
			FilesSkipped:      batch.FilesSkipped,
			FilesTooLarge:     batch.FilesTooLarge,
			FileReadErrors:    batch.FileReadErrors,
			ScanErrors:        append([]string(nil), batch.Diagnostics...),
		},
	}

	high := newRankedPatchPoints(pp.config.MaxHighRisk, patchValueOrFallback)
	medium := newRankedPatchPoints(pp.config.MaxMediumRisk, patchValueOrFallback)
	low := newRankedPatchPoints(pp.config.MaxLowRisk, patchValueOrFallback)
	library := newRankedPatchPoints(pp.config.MaxLibraryRisk, patchValueOrFallback)
	malware := newRankedPatchPoints(pp.config.MaxAuditFindings, auditValue)
	audit := newRankedPatchPoints(pp.config.MaxAuditFindings, auditValue)
	var totalScore, maxScore float64

	for _, sm := range scored {
		if ctx.Err() != nil {
			prediction.PartialResults = true
			break
		}
		allowed, reason := safeRecommendationDecision(&sm)
		// A restriction on rewriting a library/complex method is NOT a reason to
		// discard its audit signal. The audit-only path never advertises a patch.
		if !allowed && !sm.Score.VulnerabilitySignals.HasAny() && !isEconomyCandidate(economyForMethod(&sm.Method)) {
			batch.FilteredMethods++
			if len(batch.FilterReasons) < 100 {
				batch.FilterReasons = append(batch.FilterReasons, reason)
			}
			continue
		}
		var point PatchPoint
		if allowed {
			point = pp.scoredMethodToPoint(&sm)
		} else {
			point = pp.auditOnlyPoint(&sm, reason)
		}

		if isExpressionExportGetterNoise(point.MethodName) && strings.TrimSpace(string(point.Category)) == "" && strings.TrimSpace(point.CategoryName) == "" {
			point.IsFiltered = true
			point.RiskScore = 0
			point.RiskLevel = RiskClassNone
			point.SuggestedPatch = ""
			point.Warnings = append(point.Warnings, "Expression/export getter; suppressed from app patch candidates")
		}

		economyTarget := isEconomyCandidate(point.Economy) && onlyEconomySignals(point.VulnSignals) && allowed && !economyNeedsTransactionReview(point.Economy)
		if point.VulnSignals.HasAny() && !economyTarget {
			if point.VulnSignals.IsMalwareSuspect {
				malware.Add(&point)
				prediction.Stats.MalwareFindingsCount++
			} else {
				audit.Add(&point)
				prediction.Stats.AuditFindingsCount++
			}
			continue
		}
		if isEconomyCandidate(point.Economy) && (!allowed || economyNeedsTransactionReview(point.Economy)) {
			audit.Add(&point)
			prediction.Stats.AuditFindingsCount++
			continue
		}

		// Audit findings always survive heuristic gate filters. Other filtered
		// methods are omitted from patch buckets as before.
		if point.IsFiltered || point.RiskScore < pp.config.MinScore || (point.RecommendationAssessment != nil && point.RecommendationAssessment.Status == "reject") {
			prediction.Stats.FilteredMethods++
			continue
		}

		// SDK/framework internals are useful context, but they are not app-owned
		// patch targets. Keep them out of HIGH/MEDIUM/LOW patch buckets even when
		// direct-DEX materialization marks everything as app code.
		if isSDKOrFrameworkPatchNoise(&point) {
			point.IsLibraryCode = true
			point.Warnings = append(point.Warnings, "SDK/framework internal; suppressed from app patch candidates")
			library.Add(&point)
			continue
		}

		// 🆕 МАРШРУТИЗАЦИЯ: библиотеки → отдельный bucket
		if point.IsLibraryCode {
			library.Add(&point)
			continue
		}

		prediction.Stats.PatchPointsFound++
		totalScore += point.RiskScore
		if point.RiskScore > maxScore {
			maxScore = point.RiskScore
		}

		catName := string(point.Category)
		if catName == "" {
			catName = "unknown"
		}
		prediction.Stats.ByCategory[catName]++

		switch point.RiskLevel {
		case RiskClassHigh:
			high.Add(&point)
		case RiskClassMedium:
			medium.Add(&point)
		case RiskClassLow:
			low.Add(&point)
		}
	}

	if prediction.Stats.PatchPointsFound > 0 {
		prediction.Stats.AvgScore = totalScore / float64(prediction.Stats.PatchPointsFound)
	}
	prediction.Stats.MaxScore = maxScore
	prediction.Stats.TopCategories = pp.buildTopCategories(prediction.Stats.ByCategory)

	prediction.HighRisk = high.Sorted()
	prediction.MediumRisk = medium.Sorted()
	prediction.LowRisk = low.Sorted()
	prediction.LibraryFindings = library.Sorted()
	prediction.MalwareIndicators = malware.Sorted()
	prediction.AuditFindings = audit.Sorted()
	prediction.Stats.HighRiskCount = len(prediction.HighRisk)
	prediction.Stats.MediumRiskCount = len(prediction.MediumRisk)
	prediction.Stats.LowRiskCount = len(prediction.LowRisk)
	prediction.Stats.LibraryFindingsCount = len(prediction.LibraryFindings)
	prediction.Stats.FilteredMethods += batch.FilteredMethods

	// 🆕 MAIN FINDINGS + TOP ISSUES (TopIssues теперь по PatchValue)
	prediction.MainFindings = pp.buildMainFindings(prediction)
	prediction.TopIssues = pp.buildTopIssues(prediction)

	// ── ML Health v2 — schema hash, pipeline metrics, drift/ECE (offline observability) ─
	pp.enrichMLHealth(prediction)

	linkEconomyRelated(prediction)

	return prediction
}

// enrichMLHealth заполняет PredictionStats.Schema* и MLHealth (drift/ECE/pipeline/replay)
func (pp *PatchPredictor) enrichMLHealth(prediction *PatchPrediction) {
	if prediction == nil {
		return
	}
	reg := GlobalFeatureRegistry()
	prediction.Stats.SchemaHash = reg.SchemaHash()
	prediction.Stats.SchemaVersion = reg.Version()
	health := &MLHealth{DriftVerdict: "unavailable", CalibrationStatus: "unavailable_no_labeled_evaluation", MeasurementNotes: []string{"PSI requires a reference feature distribution; filtered ratio is not PSI.", "ECE/Brier require labeled predictions; no values are inferred from score counts.", "Throughput covers measured scoring/reranking stages, not file parsing or final CFG enrichment."}}
	if pp.replayBuffer != nil {
		health.ReplaySize = pp.replayBuffer.Len()
		health.ReplayBalance = pp.replayBuffer.ClassBalance()
	}
	if pm := prediction.Stats.PipelineMetrics; pm != nil {
		health.Throughput = pm.Throughput
	}
	prediction.Stats.MLHealth = health
}

// patchValueOrFallback возвращает PatchValue если он есть, иначе RiskScore/10.
// Используется как ключ сортировки — результаты в одном масштабе (0..10).
func patchValueOrFallback(p *PatchPoint) float64 {
	if p == nil {
		return 0
	}
	if p.PatchValue != nil {
		return p.PatchValue.Value
	}
	return p.RiskScore / 10.0
}

func sortByAuditValue(slice []PatchPoint) {
	sort.SliceStable(slice, func(i, j int) bool {
		return auditValue(&slice[i]) > auditValue(&slice[j])
	})
}

func auditValue(p *PatchPoint) float64 {
	if p == nil || p.VulnSignals == nil || len(p.VulnSignals.Signals) == 0 {
		return 0
	}
	rank := map[VulnSeverity]float64{
		VulnSeverityCritical: 4,
		VulnSeverityHigh:     3,
		VulnSeverityMedium:   2,
		VulnSeverityLow:      1,
	}
	best := 0.0
	for _, signal := range p.VulnSignals.Signals {
		value := rank[signal.Severity]*100 + signal.Confidence*100 + p.RiskScore*0.1
		if value > best {
			best = value
		}
	}
	return best
}

func (pp *PatchPredictor) scoredMethodToPoint(sm *ScoredMethod) PatchPoint {
	// 🆕 определяем библиотека ли
	isLib := !sm.Method.IsAppCode || IsKnownLibrary(sm.ClassPath)
	libName := ""
	if isLib {
		libName = LibraryName(sm.ClassPath)
	}

	// 🔥 NEW: Calculate enhanced analysis data
	var interestingScore *InterestingScore
	var entryPointInfo *EntryPointInfo
	isEntryPoint := false
	isInteresting := false

	if sm.Interesting != nil {
		interestingScore = sm.Interesting
		isInteresting = interestingScore.IsInteresting
	} else if pp.enableInterestingScore && pp.interestingScorer != nil {
		interestingScore = pp.interestingScorer.Calculate(&sm.Method, nil)
		sm.Interesting = interestingScore
		isInteresting = interestingScore.IsInteresting
	}

	if sm.EntryPoint != nil {
		entryPointInfo = sm.EntryPoint
		isEntryPoint = entryPointInfo != nil && pp.entryPointDetector != nil && pp.entryPointDetector.IsInteresting(entryPointInfo)
	} else if pp.entryPointDetector != nil {
		entryPointInfo = pp.entryPointDetector.Detect(&sm.Method)
		sm.EntryPoint = entryPointInfo
		isEntryPoint = entryPointInfo != nil && pp.entryPointDetector.IsInteresting(entryPointInfo)
	}

	// 🔥 NEW: DFG Analysis for license/security checks
	var dfgInfo *DFGInfo
	var dfgBonus float64
	var dfgReasons []string
	// PHASE 2: CFG поднят на уровень функции — нужен для structural signals
	// после DFG-анализа.
	var controlFlowGraph *cfg.ControlFlowGraph

	// Быстрый фильтр: пропускаем только если нет НИ if-, НИ invoke
	// Оптимизация: сканируем RawBody без strings.Join — избегаем аллокации
	// на каждом методе (10k методов × avg 50 строк = 500k строк join'ов).
	if len(sm.Method.RawBody) > 0 && sm.Method.InstructionCount >= 4 &&
		sm.Method.IfCheckCount > 0 {

		hasIf := rawBodyContains(sm.Method.RawBody, "if-")
		hasInvoke := rawBodyContains(sm.Method.RawBody, "invoke")

		if !hasIf && !hasInvoke {
			// Нет ни условий, ни вызовов → DFG не нужен
			goto dfgDone
		}

		cfgInput := cfg.BuildInputFromLines(
			sm.Method.ClassName,
			sm.Method.Name,
			sm.Method.FullSignature,
			sm.Method.RawBody,
		)

		// CFG из кеша (ключ — class + signature)
		controlFlowGraph = pp.cfgCache.GetOrBuild(cfgInput)
		if controlFlowGraph != nil {
			dfgAnalyzer := cfg.NewDFGAnalyzer(controlFlowGraph)
			dfgAnalyzer.Analyze()

			licenseChecks := dfgAnalyzer.FindLicenseChecks(10)

			if len(licenseChecks) > 0 {
				// Лучший check по confidence → в DFGInfo (для отображения)
				bestIdx := 0
				bestConf := licenseChecks[0].Confidence
				for i := 1; i < len(licenseChecks); i++ {
					if licenseChecks[i].Confidence > bestConf {
						bestConf = licenseChecks[i].Confidence
						bestIdx = i
					}
				}
				best := licenseChecks[bestIdx]
				dfgInfo = &DFGInfo{
					Available:     true,
					ConditionType: best.Condition.Opcode,
					ConditionText: fmt.Sprintf("%s == %s", best.Register, best.Condition.String()),
					Register:      best.Register,
					Trace:         convertCFGTraceToML(best.Trace),
					Confidence:    best.Confidence,
				}

				// 💥 PHASE 1: per-check delta accumulation (исправление halving bug).
				//
				// Раньше `dfgBonus *= 0.5` халвило ВЕСЬ накопленный бонус, что давало
				// destructive compounding: 5 коротких трейсов → бонус ≈ 0.
				// Теперь каждый check считается отдельно в `delta`, halving применяется
				// только к контрибу текущего check, и delta добавляется к dfgBonus.
				for _, check := range licenseChecks {
					var delta float64
					var localReasons []string

					// Базовая контрибуция check'а: confidence-weighted
					base := check.Confidence * 1.5
					delta += base
					localReasons = append(localReasons,
						fmt.Sprintf("DFG: license check (conf=%.2f, +%.2f)", check.Confidence, base))

					// Per-step контрибуции (DFGInvoke/DFGConst/DFGField) — тоже в delta
					mlTrace := convertCFGTraceToML(check.Trace)
					for _, step := range mlTrace {
						switch step.Type {
						case DFGInvoke:
							if step.InvokeRef != nil {
								invLower := strings.ToLower(*step.InvokeRef)
								switch {
								case strings.Contains(invLower, "islicensed") ||
									strings.Contains(invLower, "ispremium") ||
									strings.Contains(invLower, "checklicense"):
									delta += 1.5
									localReasons = append(localReasons,
										fmt.Sprintf("DFG: high-value invoke %s (+1.5)", *step.InvokeRef))
								case strings.Contains(invLower, "license") ||
									strings.Contains(invLower, "premium") ||
									strings.Contains(invLower, "ispro") ||
									strings.Contains(invLower, "check"):
									delta += 0.8
									localReasons = append(localReasons,
										fmt.Sprintf("DFG: license-related invoke %s (+0.8)", *step.InvokeRef))
								}
							}
						case DFGConst:
							if step.ConstValue != nil {
								constLower := strings.ToLower(*step.ConstValue)
								if strings.Contains(constLower, "premium") ||
									strings.Contains(constLower, "license") ||
									strings.Contains(constLower, "key") ||
									strings.Contains(constLower, "valid") {
									delta += 1.0
									localReasons = append(localReasons,
										fmt.Sprintf("DFG: license constant '%s' (+1.0)", *step.ConstValue))
								}
							}
						case DFGField:
							if step.FieldRef != nil {
								fldLower := strings.ToLower(*step.FieldRef)
								if strings.Contains(fldLower, "license") ||
									strings.Contains(fldLower, "premium") ||
									strings.Contains(fldLower, "ispro") {
									delta += 0.8
									localReasons = append(localReasons,
										fmt.Sprintf("DFG: license field %s (+0.8)", *step.FieldRef))
								}
							}
						}
					}

					// Trace < 2 → халвим ТОЛЬКО эту delta (а не накопленную сумму).
					// Halving применяется ко всему вкладу check'а: и базе, и per-step бонусам.
					if len(check.Trace) < 2 {
						delta *= 0.5
						localReasons = append(localReasons,
							fmt.Sprintf("DFG: short trace (<2 steps), this check halved (delta=%.2f)", delta))
					}

					dfgBonus += delta
					dfgReasons = append(dfgReasons, localReasons...)
				}

				// 💥 PHASE 1: dynamic cap.
				//
				// Раньше hard cap = 3.0 (≈4.6% от HighRiskThreshold=65) — DFG никогда
				// не мог реально повлиять. Теперь cap пропорционален FinalScore:
				//   cap = clamp(FinalScore × 0.4, [8.0, 25.0])
				// → cap=8 даже при низком FinalScore (DFG не должен глохнуть в нуле),
				// → cap=25 на высоких FinalScore (DFG может промотировать тир),
				// → пропорционален: чем выше base score, тем больше может добавить DFG.
				dfgMaxCap := 25.0
				dfgMultiplier := 0.4
				if sm.Score.PatchCategory == PatchCatBilling ||
					sm.Score.PatchCategory == PatchCatIntegrity {
					dfgMaxCap = 32.0
					dfgMultiplier = 0.45
				}
				dfgCap := math.Max(8.0, math.Min(dfgMaxCap, sm.Score.FinalScore*dfgMultiplier))
				if dfgBonus > dfgCap {
					dfgReasons = append(dfgReasons,
						fmt.Sprintf("DFG: bonus %.2f capped at %.2f (FinalScore=%.1f)",
							dfgBonus, dfgCap, sm.Score.FinalScore))
					dfgBonus = dfgCap
				}
			} else {
				dfgInfo = &DFGInfo{
					Available:  true,
					Trace:      []DFGTraceStep{},
					Confidence: 0.0,
				}
			}
		}
	}
dfgDone:

	// 💥 PHASE 2: structural signals — guards / hard gates / funnels.
	//
	// Здесь читаем path-sensitive сигналы из CFG (доминаторы + post-доминаторы +
	// guard/funnel detection), которые pkg/internal/cfg уже считает, но раньше
	// никто не использовал. Это даёт path-sensitive scoring:
	//   • method has guard (DominatesExit) → +5..15
	//   • method has hard gate (ExitPostDoms) → +3..10 — самый сильный сигнал
	//   • guards dominate >30% method body → +ratio×8
	//   • AND-funnel detected → +4 (single entry-patch может сломать chain)
	//
	// Score-promotion после DFG+structural видна в WhyVulnerable:
	//   "STRUCT: 1 HARD GATE(s) — guards post-dominate exit (+3.0)"
	var structSignals *StructuralSignals
	var structBonus float64
	var structReasons []string
	if controlFlowGraph != nil {
		structSignals = ComputeStructuralSignals(controlFlowGraph)
		structBonus, structReasons = structSignals.ScoreContribution()
	}

	// PHASE 2: оживление CallChainInfo для interestingScorer.
	//
	// Раньше callChain всегда был nil → IsEntryPoint / CallDepthScore /
	// ExportedComponentScore в InterestingScorer всегда давали 0 (40% логики
	// была мёртвой). Сейчас прокидываем минимальный CallChainInfo на основе
	// entry-point detection — это активирует exported-component path даже без
	// полного межметодного call graph (который придёт позже, отдельной фазой).
	if pp.enableInterestingScore && pp.interestingScorer != nil &&
		entryPointInfo != nil && isEntryPoint {
		callChain := &CallChainInfo{
			Depth:                 1,
			IsEntryPoint:          true,
			FromExportedComponent: true,
			Path:                  []string{sm.Method.Name},
		}
		// Пересчитываем с реальным callChain — IsEntryPoint=true теперь
		// добавит exportedComponentWeight (15) и callDepthWeight (10).
		interestingScore = pp.interestingScorer.Calculate(&sm.Method, callChain)
		isInteresting = interestingScore.IsInteresting
	}

	// 💥 PHASE 1+2: финальный risk score и tier — после DFG И structural bonus.
	// Раньше RiskLevel = sm.Score.RiskLevel блокировал промоцию тира даже при
	// сильном DFG-сигнале. Теперь все сигналы складываются перед классификацией.
	finalRiskScore := sm.Score.FinalScore + dfgBonus + structBonus
	if finalRiskScore > 100.0 {
		finalRiskScore = 100.0
	}
	finalRiskScore = math.Round(finalRiskScore*10) / 10
	finalRiskLevel := pp.classifyRisk(sm.Score.PatchCategory, finalRiskScore)

	// Лог промоции тира — критично для аудита почему скор изменился.
	if finalRiskLevel != sm.Score.RiskLevel {
		dfgReasons = append(dfgReasons,
			fmt.Sprintf("RiskLevel %s → %s (FinalScore=%.1f + DFG=%.2f + STRUCT=%.2f = %.1f)",
				sm.Score.RiskLevel, finalRiskLevel,
				sm.Score.FinalScore, dfgBonus, structBonus, finalRiskScore))
	}

	// Объединяем reasons: DFG + structural идут после оригинальных Score.Reasons.
	// Порядок важен для UI (сначала pattern matches, потом backed by DFG/struct).
	if len(structReasons) > 0 {
		dfgReasons = append(dfgReasons, structReasons...)
	}

	point := PatchPoint{
		Economy:             economyForMethod(&sm.Method),
		FilePath:            sm.ClassPath,
		ClassName:           sm.ClassName,
		MethodName:          sm.Method.Name,
		MethodSignature:     sm.Method.FullSignature,
		RiskScore:           finalRiskScore,
		RiskLevel:           finalRiskLevel,
		Confidence:          sm.Score.Confidence,
		ConfidenceBreakdown: sm.Score.ConfidenceBreakdown,
		Category:            sm.Score.PatchCategory,
		SuggestedPatch:      sm.Score.SuggestedPatch,
		WhyVulnerable:       append(sm.Score.Reasons, dfgReasons...),
		MatchedParts:        sm.Score.MatchedParts,
		Warnings:            sm.Score.Warnings,
		IsAppCode:           sm.Method.IsAppCode,
		IsLibraryCode:       isLib,
		LibraryName:         libName,
		ReturnType:          sm.Method.ReturnType,
		SourceLanguage:      sm.Method.SourceLanguage,
		MethodBody:          sm.Method.RawBody,
		MethodHeader:        sm.Method.MethodHeader,

		// 🔥 NEW: Enhanced analysis data
		InterestingScore: interestingScore,
		EntryPointInfo:   entryPointInfo,
		IsEntryPoint:     isEntryPoint,
		IsInteresting:    isInteresting,

		// DFG Analysis
		DFG: dfgInfo,

		// PHASE 2: Structural signals (guards / funnels / hard gates)
		Structural: structSignals,

		// Ensemble Boost: structural/entropy/taint feature blend (nil if disabled)
		EnsembleScore: sm.Ensemble,
		VulnSignals:   sm.Score.VulnerabilitySignals,
	}

	if catInfo, ok := GetCategoryInfo(point.Category); ok {
		point.CategoryName = catInfo.Name
	} else {
		point.CategoryName = string(point.Category)
	}
	point.CategoryConfidence = EstimateCategoryConformalConfidence(point.Category, point.Confidence)

	if sm.Score.BestPattern != nil {
		point.PatternID = sm.Score.BestPattern.ID
		point.PatternDesc = sm.Score.BestPattern.Description
	}

	if pp.crackPointIndex != nil {
		if cp, ok := pp.crackPointIndex.Lookup(sm); ok {
			point.CrackPointConfirmed = true
			point.CrackPointCategory = cp.Category
			point.WhyVulnerable = append(point.WhyVulnerable,
				fmt.Sprintf("CFG crack-point: %s gate confirmed (conf=%.2f, impact=%d)",
					cp.Category, cp.Confidence, cp.Impact))
		}
	}

	// 🧠 Semantic Gate v2 — CFG/DFG-aware (мощно, path-sensitive)
	// Параллельно с legacy GateDetector, но использует структуру CFG, а не имя.
	// Результат пишется в point.SemanticGate и влияет на PatchValue.
	if pp.semanticGateDetector != nil {
		sg := pp.semanticGateDetector.Analyze(&sm.Method, controlFlowGraph, structSignals, dfgInfo, point.CrackPointConfirmed)
		point.SemanticGate = sg
		if sg != nil {
			for _, r := range sg.Reasons {
				point.WhyVulnerable = append(point.WhyVulnerable, "SEM-GATE: "+r)
			}
		}
	}

	// 💥 PHASE 3: PatchValue — главная метрика «что патчить первым».
	// Считается ПОСЛЕ финального RiskScore и Structural — нужен полный контекст.
	point.PatchValue = ComputePatchValue(&point, &sm.Method)
	if point.PatchValue != nil {
		// Лог в WhyVulnerable: видно почему именно эта точка получила такой
		// PatchValue. Полезно для аудита и отладки.
		point.WhyVulnerable = append(point.WhyVulnerable, point.PatchValue.Explain())
		// Semantic gate v2 корректирует PatchValue: NON_GATE → ×0.15, WEAK_GATE → ×0.55
		if point.SemanticGate != nil {
			switch point.SemanticGate.Verdict {
			case GateNonGate:
				if isResourceValueMethod(&sm.Method) { break }
				old := point.PatchValue.Value
				point.PatchValue.Value *= 0.15
				point.WhyVulnerable = append(point.WhyVulnerable,
					fmt.Sprintf("SEM-GATE penalty NON_GATE (%.2f → %.2f, score=%.2f)", old, point.PatchValue.Value, point.SemanticGate.Score))
			case GateWeakGate:
				old := point.PatchValue.Value
				point.PatchValue.Value *= 0.55
				point.WhyVulnerable = append(point.WhyVulnerable,
					fmt.Sprintf("SEM-GATE penalty WEAK_GATE (%.2f → %.2f, score=%.2f)", old, point.PatchValue.Value, point.SemanticGate.Score))
			}
			if point.PatchValue.Value < 0 {
				point.PatchValue.Value = 0
			}
		}
	}

	// ═══════════════════════════════════════════════════════════════════════════════
	// 🔥 PHASE 4: Gate Detection — фильтрация equals/hashCode/toString/getters
	//
	// Проблема: 4788 точек, большинство — data methods (equals, hashCode, toString).
	// Решение: проверяем "это реально gate?" — если НЕ gate, точка ИСКЛЮЧАЕТСЯ.
	//
	// HARD REJECT для: equals, hashCode, toString, compareTo, clone, простые getters
	// SOFT PENALTY для: остальных non-gates (если есть callers и branches)
	// ═══════════════════════════════════════════════════════════════════════════════
	preserveFromGateFilter, preserveReason := shouldPreserveFromGateFilter(&point, &sm.Method)
	if pp.config.EnableGateDetection && !preserveFromGateFilter {
		// Быстрая проверка: equals/hashCode/toString — сразу HARD REJECT
		nameLower := strings.ToLower(sm.Method.Name)
		switch nameLower {
		case "equals", "hashcode", "tostring", "compareto", "clone",
			"containskey", "containsvalue", "isempty", "size", "clear", "remove", "putall", "iterator":
			point.IsFiltered = true
			point.FilterReason = "data class method (" + sm.Method.Name + ") — NEVER a security gate"
			point.RiskScore = 1.0 // минимум для сортировки
			point.RiskLevel = RiskClassLow
		}

		// UI Diff methods — RecyclerView/DiffUtil (areContentsTheSame, areItemsTheSame)
		if !point.IsFiltered {
			uiDiffPatterns := []string{"arecontentsthesame", "areitemsthesame", "getitemid", "getlayoutposition"}
			for _, p := range uiDiffPatterns {
				if strings.Contains(nameLower, p) {
					point.IsFiltered = true
					point.FilterReason = "UI diff method (" + sm.Method.Name + ") — RecyclerView optimization, NOT security gate"
					point.RiskScore = 1.0
					point.RiskLevel = RiskClassLow
					break
				}
			}
		}

		// Kotlin synthetic lambdas (create$lambda$N, access$lambda$N)
		if !point.IsFiltered && (strings.Contains(nameLower, "$lambda$") || strings.Contains(nameLower, "lambda$")) {
			point.IsFiltered = true
			point.FilterReason = "Kotlin synthetic lambda (" + sm.Method.Name + ") — compiler-generated, NOT security gate"
			point.RiskScore = 1.0
			point.RiskLevel = RiskClassLow
		}

		// UI flow methods (showXxx, isStepXxx) — login/signup flow, NOT security gates
		if !point.IsFiltered {
			uiFlowPrefixes := []string{"show", "isstep", "isnamestep", "isagestep", "isemailstep", "ispasswordstep"}
			for _, prefix := range uiFlowPrefixes {
				if strings.HasPrefix(nameLower, prefix) {
					// Проверяем что это не contains "security" or "auth"
					if !strings.Contains(nameLower, "security") && !strings.Contains(nameLower, "auth") &&
						!strings.Contains(nameLower, "verified") && !strings.Contains(nameLower, "premium") {
						point.IsFiltered = true
						point.FilterReason = "UI flow method (" + sm.Method.Name + ") — UX navigation, NOT security gate"
						point.RiskScore = 1.0
						point.RiskLevel = RiskClassLow
						break
					}
				}
			}
		}

		// Network connectivity checks — NOT security gates
		if !point.IsFiltered && (strings.Contains(nameLower, "connected") || strings.Contains(nameLower, "connecting")) {
			point.IsFiltered = true
			point.FilterReason = "network check (" + sm.Method.Name + ") — connectivity, NOT security gate"
			point.RiskScore = 1.0
			point.RiskLevel = RiskClassLow
		}

		// Intrinsic getters — Drawable UI properties
		if !point.IsFiltered && strings.Contains(nameLower, "intrinsic") {
			point.IsFiltered = true
			point.FilterReason = "intrinsic getter (" + sm.Method.Name + ") — Drawable UI property, NOT security gate"
			point.RiskScore = 1.0
			point.RiskLevel = RiskClassLow
		}

		// Protobuf clear methods — setters/cleaners
		if !point.IsFiltered && strings.HasPrefix(nameLower, "clear") && len(nameLower) > 5 {
			// clearXxx methods in protobuf generated classes
			point.IsFiltered = true
			point.FilterReason = "protobuf setter/clear (" + sm.Method.Name + ") — data mutation, NOT security gate"
			point.RiskScore = 1.0
			point.RiskLevel = RiskClassLow
		}

		// Simple getters (getInt, getLong) in data classes
		if !point.IsFiltered && (nameLower == "getint" || nameLower == "getlong" || nameLower == "getshort" || nameLower == "getbyte") {
			point.IsFiltered = true
			point.FilterReason = "primitive getter (" + sm.Method.Name + ") — data accessor, NOT security gate"
			point.RiskScore = 1.0
			point.RiskLevel = RiskClassLow
		}

		// Kotlin lambda predicates (test method in Predicate interface)
		// Usually appears as test(Ljava/lang/Object;)Z in Kotlin lambda classes
		if !point.IsFiltered && nameLower == "test" && sm.Method.ReturnsBoolean {
			// Check if class name suggests lambda context
			classLower := stringutils.ToLowerIfEmpty(sm.Method.ClassName, sm.Method.ClassNameLower)
			if strings.Contains(classLower, "$") || strings.Contains(sm.Method.FullSignature, "Ljava/lang/Object;") {
				point.IsFiltered = true
				point.FilterReason = "lambda predicate (" + sm.Method.Name + ") — collection filter, NOT security gate"
				point.RiskScore = 1.0
				point.RiskLevel = RiskClassLow
			}
		}

		// Kotlin Protobuf DSL accessors (classes like FooKt$Dsl, FooKt$AndroidKt$Dsl)
		// ALL methods in these classes are accessors/mutators — NEVER security gates
		if !point.IsFiltered {
			classLower := stringutils.ToLowerIfEmpty(sm.Method.ClassName, sm.Method.ClassNameLower)
			if strings.Contains(classLower, "kt$dsl") || strings.Contains(classLower, "kt$android") {
				point.IsFiltered = true
				point.FilterReason = "Kotlin protobuf DSL accessor (" + sm.Method.Name + ") — DSL builder, NOT security gate"
				point.RiskScore = 1.0
				point.RiskLevel = RiskClassLow
			}
		}

		// Protobuf "hasXxx" field presence checks — NOT security gates
		if !point.IsFiltered && strings.HasPrefix(nameLower, "has") && len(sm.Method.Name) > 3 {
			nextChar := sm.Method.Name[3]
			if (nextChar >= 'A' && nextChar <= 'Z') && !containsAny(nameLower, securityNameKeywords) {
				point.IsFiltered = true
				point.FilterReason = "protobuf has-field check (" + sm.Method.Name + ") — generated accessor, NOT security gate"
				point.RiskScore = 1.0
				point.RiskLevel = RiskClassLow
			}
		}

		// DSL/Builder setters and putters: setXxx, putXxx, addXxx, removeXxx
		if !point.IsFiltered {
			dslMutators := []string{"set", "put", "add", "remove", "merge", "build", "copy"}
			for _, prefix := range dslMutators {
				if strings.HasPrefix(nameLower, prefix) && len(nameLower) > len(prefix) {
					nextChar := nameLower[len(prefix)]
					if nextChar >= 'a' && nextChar <= 'z' {
						point.IsFiltered = true
						point.FilterReason = "DSL/builder mutator (" + sm.Method.Name + ") — data builder, NOT security gate"
						point.RiskScore = 1.0
						point.RiskLevel = RiskClassLow
						break
					}
				}
			}
		}

		// UI lifecycle/callback methods
		if !point.IsFiltered {
			uiCallbacks := []string{"onlayoutchange", "onpredraw", "onscrollchange", "onattach", "ondetach",
				"onmeasure", "ondraw", "onlayout", "ontouchevent", "onclick", "onlongclick",
				"onfocuschange", "onwindowfocuschanged", "whilestarted", "whilecreated", "whileresumed"}
			for _, cb := range uiCallbacks {
				if strings.Contains(nameLower, cb) {
					point.IsFiltered = true
					point.FilterReason = "UI callback/lifecycle (" + sm.Method.Name + ") — UI event handler, NOT security gate"
					point.RiskScore = 1.0
					point.RiskLevel = RiskClassLow
					break
				}
			}
		}

		// Connectivity / Network checks
		if !point.IsFiltered && (strings.Contains(nameLower, "networkavailable") ||
			strings.Contains(nameLower, "connected") || strings.Contains(nameLower, "connecting")) {
			point.IsFiltered = true
			point.FilterReason = "network connectivity (" + sm.Method.Name + ") — network check, NOT security gate"
			point.RiskScore = 1.0
			point.RiskLevel = RiskClassLow
		}

		// Utility methods: equalNullableStrings, null-safe comparisons
		if !point.IsFiltered && (strings.Contains(nameLower, "equalnull") ||
			strings.Contains(nameLower, "nullablestrings") || strings.Contains(nameLower, "safeequals")) {
			point.IsFiltered = true
			point.FilterReason = "utility comparison (" + sm.Method.Name + ") — helper method, NOT security gate"
			point.RiskScore = 1.0
			point.RiskLevel = RiskClassLow
		}

		// Kotlinx.serialization: shouldEncodeElementDefault
		if !point.IsFiltered && strings.Contains(nameLower, "shouldencode") {
			point.IsFiltered = true
			point.FilterReason = "serialization config (" + sm.Method.Name + ") — kotlinx.serialization, NOT security gate"
			point.RiskScore = 1.0
			point.RiskLevel = RiskClassLow
		}

		// Event propagation: getShouldPropagate, shouldPropagate
		if !point.IsFiltered && strings.Contains(nameLower, "propagate") {
			point.IsFiltered = true
			point.FilterReason = "event propagation (" + sm.Method.Name + ") — event handling, NOT security gate"
			point.RiskScore = 1.0
			point.RiskLevel = RiskClassLow
		}

		// UI progress/state indicators
		if !point.IsFiltered && (strings.Contains(nameLower, "showprogress") ||
			strings.Contains(nameLower, "getshowprogress") || strings.Contains(nameLower, "isshowing")) {
			point.IsFiltered = true
			point.FilterReason = "UI state indicator (" + sm.Method.Name + ") — UI property, NOT security gate"
			point.RiskScore = 1.0
			point.RiskLevel = RiskClassLow
		}

		// RxJava: subscribe, onError, onComplete in reactive classes
		if !point.IsFiltered {
			classLower := stringutils.ToLowerIfEmpty(sm.Method.ClassName, sm.Method.ClassNameLower)
			// Check if class looks like RxJava (Observable, Flowable, Single, etc.)
			isRxJavaClass := strings.Contains(classLower, "tl0/") || // RxJava package pattern
				strings.Contains(classLower, "io/reactivex") ||
				strings.Contains(classLower, "rx/") ||
				strings.Contains(classLower, "rxjava")
			if isRxJavaClass {
				rxMethods := []string{"subscribe", "onerror", "oncomplete", "onsuccess", "m", "z"}
				for _, rxm := range rxMethods {
					if nameLower == rxm || strings.Contains(nameLower, rxm) {
						point.IsFiltered = true
						point.FilterReason = "RxJava reactive method (" + sm.Method.Name + ") — reactive stream, NOT security gate"
						point.RiskScore = 1.0
						point.RiskLevel = RiskClassLow
						break
					}
				}
			}
		}

		// Identity comparison (Zendesk and similar)
		if !point.IsFiltered && strings.Contains(nameLower, "identityisdifferent") {
			point.IsFiltered = true
			point.FilterReason = "identity comparison (" + sm.Method.Name + ") — identity check, NOT security gate"
			point.RiskScore = 1.0
			point.RiskLevel = RiskClassLow
		}

		// Inventory/item checks that are not license-related
		if !point.IsFiltered && (strings.Contains(nameLower, "isgems") ||
			strings.Contains(nameLower, "isreadyforpurchase") ||
			strings.Contains(nameLower, "isfullhealth") ||
			strings.Contains(nameLower, "ispremiumitem")) {
			// Only filter if no license/premium/security keywords
			if !strings.Contains(nameLower, "license") && !strings.Contains(nameLower, "verified") &&
				!strings.Contains(nameLower, "auth") && !strings.Contains(nameLower, "check") {
				point.IsFiltered = true
				point.FilterReason = "inventory item check (" + sm.Method.Name + ") — game item, NOT security gate"
				point.RiskScore = 1.0
				point.RiskLevel = RiskClassLow
			}
		}

		// Math helpers (Math.min/Math.max wrappers)
		if !point.IsFiltered && len(nameLower) <= 1 && (nameLower == "b" || nameLower == "g") {
			// Оптимизация: без Join — скан по слайсу
			if rawBodyContains(sm.Method.RawBody, "Math;->min") || rawBodyContains(sm.Method.RawBody, "Math;->max") {
				point.IsFiltered = true
				point.FilterReason = "math helper (" + sm.Method.Name + ") — Math wrapper, NOT security gate"
				point.RiskScore = 1.0
				point.RiskLevel = RiskClassLow
			}
		}

		// Дополнительная проверка через GateDetector если доступен
		if !point.IsFiltered && pp.gateDetector != nil {
			gateAnalysis := pp.gateDetector.Analyze(&sm.Method)
			if gateAnalysis != nil && !gateAnalysis.IsRealGate {
				// SOFT PENALTY для остальных non-gates
				oldScore := point.RiskScore
				penalty := 0.90 // 90% penalty для non-data-class methods
				point.RiskScore *= (1 - penalty)
				point.RiskLevel = pp.classifyRisk(point.Category, point.RiskScore)
				for _, reason := range gateAnalysis.PenaltyReasons {
					point.WhyVulnerable = append(point.WhyVulnerable,
						fmt.Sprintf("WEAK GATE: %s (%.1f → %.1f)", reason, oldScore, point.RiskScore))
				}
			}
		}
	}
	if pp.config.EnableGateDetection && preserveFromGateFilter {
		point.WhyVulnerable = append(point.WhyVulnerable, "FILTER RESCUE: "+preserveReason)
	}
	// ═══════════════════════════════════════════════════════════════════════════════

	// ═══════════════════════════════════════════════════════════════════════════════
	// 🔥 PHASE 4: Decoy detection + Vulnerability signals
	//
	//   • Decoy — метод который «выглядит» защитой но НЕ защищает.
	//     При обнаружении: PatchValue уменьшается до 5%, moved to LowRisk tier.
	//   • VulnSignals — признаки malware (C2, SMS, overlay, native loader...).
	//     При IsMalwareSuspect=true: точка уходит в MalwareIndicators bucket.
	// ═══════════════════════════════════════════════════════════════════════════════
	if pp.config.EnableDecoyDetection {
		point.Decoy = AnalyzeDecoy(&sm.Method)
		if point.Decoy != nil && point.Decoy.IsDecoy {
			// Штраф к PatchValue: decoy имеет ~нулевую ценность для патча
			if point.PatchValue != nil {
				oldPV := point.PatchValue.Value
				point.PatchValue.Value *= point.Decoy.DecoyPenaltyMultiplier()
				point.PatchValue.DecoyPenalty = true
				point.WhyVulnerable = append(point.WhyVulnerable,
					fmt.Sprintf("DECOY: %s (PatchValue %.2f → %.2f)",
						point.Decoy.PrimaryReason, oldPV, point.PatchValue.Value))
			}
			if decoyConstantReturn(point.Decoy) && point.SuggestedPatch != "" {
				point.WhyVulnerable = append(point.WhyVulnerable,
					fmt.Sprintf("DECOY: already returns a constant; cleared suggested patch %s", point.SuggestedPatch))
				point.SuggestedPatch = ""
			}
		}
	}

	if pp.config.EnableVulnSignals {
		if point.VulnSignals == nil {
			point.VulnSignals = AnalyzeVulnerabilitySignals(&sm.Method)
		}
		if point.VulnSignals != nil && point.VulnSignals.HasAny() {
			point.WhyVulnerable = append(point.WhyVulnerable, point.VulnSignals.Explain()...)
		}
	}
	// ═══════════════════════════════════════════════════════════════════════════════

	if tmpl, ok := GetPatchTemplate(point.SuggestedPatch); ok {
		point.PatchDesc = tmpl.Description
	}

	// 💥 ФИНАЛЬНАЯ КАЛИБРОВКА: confidence пересчитывается ПОСЛЕ всех сигналов
	// (ensemble/entry-point/interesting/DFG/structural/crack-point/decoy/vuln).
	// ScoreBatch считает её слишком рано; здесь — единое финальное решение.
	pp.scorer.FinalizeConfidence(&point, sm)
	applyRecommendationAssessment(&point, &sm.Method)

	return point
}

func shouldPreserveFromGateFilter(point *PatchPoint, mi *MethodInfo) (bool, string) {
	if point == nil || mi == nil {
		return false, ""
	}
	if isResourceValueMethod(mi) { return true, "resource return is linked to state; branching is not required" }
	if isEconomyTransactionMethod(mi) { return true, "resource transaction is linked to state; branching is not required" }
	if point.VulnSignals != nil && point.VulnSignals.HasAny() {
		return true, "confirmed vulnerability signal overrides heuristic gate filter"
	}
	if point.CrackPointConfirmed {
		return true, "CFG crack-point overrides heuristic gate filter"
	}
	if point.Structural != nil && point.Structural.HardGateCount > 0 {
		return true, "path-sensitive hard gate overrides name-based filter"
	}
	if mi.HasSecurityAPI && point.Confidence >= 0.75 {
		return true, "high-confidence security API evidence overrides name-based filter"
	}
	return false, ""
}

// ═══════════════════════════════════════════════════════════════════════════════
// 🆕 MAIN FINDINGS / TOP ISSUES
// ═══════════════════════════════════════════════════════════════════════════════

func (pp *PatchPredictor) buildMainFindings(p *PatchPrediction) []string {
	findings := make([]string, 0, 5)
	seen := make(map[string]bool)

	addFinding := func(msg string) bool {
		if msg == "" || seen[msg] {
			return len(findings) >= 5
		}
		seen[msg] = true
		findings = append(findings, msg)
		return len(findings) >= 5
	}

	for i := range p.MalwareIndicators {
		pt := &p.MalwareIndicators[i]
		if pt.VulnSignals == nil {
			continue
		}
		for _, signal := range pt.VulnSignals.Signals {
			if addFinding(auditMainFindingText(signal.Kind)) {
				return findings
			}
		}
	}
	for i := range p.AuditFindings {
		pt := &p.AuditFindings[i]
		if pt.VulnSignals == nil {
			continue
		}
		for _, signal := range pt.VulnSignals.Signals {
			if addFinding(auditMainFindingText(signal.Kind)) {
				return findings
			}
		}
	}

	for _, pt := range p.HighRisk {
		var msg string
		switch pt.Category {
		case PatchCatLicense:
			msg = "License checks present (potentially bypassable)"
		case PatchCatBilling:
			msg = "Signature/purchase verification logic detected"
		case PatchCatPremium:
			msg = "Premium/entitlement gating detected"
		case PatchCatSubscription:
			msg = "Subscription validation detected"
		case PatchCatTamper:
			msg = "Tamper/integrity detection present"
		case PatchCatAds:
			msg = "Ad-control logic detected"
		case PatchCatFeatureGate:
			msg = "Feature-flag gating detected"
		case PatchCatInstaller:
			msg = "Installer-source verification present"
		case PatchCatServerAuth:
			msg = "Server authentication/token validation detected"
		case PatchCatDRM:
			msg = "DRM/content protection detected"
		case PatchCatCurrency:
			msg = "In-game currency/economy system detected"
		default:
			msg = fmt.Sprintf("%s logic detected", pt.CategoryName)
		}
		if addFinding(msg) {
			break
		}
	}
	return findings
}

func auditMainFindingText(kind VulnKind) string {
	switch kind {
	case VulnHardcodedSecret:
		return "Hardcoded secrets/API keys detected"
	case VulnInsecureTransport:
		return "Cleartext HTTP API/auth endpoint detected"
	case VulnDebugBackend:
		return "Debug/staging backend endpoint references detected"
	case VulnEndpointOverride:
		return "Runtime-configurable backend endpoint detected"
	case VulnClientAccountTrust:
		return "Client-side registration/auth state trust detected"
	case VulnWebViewBridge:
		return "WebView JavaScript bridge exposure detected"
	case VulnWeakJWTHandling:
		return "Weak JWT/token handling indicators detected"
	case VulnHTTPSCertBypass:
		return "TLS certificate validation bypass detected"
	case VulnDynamicCodeLoading:
		return "Dynamic code loading detected"
	case VulnRuntimeExec, VulnRootCommandExec:
		return "Runtime command execution detected"
	case VulnSMSInterception:
		return "SMS interception/sending APIs detected"
	case VulnOverlayAttack:
		return "Overlay attack pattern detected"
	case VulnAccessibilityAbuse:
		return "Accessibility abuse pattern detected"
	default:
		return "Security audit indicators detected"
	}
}

func (pp *PatchPredictor) buildTopIssues(p *PatchPrediction) []string {
	type issue struct {
		text  string
		score float64 // PHASE 3: ранжируем по PatchValue, fallback на RiskScore/10
	}
	collected := make([]issue, 0)
	seen := make(map[string]bool)

	add := func(pt PatchPoint) {
		key := string(pt.Category) + ":" + patchLookupKey(pt.FilePath, pt.MethodName, pt.MethodSignature)
		if seen[key] {
			return
		}
		seen[key] = true
		collected = append(collected, issue{
			text:  fmt.Sprintf("%s — %s()", pt.CategoryName, pt.MethodName),
			score: patchValueOrFallback(&pt),
		})
	}

	for _, pt := range p.HighRisk {
		add(pt)
	}
	for _, pt := range p.MediumRisk {
		add(pt)
	}

	sort.Slice(collected, func(i, j int) bool {
		return collected[i].score > collected[j].score
	})

	max := 3
	if len(collected) < max {
		max = len(collected)
	}
	out := make([]string, 0, max)
	for i := 0; i < max; i++ {
		out = append(out, collected[i].text)
	}
	return out
}

// ═══════════════════════════════════════════════════════════════════════════════
// USER FEEDBACK
// ═══════════════════════════════════════════════════════════════════════════════

func (pp *PatchPredictor) applyUserFeedback(scored []ScoredMethod) []ScoredMethod {
	if pp.history == nil || pp.history.Len() == 0 {
		return scored
	}

	noisePatterns := make([]string, 0)
	relevantPatterns := make([]string, 0)

	for _, override := range ResolveUserOverrides(pp.history.Snapshot()) {
		pattern := UserOverrideTarget(override)
		switch override.Action {
		case FeedbackNoise:
			noisePatterns = append(noisePatterns, pattern)
		case FeedbackRelevant:
			relevantPatterns = append(relevantPatterns, pattern)
		}
	}

	if len(noisePatterns) == 0 && len(relevantPatterns) == 0 {
		return scored
	}

	filtered := make([]ScoredMethod, 0, len(scored))
	for _, sm := range scored {
		if pp.matchesAnyPattern(sm, noisePatterns) {
			continue
		}
		if pp.matchesAnyPattern(sm, relevantPatterns) {
			sm.Score.FinalScore = minFloat(100.0, sm.Score.FinalScore*1.2)
			sm.Score.Confidence = minFloat(1.0, sm.Score.Confidence*1.1)
		}
		filtered = append(filtered, sm)
	}
	return filtered
}

func (pp *PatchPredictor) matchesAnyPattern(sm ScoredMethod, patterns []string) bool {
	for _, pattern := range patterns {
		pattern = NormalizeFeedbackTarget(pattern)
		pattern = strings.TrimSuffix(pattern, "/.*")
		if pattern == "" {
			continue
		}
		if strings.Contains(NormalizeFeedbackTarget(sm.ClassPath), pattern) ||
			strings.Contains(NormalizeFeedbackTarget(sm.ClassName), pattern) ||
			strings.Contains(NormalizeFeedbackTarget(sm.Method.Name), pattern) {
			return true
		}
		for _, part := range sm.Score.MatchedParts {
			if strings.Contains(NormalizeFeedbackTarget(part), pattern) {
				return true
			}
		}
	}
	return false
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// ═══════════════════════════════════════════════════════════════════════════════
// DEDUP / TOP CATEGORIES / EMPTY
// ═══════════════════════════════════════════════════════════════════════════════

func (pp *PatchPredictor) deduplicateResults(scored []ScoredMethod) []ScoredMethod {
	seen := make(map[string]int)
	result := make([]ScoredMethod, 0, len(scored))

	for _, sm := range scored {
		key := patchLookupKey(sm.Method.FilePath, sm.Method.Name, sm.Method.FullSignature)
		if existingIdx, exists := seen[key]; exists {
			if betterScoredMethod(&sm, &result[existingIdx]) {
				result[existingIdx] = sm
			}
		} else {
			seen[key] = len(result)
			result = append(result, sm)
		}
	}
	return result
}

func (pp *PatchPredictor) buildTopCategories(byCategory map[string]int) []CategoryCount {
	counts := make([]CategoryCount, 0, len(byCategory))
	for catStr, count := range byCategory {
		cat := PatchCategory(catStr)
		name := catStr
		if info, ok := GetCategoryInfo(cat); ok {
			name = info.Name
		}
		counts = append(counts, CategoryCount{Category: cat, Name: name, Count: count})
	}
	sort.Slice(counts, func(i, j int) bool {
		if counts[i].Count != counts[j].Count {
			return counts[i].Count > counts[j].Count
		}
		return counts[i].Category < counts[j].Category
	})
	if len(counts) > 5 {
		counts = counts[:5]
	}
	return counts
}

func (pp *PatchPredictor) emptyPrediction() *PatchPrediction {
	return &PatchPrediction{
		HighRisk:          make([]PatchPoint, 0),
		MediumRisk:        make([]PatchPoint, 0),
		LowRisk:           make([]PatchPoint, 0),
		LibraryFindings:   make([]PatchPoint, 0),
		MalwareIndicators: make([]PatchPoint, 0),
		AuditFindings:     make([]PatchPoint, 0),
		Mode:              pp.config.Mode,
		Stats:             PredictionStats{ByCategory: make(map[string]int)},
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// TERMINAL RENDER (с MAIN FINDINGS, LIBRARY секцией, безопасными формулировками)
// ═══════════════════════════════════════════════════════════════════════════════



func isExpressionExportGetterNoise(methodName string) bool {
	name := strings.ToLower(strings.TrimSpace(methodName))
	if !strings.HasPrefix(name, "exp") {
		return false
	}
	// Fusion/Clickteam expression exports are value getters, not security gates.
	return true
}
func isSDKOrFrameworkMethod(mi *MethodInfo, classPath, className string) bool {
	if mi == nil {
		return false
	}
	ctx := strings.ToLower(classPath + " " + className + " " + mi.FilePath + " " + mi.ClassName + " " + mi.Name)
	if strings.Contains(ctx, "extensions/iabillingmanager") || strings.Contains(ctx, "extensions/cruninappandroid") {
		name := strings.ToLower(mi.Name)
		if strings.HasPrefix(name, "exp") {
			return true
		}
		return false
	}
	if strings.Contains(ctx, "util/security") {
		return false
	}
	sdkPrefixes := []string{
		"com/android/billingclient/api/",
		"com/google/android/gms/internal/play_billing/",
		"com/android/vending/expansion/zipfile/",
		"com/google/android/play/core/",
		"com/badlogic/gdx/",
		"com/pairip/",
	}
	for _, prefix := range sdkPrefixes {
		if strings.Contains(ctx, prefix) {
			return true
		}
	}
	return strings.Contains(ctx, "api/billingclientimpl") ||
		strings.Contains(ctx, "api/purchase") ||
		strings.Contains(ctx, "api/billingflowparams") ||
		strings.Contains(ctx, "zipfile/zipresourcefile")
}

func isSDKOrFrameworkPatchNoise(p *PatchPoint) bool {
	if p == nil {
		return false
	}
	return isSDKOrFrameworkMethod(&MethodInfo{Name: p.MethodName, FilePath: p.FilePath, ClassName: p.ClassName}, p.FilePath, p.ClassName)
}
