package ml

import "time"

// ═══════════════════════════════════════════════════════════════════════════════
// BATCH PROCESSING OPTIMIZATION (Task 32 - Requirement 15)
//
// Optimizes batch analysis by:
// - Amortizing initialization costs across batches
// - Reusing compiled patterns and lookup structures
// - Efficient result collection with pre-allocated buffers
// ═══════════════════════════════════════════════════════════════════════════════

// BatchOptimizer optimizes analysis of multiple files
type BatchOptimizer struct {
	analyzer     *PatchAnalyzer
	patternIndex *PatternIndex
	resultBuffer []*EnhancedScore
	methodBuffer []*MethodInfo
	batchSize    int
}

// NewBatchOptimizer creates an optimized batch processor
func NewBatchOptimizer(batchSize int) *BatchOptimizer {
	if batchSize <= 0 {
		batchSize = 100 // default batch size
	}

	return &BatchOptimizer{
		analyzer:     NewPatchAnalyzer(),
		patternIndex: GetPatternIndex(),
		resultBuffer: make([]*EnhancedScore, 0, batchSize),
		methodBuffer: make([]*MethodInfo, 0, batchSize*10), // ~10 methods per file
		batchSize:    batchSize,
	}
}

// BatchAnalyzeOptimized performs optimized batch analysis
func (bo *BatchOptimizer) BatchAnalyzeOptimized(candidates []AnalysisCandidate) *OptimizedBatchResult {
	result := &OptimizedBatchResult{
		Results:    make([]*EnhancedScore, 0, len(candidates)*5),
		TotalFiles: len(candidates),
		StartTime:  getCurrentTime(),
	}

	// Reset buffers (reuse allocations)
	bo.resultBuffer = bo.resultBuffer[:0]
	bo.methodBuffer = bo.methodBuffer[:0]

	// Phase 1: Parse all files and extract methods (amortize parsing cost)
	for _, candidate := range candidates {
		if len(candidate.Content) == 0 {
			continue
		}

		classInfo := bo.analyzer.AnalyzeSmaliContent(candidate.FilePath, candidate.Content)
		if classInfo == nil {
			continue
		}

		result.TotalMethods += len(classInfo.Methods)

		// Filter and collect worth-analyzing methods
		for i := range classInfo.Methods {
			m := &classInfo.Methods[i]
			if bo.analyzer.IsWorthAnalyzing(m) {
				bo.methodBuffer = append(bo.methodBuffer, m)
				result.AnalyzedMethods++
			} else {
				result.SkippedMethods++
			}
		}
	}

	// Phase 2: Batch pattern matching (reuse pattern index)
	for _, method := range bo.methodBuffer {
		// Match patterns using shared pattern index
		matches := bo.analyzer.MatchVulnerablePatterns(method)

		if len(matches) == 0 {
			continue
		}

		// Calculate enhanced score
		score := CalculateEnhancedScore(method, matches)

		// Filter low-confidence results
		if score.Confidence >= 0.6 && score.FinalScore >= MinPatchScore {
			bo.resultBuffer = append(bo.resultBuffer, score)
		}
	}

	// Phase 3: Rank and collect results (efficient merging)
	result.Results = RankByConfidence(bo.resultBuffer)
	result.HighConfidenceCount = countHighConfidence(result.Results)
	result.EndTime = getCurrentTime()
	result.Duration = result.EndTime - result.StartTime

	return result
}

// OptimizedBatchResult contains batch analysis results
type OptimizedBatchResult struct {
	Results             []*EnhancedScore `json:"results"`
	TotalFiles          int              `json:"total_files"`
	TotalMethods        int              `json:"total_methods"`
	AnalyzedMethods     int              `json:"analyzed_methods"`
	SkippedMethods      int              `json:"skipped_methods"`
	HighConfidenceCount int              `json:"high_confidence_count"`
	StartTime           int64            `json:"start_time"`
	EndTime             int64            `json:"end_time"`
	Duration            int64            `json:"duration_ms"`
}

// GetPerFileOverhead calculates per-file overhead
func (r *OptimizedBatchResult) GetPerFileOverhead() float64 {
	if r.TotalFiles == 0 {
		return 0
	}
	return float64(r.Duration) / float64(r.TotalFiles)
}

// GetThroughput calculates methods analyzed per second
func (r *OptimizedBatchResult) GetThroughput() float64 {
	if r.Duration == 0 {
		return 0
	}
	return float64(r.AnalyzedMethods) * 1000.0 / float64(r.Duration)
}

// countHighConfidence counts results with confidence >= 0.6
func countHighConfidence(results []*EnhancedScore) int {
	count := 0
	for _, r := range results {
		if r.IsHighConfidence {
			count++
		}
	}
	return count
}

// getCurrentTime returns current time in milliseconds
func getCurrentTime() int64 {
	return time.Now().UnixMilli()
}

// ResetBuffers resets internal buffers for reuse
func (bo *BatchOptimizer) ResetBuffers() {
	bo.resultBuffer = bo.resultBuffer[:0]
	bo.methodBuffer = bo.methodBuffer[:0]
}

// GetStats returns batch optimizer statistics
func (bo *BatchOptimizer) GetStats() BatchOptimizerStats {
	return BatchOptimizerStats{
		BatchSize:       bo.batchSize,
		ResultBufferCap: cap(bo.resultBuffer),
		MethodBufferCap: cap(bo.methodBuffer),
		ResultBufferLen: len(bo.resultBuffer),
		MethodBufferLen: len(bo.methodBuffer),
	}
}

// BatchOptimizerStats contains optimizer statistics
type BatchOptimizerStats struct {
	BatchSize       int `json:"batch_size"`
	ResultBufferCap int `json:"result_buffer_cap"`
	MethodBufferCap int `json:"method_buffer_cap"`
	ResultBufferLen int `json:"result_buffer_len"`
	MethodBufferLen int `json:"method_buffer_len"`
}
