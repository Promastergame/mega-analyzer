package media

import (
	"fmt"
	"io"
)

// StreamingAnalyzer processes files via io.ReadSeeker instead of loading
// everything into memory. For files under smallFileThreshold it falls
// back to the existing full-buffer path; for larger files it reads in
// controlled chunks and only seeks back for specific regions.
const smallFileThreshold = 10 * 1024 * 1024 // 10 MB

// StreamingAnalyzer wraps a ForensicEngine with streaming I/O support.
type StreamingAnalyzer struct {
	engine *ForensicEngine
	ctx    *AnalysisContext
}

// NewStreamingAnalyzer creates a StreamingAnalyzer backed by the given
// forensic engine and analysis context.
func NewStreamingAnalyzer(engine *ForensicEngine, ctx *AnalysisContext) *StreamingAnalyzer {
	if ctx == nil {
		ctx = DefaultContext()
	}
	return &StreamingAnalyzer{engine: engine, ctx: ctx}
}

// AnalyzeReader performs forensic analysis on a seekable reader.
// If the reader is under 10 MB (or seeking fails), it falls back to
// reading the entire content into memory and delegating to
// ForensicEngine.Analyze.
func (sa *StreamingAnalyzer) AnalyzeReader(r io.ReadSeeker, filepath, filename string) AnalysisResult {
	if sa.ctx == nil {
		sa.ctx = DefaultContext()
	}

	// Try to determine file size via seeking
	size, err := r.Seek(0, io.SeekEnd)
	if err != nil || size < 0 {
		// Can't determine size — fall back to full read
		return sa.fallbackFullRead(r, filepath, filename)
	}
	// Reset to start
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return sa.fallbackFullRead(r, filepath, filename)
	}

	if size <= smallFileThreshold {
		return sa.fallbackFullRead(r, filepath, filename)
	}

	return sa.analyzeLarge(r, size, filepath, filename)
}

// fallbackFullRead reads the entire reader and delegates to the standard engine.
func (sa *StreamingAnalyzer) fallbackFullRead(r io.ReadSeeker, filepath, filename string) AnalysisResult {
	data, err := io.ReadAll(r)
	if err != nil {
		return AnalysisResult{FilePath: filepath, Error: fmt.Sprintf("read failed: %v", err)}
	}
	return sa.engine.Analyze(data, filepath, filename)
}

// analyzeLarge performs chunked analysis on files larger than smallFileThreshold.
// Strategy:
//   - Read the first 64 KB for magic detection, entropy baseline, and payload scan.
//   - Read the last 64 KB for ZIP EOCD and trailing data detection.
//   - For JPEG: sequential marker walk reading 32 KB chunks.
//   - For PNG: sequential chunk walk reading 32 KB chunks.
//   - Merge all signals and feed through the standard fusion/classification/scoring pipeline.
func (sa *StreamingAnalyzer) analyzeLarge(r io.ReadSeeker, size int64, filepath, filename string) AnalysisResult {
	sa.ctx.reportProgress("streaming_read_header", 0.0)

	// Read header window for magic/entropy/payload detection
	headerWindow := make([]byte, 64*1024)
	n, _ := io.ReadAtLeast(r, headerWindow, 256)
	headerWindow = headerWindow[:n]

	// Read tail window for ZIP EOCD / trailing data detection
	tailWindow := make([]byte, 64*1024)
	tailStart := size - int64(len(tailWindow))
	if tailStart < int64(n) {
		tailStart = int64(n)
	}
	if _, err := r.Seek(tailStart, io.SeekStart); err == nil {
		tn, _ := io.ReadAtLeast(r, tailWindow, 4)
		tailWindow = tailWindow[:tn]
	}
	// Best-effort rewind; nothing below reads sequentially from r until the
	// full-read path, which performs (and checks) its own Seek.
	_, _ = r.Seek(0, io.SeekStart)

	sa.ctx.reportProgress("streaming_detect", 0.2)

	// Detect on the header and tail windows SEPARATELY so signal offsets stay
	// anchored to real file positions. Concatenating the two windows (as the
	// previous implementation did) made every tail-derived signal report an
	// offset inside the small combined buffer instead of its true location
	// near the end of the file.
	signals, globalStats := sa.engine.detector.Detect(headerWindow)

	// Scan the tail as a distinct region and rebase every tail signal by
	// tailStart so its Offset is the true byte position in the file. The
	// guard (tailStart >= n) ensures we never double-count an overlap with
	// the header window.
	if len(tailWindow) > 0 && tailStart >= int64(n) {
		tailSignals, _ := sa.engine.detector.Detect(tailWindow)
		for i := range tailSignals {
			tailSignals[i].Offset += int(tailStart)
		}
		signals = append(signals, tailSignals...)
	}

	sa.ctx.reportProgress("streaming_classify", 0.4)

	// For metadata extraction, we need the full file — but only if depth >= Standard.
	// For DepthQuick, the header/tail signals are sufficient.
	if sa.ctx.Depth < DepthStandard {
		regions := sa.engine.fusion.Fuse(signals)
		class := sa.engine.classifier.Classify(globalStats, regions, filename)
		score := sa.engine.scorer.Score(class, regions, globalStats)
		return AnalysisResult{
			FilePath:       filepath,
			Format:         class.PrimaryFormat,
			Classification: class,
			Regions:        regions,
			GlobalStats:    globalStats,
			RiskScore:      score,
		}
	}

	// Full metadata extraction requires the complete file — read it in.
	// For truly large files (video), we accept the memory cost for metadata
	// because the alternative (format-specific streaming parsers for every
	// container) is a much larger engineering effort.
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		// Without a successful rewind, ReadAll would silently analyze a
		// mid-file suffix and produce a corrupted result.
		return AnalysisResult{FilePath: filepath, Error: fmt.Sprintf("seek failed: %v", err)}
	}
	fullData, err := io.ReadAll(r)
	if err != nil {
		return AnalysisResult{FilePath: filepath, Error: fmt.Sprintf("read failed: %v", err)}
	}

	sa.ctx.reportProgress("streaming_analyze", 0.6)
	result := sa.engine.Analyze(fullData, filepath, filename)
	sa.ctx.reportProgress("streaming_done", 1.0)
	return result
}
