package media

import (
	"context"
	"log/slog"
)

// AnalysisDepth controls how deep the forensic analysis goes.
type AnalysisDepth int

const (
	// DepthQuick performs magic byte detection, entropy analysis, and
	// payload scanning only. No metadata extraction, no EXIF parsing.
	DepthQuick AnalysisDepth = iota

	// DepthStandard adds metadata extraction (EXIF, XMP, PNG chunks),
	// classification, and scoring — the default analysis level.
	DepthStandard

	// DepthDeep enables all features: steganography detection, encoder
	// fingerprinting, entropy heatmap, timeline analysis, and full
	// generic EXIF tag dump.
	DepthDeep
)

// AnalysisContext carries configuration and callbacks through the
// forensic analysis pipeline. Every sub-detector and parser receives
// this context so it can respect depth gates, report progress, and
// check for cancellation.
type AnalysisContext struct {
	// Ctx is the cancellation context. Analyzers check this before
	// expensive operations (entropy scan, full EXIF walk) and abort
	// early if cancelled.
	Ctx context.Context

	// Progress is an optional callback invoked at phase boundaries
	// with a human-readable label and a 0.0–1.0 completion estimate.
	// May be nil.
	Progress func(phase string, pct float64)

	// Depth controls which analysis stages run.
	Depth AnalysisDepth

	// MaxMemory is an optional hard cap on bytes the analyzer will
	// allocate for decompression buffers, thumbnail extraction, and
	// similar operations. 0 means no limit beyond the per-feature caps
	// already in mediameta.go / pngchunks.go.
	MaxMemory int64

	// Logger is an optional structured logger. May be nil.
	// Prefer ForensicLogger for forensic-specific event logging.
	Logger *slog.Logger

	// ForensicLog is the forensic-specific structured logger. If nil,
	// a silent logger is used. Set via NewAnalysisContext or WithForensicLog.
	ForensicLog *ForensicLogger
}

// DefaultContext returns a background AnalysisContext at DepthStandard
// with a silent forensic logger (events are recorded but not printed).
func DefaultContext() *AnalysisContext {
	return &AnalysisContext{
		Ctx:         context.Background(),
		Depth:       DepthStandard,
		ForensicLog: SilentLogger(),
	}
}

// NewAnalysisContext creates a fully configured AnalysisContext.
func NewAnalysisContext(ctx context.Context, depth AnalysisDepth, logger *ForensicLogger) *AnalysisContext {
	if logger == nil {
		logger = SilentLogger()
	}
	return &AnalysisContext{
		Ctx:         ctx,
		Depth:       depth,
		ForensicLog: logger,
	}
}

// WithForensicLog returns a copy of the context with the given logger attached.
func (ac *AnalysisContext) WithForensicLog(logger *ForensicLogger) *AnalysisContext {
	if ac == nil {
		ac = DefaultContext()
	}
	ac.ForensicLog = logger
	return ac
}

// log returns the ForensicLogger, falling back to a silent logger.
func (ac *AnalysisContext) log() *ForensicLogger {
	if ac != nil && ac.ForensicLog != nil {
		return ac.ForensicLog
	}
	return SilentLogger()
}

// reportProgress calls the Progress callback if set and ctx is not done.
func (ac *AnalysisContext) reportProgress(phase string, pct float64) {
	if ac == nil || ac.Progress == nil {
		return
	}
	if ac.Ctx != nil {
		select {
		case <-ac.Ctx.Done():
			return
		default:
		}
	}
	ac.Progress(phase, pct)
}

// cancelled returns true if the context has been cancelled.
func (ac *AnalysisContext) cancelled() bool {
	if ac == nil || ac.Ctx == nil {
		return false
	}
	select {
	case <-ac.Ctx.Done():
		return true
	default:
		return false
	}
}
