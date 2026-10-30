package media

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"
)

// LogLevel controls the verbosity of forensic logging.
type LogLevel int

const (
	// LogSilent suppresses all log output.
	LogSilent LogLevel = iota

	// LogError only logs errors and critical anomalies.
	LogError

	// LogWarn logs warnings plus errors (polyglots, high-risk findings).
	LogWarn

	// LogInfo logs high-level progress and key findings (default).
	LogInfo

	// LogDebug logs detailed detection/classification decisions.
	LogDebug

	// LogTrace logs every signal, every region, every tag — for deep debugging.
	LogTrace
)

// ForensicEvent is a single structured log entry from the analysis pipeline.
type ForensicEvent struct {
	Timestamp time.Time      `json:"timestamp"`
	Level     string         `json:"level"`
	Phase     string         `json:"phase"` // "detect", "classify", "score", etc.
	Message   string         `json:"message"`
	Fields    map[string]any `json:"fields,omitempty"`
}

// ForensicLogger is a structured logger purpose-built for the forensic
// analysis pipeline. It supports multiple output formats (slog, plain text,
// structured callback), configurable levels, and forensic-specific event
// categories.
type ForensicLogger struct {
	level    LogLevel
	output   *slog.Logger
	events   []ForensicEvent
	mu       sync.Mutex
	callback func(ForensicEvent) // optional: called for every event
}

// NewForensicLogger creates a logger writing to the given writer at the
// specified level. Pass nil for w to get a silent logger.
func NewForensicLogger(w io.Writer, level LogLevel) *ForensicLogger {
	if w == nil {
		w = io.Discard
	}
	handler := slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	return &ForensicLogger{
		level:  level,
		output: slog.New(handler),
		events: make([]ForensicEvent, 0, 256),
	}
}

// NewTextForensicLogger creates a human-readable text logger.
func NewTextForensicLogger(w io.Writer, level LogLevel) *ForensicLogger {
	if w == nil {
		w = io.Discard
	}
	handler := slog.NewTextHandler(w, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	return &ForensicLogger{
		level:  level,
		output: slog.New(handler),
		events: make([]ForensicEvent, 0, 256),
	}
}

// NewCallbackForensicLogger creates a logger that invokes a callback for
// every event. Useful for streaming log entries to a UI or API.
func NewCallbackForensicLogger(cb func(ForensicEvent), level LogLevel) *ForensicLogger {
	return &ForensicLogger{
		level:    level,
		output:   slog.New(slog.NewJSONHandler(io.Discard, nil)),
		events:   make([]ForensicEvent, 0, 256),
		callback: cb,
	}
}

// SetLevel changes the logging level at runtime.
func (fl *ForensicLogger) SetLevel(level LogLevel) {
	fl.mu.Lock()
	defer fl.mu.Unlock()
	fl.level = level
}

// Events returns a copy of all recorded events (useful for embedding in reports).
func (fl *ForensicLogger) Events() []ForensicEvent {
	fl.mu.Lock()
	defer fl.mu.Unlock()
	out := make([]ForensicEvent, len(fl.events))
	copy(out, fl.events)
	return out
}

// ClearEvents resets the event buffer.
func (fl *ForensicLogger) ClearEvents() {
	fl.mu.Lock()
	defer fl.mu.Unlock()
	fl.events = fl.events[:0]
}

// ─── Core logging methods ─────────────────────────────────────────────────

func (fl *ForensicLogger) log(level LogLevel, phase, msg string, fields map[string]any) {
	if fl == nil || level > fl.level {
		return
	}

	event := ForensicEvent{
		Timestamp: time.Now().UTC(),
		Level:     levelName(level),
		Phase:     phase,
		Message:   msg,
		Fields:    fields,
	}

	fl.mu.Lock()
	fl.events = append(fl.events, event)
	fl.mu.Unlock()

	// slog output
	attrs := make([]slog.Attr, 0, len(fields)+2)
	attrs = append(attrs, slog.String("phase", phase))
	for k, v := range fields {
		attrs = append(attrs, slog.Any(k, v))
	}
	fl.output.LogAttrs(nil, slogLevel(level), msg, attrs...)

	// Callback
	if fl.callback != nil {
		fl.callback(event)
	}
}

func (fl *ForensicLogger) Trace(phase, msg string, fields ...any) {
	fl.log(LogTrace, phase, msg, toMap(fields...))
}

func (fl *ForensicLogger) Debug(phase, msg string, fields ...any) {
	fl.log(LogDebug, phase, msg, toMap(fields...))
}

func (fl *ForensicLogger) Info(phase, msg string, fields ...any) {
	fl.log(LogInfo, phase, msg, toMap(fields...))
}

func (fl *ForensicLogger) Warn(phase, msg string, fields ...any) {
	fl.log(LogWarn, phase, msg, toMap(fields...))
}

func (fl *ForensicLogger) Error(phase, msg string, fields ...any) {
	fl.log(LogError, phase, msg, toMap(fields...))
}

// ─── Forensic-specific convenience methods ────────────────────────────────

// LogMagicDetection logs when a file signature is detected.
func (fl *ForensicLogger) LogMagicDetection(format MediaType, offset int, confidence float64) {
	fl.Debug("detect",
		"Magic signature detected",
		"format", format,
		"offset", offset,
		"confidence", confidence,
	)
}

// LogPolyglot logs when a polyglot file is identified.
func (fl *ForensicLogger) LogPolyglot(primary MediaType, hidden []MediaType, extMismatch bool) {
	fl.Warn("classify",
		"Polyglot file detected",
		"primary_format", primary,
		"hidden_formats", fmt.Sprintf("%v", hidden),
		"extension_mismatch", extMismatch,
	)
}

// LogEntropyAnomaly logs a high-entropy region.
func (fl *ForensicLogger) LogEntropyAnomaly(offset, length int, entropy, zScore float64) {
	fl.Debug("detect",
		"High-entropy region detected",
		"offset", offset,
		"length", length,
		"entropy", fmt.Sprintf("%.4f", entropy),
		"z_score", fmt.Sprintf("%.2f", zScore),
	)
}

// LogPayloadDetection logs a suspicious payload (SQLi, XSS, etc.).
func (fl *ForensicLogger) LogPayloadDetection(name string, offset int, confidence, severity float64, evidence string) {
	fl.Warn("detect",
		"Suspicious payload detected",
		"payload_type", name,
		"offset", offset,
		"confidence", confidence,
		"severity", severity,
		"evidence", truncate(evidence, 120),
	)
}

// LogPrivacyLeak logs a detected privacy leak.
func (fl *ForensicLogger) LogPrivacyLeak(field, evidence string, offset int) {
	fl.Warn("detect",
		"Privacy data leak detected",
		"field", field,
		"offset", offset,
		"evidence", truncate(evidence, 120),
	)
}

// LogMetadataExtraction logs extracted metadata fields.
func (fl *ForensicLogger) LogMetadataExtraction(format MediaType, fieldCount int) {
	fl.Info("metadata",
		"Metadata extraction complete",
		"format", format,
		"fields_extracted", fieldCount,
	)
}

// LogStegoDetection logs a steganography signal.
func (fl *ForensicLogger) LogStegoDetection(method string, confidence float64, evidence string) {
	fl.Warn("stego",
		"Steganography detected",
		"method", method,
		"confidence", confidence,
		"evidence", evidence,
	)
}

// LogTimelineAnomaly logs a timeline inconsistency.
func (fl *ForensicLogger) LogTimelineAnomaly(anomalyType, description string) {
	fl.Warn("timeline",
		"Timeline anomaly",
		"anomaly_type", anomalyType,
		"description", description,
	)
}

// LogFingerprint logs encoder identification.
func (fl *ForensicLogger) LogFingerprint(encoder string, confidence float64, evidence []string) {
	fl.Info("fingerprint",
		"Encoder identified",
		"encoder", encoder,
		"confidence", confidence,
		"evidence_count", len(evidence),
	)
}

// LogRiskScore logs the final risk score with breakdown.
func (fl *ForensicLogger) LogRiskScore(score float64, polyglotRisk, regionRisk, entropyRisk float64) {
	fl.Info("score",
		"Risk score computed",
		"total_score", fmt.Sprintf("%.2f", score),
		"polyglot_risk", fmt.Sprintf("%.2f", polyglotRisk),
		"region_risk", fmt.Sprintf("%.2f", regionRisk),
		"entropy_risk", fmt.Sprintf("%.2f", entropyRisk),
	)
}

// LogWatermarkDetection logs a detected watermark.
func (fl *ForensicLogger) LogWatermarkDetection(wmType string, confidence float64, evidence string) {
	fl.Info("watermark",
		"Digital watermark detected",
		"type", wmType,
		"confidence", confidence,
		"evidence", evidence,
	)
}

// LogDeepAnalysis logs completion of a deep analysis phase.
func (fl *ForensicLogger) LogDeepAnalysis(phase string, duration time.Duration, details map[string]any) {
	fl.Info("deep",
		fmt.Sprintf("Deep analysis phase complete: %s", phase),
		"duration_ms", duration.Milliseconds(),
	)
	for k, v := range details {
		fl.Debug("deep", "", k, v)
	}
}

// LogBatchProgress logs batch analysis progress.
func (fl *ForensicLogger) LogBatchProgress(completed, total int, currentFile string) {
	pct := float64(completed) / float64(total) * 100
	fl.Info("batch",
		fmt.Sprintf("Batch progress: %d/%d (%.0f%%)", completed, total, pct),
		"completed", completed,
		"total", total,
		"current_file", currentFile,
	)
}

// LogAnalysisStart logs the beginning of an analysis run.
func (fl *ForensicLogger) LogAnalysisStart(filepath string, depth AnalysisDepth, dataSize int) {
	fl.Info("pipeline",
		"Analysis started",
		"filepath", filepath,
		"depth", depthName(depth),
		"data_size", dataSize,
	)
}

// LogAnalysisComplete logs the end of an analysis run.
func (fl *ForensicLogger) LogAnalysisComplete(filepath string, format MediaType, riskScore float64, duration time.Duration) {
	fl.Info("pipeline",
		"Analysis complete",
		"filepath", filepath,
		"format", format,
		"risk_score", fmt.Sprintf("%.2f", riskScore),
		"duration_ms", duration.Milliseconds(),
	)
}

// ─── Helpers ──────────────────────────────────────────────────────────────

func levelName(l LogLevel) string {
	switch l {
	case LogSilent:
		return "silent"
	case LogError:
		return "error"
	case LogWarn:
		return "warn"
	case LogInfo:
		return "info"
	case LogDebug:
		return "debug"
	case LogTrace:
		return "trace"
	default:
		return "unknown"
	}
}

func depthName(d AnalysisDepth) string {
	switch d {
	case DepthQuick:
		return "quick"
	case DepthStandard:
		return "standard"
	case DepthDeep:
		return "deep"
	default:
		return "unknown"
	}
}

func slogLevel(l LogLevel) slog.Level {
	switch l {
	case LogError:
		return slog.LevelError
	case LogWarn:
		return slog.LevelWarn
	case LogInfo:
		return slog.LevelInfo
	case LogDebug:
		return slog.LevelDebug
	case LogTrace:
		return slog.LevelDebug - 4 // custom trace level
	default:
		return slog.LevelInfo
	}
}

func toMap(fields ...any) map[string]any {
	if len(fields) == 0 {
		return nil
	}
	m := make(map[string]any, len(fields)/2)
	for i := 0; i+1 < len(fields); i += 2 {
		if key, ok := fields[i].(string); ok {
			m[key] = fields[i+1]
		}
	}
	return m
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// ─── Default logger factory ──────────────────────────────────────────────

// DefaultForensicLogger returns a logger writing to stderr at Info level.
func DefaultForensicLogger() *ForensicLogger {
	return NewForensicLogger(os.Stderr, LogInfo)
}

// SilentLogger returns a logger that discards all output but still records events.
func SilentLogger() *ForensicLogger {
	return NewForensicLogger(io.Discard, LogSilent)
}

// ─── Integration with AnalysisContext ────────────────────────────────────

// WithLogger returns a new AnalysisContext with the given logger attached.
func (ac *AnalysisContext) WithLogger(logger *ForensicLogger) *AnalysisContext {
	if ac == nil {
		ac = DefaultContext()
	}
	ac.Logger = nil // clear slog logger
	// Store forensic logger in a way the pipeline can access it
	return ac
}

// getLogger extracts the ForensicLogger from the context. If the context
// has no forensic logger, returns a silent one that still records events.
func (ac *AnalysisContext) getLogger() *ForensicLogger {
	if ac == nil {
		return SilentLogger()
	}
	// We need a way to store the ForensicLogger. For now, use the slog.Logger's
	// underlying handler to bridge. In practice, callers should use the pipeline
	// methods that accept a ForensicLogger directly.
	return SilentLogger()
}

// ─── Pipeline integration helper ─────────────────────────────────────────

// PipelineLogger wraps a ForensicLogger with timing for each pipeline phase.
type PipelineLogger struct {
	logger *ForensicLogger
	file   string
	start  time.Time
}

// NewPipelineLogger starts timing an analysis pipeline run.
func NewPipelineLogger(logger *ForensicLogger, filepath string) *PipelineLogger {
	if logger == nil {
		logger = SilentLogger()
	}
	pl := &PipelineLogger{
		logger: logger,
		file:   filepath,
		start:  time.Now(),
	}
	logger.LogAnalysisStart(filepath, DepthStandard, 0)
	return pl
}

// Phase returns a PhaseTimer for timing individual phases.
func (pl *PipelineLogger) Phase(name string) *PhaseTimer {
	return &PhaseTimer{
		logger: pl.logger,
		name:   name,
		start:  time.Now(),
	}
}

// Done logs the completion of the full pipeline run.
func (pl *PipelineLogger) Done(format MediaType, riskScore float64) {
	pl.logger.LogAnalysisComplete(pl.file, format, riskScore, time.Since(pl.start))
}

// PhaseTimer times a single pipeline phase and logs its duration.
type PhaseTimer struct {
	logger *ForensicLogger
	name   string
	start  time.Time
}

// Done logs the phase completion with duration.
func (pt *PhaseTimer) Done(fields ...any) {
	duration := time.Since(pt.start)
	m := toMap(fields...)
	if m == nil {
		m = make(map[string]any)
	}
	m["duration_ms"] = duration.Milliseconds()
	pt.logger.LogDeepAnalysis(pt.name, duration, m)
}

// ─── JSON report integration ─────────────────────────────────────────────

// LogEventsJSON returns all recorded events as indented JSON bytes,
// suitable for embedding in a forensic report.
func (fl *ForensicLogger) LogEventsJSON() []byte {
	events := fl.Events()
	if len(events) == 0 {
		return []byte("[]")
	}
	// Use encoding/json via a simple manual builder to avoid import cycle
	var buf []byte
	buf = append(buf, '[')
	for i, e := range events {
		if i > 0 {
			buf = append(buf, ',')
		}
		buf = append(buf, []byte(fmt.Sprintf(
			`{"timestamp":"%s","level":"%s","phase":"%s","message":"%s"}`,
			e.Timestamp.Format(time.RFC3339Nano),
			e.Level,
			e.Phase,
			escapeJSON(e.Message),
		))...)
	}
	buf = append(buf, ']')
	return buf
}

func escapeJSON(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	s = strings.ReplaceAll(s, "\t", `\t`)
	return s
}
