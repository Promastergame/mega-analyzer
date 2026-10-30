package labkit

import (
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"
)

// Level is a logging severity. Lower values are more verbose.
type Level int32

// Logging levels, ordered from most to least verbose.
const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

// String returns the lowercase name of the level.
func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "debug"
	case LevelInfo:
		return "info"
	case LevelWarn:
		return "warn"
	case LevelError:
		return "error"
	default:
		return "info"
	}
}

// ParseLevel maps a case-insensitive name to a Level, defaulting to LevelInfo
// for anything unrecognised.
func ParseLevel(s string) Level {
	switch s {
	case "debug", "DEBUG", "Debug":
		return LevelDebug
	case "warn", "WARN", "Warn", "warning", "WARNING":
		return LevelWarn
	case "error", "ERROR", "Error":
		return LevelError
	default:
		return LevelInfo
	}
}

// Fields is a set of structured key/value pairs attached to a log line.
type Fields map[string]any

// Logger is a minimal structured logger that emits one JSON object per line.
// It is safe for concurrent use: writes are serialised by a mutex so lines
// never interleave. A zero Logger is not usable; construct one with NewLogger.
type Logger struct {
	mu    sync.Mutex
	w     io.Writer
	min   Level
	base  Fields
	nowFn func() time.Time
	enc   *json.Encoder
}

// NewLogger returns a Logger writing to w. Lines below min are dropped. If w
// is nil it defaults to os.Stderr.
func NewLogger(w io.Writer, min Level) *Logger {
	if w == nil {
		w = os.Stderr
	}
	return &Logger{
		w:     w,
		min:   min,
		nowFn: time.Now,
		enc:   json.NewEncoder(w),
	}
}

// With returns a child logger that includes the given fields on every line.
// The parent is left unchanged, so a base logger can be shared and specialised
// per component without data races.
func (l *Logger) With(f Fields) *Logger {
	child := &Logger{w: l.w, min: l.min, nowFn: l.nowFn, enc: l.enc}
	merged := make(Fields, len(l.base)+len(f))
	for k, v := range l.base {
		merged[k] = v
	}
	for k, v := range f {
		merged[k] = v
	}
	child.base = merged
	return child
}

// SetLevel adjusts the minimum level at runtime.
func (l *Logger) SetLevel(min Level) {
	l.mu.Lock()
	l.min = min
	l.mu.Unlock()
}

func (l *Logger) log(level Level, msg string, f Fields) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if level < l.min {
		return
	}
	line := make(map[string]any, len(l.base)+len(f)+3)
	line["ts"] = l.nowFn().UTC().Format(time.RFC3339Nano)
	line["level"] = level.String()
	line["msg"] = msg
	for k, v := range l.base {
		line[k] = v
	}
	for k, v := range f {
		line[k] = v
	}
	// Encoder errors (e.g. a closed pipe) are intentionally ignored: logging
	// must never take down a test server.
	_ = l.enc.Encode(line)
}

// Debug logs at LevelDebug.
func (l *Logger) Debug(msg string, f Fields) { l.log(LevelDebug, msg, f) }

// Info logs at LevelInfo.
func (l *Logger) Info(msg string, f Fields) { l.log(LevelInfo, msg, f) }

// Warn logs at LevelWarn.
func (l *Logger) Warn(msg string, f Fields) { l.log(LevelWarn, msg, f) }

// Error logs at LevelError.
func (l *Logger) Error(msg string, f Fields) { l.log(LevelError, msg, f) }
