// Package logger — zero-dependency, high-performance structured logger
// Features: sync.Pool buffers, atomic level, colored output, JSON format,
//
//	async writes, caller cache, ring buffer overflow protection
package logger

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// ═══════════════════════════════════════════════════════════════════════════════
// LEVELS
// ═══════════════════════════════════════════════════════════════════════════════

// Level определяет уровень логирования
type Level int32

const (
	TraceLevel Level = iota - 2 // -2 — ultra-detailed tracing (per-signal, per-tag)
	DebugLevel                  // -1 — developer-facing diagnostics
	InfoLevel                   //  0 — high-level progress / key findings
	WarnLevel                   //  1 — warnings, anomalies, recoverable issues
	ErrorLevel                  //  2 — hard failures
	FatalLevel                  //  3 — unrecoverable, calls os.Exit(1)
)

// levelNames — статический массив, O(1) lookup без switch
var levelNames = [6]string{"TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"}

// levelColors — ANSI коды для каждого уровня
var levelColors = [6]string{
	"\033[90mTRC\033[0m",   // Dim gray
	"\033[36mDBG\033[0m",   // Cyan
	"\033[32mINF\033[0m",   // Green
	"\033[33mWRN\033[0m",   // Yellow
	"\033[31mERR\033[0m",   // Red
	"\033[1;35mFTL\033[0m", // Bold Magenta
}

var levelColorTags = [6]string{
	"\033[90m",   // Dim gray
	"\033[36m",   // Cyan
	"\033[32m",   // Green
	"\033[33m",   // Yellow
	"\033[31m",   // Red
	"\033[1;35m", // Bold Magenta
}

func (l Level) idx() int {
	i := int(l) + 2 // TraceLevel=-2 → 0
	if i < 0 {
		return 0
	}
	if i > 5 {
		return 5
	}
	return i
}

func (l Level) String() string   { return levelNames[l.idx()] }
func (l Level) Color() string    { return levelColors[l.idx()] }
func (l Level) ColorTag() string { return levelColorTags[l.idx()] }

// ═══════════════════════════════════════════════════════════════════════════════
// CONFIG
// ═══════════════════════════════════════════════════════════════════════════════

// Config описывает конфигурацию логгера
type Config struct {
	Level          Level
	OutputPath     string // путь к файлу (опционально)
	JSONFormat     bool   // true = JSON, false = красивый консольный вывод
	AsyncWrites    bool   // асинхронная запись через канал
	AsyncBufLen    int    // размер буфера асинхронного канала (default 4096)
	NoColor        bool   // отключить ANSI-цвета (для CI/CD)
	CallerSkip     int    // дополнительный skip для caller (wrapper-ы)
	DisableConsole bool   // отключить вывод в консоль (stdout)

	// New fields:
	ExtraWriter  io.Writer                   // дополнительный io.Writer (для тестов, HTTP streaming, etc.)
	MaxFileSize  int64                       // макс. размер файла байтах перед ротацией (0 = без ограничений)
	MaxBackups   int                         // макс. количество backup файлов при ротации (default 3)
	Component    string                      // имя компонента/модуля для фильтрации (подставляется в With)
	ErrorHandler func(msg string, kvs []any) // custom handler для Fatal вместо os.Exit(1)
}

// ═══════════════════════════════════════════════════════════════════════════════
// CALLER CACHE — кэшируем caller по PC чтобы не вызывать runtime.Caller лишний раз
// ═══════════════════════════════════════════════════════════════════════════════

const callerCacheSize = 512 // должна быть степенью двойки

type callerEntry struct {
	pc  uintptr
	str string
}

// callerCache — простой массив-кэш с открытой адресацией
var callerCache [callerCacheSize]atomic.Value // хранит callerEntry

func getCachedCaller(skip int) string {
	pcs := [1]uintptr{}
	if runtime.Callers(skip+1, pcs[:]) == 0 {
		return ""
	}
	pc := pcs[0]

	idx := pc & (callerCacheSize - 1)
	if v := callerCache[idx].Load(); v != nil {
		if e, ok := v.(callerEntry); ok && e.pc == pc {
			return e.str
		}
	}

	frames := runtime.CallersFrames(pcs[:])
	f, _ := frames.Next()
	_, short := filepath.Split(f.File)
	s := short + ":" + strconv.Itoa(f.Line)

	callerCache[idx].Store(callerEntry{pc: pc, str: s})
	return s
}

// ═══════════════════════════════════════════════════════════════════════════════
// LOGGER
// ═══════════════════════════════════════════════════════════════════════════════

// Logger — основная структура
type Logger struct {
	level      atomic.Int32
	json       bool
	noColor    bool
	callerSkip int
	presetKVs  []any // поля, установленные через With()

	mu      sync.Mutex
	writers []io.Writer

	bufPool sync.Pool

	// async
	asyncCh   chan []byte
	asyncStop chan struct{}
	asyncWg   sync.WaitGroup

	// rotation
	fileWriter  *os.File
	filePath    string
	fileSize    int64
	maxFileSize int64
	maxBackups  int

	// error handler for Fatal
	errorHandler func(msg string, kvs []any)
}

// New создаёт новый Logger
func New(cfg Config) (*Logger, error) {
	l := &Logger{
		json:         cfg.JSONFormat,
		noColor:      cfg.NoColor,
		callerSkip:   cfg.CallerSkip,
		maxFileSize:  cfg.MaxFileSize,
		maxBackups:   cfg.MaxBackups,
		errorHandler: cfg.ErrorHandler,
		filePath:     cfg.OutputPath,
		bufPool: sync.Pool{
			New: func() any {
				return bytes.NewBuffer(make([]byte, 0, 512))
			},
		},
	}
	if l.maxBackups <= 0 {
		l.maxBackups = 3
	}
	l.level.Store(int32(cfg.Level))

	var writers []io.Writer
	if !cfg.DisableConsole {
		writers = append(writers, os.Stdout)
	}

	if cfg.ExtraWriter != nil {
		writers = append(writers, cfg.ExtraWriter)
	}

	if cfg.OutputPath != "" {
		dir := filepath.Dir(cfg.OutputPath)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("logger: create log dir: %w", err)
		}
		f, err := os.OpenFile(cfg.OutputPath,
			os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return nil, fmt.Errorf("logger: open log file: %w", err)
		}
		// Get current file size for rotation tracking
		if info, err := f.Stat(); err == nil {
			l.fileSize = info.Size()
		}
		l.fileWriter = f
		writers = append(writers, f)
	}

	l.writers = writers

	if cfg.AsyncWrites {
		bufLen := cfg.AsyncBufLen
		if bufLen <= 0 {
			bufLen = 4096
		}
		l.asyncCh = make(chan []byte, bufLen)
		l.asyncStop = make(chan struct{})
		l.asyncWg.Add(1)
		go l.asyncWorker()
	}

	// If a component name was given, prepend it as a preset field
	if cfg.Component != "" {
		l.presetKVs = append(l.presetKVs, "component", cfg.Component)
	}

	return l, nil
}

// Close завершает async-worker и освобождает ресурсы.
// Закрывает все файловые writer'ы — это важно на Windows, где
// открытый файл блокирует удаление вместе с родительской директорией
// (часто всплывает в `t.TempDir()` cleanup'ах).
func (l *Logger) Close() {
	if l.asyncCh != nil {
		close(l.asyncStop)
		l.asyncWg.Wait()
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	for _, w := range l.writers {
		if closer, ok := w.(io.Closer); ok {
			// stdout / stderr тоже реализуют Closer, но закрывать их
			// нельзя — отфильтровываем.
			if w == os.Stdout || w == os.Stderr {
				continue
			}
			_ = closer.Close()
		}
	}
	l.writers = nil
}

// asyncWorker читает из канала и пишет в writers
func (l *Logger) asyncWorker() {
	defer l.asyncWg.Done()
	for {
		select {
		case data, ok := <-l.asyncCh:
			if !ok {
				return
			}
			l.writeAll(data)
		case <-l.asyncStop:
			// drain
			for {
				select {
				case data := <-l.asyncCh:
					l.writeAll(data)
				default:
					return
				}
			}
		}
	}
}

// Enabled возвращает true если уровень разрешён
//
//go:inline
func (l *Logger) Enabled(level Level) bool {
	return l.level.Load() <= int32(level)
}

// SetLevel меняет уровень логирования атомарно
func (l *Logger) SetLevel(level Level) {
	l.level.Store(int32(level))
}

// GetLevel возвращает текущий уровень
func (l *Logger) GetLevel() Level {
	return Level(l.level.Load())
}

// With создаёт дочерний логгер с предустановленными полями
func (l *Logger) With(kvs ...any) *Logger {
	// Создаём обёртку, которая всегда добавляет kvs
	child := &Logger{
		json:       l.json,
		noColor:    l.noColor,
		callerSkip: l.callerSkip,
		writers:    l.writers,
		bufPool: sync.Pool{
			New: func() any {
				return bytes.NewBuffer(make([]byte, 0, 512))
			},
		},
	}
	child.level.Store(l.level.Load())
	// Сохраняем предустановленные поля через замыкание в переопределённый log
	// Для простоты — храним поля в slice
	child.presetKVs = append(child.presetKVs, kvs...)
	return child
}

// presetKVs — предустановленные ключи-значения (для With)
// Добавляем поле в структуру ниже через расширение.

// ─── log core ────────────────────────────────────────────────────────────────

func (l *Logger) log(level Level, msg string, kvs ...any) {
	if !l.Enabled(level) {
		return
	}

	buf := l.bufPool.Get().(*bytes.Buffer)
	buf.Reset()

	// Объединяем preset + caller kvs
	allKVs := kvs
	if len(l.presetKVs) > 0 {
		merged := make([]any, 0, len(l.presetKVs)+len(kvs))
		merged = append(merged, l.presetKVs...)
		merged = append(merged, kvs...)
		allKVs = merged
	}

	skip := 3 + l.callerSkip
	if l.json {
		l.formatJSON(buf, level, msg, skip, allKVs...)
	} else {
		l.formatConsole(buf, level, msg, skip, allKVs...)
	}

	// Копируем данные из пула ДО того как вернуть буфер
	if l.asyncCh != nil {
		data := make([]byte, buf.Len())
		copy(data, buf.Bytes())
		l.bufPool.Put(buf)

		// Non-blocking отправка — дропаем если канал переполнен
		select {
		case l.asyncCh <- data:
		default:
			// overflow — пишем синхронно чтобы не потерять критичные сообщения
			if level >= ErrorLevel {
				l.writeAll(data)
			}
		}
	} else {
		l.writeAll(buf.Bytes())
		l.bufPool.Put(buf)
	}

	if level == FatalLevel {
		if l.errorHandler != nil {
			l.errorHandler(msg, kvs)
		} else {
			os.Exit(1)
		}
	}
}

func (l *Logger) writeAll(data []byte) {
	l.mu.Lock()
	l.rotateIfNeeded(data)
	for _, w := range l.writers {
		_, _ = w.Write(data)
	}
	l.mu.Unlock()
}

// ═══════════════════════════════════════════════════════════════════════════════
// JSON FORMATTER
// ═══════════════════════════════════════════════════════════════════════════════

func (l *Logger) formatJSON(buf *bytes.Buffer, level Level, msg string, callerSkip int, kvs ...any) {
	buf.WriteByte('{')

	// time
	buf.WriteString(`"time":"`)
	buf.WriteString(time.Now().UTC().Format(time.RFC3339Nano))
	buf.WriteString(`",`)

	// level
	buf.WriteString(`"level":"`)
	buf.WriteString(level.String())
	buf.WriteString(`",`)

	// caller
	if c := getCachedCaller(callerSkip); c != "" {
		buf.WriteString(`"caller":"`)
		buf.WriteString(c)
		buf.WriteString(`",`)
	}

	// msg
	buf.WriteString(`"msg":`)
	appendJSONString(buf, msg)

	// fields
	if len(kvs) >= 2 {
		buf.WriteString(`,"fields":{`)
		for i := 0; i+1 < len(kvs); i += 2 {
			if i > 0 {
				buf.WriteByte(',')
			}
			key, _ := kvs[i].(string)
			appendJSONString(buf, key)
			buf.WriteByte(':')
			appendJSONValue(buf, kvs[i+1])
		}
		buf.WriteByte('}')
	}

	buf.WriteString("}\n")
}

// appendJSONString пишет строку с JSON-эскейпингом без alloc
func appendJSONString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	start := 0
	for i := 0; i < len(s); {
		b := s[i]
		if b < utf8.RuneSelf {
			if htmlSafeSet[b] {
				i++
				continue
			}
			if start < i {
				buf.WriteString(s[start:i])
			}
			switch b {
			case '"':
				buf.WriteString(`\"`)
			case '\\':
				buf.WriteString(`\\`)
			case '\n':
				buf.WriteString(`\n`)
			case '\r':
				buf.WriteString(`\r`)
			case '\t':
				buf.WriteString(`\t`)
			default:
				buf.WriteString(`\u00`)
				buf.WriteByte(hexChars[b>>4])
				buf.WriteByte(hexChars[b&0xf])
			}
			i++
			start = i
			continue
		}
		i++
	}
	if start < len(s) {
		buf.WriteString(s[start:])
	}
	buf.WriteByte('"')
}

const hexChars = "0123456789abcdef"

// htmlSafeSet — символы которые не нужно эскейпить
var htmlSafeSet [256]bool

func init() {
	for i := 0; i < 256; i++ {
		htmlSafeSet[i] = i >= 0x20 && i != '"' && i != '\\'
	}
}

func appendJSONValue(buf *bytes.Buffer, v any) {
	if v == nil {
		buf.WriteString("null")
		return
	}
	switch val := v.(type) {
	case string:
		appendJSONString(buf, val)
	case bool:
		if val {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case int:
		buf.WriteString(strconv.FormatInt(int64(val), 10))
	case int8:
		buf.WriteString(strconv.FormatInt(int64(val), 10))
	case int16:
		buf.WriteString(strconv.FormatInt(int64(val), 10))
	case int32:
		buf.WriteString(strconv.FormatInt(int64(val), 10))
	case int64:
		buf.WriteString(strconv.FormatInt(val, 10))
	case uint:
		buf.WriteString(strconv.FormatUint(uint64(val), 10))
	case uint8:
		buf.WriteString(strconv.FormatUint(uint64(val), 10))
	case uint16:
		buf.WriteString(strconv.FormatUint(uint64(val), 10))
	case uint32:
		buf.WriteString(strconv.FormatUint(uint64(val), 10))
	case uint64:
		buf.WriteString(strconv.FormatUint(val, 10))
	case float32:
		buf.WriteString(strconv.FormatFloat(float64(val), 'f', -1, 32))
	case float64:
		buf.WriteString(strconv.FormatFloat(val, 'f', -1, 64))
	case error:
		appendJSONString(buf, val.Error())
	case fmt.Stringer:
		appendJSONString(buf, val.String())
	default:
		appendJSONString(buf, fmt.Sprintf("%+v", v))
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONSOLE FORMATTER
// ═══════════════════════════════════════════════════════════════════════════════

// reusable time format scratch buffer (per-goroutine via stack alloc)
func (l *Logger) formatConsole(buf *bytes.Buffer, level Level, msg string, callerSkip int, kvs ...any) {
	now := time.Now()

	// ── Timestamp ────────────────────────────────────────────────
	buf.WriteString(formatTime(now))
	buf.WriteByte(' ')

	// ── Level ────────────────────────────────────────────────────
	if l.noColor {
		buf.WriteByte('[')
		buf.WriteString(level.String())
		buf.WriteByte(']')
	} else {
		buf.WriteString(level.Color())
	}
	buf.WriteByte(' ')

	// ── Caller ───────────────────────────────────────────────────
	if c := getCachedCaller(callerSkip); c != "" {
		if !l.noColor {
			buf.WriteString("\033[90m")
		}
		buf.WriteByte('[')
		buf.WriteString(c)
		buf.WriteByte(']')
		if !l.noColor {
			buf.WriteString("\033[0m")
		}
		buf.WriteByte(' ')
	}

	// ── Message ──────────────────────────────────────────────────
	if !l.noColor {
		buf.WriteString(level.ColorTag())
	}
	buf.WriteString(msg)
	if !l.noColor {
		buf.WriteString("\033[0m")
	}

	// ── Fields ───────────────────────────────────────────────────
	if len(kvs) >= 2 {
		if !l.noColor {
			buf.WriteString(" \033[90m{")
		} else {
			buf.WriteString(" {")
		}
		for i := 0; i+1 < len(kvs); i += 2 {
			if i > 0 {
				buf.WriteString(", ")
			}
			key, _ := kvs[i].(string)
			buf.WriteString(key)
			buf.WriteByte('=')
			if !l.noColor {
				buf.WriteString("\033[36m")
			}
			appendConsoleValue(buf, kvs[i+1])
			if !l.noColor {
				buf.WriteString("\033[90m")
			}
		}
		if !l.noColor {
			buf.WriteString("}\033[0m")
		} else {
			buf.WriteByte('}')
		}
	}

	buf.WriteByte('\n')
}

func appendConsoleValue(buf *bytes.Buffer, v any) {
	switch val := v.(type) {
	case string:
		buf.WriteString(val)
	case error:
		buf.WriteString(val.Error())
	case fmt.Stringer:
		buf.WriteString(val.String())
	case bool:
		if val {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case int:
		buf.WriteString(strconv.FormatInt(int64(val), 10))
	case int64:
		buf.WriteString(strconv.FormatInt(val, 10))
	case uint64:
		buf.WriteString(strconv.FormatUint(val, 10))
	case float64:
		buf.WriteString(strconv.FormatFloat(val, 'f', -1, 64))
	default:
		fmt.Fprint(buf, v)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// FAST TIME FORMAT — избегаем лишних аллокаций time.Format
// ═══════════════════════════════════════════════════════════════════════════════

// formatTime форматирует время в "2006-01-02T15:04:05.000" без аллокаций
func formatTime(t time.Time) string {
	var b [23]byte
	year, month, day := t.Date()
	hour, min, sec := t.Clock()
	ms := t.Nanosecond() / 1e6

	b[0] = byte('0' + year/1000)
	b[1] = byte('0' + (year/100)%10)
	b[2] = byte('0' + (year/10)%10)
	b[3] = byte('0' + year%10)
	b[4] = '-'
	b[5] = byte('0' + month/10)
	b[6] = byte('0' + month%10)
	b[7] = '-'
	b[8] = byte('0' + day/10)
	b[9] = byte('0' + day%10)
	b[10] = 'T'
	b[11] = byte('0' + hour/10)
	b[12] = byte('0' + hour%10)
	b[13] = ':'
	b[14] = byte('0' + min/10)
	b[15] = byte('0' + min%10)
	b[16] = ':'
	b[17] = byte('0' + sec/10)
	b[18] = byte('0' + sec%10)
	b[19] = '.'
	b[20] = byte('0' + ms/100)
	b[21] = byte('0' + (ms/10)%10)
	b[22] = byte('0' + ms%10)

	return string(b[:])
}

// ═══════════════════════════════════════════════════════════════════════════════
// GLOBAL INSTANCE
// ═══════════════════════════════════════════════════════════════════════════════

var (
	globalLogger atomic.Pointer[Logger]
	globalMu     sync.Mutex
	globalIsInit bool
)

// Init инициализирует глобальный логгер (можно вызвать только один раз)
func Init(cfg Config) error {
	globalMu.Lock()
	defer globalMu.Unlock()
	if globalIsInit {
		return nil
	}
	l, err := New(cfg)
	if err != nil {
		return err
	}
	globalLogger.Store(l)
	globalIsInit = true
	return nil
}

// Get возвращает глобальный логгер (создаёт дефолтный если не инициализирован)
func Get() *Logger {
	if l := globalLogger.Load(); l != nil {
		return l
	}
	l, _ := New(Config{Level: InfoLevel})
	globalLogger.CompareAndSwap(nil, l)
	return globalLogger.Load()
}

// SetGlobal устанавливает произвольный логгер как глобальный
func SetGlobal(l *Logger) {
	globalLogger.Store(l)
}

// Close закрывает глобальный логгер и сбрасывает state, чтобы повторный
// Init мог создать новый инстанс. Используется в тестах и в командах,
// которые завершают процесс не штатно (rebuild, sandbox).
func Close() {
	if l := globalLogger.Swap(nil); l != nil {
		l.Close()
	}
	globalMu.Lock()
	globalIsInit = false
	globalMu.Unlock()
}

// ═══════════════════════════════════════════════════════════════════════════════
// METHODS ON LOGGER
// ═══════════════════════════════════════════════════════════════════════════════

func (l *Logger) Debug(msg string, kvs ...any) { l.log(DebugLevel, msg, kvs...) }
func (l *Logger) Info(msg string, kvs ...any)  { l.log(InfoLevel, msg, kvs...) }
func (l *Logger) Warn(msg string, kvs ...any)  { l.log(WarnLevel, msg, kvs...) }
func (l *Logger) Error(msg string, kvs ...any) { l.log(ErrorLevel, msg, kvs...) }
func (l *Logger) Fatal(msg string, kvs ...any) { l.log(FatalLevel, msg, kvs...) }
func (l *Logger) Trace(msg string, kvs ...any) { l.log(TraceLevel, msg, kvs...) }

// Sync flushes all buffered writes without closing the logger.
// Useful for graceful shutdown or forcing output before a checkpoint.
func (l *Logger) Sync() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.fileWriter != nil {
		_ = l.fileWriter.Sync()
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// FILE ROTATION
// ═══════════════════════════════════════════════════════════════════════════════

// rotateIfNeeded checks if the log file exceeds MaxFileSize and rotates if so.
// Must be called with l.mu held.
func (l *Logger) rotateIfNeeded(data []byte) {
	if l.maxFileSize <= 0 || l.fileWriter == nil {
		return
	}
	l.fileSize += int64(len(data))
	if l.fileSize < l.maxFileSize {
		return
	}

	// Close current file
	_ = l.fileWriter.Close()

	// Shift existing backups: .3 -> delete, .2 -> .3, .1 -> .2, current -> .1
	for i := l.maxBackups; i >= 1; i-- {
		src := l.filePath
		if i > 1 {
			src = fmt.Sprintf("%s.%d", l.filePath, i-1)
		}
		dst := fmt.Sprintf("%s.%d", l.filePath, i)
		_ = os.Remove(dst) // best effort
		_ = os.Rename(src, dst)
	}

	// Open new file
	f, err := os.OpenFile(l.filePath,
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		// Can't rotate — keep writing to nil (writes will be lost but we can't panic)
		return
	}
	l.fileWriter = f
	l.fileSize = 0

	// Replace file writer in writers list
	for i, w := range l.writers {
		if _, isFile := w.(*os.File); isFile || w == nil {
			l.writers[i] = f
			break
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// slog.Handler ADAPTER — allows using this logger with log/slog
// ═══════════════════════════════════════════════════════════════════════════════

// SlogHandler returns a log/slog.Handler that routes slog output through
// this Logger. Useful for integrating third-party libraries that use slog.
func (l *Logger) SlogHandler() *SlogAdapter {
	return &SlogAdapter{logger: l}
}

// SlogAdapter implements log/slog.Handler backed by a *Logger.
type SlogAdapter struct {
	logger *Logger
	preset []any
}

// Enabled returns true if the given level is at or above the logger's threshold.
func (h *SlogAdapter) Enabled(_ context.Context, level slog.Level) bool {
	var l Level
	switch {
	case level <= slog.LevelDebug-4:
		l = TraceLevel
	case level < slog.LevelInfo:
		l = DebugLevel
	case level < slog.LevelWarn:
		l = InfoLevel
	case level < slog.LevelError:
		l = WarnLevel
	default:
		l = ErrorLevel
	}
	return h.logger.Enabled(l)
}

// Handle processes a slog record.
func (h *SlogAdapter) Handle(_ context.Context, r slog.Record) error {
	var l Level
	switch {
	case r.Level <= slog.LevelDebug-4:
		l = TraceLevel
	case r.Level < slog.LevelInfo:
		l = DebugLevel
	case r.Level < slog.LevelWarn:
		l = InfoLevel
	case r.Level < slog.LevelWarn:
		l = WarnLevel
	default:
		l = ErrorLevel
	}

	kvs := make([]any, 0, len(h.preset)*2+r.NumAttrs())
	kvs = append(kvs, h.preset...)
	r.Attrs(func(a slog.Attr) bool {
		kvs = append(kvs, a.Key, a.Value.Any())
		return true
	})

	h.logger.log(l, r.Message, kvs...)
	return nil
}

// WithAttrs returns a new handler with additional attributes.
func (h *SlogAdapter) WithAttrs(attrs []slog.Attr) slog.Handler {
	newPreset := make([]any, 0, len(h.preset)+len(attrs)*2)
	newPreset = append(newPreset, h.preset...)
	for _, a := range attrs {
		newPreset = append(newPreset, a.Key, a.Value.Any())
	}
	return &SlogAdapter{logger: h.logger, preset: newPreset}
}

// WithGroup returns a new handler with a group name prefixed to all keys.
func (h *SlogAdapter) WithGroup(name string) slog.Handler {
	newPreset := make([]any, 0, len(h.preset)+2)
	newPreset = append(newPreset, h.preset...)
	newPreset = append(newPreset, "group", name)
	return &SlogAdapter{logger: h.logger, preset: newPreset}
}

// ═══════════════════════════════════════════════════════════════════════════════
// RATE LIMITER — prevents log spam from repeated identical messages
// ═══════════════════════════════════════════════════════════════════════════════

// RateLimiter wraps a Logger and suppresses repeated identical messages
// within a cooldown window. Thread-safe.
type RateLimiter struct {
	logger   *Logger
	cooldown time.Duration
	lastSeen map[string]time.Time
	mu       sync.Mutex
}

// NewRateLimiter wraps a logger with rate limiting. Messages with the same
// first 64 bytes of the formatted output are suppressed for `cooldown`.
func NewRateLimiter(l *Logger, cooldown time.Duration) *RateLimiter {
	return &RateLimiter{
		logger:   l,
		cooldown: cooldown,
		lastSeen: make(map[string]time.Time),
	}
}

func (rl *RateLimiter) log(level Level, msg string, kvs ...any) {
	if !rl.logger.Enabled(level) {
		return
	}

	// Build a dedup key from msg + first few kvs
	key := msg
	for i := 0; i+1 < len(kvs) && i < 6; i += 2 {
		if s, ok := kvs[i].(string); ok {
			key += "|" + s
		}
	}
	if len(key) > 128 {
		key = key[:128]
	}

	now := time.Now()
	rl.mu.Lock()
	if last, ok := rl.lastSeen[key]; ok && now.Sub(last) < rl.cooldown {
		rl.mu.Unlock()
		return
	}
	rl.lastSeen[key] = now
	rl.mu.Unlock()

	rl.logger.log(level, msg, kvs...)
}

func (rl *RateLimiter) Debug(msg string, kvs ...any) { rl.log(DebugLevel, msg, kvs...) }
func (rl *RateLimiter) Info(msg string, kvs ...any)  { rl.log(InfoLevel, msg, kvs...) }
func (rl *RateLimiter) Warn(msg string, kvs ...any)  { rl.log(WarnLevel, msg, kvs...) }
func (rl *RateLimiter) Error(msg string, kvs ...any) { rl.log(ErrorLevel, msg, kvs...) }
func (rl *RateLimiter) Trace(msg string, kvs ...any) { rl.log(TraceLevel, msg, kvs...) }

// ═══════════════════════════════════════════════════════════════════════════════
// PACKAGE-LEVEL FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

func Trace(msg string, kvs ...any) { Get().log(TraceLevel, msg, kvs...) }
func Debug(msg string, kvs ...any) { Get().log(DebugLevel, msg, kvs...) }
func Info(msg string, kvs ...any)  { Get().log(InfoLevel, msg, kvs...) }
func Warn(msg string, kvs ...any)  { Get().log(WarnLevel, msg, kvs...) }
func Error(msg string, kvs ...any) { Get().log(ErrorLevel, msg, kvs...) }
func Fatal(msg string, kvs ...any) { Get().log(FatalLevel, msg, kvs...) }

// Sync flushes the global logger's buffers.
func Sync() { Get().Sync() }
