package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"mega-analyzer/pkg/logger"
)

// ═══════════════════════════════════════════════════════════════════════════════
// Константы и ограничения
// ═══════════════════════════════════════════════════════════════════════════════

const (
	// Границы для Workers
	MinWorkers = 1
	MaxWorkers = 128

	// Границы для ContextLines
	MinContextLines     = 0
	MaxContextLines     = 50
	DefaultContextLines = 5

	// Границы для размера файла (старое поле, в байтах)
	MinFileSize     = 1024             // 1 KB
	MaxFileSize     = 1 << 30          // 1 GB
	DefaultFileSize = 10 * 1024 * 1024 // 10 MB

	// Границы для размера файла (новые поля, в мегабайтах)
	// 0 = без лимита, максимум 1024 МБ (1 ГБ)
	MaxFileSizeMBLimit = 1024

	// Дефолты для профилей (используются в runner.go)
	DefaultCodeFileSizeMB     = 32
	DefaultResourceFileSizeMB = 64

	// Границы для энтропии
	MinEntropyThreshold     = 0.0
	MaxEntropyThreshold     = 8.0 // максимум для байтовой энтропии
	DefaultEntropyThreshold = 4.5

	// DefaultSuspiciousScoreThreshold - app-code SuspiciousScore cutoff.
	// Was hardcoded as `> 5` in two places in workers.go.
	DefaultSuspiciousScoreThreshold = 5.0

	// Границы для строк
	MinStringLength     = 10
	MaxStringLengthVal  = 10000
	DefaultStringLength = 500

	// Границы для совпадений
	MinMatchesPerFile         = 1
	MaxMatchesPerFileVal      = 10000
	DefaultMatchesPerFile     = 100
	DefaultMatchesPerCategory = 500

	// Нормализация скоринга
	DefaultScoreNormalizationCap = 100.0
	MinScoreNormalizationCap     = 1.0
	MaxScoreNormalizationCap     = 10000.0

	// Форматы вывода
	OutputFormatJSON = "json"
	OutputFormatHTML = "html"
	OutputFormatText = "text"
	OutputFormatAll  = "all"
)

// Поддерживаемые форматы вывода
var validOutputFormats = map[string]bool{
	OutputFormatJSON: true,
	OutputFormatHTML: true,
	OutputFormatText: true,
	OutputFormatAll:  true,
}

// ═══════════════════════════════════════════════════════════════════════════════
// Ошибки
// ═══════════════════════════════════════════════════════════════════════════════

var (
	ErrConfigNotFound = errors.New("config file not found")
	ErrInvalidJSON    = errors.New("invalid JSON in config file")
	ErrEmptyConfig    = errors.New("config file is empty")
)

// ValidationError представляет ошибку валидации с деталями
type ValidationError struct {
	Field   string
	Value   any
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation error for field '%s' (value: %v): %s",
		e.Field, e.Value, e.Message)
}

// ValidationErrors — коллекция ошибок валидации
type ValidationErrors []ValidationError

func (ve ValidationErrors) Error() string {
	if len(ve) == 0 {
		return "no validation errors"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%d validation error(s):\n", len(ve)))
	for i, err := range ve {
		sb.WriteString(fmt.Sprintf("  %d. %s\n", i+1, err.Error()))
	}
	return sb.String()
}

func (ve ValidationErrors) HasErrors() bool {
	return len(ve) > 0
}

// ═══════════════════════════════════════════════════════════════════════════════
// Основная структура конфигурации
// ═══════════════════════════════════════════════════════════════════════════════

// Config содержит все настройки анализатора
type Config struct {
	mu sync.RWMutex `json:"-"`

	// Параллелизм
	Workers int `json:"workers"`

	// Анализ контекста
	ContextLines int `json:"context_lines"`

	// Ограничения файлов (старое поле — для обратной совместимости)
	MaxFileSize int64 `json:"max_file_size"`
	MaxFiles    int   `json:"max_files"`

	// ── NEW: Раздельные лимиты размера файлов (в мегабайтах) ─────────────
	// MaxFileSizeMB — лимит для файлов кода (smali, java, kt, dex).
	// 0 = без лимита. Устанавливается профилем, перезаписывается CLI.
	MaxFileSizeMB int `json:"max_file_size_mb"`

	// MaxResourceSizeMB — лимит для ресурсов (xml, json в assets/, res/).
	// В APK ресурсы бывают большими: словари, базы данных, конфиги.
	// 0 = без лимита. Устанавливается профилем, перезаписывается CLI.
	MaxResourceSizeMB int `json:"max_resource_size_mb"`

	// Энтропийный анализ
	MinEntropyThreshold float64 `json:"min_entropy_threshold"`
	// SuspiciousScoreThreshold - cutoff above which an app-code file counts
	// as a finding without explicit matches. 0 keeps the historical default.
	SuspiciousScoreThreshold float64 `json:"suspicious_score_threshold"`

	// Ограничения совпадений
	MaxStringLength       int `json:"max_string_length"`
	MaxMatchesPerFile     int `json:"max_matches_per_file"`
	MaxMatchesPerCategory int `json:"max_matches_per_category"`

	// Функциональные флаги
	EnableEntropyAnalysis bool `json:"enable_entropy_analysis"`
	EnableCallGraph       bool `json:"enable_call_graph"`
	EnableCorrelations    bool `json:"enable_correlations"`
	EnableTracing         bool `json:"enable_tracing"`

	// Elite Research Features (🆕 v9.0.0)
	EnableDeobfuscation      bool `json:"enable_deobfuscation"`
	EnableCrackPointAnalysis bool `json:"enable_crack_point_analysis"`
	EnableAnomalyDetection   bool `json:"enable_anomaly_detection"`

	// Persistent content-addressed method cache. Cache failures are non-fatal:
	// the pipeline logs a warning and continues without reuse.
	EnableContentCache    bool   `json:"enable_content_cache"`
	ContentCacheDir       string `json:"content_cache_dir"`
	ContentCacheMaxDiskMB int64  `json:"content_cache_max_disk_mb"`
	EnableDataFlow        bool   `json:"enable_data_flow"`
	DataFlowMaxMethods    int    `json:"data_flow_max_methods"`
	DataFlowMaxFindings   int    `json:"data_flow_max_findings"`

	// Скоринг
	ScoreNormalizationCap float64 `json:"score_normalization_cap"`

	// Логирование
	LogLevel logger.Level `json:"log_level"`
	LogFile  string       `json:"log_file"`

	// Вывод
	OutputDir    string `json:"output_dir"`
	OutputFormat string `json:"output_format"`

	// ML Patch Configuration
	MLPatch MLPatchConfig `json:"ml_patch"`

	// Deobfuscation Options (🆕 v9.0.0)
	DeobfuscationOptions DeobfuscationOptions `json:"deobfuscation_options"`

	// False Positive Filter Configuration
	FPFilter FPFilterConfig `json:"fp_filter"`

	// Метаданные (не сериализуются)
	loadedFrom string `json:"-"`
	validated  bool   `json:"-"`
}

// MLPatchConfig содержит настройки для ML Patch Pattern системы
type MLPatchConfig struct {
	// Pattern filtering
	EnableDeprecatedPatterns bool   `json:"enable_deprecated_patterns"`
	MinPatternTier           string `json:"min_pattern_tier"` // "имба", "нормально", "мусор"

	// Feedback collection
	EnableFeedbackCollection bool   `json:"enable_feedback_collection"`
	FeedbackStorePath        string `json:"feedback_store_path"`

	// SDK detection
	EnableSDKDetection bool   `json:"enable_sdk_detection"`
	SDKLibrariesPath   string `json:"sdk_libraries_path"`

	// Obfuscation handling
	ObfuscationDetection     bool    `json:"obfuscation_detection"`
	StructuralMatchingWeight float64 `json:"structural_matching_weight"`

	// Performance
	EnablePatternIndex    bool `json:"enable_pattern_index"`
	MaxConcurrentAnalysis int  `json:"max_concurrent_analysis"`
}

// FPFilterConfig содержит настройки для False Positive фильтра (Noise Reduction)
type FPFilterConfig struct {
	Enabled          bool    `json:"enabled"`
	StrictMode       bool    `json:"strict_mode"`
	ShowSuppressed   bool    `json:"show_suppressed"`
	SuppressedLimit  int     `json:"suppressed_limit"`
	MinScore         float64 `json:"min_score"`
	SDKStrongSignals bool    `json:"sdk_strong_signals"`
	NoSDKAutoIgnore  bool    `json:"no_sdk_auto_ignore"`
}

// DeobfuscationOptions содержит настройки движка де-обфускации
type DeobfuscationOptions struct {
	MaxIterations          int  `json:"max_iterations"`
	MinConfidenceThreshold int  `json:"min_confidence_threshold"`
	EnableCP               bool `json:"enable_cp"`
	EnableDCE              bool `json:"enable_dce"`
	EnableOPR              bool `json:"enable_opr"`
	EnablePS               bool `json:"enable_ps"`
	EnableVR               bool `json:"enable_vr"`
	EnableMR               bool `json:"enable_mr"`
	EnableNameQuality      bool `json:"enable_name_quality"`
	// Deprecated fields (kept for backward compatibility)
	EnableCFF       bool `json:"enable_cff"`
	EnableOpaque    bool `json:"enable_opaque"`
	EnableDeadCode  bool `json:"enable_dead_code"`
	EnableStringDec bool `json:"enable_string_dec"`
}

// ═══════════════════════════════════════════════════════════════════════════════
// Конструкторы
// ═══════════════════════════════════════════════════════════════════════════════

// DefaultConfig возвращает конфигурацию с дефолтными значениями.
// Лимиты MB = 0 (без лимита) — профили в runner.go устанавливают конкретные.
func DefaultConfig() *Config {
	return &Config{
		Workers:                  runtime.NumCPU(),
		ContextLines:             DefaultContextLines,
		MaxFileSize:              DefaultFileSize,
		MaxFiles:                 0,
		MaxFileSizeMB:            0, // профиль установит нужное значение
		MaxResourceSizeMB:        0, // профиль установит нужное значение
		MinEntropyThreshold:      DefaultEntropyThreshold,
		SuspiciousScoreThreshold: DefaultSuspiciousScoreThreshold,
		MaxStringLength:          DefaultStringLength,
		MaxMatchesPerFile:        DefaultMatchesPerFile,
		MaxMatchesPerCategory:    DefaultMatchesPerCategory,
		EnableEntropyAnalysis:    true,
		EnableCallGraph:          true,
		EnableCorrelations:       true,
		EnableTracing:            false,
		EnableDeobfuscation:      true,
		EnableCrackPointAnalysis: true,
		EnableAnomalyDetection:   true,
		EnableContentCache:       false,
		ContentCacheDir:          ".analyzer-cache/content",
		ContentCacheMaxDiskMB:    2048,
		EnableDataFlow:           true,
		DataFlowMaxMethods:       200000,
		DataFlowMaxFindings:      2000,
		ScoreNormalizationCap:    DefaultScoreNormalizationCap,
		LogLevel:                 logger.InfoLevel,
		OutputDir:                "analysis_output",
		OutputFormat:             OutputFormatAll,
		MLPatch: MLPatchConfig{
			EnableDeprecatedPatterns: false,
			MinPatternTier:           "нормально",
			EnableFeedbackCollection: true,
			FeedbackStorePath:        "",
			EnableSDKDetection:       true,
			SDKLibrariesPath:         "",
			ObfuscationDetection:     true,
			StructuralMatchingWeight: 0.7,
			EnablePatternIndex:       true,
			MaxConcurrentAnalysis:    runtime.NumCPU(),
		},
		FPFilter: FPFilterConfig{
			Enabled:          true,
			StrictMode:       false,
			ShowSuppressed:   false,
			SuppressedLimit:  100,
			MinScore:         0.55,
			SDKStrongSignals: true,
			NoSDKAutoIgnore:  true,
		},
		DeobfuscationOptions: DeobfuscationOptions{
			MaxIterations:          5,
			MinConfidenceThreshold: 50,
			EnableCP:               true,
			EnableDCE:              true,
			EnableOPR:              true,
			EnablePS:               true,
			EnableVR:               true,
			EnableMR:               true,
			EnableNameQuality:      true,
			// Backward compatibility
			EnableCFF:       true,
			EnableOpaque:    true,
			EnableDeadCode:  true,
			EnableStringDec: true,
		},
		validated: true,
	}
}

// Option — функциональная опция для конфигурации
type Option func(*Config)

// New создаёт конфигурацию с применением опций
func New(opts ...Option) *Config {
	cfg := DefaultConfig()
	for _, opt := range opts {
		opt(cfg)
	}
	return cfg
}

// ═══════════════════════════════════════════════════════════════════════════════
// Функциональные опции
// ═══════════════════════════════════════════════════════════════════════════════

func WithWorkers(n int) Option {
	return func(c *Config) {
		c.Workers = n
	}
}

func WithContextLines(n int) Option {
	return func(c *Config) {
		c.ContextLines = n
	}
}

func WithMaxFileSize(size int64) Option {
	return func(c *Config) {
		c.MaxFileSize = size
	}
}

func WithMaxFiles(n int) Option {
	return func(c *Config) {
		c.MaxFiles = n
	}
}

// WithFileSizeLimits устанавливает раздельные лимиты для кода и ресурсов.
// codeMB — лимит для smali/java/kt (0 = без лимита).
// resourceMB — лимит для xml/json/assets (0 = без лимита).
func WithFileSizeLimits(codeMB, resourceMB int) Option {
	return func(c *Config) {
		c.MaxFileSizeMB = codeMB
		c.MaxResourceSizeMB = resourceMB
	}
}

func WithEntropyThreshold(threshold float64) Option {
	return func(c *Config) {
		c.MinEntropyThreshold = threshold
	}
}

func WithSuspiciousScoreThreshold(threshold float64) Option {
	return func(c *Config) {
		c.SuspiciousScoreThreshold = threshold
	}
}

func WithOutput(dir, format string) Option {
	return func(c *Config) {
		c.OutputDir = dir
		c.OutputFormat = format
	}
}

func WithLogging(level logger.Level, file string) Option {
	return func(c *Config) {
		c.LogLevel = level
		c.LogFile = file
	}
}

func WithFeatures(entropy, callGraph, correlations, tracing bool) Option {
	return func(c *Config) {
		c.EnableEntropyAnalysis = entropy
		c.EnableCallGraph = callGraph
		c.EnableCorrelations = correlations
		c.EnableTracing = tracing
	}
}

func WithMatchLimits(perFile, perCategory int) Option {
	return func(c *Config) {
		c.MaxMatchesPerFile = perFile
		c.MaxMatchesPerCategory = perCategory
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Загрузка конфигурации
// ═══════════════════════════════════════════════════════════════════════════════

func LoadFromFile(path string) (*Config, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrConfigNotFound, path)
		}
		return nil, fmt.Errorf("failed to access config file: %w", err)
	}

	if info.Size() == 0 {
		return nil, fmt.Errorf("%w: %s", ErrEmptyConfig, path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	cfg := DefaultConfig()
	cfg.loadedFrom = path
	cfg.validated = false

	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidJSON, err)
	}

	return cfg, nil
}

func LoadFromFileOrDefault(path string) *Config {
	cfg, err := LoadFromFile(path)
	if err != nil {
		logger.Warn("Failed to load config file, using default", "path", path, "error", err)
		return DefaultConfig()
	}
	return cfg
}

// ═══════════════════════════════════════════════════════════════════════════════
// Геттеры для лимитов (потокобезопасные, удобные)
// ═══════════════════════════════════════════════════════════════════════════════

// GetMaxCodeFileSize возвращает лимит для файлов кода в байтах.
// 0 = без лимита.
func (c *Config) GetMaxCodeFileSize() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.MaxFileSizeMB > 0 {
		return int64(c.MaxFileSizeMB) * 1024 * 1024
	}
	return 0 // без лимита
}

// GetMaxResourceFileSize возвращает лимит для ресурсов в байтах.
// 0 = без лимита.
func (c *Config) GetMaxResourceFileSize() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.MaxResourceSizeMB > 0 {
		return int64(c.MaxResourceSizeMB) * 1024 * 1024
	}
	return 0 // без лимита
}

// ═══════════════════════════════════════════════════════════════════════════════
// Валидация и нормализация
// ═══════════════════════════════════════════════════════════════════════════════

func (c *Config) Validate() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var errs ValidationErrors

	// Workers
	if c.Workers < 0 {
		errs = append(errs, ValidationError{
			Field:   "workers",
			Value:   c.Workers,
			Message: fmt.Sprintf("must be >= 0 (0 means auto-detect, using NumCPU=%d)", runtime.NumCPU()),
		})
	}
	if c.Workers > MaxWorkers {
		errs = append(errs, ValidationError{
			Field:   "workers",
			Value:   c.Workers,
			Message: fmt.Sprintf("exceeds maximum allowed value of %d", MaxWorkers),
		})
	}

	// Context lines
	if c.ContextLines < MinContextLines || c.ContextLines > MaxContextLines {
		errs = append(errs, ValidationError{
			Field:   "context_lines",
			Value:   c.ContextLines,
			Message: fmt.Sprintf("must be between %d and %d", MinContextLines, MaxContextLines),
		})
	}

	// MaxFileSize (старое поле)
	if c.MaxFileSize < MinFileSize || c.MaxFileSize > MaxFileSize {
		errs = append(errs, ValidationError{
			Field:   "max_file_size",
			Value:   c.MaxFileSize,
			Message: fmt.Sprintf("must be between %d and %d bytes", MinFileSize, MaxFileSize),
		})
	}

	// MaxFiles
	if c.MaxFiles < 0 {
		errs = append(errs, ValidationError{
			Field:   "max_files",
			Value:   c.MaxFiles,
			Message: "must be >= 0 (0 means unlimited)",
		})
	}

	// ── NEW: File size MB validation ─────────────────────────────────────
	if c.MaxFileSizeMB < 0 {
		errs = append(errs, ValidationError{
			Field:   "max_file_size_mb",
			Value:   c.MaxFileSizeMB,
			Message: "must be >= 0 (0 means unlimited)",
		})
	}
	if c.MaxFileSizeMB > MaxFileSizeMBLimit {
		errs = append(errs, ValidationError{
			Field:   "max_file_size_mb",
			Value:   c.MaxFileSizeMB,
			Message: fmt.Sprintf("exceeds maximum of %d MB", MaxFileSizeMBLimit),
		})
	}

	if c.MaxResourceSizeMB < 0 {
		errs = append(errs, ValidationError{
			Field:   "max_resource_size_mb",
			Value:   c.MaxResourceSizeMB,
			Message: "must be >= 0 (0 means unlimited)",
		})
	}
	if c.MaxResourceSizeMB > MaxFileSizeMBLimit {
		errs = append(errs, ValidationError{
			Field:   "max_resource_size_mb",
			Value:   c.MaxResourceSizeMB,
			Message: fmt.Sprintf("exceeds maximum of %d MB", MaxFileSizeMBLimit),
		})
	}

	// Entropy
	if c.MinEntropyThreshold < MinEntropyThreshold || c.MinEntropyThreshold > MaxEntropyThreshold {
		errs = append(errs, ValidationError{
			Field:   "min_entropy_threshold",
			Value:   c.MinEntropyThreshold,
			Message: fmt.Sprintf("must be between %.1f and %.1f", MinEntropyThreshold, MaxEntropyThreshold),
		})
	}

	// Output format
	if !validOutputFormats[strings.ToLower(c.OutputFormat)] {
		errs = append(errs, ValidationError{
			Field:   "output_format",
			Value:   c.OutputFormat,
			Message: fmt.Sprintf("must be one of: %s", strings.Join(getValidFormats(), ", ")),
		})
	}

	// Output dir
	if c.OutputDir == "" {
		errs = append(errs, ValidationError{
			Field:   "output_dir",
			Value:   c.OutputDir,
			Message: "cannot be empty",
		})
	}

	// Score normalization
	if c.ScoreNormalizationCap < MinScoreNormalizationCap {
		errs = append(errs, ValidationError{
			Field:   "score_normalization_cap",
			Value:   c.ScoreNormalizationCap,
			Message: fmt.Sprintf("must be at least %.1f", MinScoreNormalizationCap),
		})
	}

	if errs.HasErrors() {
		return errs
	}

	c.validated = true
	return nil
}

// Normalize корректирует значения в допустимые границы
func (c *Config) Normalize() *Config {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.Workers <= 0 {
		c.Workers = runtime.NumCPU()
	}
	c.Workers = clamp(c.Workers, MinWorkers, MaxWorkers)
	c.ContextLines = clamp(c.ContextLines, MinContextLines, MaxContextLines)
	c.MaxFileSize = clamp64(c.MaxFileSize, MinFileSize, MaxFileSize)
	c.MinEntropyThreshold = clampFloat(c.MinEntropyThreshold, MinEntropyThreshold, MaxEntropyThreshold)
	c.MaxStringLength = clamp(c.MaxStringLength, MinStringLength, MaxStringLengthVal)

	if c.MaxFiles < 0 {
		c.MaxFiles = 0
	}

	// ── NEW: Нормализация MB-лимитов ─────────────────────────────────────
	// Отрицательные → 0 (без лимита)
	// Слишком большие → MaxFileSizeMBLimit
	if c.MaxFileSizeMB < 0 {
		c.MaxFileSizeMB = 0
	}
	if c.MaxFileSizeMB > MaxFileSizeMBLimit {
		c.MaxFileSizeMB = MaxFileSizeMBLimit
	}

	if c.MaxResourceSizeMB < 0 {
		c.MaxResourceSizeMB = 0
	}
	if c.MaxResourceSizeMB > MaxFileSizeMBLimit {
		c.MaxResourceSizeMB = MaxFileSizeMBLimit
	}

	if c.MaxMatchesPerFile <= 0 {
		c.MaxMatchesPerFile = DefaultMatchesPerFile
	}
	c.MaxMatchesPerFile = clamp(c.MaxMatchesPerFile, MinMatchesPerFile, MaxMatchesPerFileVal)

	if c.MaxMatchesPerCategory <= 0 {
		c.MaxMatchesPerCategory = DefaultMatchesPerCategory
	}

	c.ScoreNormalizationCap = clampFloat(c.ScoreNormalizationCap, MinScoreNormalizationCap, MaxScoreNormalizationCap)

	c.OutputFormat = strings.ToLower(c.OutputFormat)
	if !validOutputFormats[c.OutputFormat] {
		c.OutputFormat = OutputFormatAll
	}

	if c.OutputDir == "" {
		c.OutputDir = "analysis_output"
	}

	return c
}

// ═══════════════════════════════════════════════════════════════════════════════
// Геттеры (потокобезопасные)
// ═══════════════════════════════════════════════════════════════════════════════

func (c *Config) GetWorkers() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Workers
}

func (c *Config) GetMaxFileSize() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.MaxFileSize
}

func (c *Config) IsEntropyEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.EnableEntropyAnalysis
}

// ═══════════════════════════════════════════════════════════════════════════════
// Сериализация
// ═══════════════════════════════════════════════════════════════════════════════

func (c *Config) Save(path string) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	return os.WriteFile(path, data, 0644)
}

func (c *Config) String() string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Sprintf("<error: %v>", err)
	}
	return string(data)
}

func (c *Config) Clone() *Config {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return &Config{
		Workers:                  c.Workers,
		ContextLines:             c.ContextLines,
		MaxFileSize:              c.MaxFileSize,
		MaxFiles:                 c.MaxFiles,
		MaxFileSizeMB:            c.MaxFileSizeMB,     // ← NEW
		MaxResourceSizeMB:        c.MaxResourceSizeMB, // ← NEW
		MinEntropyThreshold:      c.MinEntropyThreshold,
		MaxStringLength:          c.MaxStringLength,
		MaxMatchesPerFile:        c.MaxMatchesPerFile,
		MaxMatchesPerCategory:    c.MaxMatchesPerCategory,
		EnableEntropyAnalysis:    c.EnableEntropyAnalysis,
		EnableCallGraph:          c.EnableCallGraph,
		EnableCorrelations:       c.EnableCorrelations,
		EnableTracing:            c.EnableTracing,
		EnableDeobfuscation:      c.EnableDeobfuscation,
		EnableCrackPointAnalysis: c.EnableCrackPointAnalysis,
		EnableAnomalyDetection:   c.EnableAnomalyDetection,
		EnableContentCache:       c.EnableContentCache,
		ContentCacheDir:          c.ContentCacheDir,
		ContentCacheMaxDiskMB:    c.ContentCacheMaxDiskMB,
		EnableDataFlow:           c.EnableDataFlow,
		DataFlowMaxMethods:       c.DataFlowMaxMethods,
		DataFlowMaxFindings:      c.DataFlowMaxFindings,
		ScoreNormalizationCap:    c.ScoreNormalizationCap,
		LogLevel:                 c.LogLevel,
		LogFile:                  c.LogFile,
		OutputDir:                c.OutputDir,
		OutputFormat:             c.OutputFormat,
		MLPatch:                  c.MLPatch,
		DeobfuscationOptions:     c.DeobfuscationOptions,
		FPFilter:                 c.FPFilter,
		loadedFrom:               c.loadedFrom,
		validated:                c.validated,
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Вспомогательные функции
// ═══════════════════════════════════════════════════════════════════════════════

func clamp(value, min, max int) int {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

func clamp64(value, min, max int64) int64 {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

func clampFloat(value, min, max float64) float64 {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

func getValidFormats() []string {
	formats := make([]string, 0, len(validOutputFormats))
	for f := range validOutputFormats {
		formats = append(formats, f)
	}
	return formats
}
