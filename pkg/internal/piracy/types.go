// Package piracy — types.go
// Типы для детектора пиратства (схема v2)
package piracy

import (
	"regexp"
)

// SchemaVersion текущая версия схемы
const SchemaVersion = 2

// ═══════════════════════════════════════════════════════════════════════════════
// MATCH MODE & SCOPE
// ═══════════════════════════════════════════════════════════════════════════════

// MatchMode режим матчинга паттерна
type MatchMode string

const (
	MatchSubstring MatchMode = "substring" // содержит подстроку (default)
	MatchWord      MatchMode = "word"      // слово с границами \b
	MatchExact     MatchMode = "exact"     // точное совпадение
	MatchRegex     MatchMode = "regex"     // регулярное выражение
)

// Watermark описывает watermark-паттерн для ресурсов.
type Watermark struct {
	Value      string  `json:"value"`
	Confidence float64 `json:"confidence,omitempty"`
}

// PatternScope область применения паттерна
type PatternScope string

const (
	ScopeContent  PatternScope = "content"  // содержимое файла
	ScopePath     PatternScope = "path"     // путь к файлу
	ScopeFilename PatternScope = "filename" // имя файла
	ScopeResource PatternScope = "resource" // ресурс (изображение и т.д.)
)

// ═══════════════════════════════════════════════════════════════════════════════
// WEIGHTED PATTERN
// ═══════════════════════════════════════════════════════════════════════════════

// WeightedPattern паттерн с весом
type WeightedPattern struct {
	Value  string    `json:"value"`
	Weight float64   `json:"weight,omitempty"` // 0.0-1.0, default 1.0
	Mode   MatchMode `json:"mode,omitempty"`   // default: substring
}

// CompiledPattern предкомпилированный паттерн
type CompiledPattern struct {
	Original string
	Lower    []byte
	Weight   float64
	Mode     MatchMode
	Regex    *regexp.Regexp // для word/regex mode
}

// ═══════════════════════════════════════════════════════════════════════════════
// WATERMARK PATTERN
// ═══════════════════════════════════════════════════════════════════════════════

// WatermarkPattern паттерн watermark
type WatermarkPattern struct {
	Value      string  `json:"value"`
	Confidence float64 `json:"confidence,omitempty"` // override site confidence
}

// ═══════════════════════════════════════════════════════════════════════════════
// PIRACY SITE
// ═══════════════════════════════════════════════════════════════════════════════

// Site информация о пиратском сайте (схема v2)
type Site struct {
	// Идентификация
	Name   string `json:"name"`
	Type   string `json:"type"`   // warez, modding, cracking, forum, mirror, store
	Region string `json:"region"` // RU, GLOBAL, CN, etc.

	// Домены и паттерны
	Domains           []string           `json:"domains"`
	Patterns          []WeightedPattern  `json:"patterns"`
	Aliases           []string           `json:"aliases,omitempty"`
	Watermarks        []WatermarkPattern `json:"watermarks,omitempty"`
	PatternsRegex     []string           `json:"patterns_regex,omitempty"`
	HistoricalDomains []string           `json:"historical_domains,omitempty"`

	// Scope и matching
	Scope []PatternScope `json:"scope,omitempty"` // default: all

	// Scoring
	Confidence         float64  `json:"confidence"`
	RiskTags           []string `json:"risk_tags,omitempty"`
	IsLegitMirror      bool     `json:"is_legitimate_mirror,omitempty"`
	FalsePositiveWords []string `json:"false_positive_words,omitempty"`

	// Metadata
	Description      string `json:"description"`
	EvidenceStrength string `json:"evidence_strength,omitempty"` // weak, medium, strong

	// Pre-compiled (не сериализуется)
	CompiledPatterns []*CompiledPattern `json:"-"`
	CompiledRegex    []*regexp.Regexp   `json:"-"`
	// FalsePositiveLower is FalsePositiveWords pre-lowercased at compile time,
	// so the false-positive check does not re-lowercase on every finding.
	FalsePositiveLower []string `json:"-"`
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONFIG
// ═══════════════════════════════════════════════════════════════════════════════

// Config конфигурация детектора v2
type Config struct {
	SchemaVersion     int                `json:"schema_version"`
	Sites             []Site             `json:"sites"`
	ModPatterns       []WeightedPattern  `json:"mod_patterns"`
	CrackPatterns     []WeightedPattern  `json:"crack_patterns"`
	WatermarkPatterns []WatermarkPattern `json:"watermark_patterns"`

	// Pre-compiled
	ModCompiled   []*CompiledPattern `json:"-"`
	CrackCompiled []*CompiledPattern `json:"-"`
	Compiled      bool               `json:"-"`
}

// ═══════════════════════════════════════════════════════════════════════════════
// FINDING & RESULT
// ═══════════════════════════════════════════════════════════════════════════════

// Finding находка пиратства
type Finding struct {
	Type       string  `json:"type"` // site, mod, crack, watermark, path
	Source     string  `json:"source"`
	Pattern    string  `json:"pattern"`
	Location   string  `json:"location"`
	Line       int     `json:"line,omitempty"`
	Confidence float64 `json:"confidence"`
	Weight     float64 `json:"weight,omitempty"`
	// Strength is semantic severity, independent from Confidence (match quality).
	// Optional: when empty, the scoring engine will infer it from Type/Signal/Tags.
	Strength    SignalStrength `json:"strength,omitempty"`
	Description string         `json:"description"`
	RiskTags    []string       `json:"risk_tags,omitempty"`

	// Информация о сайте (копия, не указатель!)
	SiteName   string `json:"site_name,omitempty"`
	SiteDomain string `json:"site_domain,omitempty"`
	SiteType   string `json:"site_type,omitempty"`
}

// Result результат анализа пиратства
type Result struct {
	IsPirated     bool      `json:"is_pirated"`
	Confidence    float64   `json:"confidence"`
	Findings      []Finding `json:"findings"`
	SitesFound    []string  `json:"sites_found"`
	ModIndicators []string  `json:"mod_indicators"`
	RiskLevel     string    `json:"risk_level"` // low, medium, high, critical
	RiskTags      []string  `json:"risk_tags,omitempty"`
}
