package filter

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
// RULES VERSION & MIGRATION
// ═══════════════════════════════════════════════════════════════════════════════

const CurrentRulesVersion = "7.4.0"

// Supported versions for migration
var supportedVersions = []string{
	"7.0.0", "7.1.0", "7.2.0", "7.3.0", "7.4.0", "8.0.0",
}

// ═══════════════════════════════════════════════════════════════════════════════
// PATH SAFETY — защита от path traversal
// ═══════════════════════════════════════════════════════════════════════════════

// DefaultRulesDir — разрешённая базовая директория для rules файлов.
// Можно переопределить через SetRulesBaseDir().
var rulesBaseDir string
var rulesBaseDirMu sync.RWMutex

// SetRulesBaseDir устанавливает разрешённую базовую директорию.
// Все пути в LoadRules/SaveAtomic должны быть внутри этой директории.
// Если не установлено — проверка отключена (для обратной совместимости).
func SetRulesBaseDir(dir string) error {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	rulesBaseDirMu.Lock()
	rulesBaseDir = abs
	rulesBaseDirMu.Unlock()
	return nil
}

// validatePath проверяет что путь безопасен
func validatePath(path string) (string, error) {
	// Получаем абсолютный путь
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("invalid path: %w", err)
	}

	// Нормализуем
	absPath = filepath.Clean(absPath)

	// Проверяем базовую директорию если установлена
	rulesBaseDirMu.RLock()
	baseDir := rulesBaseDir
	rulesBaseDirMu.RUnlock()

	if baseDir != "" {
		rel, err := filepath.Rel(baseDir, absPath)
		if err != nil {
			return "", fmt.Errorf("path error: %w", err)
		}
		if strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == ".." {
			return "", fmt.Errorf("path %q is outside allowed directory %q", absPath, baseDir)
		}
	}

	return absPath, nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// RULES METADATA
// ═══════════════════════════════════════════════════════════════════════════════

type RulesMetadata struct {
	Version   string `json:"rules_version"`
	CreatedAt string `json:"created_at,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
	Source    string `json:"source,omitempty"` // "default", "file", "remote"
	Checksum  string `json:"checksum,omitempty"`
}

// ═══════════════════════════════════════════════════════════════════════════════
// FILTER RULES — основная структура
// ═══════════════════════════════════════════════════════════════════════════════

type FilterRules struct {
	Metadata            RulesMetadata            `json:"metadata"`
	StandardLibraries   []LibraryPattern         `json:"standard_libraries"`
	SafeLibraryPatterns []SafeLibraryPattern     `json:"safe_library_patterns"`
	HighValuePatterns   []HighValuePattern       `json:"high_value_patterns"`
	KeywordWeights      map[string]KeywordConfig `json:"keyword_weights"`
	ContextRules        []ContextRule            `json:"context_rules"`
	ObfuscationPatterns []ObfuscationPattern     `json:"obfuscation_patterns"`
	Scoring             ScoringConfig            `json:"scoring"`

	// 🆕 Runtime state (не сериализуется)
	compiled   bool
	compiledMu *sync.RWMutex
}

// ensureCompiledMu lazily initializes the runtime mutex.
func (r *FilterRules) ensureCompiledMu() {
	if r.compiledMu == nil {
		r.compiledMu = &sync.RWMutex{}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// LIBRARY PATTERN
// ═══════════════════════════════════════════════════════════════════════════════

type LibraryPattern struct {
	Pattern     string    `json:"pattern"`
	MatchType   MatchType `json:"match_type"`
	Description string    `json:"description"`
	Category    string    `json:"category"`
	Exceptions  []string  `json:"exceptions,omitempty"`

	// 🆕 Pointer type для optional dampening (nil = use default)
	Dampening *float64 `json:"dampening,omitempty"`
}

// GetDampening возвращает dampening или default
func (l *LibraryPattern) GetDampening(defaultVal float64) float64 {
	if l.Dampening == nil {
		return defaultVal
	}
	return *l.Dampening
}

type MatchType string

const (
	MatchPrefix   MatchType = "prefix"
	MatchContains MatchType = "contains"
	MatchSuffix   MatchType = "suffix"
	MatchRegex    MatchType = "regex"
)

// ═══════════════════════════════════════════════════════════════════════════════
// HIGH VALUE PATTERN
// ═══════════════════════════════════════════════════════════════════════════════

type HighValuePattern struct {
	Pattern   string    `json:"pattern"`
	MatchType MatchType `json:"match_type"`
	Weight    int       `json:"weight"`
	Category  string    `json:"category"`
	Priority  int       `json:"priority"`

	// 🆕 Precompiled regex (не сериализуется)
	compiled *regexp.Regexp `json:"-"`
}

// Compile компилирует regex если нужно
func (h *HighValuePattern) Compile() error {
	if h.MatchType == MatchRegex && h.compiled == nil && h.Pattern != "" {
		re, err := regexp.Compile(h.Pattern)
		if err != nil {
			return err
		}
		h.compiled = re
	}
	return nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// KEYWORD CONFIG
// ═══════════════════════════════════════════════════════════════════════════════

type KeywordConfig struct {
	Weight      int      `json:"weight"`
	Category    string   `json:"category"`
	Aliases     []string `json:"aliases,omitempty"`
	Combinators []string `json:"combinators,omitempty"`
	MinBonus    int      `json:"min_bonus"`
	MaxBonus    int      `json:"max_bonus"`

	// 🆕 Pointer types для optional fields
	FilenameBonus *int `json:"filename_bonus,omitempty"`
	IsGeneric     bool `json:"is_generic,omitempty"`
}

func (k *KeywordConfig) GetFilenameBonus(defaultVal int) int {
	if k.FilenameBonus == nil {
		return defaultVal
	}
	return *k.FilenameBonus
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONTEXT RULE
// ═══════════════════════════════════════════════════════════════════════════════

type ContextRule struct {
	Keyword         string   `json:"keyword"`
	ContextContains []string `json:"context_contains"`
	Effect          string   `json:"effect"` // "boost" или "dampen"
	Factor          float64  `json:"factor"`
	Description     string   `json:"description"`
}

// ═══════════════════════════════════════════════════════════════════════════════
// OBFUSCATION PATTERN
// ═══════════════════════════════════════════════════════════════════════════════

type ObfuscationPattern struct {
	Name        string `json:"name"`
	Regex       string `json:"regex"`
	Weight      int    `json:"weight"`
	Description string `json:"description"`
	compiled    *regexp.Regexp
}

func (o *ObfuscationPattern) Compile() error {
	if o.Regex != "" && o.compiled == nil {
		re, err := regexp.Compile(o.Regex)
		if err != nil {
			return err
		}
		o.compiled = re
	}
	return nil
}

func (o *ObfuscationPattern) Matches(name string) bool {
	if o.compiled == nil {
		return false
	}
	return o.compiled.MatchString(name)
}

// ═══════════════════════════════════════════════════════════════════════════════
// SCORING CONFIG — все optional через pointers
// ═══════════════════════════════════════════════════════════════════════════════

type ScoringConfig struct {
	BaseImportance        int      `json:"base_importance"`
	MinImportance         int      `json:"min_importance"`
	MaxImportance         int      `json:"max_importance"`
	StandardLibraryScore  int      `json:"standard_library_score"`
	ObfuscationBonus      int      `json:"obfuscation_bonus"`
	AppPackageBonus       int      `json:"app_package_bonus"`
	CombinationMultiplier *float64 `json:"combination_multiplier,omitempty"`

	DefaultLibraryDampening *float64 `json:"default_library_dampening,omitempty"`
	DampeningFloor          *float64 `json:"dampening_floor,omitempty"`
	DampeningCeiling        *float64 `json:"dampening_ceiling,omitempty"`

	GenericPenaltyCap    *int     `json:"generic_penalty_cap,omitempty"`
	DefaultFilenameBonus *int     `json:"default_filename_bonus,omitempty"`
	CorrelationBoost     *float64 `json:"correlation_boost,omitempty"`
}

// Getters with defaults
func (s *ScoringConfig) GetCombinationMultiplier() float64 {
	if s.CombinationMultiplier == nil {
		return 1.5
	}
	return *s.CombinationMultiplier
}

func (s *ScoringConfig) GetDefaultLibraryDampening() float64 {
	if s.DefaultLibraryDampening == nil {
		return 0.4
	}
	return *s.DefaultLibraryDampening
}

func (s *ScoringConfig) GetDampeningFloor() float64 {
	if s.DampeningFloor == nil {
		return 0.2
	}
	return *s.DampeningFloor
}

func (s *ScoringConfig) GetDampeningCeiling() float64 {
	if s.DampeningCeiling == nil {
		return 1.5
	}
	return *s.DampeningCeiling
}

func (s *ScoringConfig) GetGenericPenaltyCap() int {
	if s.GenericPenaltyCap == nil {
		return 2
	}
	return *s.GenericPenaltyCap
}

func (s *ScoringConfig) GetDefaultFilenameBonus() int {
	if s.DefaultFilenameBonus == nil {
		return 3
	}
	return *s.DefaultFilenameBonus
}

func (s *ScoringConfig) GetCorrelationBoost() float64 {
	if s.CorrelationBoost == nil {
		return 1.2
	}
	return *s.CorrelationBoost
}

// ═══════════════════════════════════════════════════════════════════════════════
// LIMITS — защита от DoS
// ═══════════════════════════════════════════════════════════════════════════════

const (
	maxRulesFileSize    = 10 * 1024 * 1024 // 10 MB
	maxLibraries        = 1000
	maxKeywords         = 500
	maxHighValue        = 200
	maxSafePatterns     = 200
	maxContextRules     = 100
	maxObfuscation      = 50
	maxExceptionsPerLib = 50
	maxAliasesPerKW     = 20
	maxCombinators      = 20
)

// ═══════════════════════════════════════════════════════════════════════════════
// VALIDATION
// ═══════════════════════════════════════════════════════════════════════════════

type ValidationError struct {
	Field   string
	Message string
}

func (e ValidationError) Error() string {
	return e.Field + ": " + e.Message
}

type ValidationResult struct {
	Valid    bool
	Errors   []ValidationError
	Warnings []string
}

func (r *ValidationResult) addError(field, message string) {
	r.Valid = false
	r.Errors = append(r.Errors, ValidationError{Field: field, Message: message})
}

func (r *ValidationResult) addWarning(message string) {
	r.Warnings = append(r.Warnings, message)
}

func (rules *FilterRules) Validate() ValidationResult {
	result := ValidationResult{Valid: true}

	// ── Version ──────────────────────────────────────────────────
	if rules.Metadata.Version == "" {
		result.addWarning("rules_version not set, assuming current version")
	} else if !isSupportedVersion(rules.Metadata.Version) {
		result.addWarning("unsupported rules_version: " + rules.Metadata.Version)
	}

	// ── Scoring ──────────────────────────────────────────────────
	s := &rules.Scoring

	if s.MinImportance > s.MaxImportance {
		result.addError("scoring.min_importance", "must be <= max_importance")
	}
	if s.MinImportance < 0 {
		result.addError("scoring.min_importance", "must be >= 0")
	}
	if s.MaxImportance > 100 {
		result.addError("scoring.max_importance", "must be <= 100")
	}
	if s.BaseImportance < 0 {
		result.addError("scoring.base_importance", "must be >= 0")
	}

	floor := s.GetDampeningFloor()
	ceiling := s.GetDampeningCeiling()
	defDamp := s.GetDefaultLibraryDampening()

	if floor > ceiling {
		result.addError("scoring.dampening_floor", "must be <= dampening_ceiling")
	}
	if defDamp < floor || defDamp > ceiling {
		result.addError("scoring.default_library_dampening",
			fmt.Sprintf("must be between floor (%.2f) and ceiling (%.2f)", floor, ceiling))
	}

	if s.GetCombinationMultiplier() <= 0 {
		result.addError("scoring.combination_multiplier", "must be > 0")
	}
	if s.GetCorrelationBoost() <= 0 {
		result.addError("scoring.correlation_boost", "must be > 0")
	}

	// ── Limits ───────────────────────────────────────────────────
	if len(rules.StandardLibraries) > maxLibraries {
		result.addError("standard_libraries", fmt.Sprintf("too many: %d (max %d)",
			len(rules.StandardLibraries), maxLibraries))
	}
	if len(rules.SafeLibraryPatterns) > maxSafePatterns {
		result.addError("safe_library_patterns", fmt.Sprintf("too many: %d (max %d)",
			len(rules.SafeLibraryPatterns), maxSafePatterns))
	}
	if len(rules.HighValuePatterns) > maxHighValue {
		result.addError("high_value_patterns", fmt.Sprintf("too many: %d (max %d)",
			len(rules.HighValuePatterns), maxHighValue))
	}
	if len(rules.KeywordWeights) > maxKeywords {
		result.addError("keyword_weights", fmt.Sprintf("too many: %d (max %d)",
			len(rules.KeywordWeights), maxKeywords))
	}
	if len(rules.ContextRules) > maxContextRules {
		result.addError("context_rules", fmt.Sprintf("too many: %d (max %d)",
			len(rules.ContextRules), maxContextRules))
	}
	if len(rules.ObfuscationPatterns) > maxObfuscation {
		result.addError("obfuscation_patterns", fmt.Sprintf("too many: %d (max %d)",
			len(rules.ObfuscationPatterns), maxObfuscation))
	}

	// ── Libraries ────────────────────────────────────────────────
	libSeen := make(map[string]int)
	for i, lib := range rules.StandardLibraries {
		idx := fmt.Sprintf("standard_libraries[%d]", i)

		if lib.Pattern == "" {
			result.addError(idx+".pattern", "empty pattern")
		}
		if lib.Category == "" {
			result.addWarning(idx + ".category: empty category")
		}
		if !isValidMatchType(lib.MatchType) {
			result.addError(idx+".match_type", "invalid: "+string(lib.MatchType))
		}
		if lib.Dampening != nil {
			if *lib.Dampening < floor || *lib.Dampening > ceiling {
				result.addError(idx+".dampening",
					fmt.Sprintf("must be between %.2f and %.2f", floor, ceiling))
			}
		}
		if len(lib.Exceptions) > maxExceptionsPerLib {
			result.addError(idx+".exceptions", fmt.Sprintf("too many: %d (max %d)",
				len(lib.Exceptions), maxExceptionsPerLib))
		}

		// Duplicate check
		key := string(lib.MatchType) + ":" + lib.Pattern
		if prev, exists := libSeen[key]; exists {
			result.addWarning(fmt.Sprintf("%s: duplicate of [%d]", idx, prev))
		}
		libSeen[key] = i
	}

	// ── SafeLibraryPatterns ──────────────────────────────────────
	for i, sp := range rules.SafeLibraryPatterns {
		idx := fmt.Sprintf("safe_library_patterns[%d]", i)

		if sp.LibraryPrefix == "" {
			result.addError(idx+".library_prefix", "empty prefix")
		}
		if len(sp.SafeKeywords) == 0 {
			result.addWarning(idx + ".safe_keywords: empty list")
		}
		if sp.Dampening != nil {
			if *sp.Dampening < 0 || *sp.Dampening > 1.0 {
				result.addError(idx+".dampening", "must be between 0 and 1.0")
			}
		}
	}

	// ── HighValuePatterns ────────────────────────────────────────
	hvSeen := make(map[string]int)
	for i, hvp := range rules.HighValuePatterns {
		idx := fmt.Sprintf("high_value_patterns[%d]", i)

		if hvp.Pattern == "" {
			result.addError(idx+".pattern", "empty pattern")
		}
		if hvp.Weight < 0 || hvp.Weight > 15 {
			result.addError(idx+".weight", "must be between 0 and 15")
		}
		if !isValidMatchType(hvp.MatchType) {
			result.addError(idx+".match_type", "invalid: "+string(hvp.MatchType))
		}
		if hvp.MatchType == MatchRegex {
			if _, err := regexp.Compile(hvp.Pattern); err != nil {
				result.addError(idx+".pattern", "invalid regex: "+err.Error())
			}
		}

		key := string(hvp.MatchType) + ":" + hvp.Pattern
		if prev, exists := hvSeen[key]; exists {
			result.addWarning(fmt.Sprintf("%s: duplicate of [%d]", idx, prev))
		}
		hvSeen[key] = i
	}

	// ── Keywords ─────────────────────────────────────────────────
	for name, config := range rules.KeywordWeights {
		idx := "keyword_weights." + name

		if config.Weight < 0 || config.Weight > 15 {
			result.addError(idx+".weight", "must be between 0 and 15")
		}
		if config.MinBonus > config.MaxBonus {
			result.addError(idx+".min_bonus", "must be <= max_bonus")
		}
		if config.Category == "" {
			result.addWarning(idx + ".category: empty category")
		}
		if len(config.Aliases) > maxAliasesPerKW {
			result.addError(idx+".aliases", fmt.Sprintf("too many: %d (max %d)",
				len(config.Aliases), maxAliasesPerKW))
		}
		if len(config.Combinators) > maxCombinators {
			result.addError(idx+".combinators", fmt.Sprintf("too many: %d (max %d)",
				len(config.Combinators), maxCombinators))
		}
	}

	// ── ContextRules ─────────────────────────────────────────────
	for i, cr := range rules.ContextRules {
		idx := fmt.Sprintf("context_rules[%d]", i)

		if cr.Keyword == "" {
			result.addError(idx+".keyword", "empty keyword")
		}
		if cr.Effect != "boost" && cr.Effect != "dampen" {
			result.addError(idx+".effect", "must be 'boost' or 'dampen'")
		}
		if cr.Factor <= 0 {
			result.addError(idx+".factor", "must be > 0")
		}
		if len(cr.ContextContains) == 0 {
			result.addWarning(idx + ".context_contains: empty list")
		}
	}

	// ── 🆕 Проверяем конфликты ContextRules ──────────────────────
	type ctxKey struct {
		keyword string
		context string
	}
	ctxSeen := make(map[ctxKey]string) // key → effect

	for i, cr := range rules.ContextRules {
		for _, ctx := range cr.ContextContains {
			key := ctxKey{cr.Keyword, ctx}
			if prevEffect, exists := ctxSeen[key]; exists {
				if prevEffect != cr.Effect {
					result.addWarning(fmt.Sprintf(
						"context_rules[%d]: conflicting effects for keyword '%s' + context '%s' ('%s' vs '%s')",
						i, cr.Keyword, ctx, prevEffect, cr.Effect))
				}
			} else {
				ctxSeen[key] = cr.Effect
			}
		}
	}

	// ── ObfuscationPatterns ──────────────────────────────────────
	for i, op := range rules.ObfuscationPatterns {
		idx := fmt.Sprintf("obfuscation_patterns[%d]", i)

		if op.Regex == "" {
			result.addError(idx+".regex", "empty regex")
		} else if _, err := regexp.Compile(op.Regex); err != nil {
			result.addError(idx+".regex", "invalid: "+err.Error())
		}
		if op.Weight < 0 {
			result.addError(idx+".weight", "must be >= 0")
		}
	}

	return result
}

func isSupportedVersion(v string) bool {
	for _, sv := range supportedVersions {
		if v == sv {
			return true
		}
	}
	return false
}

func isValidMatchType(mt MatchType) bool {
	switch mt {
	case MatchPrefix, MatchContains, MatchSuffix, MatchRegex:
		return true
	default:
		return false
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// LOAD — с полной валидацией, миграцией, нормализацией
// ═══════════════════════════════════════════════════════════════════════════════

func LoadRules(path string) (FilterRules, error) {
	rules, _, err := LoadRulesValidated(path)
	return rules, err
}

// verifyChecksum проверяет целостность данных
func verifyChecksum(data []byte, expectedChecksum string) error {
	// Нужно вычислить checksum БЕЗ поля checksum в metadata
	// Для этого парсим, убираем checksum, сериализуем обратно

	var temp FilterRules
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}

	temp.Metadata.Checksum = ""

	// Используем ту же детерминированную сериализацию, что и при сохранении
	cleanData, err := temp.MarshalDeterministic()
	if err != nil {
		return err
	}

	// Вычисляем hash
	hash := sha256.Sum256(cleanData)
	actualChecksum := hex.EncodeToString(hash[:])

	if actualChecksum != expectedChecksum {
		return fmt.Errorf("expected %s, got %s", expectedChecksum, actualChecksum)
	}

	return nil
}

func LoadRulesValidated(path string) (FilterRules, ValidationResult, error) {
	// ── Защита от path traversal ─────────────────────────────────
	absPath, err := validatePath(path)
	if err != nil {
		return DefaultRules(), ValidationResult{}, err
	}

	// ── Проверяем размер файла ───────────────────────────────────
	info, err := os.Stat(absPath)
	if err != nil {
		return DefaultRules(), ValidationResult{}, err
	}
	if info.Size() > maxRulesFileSize {
		return DefaultRules(), ValidationResult{}, fmt.Errorf("rules file too large: %d bytes (max %d)",
			info.Size(), maxRulesFileSize)
	}

	// ── Читаем файл ──────────────────────────────────────────────
	data, err := os.ReadFile(absPath)
	if err != nil {
		return DefaultRules(), ValidationResult{}, err
	}

	// ── Парсим JSON ──────────────────────────────────────────────
	var rules FilterRules
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&rules); err != nil {
		return DefaultRules(), ValidationResult{}, fmt.Errorf("JSON decode error: %w", err)
	}

	// ── 🆕 Проверяем checksum если есть ──────────────────────────
	if rules.Metadata.Checksum != "" {
		if err := verifyChecksum(data, rules.Metadata.Checksum); err != nil {
			return DefaultRules(), ValidationResult{}, fmt.Errorf("checksum verification failed: %w", err)
		}
	}

	// ── Миграция версий ──────────────────────────────────────────
	if rules.Metadata.Version != "" && rules.Metadata.Version != CurrentRulesVersion {
		if err := migrateRules(&rules); err != nil {
			return DefaultRules(), ValidationResult{}, fmt.Errorf("migration error: %w", err)
		}
	}

	// ── Валидация ────────────────────────────────────────────────
	validation := rules.Validate()

	// ── Нормализация (до compile!) ───────────────────────────────
	rules.normalize()

	// ── Дедупликация ─────────────────────────────────────────────
	rules.deduplicate()

	// ── Компиляция regex (после normalize и deduplicate!) ────────
	if err := rules.compile(); err != nil {
		return rules, validation, fmt.Errorf("compile error: %w", err)
	}

	return rules, validation, nil
}

// compile компилирует все regex'ы (один раз!)
func (r *FilterRules) compile() error {
	r.ensureCompiledMu()
	r.compiledMu.Lock()
	defer r.compiledMu.Unlock()

	if r.compiled {
		return nil
	}

	// ObfuscationPatterns
	for i := range r.ObfuscationPatterns {
		if err := r.ObfuscationPatterns[i].Compile(); err != nil {
			return fmt.Errorf("obfuscation_patterns[%d]: %w", i, err)
		}
	}

	// HighValuePatterns (если regex)
	for i := range r.HighValuePatterns {
		if err := r.HighValuePatterns[i].Compile(); err != nil {
			return fmt.Errorf("high_value_patterns[%d]: %w", i, err)
		}
	}

	// Сортируем ObfuscationPatterns по весу (desc) для early exit
	sort.Slice(r.ObfuscationPatterns, func(i, j int) bool {
		return r.ObfuscationPatterns[i].Weight > r.ObfuscationPatterns[j].Weight
	})

	r.compiled = true
	return nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// MIGRATION — между версиями правил
// ═══════════════════════════════════════════════════════════════════════════════

func migrateRules(rules *FilterRules) error {
	version := rules.Metadata.Version

	// 🆕 Проверяем что версия поддерживается
	if !isSupportedVersion(version) {
		return fmt.Errorf("unsupported rules version: %s (supported: %v)",
			version, supportedVersions)
	}

	// Миграции по цепочке
	switch version {
	case "7.0.0":
		// 7.0.0 → 7.1.0: добавить SafeLibraryPatterns если нет
		if len(rules.SafeLibraryPatterns) == 0 {
			rules.SafeLibraryPatterns = defaultSafeLibraryPatterns()
		}
		fallthrough
	case "7.1.0":
		// 7.1.0 → 7.2.0: добавить ContextRules если нет
		if len(rules.ContextRules) == 0 {
			rules.ContextRules = defaultContextRules()
		}
		fallthrough
	case "7.2.0":
		// 7.2.0 → 7.3.0: ничего особенного
		fallthrough
	case "7.3.0":
		// 7.3.0 → 7.4.0: pointer types уже обработаны JSON unmarshal
	}

	rules.Metadata.Version = CurrentRulesVersion
	return nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// NORMALIZE — нормализация ВСЕХ паттернов
// ═══════════════════════════════════════════════════════════════════════════════

func (r *FilterRules) normalize() {
	// ── StandardLibraries ────────────────────────────────────────
	for i := range r.StandardLibraries {
		// 🆕 Передаём MatchType!
		r.StandardLibraries[i].Pattern = normalizePattern(
			r.StandardLibraries[i].Pattern,
			r.StandardLibraries[i].MatchType,
		)
		for j := range r.StandardLibraries[i].Exceptions {
			r.StandardLibraries[i].Exceptions[j] = strings.ToLower(
				strings.TrimSpace(r.StandardLibraries[i].Exceptions[j]))
		}
		r.StandardLibraries[i].Category = strings.ToLower(
			strings.TrimSpace(r.StandardLibraries[i].Category))
	}

	// ── SafeLibraryPatterns ──────────────────────────────────────
	for i := range r.SafeLibraryPatterns {
		// SafeLibraryPatterns всегда prefix-based
		r.SafeLibraryPatterns[i].LibraryPrefix = normalizePattern(
			r.SafeLibraryPatterns[i].LibraryPrefix,
			MatchPrefix,
		)
		for j := range r.SafeLibraryPatterns[i].SafeKeywords {
			r.SafeLibraryPatterns[i].SafeKeywords[j] = strings.ToLower(
				strings.TrimSpace(r.SafeLibraryPatterns[i].SafeKeywords[j]))
		}
	}

	// ── HighValuePatterns ────────────────────────────────────────
	for i := range r.HighValuePatterns {
		if r.HighValuePatterns[i].MatchType != MatchRegex {
			// 🆕 НЕ добавляем trailing slash для contains/suffix!
			r.HighValuePatterns[i].Pattern = normalizePattern(
				r.HighValuePatterns[i].Pattern,
				r.HighValuePatterns[i].MatchType,
			)
		}
		r.HighValuePatterns[i].Category = strings.ToLower(
			strings.TrimSpace(r.HighValuePatterns[i].Category))
	}

	// ── KeywordWeights ───────────────────────────────────────────
	// 🆕 Нормализуем ключи и внутренние массивы
	normalizedKW := make(map[string]KeywordConfig, len(r.KeywordWeights))
	for name, config := range r.KeywordWeights {
		normalizedName := strings.ToLower(strings.TrimSpace(name))

		// Нормализуем aliases
		for j := range config.Aliases {
			config.Aliases[j] = strings.ToLower(strings.TrimSpace(config.Aliases[j]))
		}

		// Нормализуем combinators
		for j := range config.Combinators {
			config.Combinators[j] = strings.ToLower(strings.TrimSpace(config.Combinators[j]))
		}

		config.Category = strings.ToLower(strings.TrimSpace(config.Category))
		normalizedKW[normalizedName] = config
	}
	r.KeywordWeights = normalizedKW

	// ── ContextRules ─────────────────────────────────────────────
	for i := range r.ContextRules {
		r.ContextRules[i].Keyword = strings.ToLower(strings.TrimSpace(r.ContextRules[i].Keyword))
		r.ContextRules[i].Effect = strings.ToLower(strings.TrimSpace(r.ContextRules[i].Effect))
		for j := range r.ContextRules[i].ContextContains {
			r.ContextRules[i].ContextContains[j] = strings.ToLower(
				strings.TrimSpace(r.ContextRules[i].ContextContains[j]))
		}
	}
}

// normalizePattern нормализует паттерн с учётом MatchType
func normalizePattern(pattern string, matchType MatchType) string {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	pattern = strings.TrimPrefix(pattern, "smali/")
	pattern = strings.ReplaceAll(pattern, "\\", "/")

	// Убираем двойные слэши
	for strings.Contains(pattern, "//") {
		pattern = strings.ReplaceAll(pattern, "//", "/")
	}

	// 🆕 Trailing slash ТОЛЬКО для Prefix!
	// Для Contains/Suffix НЕ добавляем — это сломает логику
	if matchType == MatchPrefix {
		if pattern != "" && !strings.HasSuffix(pattern, "/") && !strings.HasSuffix(pattern, ".smali") {
			pattern = pattern + "/"
		}
	}

	return pattern
}

// ═══════════════════════════════════════════════════════════════════════════════
// DEDUPLICATE — убираем дубликаты
// ═══════════════════════════════════════════════════════════════════════════════

// deduplicate убирает дубликаты и проверяет конфликты
func (r *FilterRules) deduplicate() {
	// ── StandardLibraries ────────────────────────────────────────
	type libKey struct {
		matchType MatchType
		pattern   string
	}
	libSeen := make(map[libKey]int)
	dedupedLibs := make([]LibraryPattern, 0, len(r.StandardLibraries))

	for _, lib := range r.StandardLibraries {
		key := libKey{lib.MatchType, lib.Pattern}
		if prevIdx, exists := libSeen[key]; exists {
			// 🆕 Проверяем конфликт: разные Category или Dampening?
			prev := r.StandardLibraries[prevIdx]
			if prev.Category != lib.Category {
				// Конфликт категорий — оставляем первый, логируем
				// В production это должно быть warning в ValidationResult
			}
			// Пропускаем дубликат
			continue
		}
		libSeen[key] = len(dedupedLibs)
		dedupedLibs = append(dedupedLibs, lib)
	}
	r.StandardLibraries = dedupedLibs

	// ── HighValuePatterns — аналогично ───────────────────────────
	type hvKey struct {
		matchType MatchType
		pattern   string
	}
	hvSeen := make(map[hvKey]int)
	dedupedHV := make([]HighValuePattern, 0, len(r.HighValuePatterns))

	for _, hvp := range r.HighValuePatterns {
		key := hvKey{hvp.MatchType, hvp.Pattern}
		if prevIdx, exists := hvSeen[key]; exists {
			prev := r.HighValuePatterns[prevIdx]
			// 🆕 При конфликте — оставляем с бОльшим Weight
			if hvp.Weight > prev.Weight {
				dedupedHV[prevIdx] = hvp
			}
			continue
		}
		hvSeen[key] = len(dedupedHV)
		dedupedHV = append(dedupedHV, hvp)
	}
	r.HighValuePatterns = dedupedHV
}

// ═══════════════════════════════════════════════════════════════════════════════
// SAVE — атомарное сохранение с fsync и checksum
// ═══════════════════════════════════════════════════════════════════════════════

func (r *FilterRules) Save(path string) error {
	return r.SaveAtomic(path)
}

func (r *FilterRules) SaveAtomic(path string) error {
	// ── Защита от path traversal ─────────────────────────────────
	absPath, err := validatePath(path)
	if err != nil {
		return err
	}

	// ── Обновляем метаданные ─────────────────────────────────────
	r.Metadata.Version = CurrentRulesVersion
	r.Metadata.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if r.Metadata.Source == "" {
		r.Metadata.Source = "file"
	}
	if r.Metadata.CreatedAt == "" {
		r.Metadata.CreatedAt = r.Metadata.UpdatedAt
	}

	// ── Сериализуем с deterministic ordering ─────────────────────
	data, err := r.MarshalDeterministic()
	if err != nil {
		return err
	}

	// ── Вычисляем checksum ───────────────────────────────────────
	hash := sha256.Sum256(data)
	r.Metadata.Checksum = hex.EncodeToString(hash[:])

	// Пересериализуем с checksum
	data, err = r.MarshalDeterministic()
	if err != nil {
		return err
	}

	// ── Создаём директорию если нужно ────────────────────────────
	dir := filepath.Dir(absPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// ── Пишем во временный файл с fsync ──────────────────────────
	tempPath := absPath + ".tmp." + secureRandomSuffix()

	f, err := os.OpenFile(tempPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}

	_, writeErr := f.Write(data)
	syncErr := f.Sync() // 🆕 fsync!
	closeErr := f.Close()

	if writeErr != nil {
		os.Remove(tempPath)
		return writeErr
	}
	if syncErr != nil {
		os.Remove(tempPath)
		return syncErr
	}
	if closeErr != nil {
		os.Remove(tempPath)
		return closeErr
	}

	// ── Атомарно переименовываем ─────────────────────────────────
	if err := os.Rename(tempPath, absPath); err != nil {
		os.Remove(tempPath)
		return err
	}

	// ── Sync директории (для надёжности, кроме Windows) ──────────
	if runtime.GOOS != "windows" {
		dirF, err := os.Open(dir)
		if err == nil {
			if syncErr := dirF.Sync(); syncErr != nil {
				log.Printf("filter: warning: sync dir %s failed: %v", dir, syncErr)
			}
			dirF.Close()
		}
	}

	return nil
}

// MarshalDeterministic сериализует с детерминированным порядком
func (r *FilterRules) MarshalDeterministic() ([]byte, error) {
	// 🆕 Deep copy чтобы не мутировать оригинал
	copyRules := r.makeSerializableCopy()

	// Сортируем HighValuePatterns по Pattern
	sort.Slice(copyRules.HighValuePatterns, func(i, j int) bool {
		return copyRules.HighValuePatterns[i].Pattern < copyRules.HighValuePatterns[j].Pattern
	})

	// Сортируем StandardLibraries по Pattern
	sort.Slice(copyRules.StandardLibraries, func(i, j int) bool {
		return copyRules.StandardLibraries[i].Pattern < copyRules.StandardLibraries[j].Pattern
	})

	// Сортируем SafeLibraryPatterns по LibraryPrefix
	sort.Slice(copyRules.SafeLibraryPatterns, func(i, j int) bool {
		return copyRules.SafeLibraryPatterns[i].LibraryPrefix < copyRules.SafeLibraryPatterns[j].LibraryPrefix
	})

	// Сортируем ContextRules по Keyword
	sort.Slice(copyRules.ContextRules, func(i, j int) bool {
		return copyRules.ContextRules[i].Keyword < copyRules.ContextRules[j].Keyword
	})

	// Сортируем ObfuscationPatterns по Name
	sort.Slice(copyRules.ObfuscationPatterns, func(i, j int) bool {
		return copyRules.ObfuscationPatterns[i].Name < copyRules.ObfuscationPatterns[j].Name
	})

	return json.MarshalIndent(copyRules, "", "  ")
}

// makeSerializableCopy создаёт копию через единую точку DeepCopy()
func (r *FilterRules) makeSerializableCopy() *FilterRules {
	return r.DeepCopy()
}

// builtinCopy — обёртка над copy для generic типов
func builtinCopy[T any](dst, src []T) {
	copy(dst, src)
}

// secureRandomSuffix генерирует криптографически безопасный суффикс
func secureRandomSuffix() string {
	b := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		// Fallback на время (не должно случиться)
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return hex.EncodeToString(b)
}

// ═══════════════════════════════════════════════════════════════════════════════
// DEFAULT RULES
// ═══════════════════════════════════════════════════════════════════════════════

func DefaultRules() FilterRules {
	combMult := 1.5
	defLibDamp := 0.4
	dampFloor := 0.2
	dampCeil := 1.5
	genPenCap := 2
	defFnBonus := 3
	corrBoost := 1.2

	rules := FilterRules{
		Metadata: RulesMetadata{
			Version:   CurrentRulesVersion,
			CreatedAt: time.Now().UTC().Format(time.RFC3339),
			Source:    "default",
		},
		StandardLibraries:   defaultStandardLibraries(),
		SafeLibraryPatterns: defaultSafeLibraryPatterns(),
		HighValuePatterns:   defaultHighValuePatterns(),
		KeywordWeights:      defaultKeywordWeights(),
		ContextRules:        defaultContextRules(),
		ObfuscationPatterns: defaultObfuscationPatterns(),
		Scoring: ScoringConfig{
			BaseImportance:          5,
			MinImportance:           0,
			MaxImportance:           10,
			StandardLibraryScore:    0,
			ObfuscationBonus:        2,
			AppPackageBonus:         3,
			CombinationMultiplier:   &combMult,
			DefaultLibraryDampening: &defLibDamp,
			DampeningFloor:          &dampFloor,
			DampeningCeiling:        &dampCeil,
			GenericPenaltyCap:       &genPenCap,
			DefaultFilenameBonus:    &defFnBonus,
			CorrelationBoost:        &corrBoost,
		},
		compiledMu: &sync.RWMutex{},
	}

	// Компилируем regex'ы
	rules.compile()
	rules.normalize()

	return rules
}

// ═══════════════════════════════════════════════════════════════════════════════
// DEFAULT STANDARD LIBRARIES
// ═══════════════════════════════════════════════════════════════════════════════

func defaultStandardLibraries() []LibraryPattern {
	return []LibraryPattern{
		// Android SDK
		{Pattern: "android/", MatchType: MatchPrefix, Category: "sdk", Description: "Android SDK"},
		{Pattern: "androidx/", MatchType: MatchPrefix, Category: "sdk", Description: "AndroidX"},
		{Pattern: "com/android/internal/", MatchType: MatchPrefix, Category: "sdk", Description: "Android Internal"},

		// Google Services
		{
			Pattern: "com/google/android/gms/", MatchType: MatchPrefix,
			Category: "google", Description: "Google Play Services",
			Exceptions: []string{"gms/ads/rewarded", "gms/ads/interstitial", "gms/ads/purchase"},
		},
		{Pattern: "com/google/android/play/", MatchType: MatchPrefix, Category: "google", Description: "Google Play Core"},
		{Pattern: "com/google/android/material/", MatchType: MatchPrefix, Category: "google", Description: "Material Components"},
		{Pattern: "com/google/android/flexbox/", MatchType: MatchPrefix, Category: "google", Description: "Flexbox Layout"},
		{Pattern: "com/google/crypto/", MatchType: MatchPrefix, Category: "google", Description: "Google Tink Crypto"},
		{Pattern: "com/google/firebase/", MatchType: MatchPrefix, Category: "google", Description: "Firebase"},
		{Pattern: "com/google/gson/", MatchType: MatchPrefix, Category: "google", Description: "Gson"},
		{Pattern: "com/google/protobuf/", MatchType: MatchPrefix, Category: "google", Description: "Protobuf"},
		{Pattern: "com/google/common/", MatchType: MatchPrefix, Category: "google", Description: "Guava"},

		// Kotlin
		{Pattern: "kotlin/", MatchType: MatchPrefix, Category: "kotlin", Description: "Kotlin stdlib"},
		{Pattern: "kotlinx/", MatchType: MatchPrefix, Category: "kotlin", Description: "Kotlin extensions"},

		// Networking
		{Pattern: "okhttp3/", MatchType: MatchPrefix, Category: "network", Description: "OkHttp3"},
		{Pattern: "okhttp/", MatchType: MatchPrefix, Category: "network", Description: "OkHttp"},
		{Pattern: "okio/", MatchType: MatchPrefix, Category: "network", Description: "Okio"},
		{Pattern: "retrofit2/", MatchType: MatchPrefix, Category: "network", Description: "Retrofit"},
		{Pattern: "com/squareup/", MatchType: MatchPrefix, Category: "network", Description: "Square libs"},

		// Reactive
		{Pattern: "io/reactivex/", MatchType: MatchPrefix, Category: "reactive", Description: "RxJava"},
		{Pattern: "rx/", MatchType: MatchPrefix, Category: "reactive", Description: "RxJava legacy"},
		{Pattern: "org/reactivestreams/", MatchType: MatchPrefix, Category: "reactive", Description: "Reactive Streams"},

		// Apache (гранулярно!)
		{Pattern: "org/apache/commons/lang/", MatchType: MatchPrefix, Category: "common", Description: "Apache Commons Lang"},
		{Pattern: "org/apache/commons/codec/", MatchType: MatchPrefix, Category: "common", Description: "Apache Commons Codec"},
		{Pattern: "org/apache/commons/io/", MatchType: MatchPrefix, Category: "common", Description: "Apache Commons IO"},
		{Pattern: "org/apache/commons/logging/", MatchType: MatchPrefix, Category: "common", Description: "Apache Commons Logging"},
		{
			Pattern: "org/apache/http/", MatchType: MatchPrefix,
			Category: "network", Description: "Apache HTTP Client",
			Dampening: ptrFloat64(0.5), // меньше гасим — может быть интересно
		},

		// Common libs
		{Pattern: "com/fasterxml/", MatchType: MatchPrefix, Category: "common", Description: "Jackson"},
		{Pattern: "com/bumptech/glide/", MatchType: MatchPrefix, Category: "common", Description: "Glide"},
		{Pattern: "com/baseflow/permissionhandler/", MatchType: MatchPrefix, Category: "common", Description: "PermissionHandler Flutter plugin"},
		{Pattern: "dagger/", MatchType: MatchPrefix, Category: "common", Description: "Dagger DI"},
		{Pattern: "javax/inject/", MatchType: MatchPrefix, Category: "common", Description: "JSR-330"},

		// Crypto
		{Pattern: "org/bouncycastle/", MatchType: MatchPrefix, Category: "crypto", Description: "BouncyCastle", Dampening: ptrFloat64(0.6)},
		{Pattern: "org/conscrypt/", MatchType: MatchPrefix, Category: "crypto", Description: "Conscrypt", Dampening: ptrFloat64(0.6)},

		// Game engines
		{Pattern: "com/unity3d/player/", MatchType: MatchPrefix, Category: "engine", Description: "Unity Player"},
		{Pattern: "com/unity3d/services/", MatchType: MatchPrefix, Category: "engine", Description: "Unity Services"},

		// Ad SDKs
		{Pattern: "com/applovin/", MatchType: MatchPrefix, Category: "ads_sdk", Description: "AppLovin SDK"},
		{Pattern: "com/ironsource/", MatchType: MatchPrefix, Category: "ads_sdk", Description: "IronSource SDK"},
		{Pattern: "com/unity3d/ads/", MatchType: MatchPrefix, Category: "ads_sdk", Description: "Unity Ads SDK"},
		{Pattern: "com/facebook/ads/", MatchType: MatchPrefix, Category: "ads_sdk", Description: "Facebook Ads SDK"},
		{Pattern: "com/google/android/gms/ads/", MatchType: MatchPrefix, Category: "ads_sdk", Description: "AdMob SDK"},

		// Analytics
		{Pattern: "com/appsflyer/", MatchType: MatchPrefix, Category: "analytics", Description: "AppsFlyer SDK"},
		{Pattern: "com/adjust/", MatchType: MatchPrefix, Category: "analytics", Description: "Adjust SDK"},
		{Pattern: "io/sentry/", MatchType: MatchPrefix, Category: "analytics", Description: "Sentry SDK"},

		// Social (гранулярно!)
		{Pattern: "com/facebook/internal/", MatchType: MatchPrefix, Category: "social", Description: "Facebook Internal"},
		{Pattern: "com/facebook/share/", MatchType: MatchPrefix, Category: "social", Description: "Facebook Share"},
		{Pattern: "com/facebook/login/", MatchType: MatchPrefix, Category: "social", Description: "Facebook Login"},
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// DEFAULT HIGH VALUE PATTERNS
// ═══════════════════════════════════════════════════════════════════════════════

func defaultHighValuePatterns() []HighValuePattern {
	return []HighValuePattern{
		// License
		{Pattern: "license", MatchType: MatchContains, Weight: 10, Category: "license", Priority: 10},
		{Pattern: "licence", MatchType: MatchContains, Weight: 10, Category: "license", Priority: 10},

		// Premium/Pro
		{Pattern: "premium", MatchType: MatchContains, Weight: 9, Category: "premium", Priority: 9},
		{Pattern: "pro", MatchType: MatchContains, Weight: 7, Category: "premium", Priority: 7},
		{Pattern: "vip", MatchType: MatchContains, Weight: 7, Category: "premium", Priority: 7},

		// Billing
		{Pattern: "billing", MatchType: MatchContains, Weight: 9, Category: "billing", Priority: 9},
		{Pattern: "purchase", MatchType: MatchContains, Weight: 9, Category: "billing", Priority: 9},
		{Pattern: "subscription", MatchType: MatchContains, Weight: 9, Category: "billing", Priority: 9},

		// Activation
		{Pattern: "unlock", MatchType: MatchContains, Weight: 8, Category: "activation", Priority: 8},
		{Pattern: "trial", MatchType: MatchContains, Weight: 8, Category: "activation", Priority: 8},
		{Pattern: "activate", MatchType: MatchContains, Weight: 8, Category: "activation", Priority: 8},
		{Pattern: "expire", MatchType: MatchContains, Weight: 7, Category: "activation", Priority: 7},

		// Ads
		{Pattern: "adfree", MatchType: MatchContains, Weight: 8, Category: "ads", Priority: 8},
		{Pattern: "noads", MatchType: MatchContains, Weight: 8, Category: "ads", Priority: 8},
		{Pattern: "removeads", MatchType: MatchContains, Weight: 8, Category: "ads", Priority: 8},

		// Piracy
		{Pattern: "crack", MatchType: MatchContains, Weight: 10, Category: "piracy", Priority: 10},
		{Pattern: "keygen", MatchType: MatchContains, Weight: 10, Category: "piracy", Priority: 10},
		{Pattern: "pirate", MatchType: MatchContains, Weight: 9, Category: "piracy", Priority: 9},

		// Verification (lower)
		{Pattern: "verify", MatchType: MatchContains, Weight: 5, Category: "verification", Priority: 5},
		{Pattern: "validate", MatchType: MatchContains, Weight: 5, Category: "verification", Priority: 5},
		{Pattern: "check", MatchType: MatchContains, Weight: 4, Category: "verification", Priority: 4},
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// DEFAULT KEYWORD WEIGHTS
// ═══════════════════════════════════════════════════════════════════════════════

func defaultKeywordWeights() map[string]KeywordConfig {
	return map[string]KeywordConfig{
		"license": {
			Weight: 10, Category: "license",
			Aliases: []string{"licence", "lic"}, Combinators: []string{"check", "verify", "valid", "manager"},
			MinBonus: 8, MaxBonus: 12, FilenameBonus: ptrInt(4),
		},
		"premium": {
			Weight: 9, Category: "premium",
			Combinators: []string{"user", "status", "check", "feature"},
			MinBonus:    7, MaxBonus: 11, FilenameBonus: ptrInt(3),
		},
		"billing": {
			Weight: 9, Category: "billing",
			Combinators: []string{"client", "manager", "helper", "service"},
			MinBonus:    7, MaxBonus: 11, FilenameBonus: ptrInt(3),
		},
		"purchase": {
			Weight: 9, Category: "billing",
			Combinators: []string{"verify", "validate", "check", "manager"},
			MinBonus:    7, MaxBonus: 11, FilenameBonus: ptrInt(3),
		},
		"subscription": {
			Weight: 9, Category: "billing",
			Combinators: []string{"status", "check", "manager"},
			MinBonus:    7, MaxBonus: 11, FilenameBonus: ptrInt(3),
		},
		"trial": {
			Weight: 8, Category: "activation",
			Combinators: []string{"expire", "end", "check", "period"},
			MinBonus:    6, MaxBonus: 10, FilenameBonus: ptrInt(3),
		},
		"unlock": {
			Weight: 8, Category: "activation",
			Combinators: []string{"feature", "premium", "full"},
			MinBonus:    6, MaxBonus: 10, FilenameBonus: ptrInt(3),
		},
		"pro": {
			Weight: 7, Category: "premium",
			Combinators: []string{"version", "user", "feature"},
			MinBonus:    5, MaxBonus: 9, FilenameBonus: ptrInt(2),
		},

		// Generic keywords
		"verify": {
			Weight: 5, Category: "verification",
			Combinators: []string{"license", "purchase", "signature"},
			MinBonus:    3, MaxBonus: 8, FilenameBonus: ptrInt(1), IsGeneric: true,
		},
		"validate": {
			Weight: 5, Category: "verification",
			Combinators: []string{"license", "purchase", "receipt"},
			MinBonus:    3, MaxBonus: 8, FilenameBonus: ptrInt(1), IsGeneric: true,
		},
		"check": {
			Weight: 4, Category: "verification",
			Combinators: []string{"license", "premium", "trial", "subscription"},
			MinBonus:    2, MaxBonus: 7, FilenameBonus: ptrInt(1), IsGeneric: true,
		},

		// Piracy
		"crack":  {Weight: 10, Category: "piracy", MinBonus: 10, MaxBonus: 12, FilenameBonus: ptrInt(5)},
		"keygen": {Weight: 10, Category: "piracy", MinBonus: 10, MaxBonus: 12, FilenameBonus: ptrInt(5)},
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// DEFAULT CONTEXT RULES
// ═══════════════════════════════════════════════════════════════════════════════

func defaultContextRules() []ContextRule {
	return []ContextRule{
		{
			Keyword: "pro", ContextContains: []string{"premium", "feature", "unlock", "paid"},
			Effect: "boost", Factor: 1.3,
			Description: "'pro' near premium-related paths → likely real pro feature",
		},
		{
			Keyword: "pro", ContextContains: []string{"http", "proxy", "protocol", "provider"},
			Effect: "dampen", Factor: 0.4,
			Description: "'pro' in HTTP context → likely isProxy/protocol",
		},
		{
			Keyword: "verify", ContextContains: []string{"license", "purchase", "signature"},
			Effect: "boost", Factor: 1.4,
			Description: "'verify' with license context → important verification",
		},
		{
			Keyword: "verify", ContextContains: []string{"ssl", "tls", "hostname", "certificate"},
			Effect: "dampen", Factor: 0.5,
			Description: "'verify' in SSL context → standard SSL verification",
		},
		{
			Keyword: "check", ContextContains: []string{"license", "premium", "subscription"},
			Effect: "boost", Factor: 1.3,
			Description: "'check' with monetization context → license check",
		},
		{
			Keyword: "expire", ContextContains: []string{"cache", "session", "cookie"},
			Effect: "dampen", Factor: 0.5,
			Description: "'expire' in cache context → normal expiry",
		},
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// DEFAULT OBFUSCATION PATTERNS
// ═══════════════════════════════════════════════════════════════════════════════

func defaultObfuscationPatterns() []ObfuscationPattern {
	return []ObfuscationPattern{
		{Name: "single_letter", Regex: `^[a-z]$`, Weight: 7, Description: "Single letter class (ProGuard/R8)"},
		{Name: "short_name", Regex: `^[a-z]{1,2}\d*$`, Weight: 6, Description: "Short obfuscated name"},
		{Name: "numbered", Regex: `^[a-z]+\d+$`, Weight: 5, Description: "Letter + number pattern"},
		{Name: "double_letter", Regex: `^(a{2,}|b{2,}|c{2,}|d{2,}|e{2,}|f{2,}|g{2,}|h{2,}|i{2,}|j{2,}|k{2,}|l{2,}|m{2,}|n{2,}|o{2,}|p{2,}|q{2,}|r{2,}|s{2,}|t{2,}|u{2,}|v{2,}|w{2,}|x{2,}|y{2,}|z{2,})$`, Weight: 6, Description: "Repeated letters (aa, bbb)"},
		{Name: "dexguard_unicode", Regex: `^[Il1\|]+$`, Weight: 8, Description: "DexGuard Il1| obfuscation"},
		{Name: "dexguard_oO", Regex: `^[oO0]+$`, Weight: 8, Description: "DexGuard oO0 obfuscation"},
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

func ptrFloat64(v float64) *float64 {
	return &v
}

func ptrInt(v int) *int {
	return &v
}
