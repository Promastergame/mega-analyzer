package filter

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// ═══════════════════════════════════════════════════════════════════════════════
// FILTER PROFILES v7.4.1
// ═══════════════════════════════════════════════════════════════════════════════
//
// Исправления:
//   1. Pointer-поля: используем ptrFloat64/ptrInt
//   2. Deep copy: полная изоляция между профилями
//   3. compile() вызывается после модификаций
//   4. HasPrefix вместо == для modern-prefix check
//   5. ProfileModifier интерфейс для расширяемости

type ProfileType string

const (
	ProfileStrict   ProfileType = "strict"
	ProfileBalanced ProfileType = "balanced"
	ProfileLoose    ProfileType = "loose"
	ProfileParanoid ProfileType = "paranoid"
	ProfileAudit    ProfileType = "audit"
)

// AllProfiles возвращает список всех доступных профилей
func AllProfiles() []ProfileType {
	return []ProfileType{
		ProfileStrict,
		ProfileBalanced,
		ProfileLoose,
		ProfileParanoid,
		ProfileAudit,
	}
}

// ProfileDescription возвращает описание профиля для UI/CLI
func ProfileDescription(profile ProfileType) string {
	switch profile {
	case ProfileStrict:
		return "Strict: Minimum false positives, high-confidence findings only"
	case ProfileBalanced:
		return "Balanced: Trade-off between precision and recall (default)"
	case ProfileLoose:
		return "Loose: Maximum findings, including weak signals"
	case ProfileParanoid:
		return "Paranoid: For old/suspicious APKs, less dampening, more scrutiny"
	case ProfileAudit:
		return "Audit: Show everything including libraries, for manual review"
	default:
		return "Unknown profile"
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// PROFILE MODIFIER INTERFACE — для кастомных профилей
// ═══════════════════════════════════════════════════════════════════════════════

// ProfileModifier позволяет создавать кастомные профили
type ProfileModifier interface {
	// Name возвращает имя профиля
	Name() string
	// Description возвращает описание
	Description() string
	// Apply модифицирует правила и возвращает новую копию
	Apply(rules FilterRules) FilterRules
}

// BuiltinModifier реализует ProfileModifier для встроенных профилей
type BuiltinModifier struct {
	name        string
	description string
	applyFunc   func(FilterRules) FilterRules
}

func (m *BuiltinModifier) Name() string                        { return m.name }
func (m *BuiltinModifier) Description() string                 { return m.description }
func (m *BuiltinModifier) Apply(rules FilterRules) FilterRules { return m.applyFunc(rules) }

// GetModifier возвращает модификатор для профиля
func GetModifier(profile ProfileType) ProfileModifier {
	switch profile {
	case ProfileStrict:
		return &BuiltinModifier{"strict", ProfileDescription(ProfileStrict), applyStrictProfile}
	case ProfileLoose:
		return &BuiltinModifier{"loose", ProfileDescription(ProfileLoose), applyLooseProfile}
	case ProfileParanoid:
		return &BuiltinModifier{"paranoid", ProfileDescription(ProfileParanoid), applyParanoidProfile}
	case ProfileAudit:
		return &BuiltinModifier{"audit", ProfileDescription(ProfileAudit), applyAuditProfile}
	default:
		return &BuiltinModifier{"balanced", ProfileDescription(ProfileBalanced), func(r FilterRules) FilterRules { return r }}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// GET PROFILE — возвращает правила для профиля
// ═══════════════════════════════════════════════════════════════════════════════

func GetProfile(profile ProfileType) FilterRules {
	// 🆕 Получаем ГЛУБОКУЮ копию default rules
	defaultRules := DefaultRules()
	base := defaultRules.DeepCopy()

	// 🆕 Сначала нормализуем — чтобы Category были в lowercase
	base.normalize()

	var result FilterRules
	switch profile {
	case ProfileStrict:
		result = applyStrictProfile(*base)
	case ProfileLoose:
		result = applyLooseProfile(*base)
	case ProfileParanoid:
		result = applyParanoidProfile(*base)
	case ProfileAudit:
		result = applyAuditProfile(*base)
	default:
		result = *base
	}

	// 🆕 Компилируем regex ПОСЛЕ всех модификаций
	result.compile()

	return result
}

// ═══════════════════════════════════════════════════════════════════════════════
// DEEP COPY — полная изоляция между профилями
// ═══════════════════════════════════════════════════════════════════════════════

// DeepCopy создаёт полностью независимую копию FilterRules
func (r *FilterRules) DeepCopy() *FilterRules {
	if r == nil {
		return nil
	}

	copy := &FilterRules{
		Metadata:   r.Metadata,
		compiledMu: &sync.RWMutex{}, // fresh mutex per copy
		// compiled: false — compile() будет вызван позже в GetProfile()
	}

	// Deep copy Scoring (с pointer-полями)
	copy.Scoring = deepCopyScoring(r.Scoring)

	// Deep copy StandardLibraries
	if len(r.StandardLibraries) > 0 {
		copy.StandardLibraries = make([]LibraryPattern, len(r.StandardLibraries))
		for i, lib := range r.StandardLibraries {
			copy.StandardLibraries[i] = deepCopyLibraryPattern(lib)
		}
	}

	// Deep copy SafeLibraryPatterns
	if len(r.SafeLibraryPatterns) > 0 {
		copy.SafeLibraryPatterns = make([]SafeLibraryPattern, len(r.SafeLibraryPatterns))
		for i, sp := range r.SafeLibraryPatterns {
			copy.SafeLibraryPatterns[i] = deepCopySafeLibraryPattern(sp)
		}
	}

	// Deep copy HighValuePatterns
	if len(r.HighValuePatterns) > 0 {
		copy.HighValuePatterns = make([]HighValuePattern, len(r.HighValuePatterns))
		for i, hvp := range r.HighValuePatterns {
			copy.HighValuePatterns[i] = hvp // struct без slices/maps
		}
	}

	// Deep copy KeywordWeights (map!)
	if len(r.KeywordWeights) > 0 {
		copy.KeywordWeights = make(map[string]KeywordConfig, len(r.KeywordWeights))
		for k, v := range r.KeywordWeights {
			copy.KeywordWeights[k] = deepCopyKeywordConfig(v)
		}
	}

	// Deep copy ContextRules
	if len(r.ContextRules) > 0 {
		copy.ContextRules = make([]ContextRule, len(r.ContextRules))
		for i, cr := range r.ContextRules {
			copy.ContextRules[i] = deepCopyContextRule(cr)
		}
	}

	// Deep copy ObfuscationPatterns
	if len(r.ObfuscationPatterns) > 0 {
		copy.ObfuscationPatterns = make([]ObfuscationPattern, len(r.ObfuscationPatterns))
		for i, op := range r.ObfuscationPatterns {
			copy.ObfuscationPatterns[i] = op // compiled regexp будет nil — OK, compile() вызовется позже
		}
	}

	return copy
}

func deepCopyScoring(s ScoringConfig) ScoringConfig {
	copy := s

	// Deep copy pointer fields
	if s.CombinationMultiplier != nil {
		v := *s.CombinationMultiplier
		copy.CombinationMultiplier = &v
	}
	if s.DefaultLibraryDampening != nil {
		v := *s.DefaultLibraryDampening
		copy.DefaultLibraryDampening = &v
	}
	if s.DampeningFloor != nil {
		v := *s.DampeningFloor
		copy.DampeningFloor = &v
	}
	if s.DampeningCeiling != nil {
		v := *s.DampeningCeiling
		copy.DampeningCeiling = &v
	}
	if s.GenericPenaltyCap != nil {
		v := *s.GenericPenaltyCap
		copy.GenericPenaltyCap = &v
	}
	if s.DefaultFilenameBonus != nil {
		v := *s.DefaultFilenameBonus
		copy.DefaultFilenameBonus = &v
	}
	if s.CorrelationBoost != nil {
		v := *s.CorrelationBoost
		copy.CorrelationBoost = &v
	}

	return copy
}

func deepCopyLibraryPattern(lib LibraryPattern) LibraryPattern {
	copy := lib

	if len(lib.Exceptions) > 0 {
		copy.Exceptions = make([]string, len(lib.Exceptions))
		builtinCopy(copy.Exceptions, lib.Exceptions)
	}

	if lib.Dampening != nil {
		v := *lib.Dampening
		copy.Dampening = &v
	}

	return copy
}

func deepCopySafeLibraryPattern(sp SafeLibraryPattern) SafeLibraryPattern {
	copy := sp

	if len(sp.SafeKeywords) > 0 {
		copy.SafeKeywords = make([]string, len(sp.SafeKeywords))
		builtinCopy(copy.SafeKeywords, sp.SafeKeywords)
	}

	if sp.Dampening != nil {
		v := *sp.Dampening
		copy.Dampening = &v
	}

	return copy
}

func deepCopyKeywordConfig(kc KeywordConfig) KeywordConfig {
	copy := kc

	if len(kc.Aliases) > 0 {
		copy.Aliases = make([]string, len(kc.Aliases))
		builtinCopy(copy.Aliases, kc.Aliases)
	}

	if len(kc.Combinators) > 0 {
		copy.Combinators = make([]string, len(kc.Combinators))
		builtinCopy(copy.Combinators, kc.Combinators)
	}

	if kc.FilenameBonus != nil {
		v := *kc.FilenameBonus
		copy.FilenameBonus = &v
	}

	return copy
}

func deepCopyContextRule(cr ContextRule) ContextRule {
	copy := cr

	if len(cr.ContextContains) > 0 {
		copy.ContextContains = make([]string, len(cr.ContextContains))
		builtinCopy(copy.ContextContains, cr.ContextContains)
	}

	return copy
}

// ═══════════════════════════════════════════════════════════════════════════════
// STRICT PROFILE — минимум ложных срабатываний
// ═══════════════════════════════════════════════════════════════════════════════

func applyStrictProfile(rules FilterRules) FilterRules {
	// ── Добавляем библиотечные паттерны ──────────────────────────
	additionalLibraries := []LibraryPattern{
		{Pattern: "com/facebook/common/", MatchType: MatchPrefix, Category: "social", Description: "Facebook Common"},
		{Pattern: "com/facebook/datasource/", MatchType: MatchPrefix, Category: "social", Description: "Facebook DataSource"},
		{Pattern: "io/fabric/", MatchType: MatchPrefix, Category: "analytics", Description: "Fabric SDK"},
		{Pattern: "com/android/support/", MatchType: MatchPrefix, Category: "sdk", Description: "Android Support Library"},
		{Pattern: "android/support/", MatchType: MatchPrefix, Category: "sdk", Description: "Android Support Library v2"},
	}
	rules.StandardLibraries = append(rules.StandardLibraries, additionalLibraries...)

	// ── Повышаем базовый importance ──────────────────────────────
	rules.Scoring.BaseImportance = 3

	// ── 🆕 Усиливаем dampening через pointer ─────────────────────
	rules.Scoring.DefaultLibraryDampening = ptrFloat64(0.3)

	// ── Удаляем низковесовые keywords ────────────────────────────
	lowWeightKeywords := []string{"check", "validate", "flag", "enable", "disable"}
	for _, kw := range lowWeightKeywords {
		delete(rules.KeywordWeights, kw)
	}

	// ── Повышаем веса важных keywords ────────────────────────────
	highPriorityKeywords := []string{"license", "billing", "purchase", "subscription", "premium"}
	for _, kw := range highPriorityKeywords {
		if config, ok := rules.KeywordWeights[kw]; ok {
			config.Weight += 2
			config.MinBonus += 2
			rules.KeywordWeights[kw] = config
		}
	}

	// ── Оставляем только boost context rules ─────────────────────
	filteredContextRules := make([]ContextRule, 0, len(rules.ContextRules))
	for _, cr := range rules.ContextRules {
		if cr.Effect == "boost" {
			filteredContextRules = append(filteredContextRules, cr)
		}
	}
	rules.ContextRules = filteredContextRules

	return rules
}

// ═══════════════════════════════════════════════════════════════════════════════
// LOOSE PROFILE — максимум находок
// ═══════════════════════════════════════════════════════════════════════════════

func applyLooseProfile(rules FilterRules) FilterRules {
	// ── Оставляем только критичные библиотеки ────────────────────
	// 🆕 Категории уже lowercase после normalize()
	criticalCategories := map[string]bool{
		"sdk":    true,
		"kotlin": true,
		"google": true,
	}

	filteredLibraries := make([]LibraryPattern, 0, len(rules.StandardLibraries)/2)
	for _, lib := range rules.StandardLibraries {
		// 🆕 Категория уже lowercase
		if criticalCategories[lib.Category] {
			filteredLibraries = append(filteredLibraries, lib)
		}
	}
	rules.StandardLibraries = filteredLibraries

	// ── Понижаем базовый importance ──────────────────────────────
	rules.Scoring.BaseImportance = 6

	// ── 🆕 Ослабляем dampening через pointer ─────────────────────
	rules.Scoring.DefaultLibraryDampening = ptrFloat64(0.6)
	rules.Scoring.DampeningFloor = ptrFloat64(0.3)

	// ── Добавляем дополнительные keywords ────────────────────────
	additionalKeywords := map[string]KeywordConfig{
		"feature": {
			Weight: 4, Category: "feature",
			Combinators: []string{"flag", "toggle", "enable"},
			MinBonus:    2, MaxBonus: 6, FilenameBonus: ptrInt(2),
		},
		"config": {
			Weight: 3, Category: "config",
			Combinators: []string{"remote", "feature", "flag"},
			MinBonus:    1, MaxBonus: 5, FilenameBonus: ptrInt(2),
		},
		"gate": {
			Weight: 4, Category: "feature",
			Combinators: []string{"feature", "premium", "pro"},
			MinBonus:    2, MaxBonus: 6, FilenameBonus: ptrInt(2),
		},
		"entitlement": {
			Weight: 7, Category: "billing",
			Combinators: []string{"check", "verify", "manager"},
			MinBonus:    5, MaxBonus: 9, FilenameBonus: ptrInt(3),
		},
	}
	for k, v := range additionalKeywords {
		rules.KeywordWeights[k] = v
	}

	return rules
}

// ═══════════════════════════════════════════════════════════════════════════════
// PARANOID PROFILE — для старых/подозрительных APK
// ═══════════════════════════════════════════════════════════════════════════════

func applyParanoidProfile(rules FilterRules) FilterRules {
	// ── Убираем современные библиотеки ───────────────────────────
	// 🆕 Используем HasPrefix вместо ==
	modernPrefixes := []string{
		"androidx/",
		"com/google/firebase/",
		"kotlin/",
		"kotlinx/",
		"io/reactivex/",
		"com/google/android/material/",
		"com/google/android/play/",
	}

	isModern := func(pattern string) bool {
		// 🆕 Нормализуем для сравнения
		patternLower := strings.ToLower(pattern)
		patternLower = strings.TrimPrefix(patternLower, "smali/")

		for _, prefix := range modernPrefixes {
			// 🆕 HasPrefix вместо ==
			if strings.HasPrefix(patternLower, prefix) {
				return true
			}
		}
		return false
	}

	filteredLibraries := make([]LibraryPattern, 0, len(rules.StandardLibraries))
	for _, lib := range rules.StandardLibraries {
		if !isModern(lib.Pattern) {
			filteredLibraries = append(filteredLibraries, lib)
		}
	}
	rules.StandardLibraries = filteredLibraries

	// ── Добавляем старые SDK как высокоценные паттерны ───────────
	oldSDKPatterns := []HighValuePattern{
		{Pattern: "mobclix", MatchType: MatchContains, Weight: 5, Category: "old_ads", Priority: 5},
		{Pattern: "millennial", MatchType: MatchContains, Weight: 5, Category: "old_ads", Priority: 5},
		{Pattern: "admob", MatchType: MatchContains, Weight: 4, Category: "old_ads", Priority: 4},
		{Pattern: "flurry", MatchType: MatchContains, Weight: 4, Category: "old_analytics", Priority: 4},
	}
	rules.HighValuePatterns = append(rules.HighValuePatterns, oldSDKPatterns...)

	// ── 🆕 Минимальное гашение через pointer ─────────────────────
	rules.Scoring.DefaultLibraryDampening = ptrFloat64(0.6)
	rules.Scoring.DampeningFloor = ptrFloat64(0.3)

	// ── Повышаем внимание к крипто ───────────────────────────────
	cryptoDampening := 0.8
	for i := range rules.StandardLibraries {
		if rules.StandardLibraries[i].Category == "crypto" {
			rules.StandardLibraries[i].Dampening = &cryptoDampening
		}
	}

	// ── Добавляем keywords для подозрительного поведения ─────────
	suspiciousKeywords := map[string]KeywordConfig{
		"reflection": {
			Weight: 6, Category: "suspicious",
			MinBonus: 4, MaxBonus: 8, FilenameBonus: ptrInt(3),
		},
		"invoke": {
			Weight: 5, Category: "suspicious",
			Combinators: []string{"method", "dynamic"},
			MinBonus:    3, MaxBonus: 7, FilenameBonus: ptrInt(2),
		},
		"classloader": {
			Weight: 7, Category: "suspicious",
			MinBonus: 5, MaxBonus: 9, FilenameBonus: ptrInt(4),
		},
		"dexclassloader": {
			Weight: 8, Category: "suspicious",
			MinBonus: 6, MaxBonus: 10, FilenameBonus: ptrInt(5),
		},
		"native": {
			Weight: 5, Category: "native",
			Combinators: []string{"load", "library"},
			MinBonus:    3, MaxBonus: 7, FilenameBonus: ptrInt(2),
		},
		"socket": {
			Weight: 5, Category: "network",
			Combinators: []string{"connect", "server", "client"},
			MinBonus:    3, MaxBonus: 7, FilenameBonus: ptrInt(2),
		},
		"root": {
			Weight: 6, Category: "suspicious",
			Combinators: []string{"check", "detect", "su"},
			MinBonus:    4, MaxBonus: 8, FilenameBonus: ptrInt(3),
		},
		"emulator": {
			Weight: 6, Category: "suspicious",
			Combinators: []string{"check", "detect"},
			MinBonus:    4, MaxBonus: 8, FilenameBonus: ptrInt(3),
		},
		"debugger": {
			Weight: 6, Category: "suspicious",
			Combinators: []string{"check", "detect", "attached"},
			MinBonus:    4, MaxBonus: 8, FilenameBonus: ptrInt(3),
		},
	}
	for k, v := range suspiciousKeywords {
		rules.KeywordWeights[k] = v
	}

	// ── Повышаем базовый importance ──────────────────────────────
	rules.Scoring.BaseImportance = 6

	return rules
}

// ═══════════════════════════════════════════════════════════════════════════════
// AUDIT PROFILE — показываем ВСЁ
// ═══════════════════════════════════════════════════════════════════════════════

func applyAuditProfile(rules FilterRules) FilterRules {
	// ── Убираем ВСЕ библиотечные исключения ──────────────────────
	rules.StandardLibraries = nil

	// ── Максимальный базовый importance ──────────────────────────
	rules.Scoring.BaseImportance = 7
	rules.Scoring.StandardLibraryScore = 3

	// ── 🆕 Отключаем dampening через pointer ─────────────────────
	rules.Scoring.DefaultLibraryDampening = ptrFloat64(1.0)
	rules.Scoring.DampeningFloor = ptrFloat64(1.0)

	return rules
}

// ═══════════════════════════════════════════════════════════════════════════════
// PROFILE VALIDATION
// ═══════════════════════════════════════════════════════════════════════════════

func IsValidProfile(profile ProfileType) bool {
	switch profile {
	case ProfileStrict, ProfileBalanced, ProfileLoose, ProfileParanoid, ProfileAudit:
		return true
	default:
		return false
	}
}

func ParseProfile(s string) (ProfileType, bool) {
	p := ProfileType(strings.ToLower(strings.TrimSpace(s)))
	if IsValidProfile(p) {
		return p, true
	}
	return ProfileBalanced, false
}

// ═══════════════════════════════════════════════════════════════════════════════
// CUSTOM PROFILE BUILDER — для создания кастомных профилей
// ═══════════════════════════════════════════════════════════════════════════════

// ProfileBuilder позволяет создавать кастомные профили декларативно
type ProfileBuilder struct {
	base      ProfileType
	modifiers []func(*FilterRules)
}

// NewProfileBuilder создаёт builder на основе базового профиля
func NewProfileBuilder(base ProfileType) *ProfileBuilder {
	return &ProfileBuilder{
		base:      base,
		modifiers: make([]func(*FilterRules), 0, 4),
	}
}

// WithBaseImportance устанавливает базовый importance
func (b *ProfileBuilder) WithBaseImportance(v int) *ProfileBuilder {
	b.modifiers = append(b.modifiers, func(r *FilterRules) {
		r.Scoring.BaseImportance = v
	})
	return b
}

// WithDampening устанавливает dampening параметры
func (b *ProfileBuilder) WithDampening(defaultVal, floor, ceiling float64) *ProfileBuilder {
	b.modifiers = append(b.modifiers, func(r *FilterRules) {
		r.Scoring.DefaultLibraryDampening = ptrFloat64(defaultVal)
		r.Scoring.DampeningFloor = ptrFloat64(floor)
		r.Scoring.DampeningCeiling = ptrFloat64(ceiling)
	})
	return b
}

// WithoutLibraries удаляет библиотеки по категории
func (b *ProfileBuilder) WithoutLibraries(categories ...string) *ProfileBuilder {
	catSet := make(map[string]bool, len(categories))
	for _, c := range categories {
		catSet[strings.ToLower(c)] = true
	}

	b.modifiers = append(b.modifiers, func(r *FilterRules) {
		filtered := make([]LibraryPattern, 0, len(r.StandardLibraries))
		for _, lib := range r.StandardLibraries {
			if !catSet[lib.Category] {
				filtered = append(filtered, lib)
			}
		}
		r.StandardLibraries = filtered
	})
	return b
}

// WithKeyword добавляет или обновляет keyword
func (b *ProfileBuilder) WithKeyword(name string, config KeywordConfig) *ProfileBuilder {
	b.modifiers = append(b.modifiers, func(r *FilterRules) {
		// 🆕 Нормализуем config перед добавлением
		normalized := normalizeKeywordConfig(config)
		r.KeywordWeights[strings.ToLower(strings.TrimSpace(name))] = normalized
	})
	return b
}

// normalizeKeywordConfig приводит все строковые поля к lowercase
func normalizeKeywordConfig(kc KeywordConfig) KeywordConfig {
	kc.Category = strings.ToLower(strings.TrimSpace(kc.Category))

	if len(kc.Aliases) > 0 {
		for i := range kc.Aliases {
			kc.Aliases[i] = strings.ToLower(strings.TrimSpace(kc.Aliases[i]))
		}
	}

	if len(kc.Combinators) > 0 {
		for i := range kc.Combinators {
			kc.Combinators[i] = strings.ToLower(strings.TrimSpace(kc.Combinators[i]))
		}
	}

	return kc
}

// WithoutKeywords удаляет keywords
func (b *ProfileBuilder) WithoutKeywords(names ...string) *ProfileBuilder {
	b.modifiers = append(b.modifiers, func(r *FilterRules) {
		for _, name := range names {
			delete(r.KeywordWeights, strings.ToLower(name))
		}
	})
	return b
}

// Build создаёт финальные правила
func (b *ProfileBuilder) Build() FilterRules {
	rules := GetProfile(b.base)

	for _, mod := range b.modifiers {
		mod(&rules)
	}

	// 🆕 normalize после модификаций (чтобы новые keywords были lowercase)
	rules.normalize()

	// 🆕 Сбрасываем compiled flag чтобы compile() пересобрал
	rules.ensureCompiledMu()
	rules.compiledMu.Lock()
	rules.compiled = false
	rules.compiledMu.Unlock()

	rules.compile()

	return rules
}

// ═══════════════════════════════════════════════════════════════════════════════
// PROFILE COMPARISON — для дебага
// ═══════════════════════════════════════════════════════════════════════════════

// ProfileDiff описывает разницу между двумя профилями
type ProfileDiff struct {
	AddedLibraries   []string
	RemovedLibraries []string
	AddedKeywords    []string
	RemovedKeywords  []string
	ScoringChanges   map[string]string // "field" → "old → new"
}

// CompareProfiles возвращает различия между двумя профилями
func CompareProfiles(a, b ProfileType) ProfileDiff {
	rulesA := GetProfile(a)
	rulesB := GetProfile(b)

	diff := ProfileDiff{
		ScoringChanges: make(map[string]string),
	}

	// Libraries
	libsA := make(map[string]bool)
	for _, lib := range rulesA.StandardLibraries {
		libsA[lib.Pattern] = true
	}
	libsB := make(map[string]bool)
	for _, lib := range rulesB.StandardLibraries {
		libsB[lib.Pattern] = true
	}

	for lib := range libsB {
		if !libsA[lib] {
			diff.AddedLibraries = append(diff.AddedLibraries, lib)
		}
	}
	for lib := range libsA {
		if !libsB[lib] {
			diff.RemovedLibraries = append(diff.RemovedLibraries, lib)
		}
	}

	// Keywords
	for kw := range rulesB.KeywordWeights {
		if _, ok := rulesA.KeywordWeights[kw]; !ok {
			diff.AddedKeywords = append(diff.AddedKeywords, kw)
		}
	}
	for kw := range rulesA.KeywordWeights {
		if _, ok := rulesB.KeywordWeights[kw]; !ok {
			diff.RemovedKeywords = append(diff.RemovedKeywords, kw)
		}
	}

	// 🆕 Полное сравнение Scoring
	sA := &rulesA.Scoring
	sB := &rulesB.Scoring

	compareInt := func(name string, a, b int) {
		if a != b {
			diff.ScoringChanges[name] = fmt.Sprintf("%d → %d", a, b)
		}
	}

	compareFloat := func(name string, a, b float64) {
		if a != b {
			diff.ScoringChanges[name] = fmt.Sprintf("%.2f → %.2f", a, b)
		}
	}

	compareInt("BaseImportance", sA.BaseImportance, sB.BaseImportance)
	compareInt("MinImportance", sA.MinImportance, sB.MinImportance)
	compareInt("MaxImportance", sA.MaxImportance, sB.MaxImportance)
	compareInt("StandardLibraryScore", sA.StandardLibraryScore, sB.StandardLibraryScore)
	compareInt("ObfuscationBonus", sA.ObfuscationBonus, sB.ObfuscationBonus)
	compareInt("AppPackageBonus", sA.AppPackageBonus, sB.AppPackageBonus)

	compareFloat("CombinationMultiplier", sA.GetCombinationMultiplier(), sB.GetCombinationMultiplier())
	compareFloat("DefaultLibraryDampening", sA.GetDefaultLibraryDampening(), sB.GetDefaultLibraryDampening())
	compareFloat("DampeningFloor", sA.GetDampeningFloor(), sB.GetDampeningFloor())
	compareFloat("DampeningCeiling", sA.GetDampeningCeiling(), sB.GetDampeningCeiling())
	compareFloat("CorrelationBoost", sA.GetCorrelationBoost(), sB.GetCorrelationBoost())

	compareInt("GenericPenaltyCap", sA.GetGenericPenaltyCap(), sB.GetGenericPenaltyCap())
	compareInt("DefaultFilenameBonus", sA.GetDefaultFilenameBonus(), sB.GetDefaultFilenameBonus())

	// Сортируем для детерминированного вывода
	sort.Strings(diff.AddedLibraries)
	sort.Strings(diff.RemovedLibraries)
	sort.Strings(diff.AddedKeywords)
	sort.Strings(diff.RemovedKeywords)

	return diff
}
