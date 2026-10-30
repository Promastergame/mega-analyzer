package filter

import (
	"fmt"
	"strings"
	"unicode"
)

// ═══════════════════════════════════════════════════════════════════════════════
// SIGNAL STRENGTH — уровень силы сигнала
// ═══════════════════════════════════════════════════════════════════════════════
//
// Разделяет сигналы по силе для более точного анализа:
//   Weak:     "check" в пути → вес 1-3
//   Medium:   "trial" в пути → вес 4-6
//   Strong:   "license" в имени файла → вес 7-8
//   Critical: "license" + "verify" + app package → вес 9-10

type SignalStrength int

const (
	SignalWeak     SignalStrength = iota // 1-3: общие keywords, слабые совпадения
	SignalMedium                         // 4-6: специфичные keywords, контекст
	SignalStrong                         // 7-8: high-value, комбинации
	SignalCritical                       // 9-10: множественные сильные сигналы
)

func (s SignalStrength) String() string {
	switch s {
	case SignalWeak:
		return "Weak"
	case SignalMedium:
		return "Medium"
	case SignalStrong:
		return "Strong"
	case SignalCritical:
		return "Critical"
	default:
		return "Unknown"
	}
}

func strengthFromScore(score int) SignalStrength {
	switch {
	case score >= 9:
		return SignalCritical
	case score >= 7:
		return SignalStrong
	case score >= 4:
		return SignalMedium
	default:
		return SignalWeak
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// SIGNAL CATEGORIES — структурные vs семантические vs контекстные
// ═══════════════════════════════════════════════════════════════════════════════
//
// Structural:  path, library, obfuscation → объективные факты о файле
// Semantic:    keywords, combos → смысловое содержание
// Contextual:  app package, filename, position → где находится

type SignalCategory int

const (
	SignalStructural SignalCategory = iota
	SignalSemantic
	SignalContextual
)

// ═══════════════════════════════════════════════════════════════════════════════
// CLASSIFICATION RESULT
// ═══════════════════════════════════════════════════════════════════════════════

type ClassificationResult struct {
	Path              string
	IsAppCode         bool
	IsLibrary         bool
	Importance        int            // ПОСЛЕ dampening (финальный score)
	RawImportance     int            // 🆕 ДО dampening (исходная сила сигнала)
	Confidence        float64        // 0.0 - 1.0: насколько уверены в результате
	RawStrength       SignalStrength // 🆕 сила до гашения
	EffectiveStrength SignalStrength // 🆕 сила после гашения (то, что видит пользователь)

	// Детали (lazy — nil пока не нужны)
	Reasons    []ClassificationReason
	Categories []string

	// Совпадения
	MatchedLibrary   *LibraryPattern
	MatchedKeywords  []KeywordMatch
	MatchedHighValue []HighValuePattern
	ObfuscationType  string

	// Dampening tracking
	TotalDampening   float64
	DampeningSources []string
}

// addReason добавляет причину с lazy-init слайса
func (r *ClassificationResult) addReason(reason ClassificationReason) {
	r.Reasons = append(r.Reasons, reason)
}

// addCategory добавляет категорию с дедупликацией
func (r *ClassificationResult) addCategory(cat string) {
	for _, c := range r.Categories {
		if c == cat {
			return
		}
	}
	r.Categories = append(r.Categories, cat)
}

// ═══════════════════════════════════════════════════════════════════════════════
// CLASSIFICATION REASON
// ═══════════════════════════════════════════════════════════════════════════════

type ClassificationReason struct {
	Type        ReasonType
	Description string
	Impact      int
	Category    SignalCategory // 🆕 structural/semantic/contextual
}

type ReasonType string

const (
	ReasonStandardLibrary ReasonType = "standard_library"
	ReasonHighValuePath   ReasonType = "high_value_path"
	ReasonKeyword         ReasonType = "keyword"
	ReasonKeywordCombo    ReasonType = "keyword_combination"
	ReasonObfuscation     ReasonType = "obfuscation"
	ReasonAppPackage      ReasonType = "app_package"
	ReasonException       ReasonType = "exception"
	ReasonSafeKeyword     ReasonType = "safe_keyword"
	ReasonContextAdjust   ReasonType = "context_adjust"
	ReasonDampening       ReasonType = "dampening"
	ReasonCorrelation     ReasonType = "correlation" // 🆕
)

type KeywordMatch struct {
	Keyword     string
	Config      KeywordConfig
	Bonus       int
	Combinators []string
	Context     KeywordContext
	Dampened    bool
	Strength    SignalStrength // 🆕
}

// ═══════════════════════════════════════════════════════════════════════════════
// KEYWORD CONTEXT
// ═══════════════════════════════════════════════════════════════════════════════

type KeywordContext int

const (
	ContextUnknown KeywordContext = iota
	ContextFileName
	ContextPackagePath
	ContextLibraryPath
)

func (c KeywordContext) String() string {
	switch c {
	case ContextFileName:
		return "FileName"
	case ContextPackagePath:
		return "PackagePath"
	case ContextLibraryPath:
		return "LibraryPath"
	default:
		return "Unknown"
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// PATH RELIABILITY — для умной проверки обфускации
// ═══════════════════════════════════════════════════════════════════════════════
//
// Fix #4: a/b/c/LicenseManager.smali
//   3 обфусцированных сегмента, НО "LicenseManager" = 14 символов = читаемый!
//   → Путь ЧАСТИЧНО надёжен для контекста!
//
// Три уровня:
//   Reliable    — большинство сегментов читаемые → контекст работает полностью
//   Partial     — есть хотя бы один длинный читаемый → контекст для filename
//   Unreliable  — всё обфусцировано → контекст отключён

type PathReliability int

const (
	PathReliable   PathReliability = iota // контекст полностью надёжен
	PathPartial                           // контекст только для filename
	PathUnreliable                        // контекст отключён
)

func (p PathReliability) String() string {
	switch p {
	case PathReliable:
		return "Reliable"
	case PathPartial:
		return "Partial"
	case PathUnreliable:
		return "Unreliable"
	default:
		return "Unknown"
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// EXPLAINABILITY TRACE
// ═══════════════════════════════════════════════════════════════════════════════

type ExplainTrace struct {
	File  string         `json:"file"`
	Steps []ExplainStep  `json:"steps"`
	Final ExplainSummary `json:"final"`
}

type ExplainStep struct {
	Phase     string  `json:"phase"`
	Action    string  `json:"action"`
	Pattern   string  `json:"pattern,omitempty"`
	Before    int     `json:"before,omitempty"`
	After     int     `json:"after,omitempty"`
	Dampening float64 `json:"dampening,omitempty"`
	Reason    string  `json:"reason"`
}

type ExplainSummary struct {
	FinalImportance   int            `json:"final_importance"`
	RawImportance     int            `json:"raw_importance"`
	FinalConfidence   float64        `json:"final_confidence"`
	TotalDampening    float64        `json:"total_dampening"`
	RawStrength       SignalStrength `json:"raw_strength"`       // 🆕
	EffectiveStrength SignalStrength `json:"effective_strength"` // 🆕
	KeyDecisions      []string       `json:"key_decisions"`
}

func newExplainTrace(file string) *ExplainTrace {
	return &ExplainTrace{
		File:  file,
		Steps: make([]ExplainStep, 0, 8),
	}
}

func (t *ExplainTrace) log(phase, action, pattern, reason string) {
	if t == nil {
		return
	}
	t.Steps = append(t.Steps, ExplainStep{
		Phase:   phase,
		Action:  action,
		Pattern: pattern,
		Reason:  reason,
	})
}

func (t *ExplainTrace) logWithImpact(phase, action, pattern, reason string, before, after int, dampening float64) {
	if t == nil {
		return
	}
	t.Steps = append(t.Steps, ExplainStep{
		Phase:     phase,
		Action:    action,
		Pattern:   pattern,
		Before:    before,
		After:     after,
		Dampening: dampening,
		Reason:    reason,
	})
}

func (t *ExplainTrace) finalize(result *ClassificationResult) {
	if t == nil {
		return
	}
	t.Final = ExplainSummary{
		FinalImportance:   result.Importance,
		RawImportance:     result.RawImportance,
		FinalConfidence:   result.Confidence,
		TotalDampening:    result.TotalDampening,
		RawStrength:       result.RawStrength,
		EffectiveStrength: result.EffectiveStrength,
	}

	for _, step := range t.Steps {
		switch step.Action {
		case "dampened", "safe_dampened", "context_dampened",
			"context_boost", "combo_boost", "multi_high_value_boost",
			"critical_match", "exception", "correlation_boost",
			"partial_context", "same_word_skip", "boosted":
			decision := fmt.Sprintf("[%s] %s: %s", step.Phase, step.Action, step.Reason)
			t.Final.KeyDecisions = append(t.Final.KeyDecisions, decision)
		}
	}

	if len(t.Final.KeyDecisions) > 5 {
		t.Final.KeyDecisions = t.Final.KeyDecisions[:5]
	}
}

func (t *ExplainTrace) String() string {
	if t == nil {
		return ""
	}

	var sb strings.Builder
	sb.Grow(512)

	sb.WriteString(fmt.Sprintf("\n═══ EXPLAIN: %s ═══\n\n", t.File))

	for i, step := range t.Steps {
		sb.WriteString(fmt.Sprintf("Step %d: [%s] %s", i+1, step.Phase, step.Action))
		if step.Pattern != "" {
			sb.WriteString(fmt.Sprintf(" | pattern=%s", step.Pattern))
		}
		if step.Before != 0 || step.After != 0 {
			sb.WriteString(fmt.Sprintf(" | %d→%d", step.Before, step.After))
		}
		if step.Dampening != 0 {
			sb.WriteString(fmt.Sprintf(" | dampening=%.2f", step.Dampening))
		}
		sb.WriteString(fmt.Sprintf("\n         %s\n", step.Reason))
	}

	sb.WriteString(fmt.Sprintf(
		"\nSUMMARY: importance=%d (raw=%d) confidence=%.0f%% dampening=%.2f\n"+
			"         rawStrength=%s effectiveStrength=%s\n",
		t.Final.FinalImportance, t.Final.RawImportance,
		t.Final.FinalConfidence*100, t.Final.TotalDampening,
		t.Final.RawStrength, t.Final.EffectiveStrength))

	if len(t.Final.KeyDecisions) > 0 {
		sb.WriteString("Key decisions:\n")
		for i, d := range t.Final.KeyDecisions {
			sb.WriteString(fmt.Sprintf("  %d. %s\n", i+1, d))
		}
	}

	return sb.String()
}

// ═══════════════════════════════════════════════════════════════════════════════
// DAMPENING TRACKER
// ═══════════════════════════════════════════════════════════════════════════════

const (
	dampeningFloor   = 0.20 // НИКОГДА не гасить ниже 20%
	dampeningCeiling = 1.50 // 🆕 НИКОГДА не усиливать выше 150%!
)

type dampeningTracker struct {
	factors []dampeningFactor
	total   float64
}

type dampeningFactor struct {
	source string
	value  float64
}

func newDampeningTracker() *dampeningTracker {
	return &dampeningTracker{
		factors: make([]dampeningFactor, 0, 4),
		total:   1.0,
	}
}

func (d *dampeningTracker) apply(source string, factor float64) {
	d.factors = append(d.factors, dampeningFactor{source, factor})
	d.total *= factor

	// 🛡️ FLOOR: никогда не ниже 20%!
	if d.total < dampeningFloor {
		d.total = dampeningFloor
	}

	// 🛡️ 🆕 CEILING: никогда не выше 150%!
	if d.total > dampeningCeiling {
		d.total = dampeningCeiling
	}
}

func (d *dampeningTracker) sources() []string {
	result := make([]string, len(d.factors))
	for i, f := range d.factors {
		result[i] = fmt.Sprintf("%s(×%.2f)", f.source, f.value)
	}
	return result
}

// ═══════════════════════════════════════════════════════════════════════════════
// SAFE LIBRARY PATTERNS
// ═══════════════════════════════════════════════════════════════════════════════

type SafeLibraryPattern struct {
	LibraryPrefix string   `json:"library_prefix"`
	SafeKeywords  []string `json:"safe_keywords"`
	Description   string   `json:"description"`

	// 🆕 Pointer type для optional dampening
	Dampening *float64 `json:"dampening,omitempty"`
}

func (s *SafeLibraryPattern) GetDampening(defaultVal float64) float64 {
	if s.Dampening == nil {
		return defaultVal
	}
	return *s.Dampening
}

type compiledSafePattern struct {
	original        SafeLibraryPattern
	prefixLow       string
	safeKeywordsLow []string
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMPILED RULES
// ═══════════════════════════════════════════════════════════════════════════════

type compiledLibrary struct {
	original      LibraryPattern
	patternLow    string
	exceptionsLow []string
}

type compiledHighValue struct {
	original   HighValuePattern
	patternLow string
}

type compiledKeyword struct {
	keyword    string
	config     KeywordConfig
	aliasesLow []string
	combsLow   []string
}

// ═══════════════════════════════════════════════════════════════════════════════
// CLASSIFIER
// ═══════════════════════════════════════════════════════════════════════════════

type Classifier struct {
	rules      FilterRules
	appPackage string
	cache      *LRUCache[string, *ClassificationResult]

	compiledLibs      []compiledLibrary
	compiledHighValue []compiledHighValue
	compiledKeywords  []compiledKeyword
	keywordByName     map[string]*compiledKeyword
	compiledSafe      []compiledSafePattern

	explainEnabled bool
	lastTrace      *ExplainTrace
}

func NewClassifier(rules FilterRules) *Classifier {
	c := &Classifier{
		rules: rules,
		cache: NewLRUCache[string, *ClassificationResult](10000),
	}

	for i := range c.rules.ObfuscationPatterns {
		c.rules.ObfuscationPatterns[i].Compile()
	}

	c.compileLibraries()
	c.compileHighValue()
	c.compileKeywords()
	c.compileSafePatterns()

	return c
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMPILE
// ═══════════════════════════════════════════════════════════════════════════════

func (c *Classifier) compileLibraries() {
	c.compiledLibs = make([]compiledLibrary, 0, len(c.rules.StandardLibraries))
	for _, lib := range c.rules.StandardLibraries {
		cl := compiledLibrary{
			original:   lib,
			patternLow: strings.ToLower(lib.Pattern),
		}
		cl.exceptionsLow = make([]string, len(lib.Exceptions))
		for i, exc := range lib.Exceptions {
			cl.exceptionsLow[i] = strings.ToLower(exc)
		}
		c.compiledLibs = append(c.compiledLibs, cl)
	}
}

func (c *Classifier) compileHighValue() {
	c.compiledHighValue = make([]compiledHighValue, 0, len(c.rules.HighValuePatterns))
	for _, hvp := range c.rules.HighValuePatterns {
		c.compiledHighValue = append(c.compiledHighValue, compiledHighValue{
			original:   hvp,
			patternLow: strings.ToLower(hvp.Pattern),
		})
	}
}

func (c *Classifier) compileKeywords() {
	c.compiledKeywords = make([]compiledKeyword, 0, len(c.rules.KeywordWeights))
	c.keywordByName = make(map[string]*compiledKeyword, len(c.rules.KeywordWeights))

	for keyword, config := range c.rules.KeywordWeights {
		ck := compiledKeyword{
			keyword: strings.ToLower(keyword),
			config:  config,
		}

		ck.aliasesLow = make([]string, len(config.Aliases))
		for i, a := range config.Aliases {
			ck.aliasesLow[i] = strings.ToLower(a)
		}

		ck.combsLow = make([]string, len(config.Combinators))
		for i, cb := range config.Combinators {
			ck.combsLow[i] = strings.ToLower(cb)
		}

		c.compiledKeywords = append(c.compiledKeywords, ck)
		c.keywordByName[ck.keyword] = &c.compiledKeywords[len(c.compiledKeywords)-1]
	}
}

func (c *Classifier) compileSafePatterns() {
	patterns := defaultSafeLibraryPatterns()

	c.compiledSafe = make([]compiledSafePattern, 0, len(patterns))
	for _, sp := range patterns {
		csp := compiledSafePattern{
			original:  sp,
			prefixLow: strings.ToLower(sp.LibraryPrefix),
		}
		csp.safeKeywordsLow = make([]string, len(sp.SafeKeywords))
		for i, kw := range sp.SafeKeywords {
			csp.safeKeywordsLow[i] = strings.ToLower(kw)
		}
		c.compiledSafe = append(c.compiledSafe, csp)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// DEFAULT SAFE LIBRARY PATTERNS
// ═══════════════════════════════════════════════════════════════════════════════

func defaultSafeLibraryPatterns() []SafeLibraryPattern {
	d30 := 0.3
	return []SafeLibraryPattern{
		{
			LibraryPrefix: "org/apache/commons/",
			SafeKeywords:  []string{"register", "validate", "check", "serial", "verify"},
			Description:   "Apache Commons utility methods (Builder pattern, validation)",
			Dampening:     &d30,
		},
		{
			LibraryPrefix: "org/apache/http/",
			SafeKeywords:  []string{"pro", "verify", "check", "validate", "expire", "trial", "serial"},
			Description:   "Apache HTTP client (isProxy, SSL verify, cookie expiry)",
			Dampening:     &d30,
		},
		{
			LibraryPrefix: "org/apache/james/",
			SafeKeywords:  []string{"check", "validate", "verify"},
			Description:   "Apache James MIME library",
			Dampening:     &d30,
		},
		{
			LibraryPrefix: "com/facebook/",
			SafeKeywords:  []string{"token", "expire", "validate", "verify", "check", "activate"},
			Description:   "Facebook SDK auth flow (token expiry, validation)",
			Dampening:     &d30,
		},
		{
			LibraryPrefix: "com/google/android/gms/",
			SafeKeywords:  []string{"check", "verify", "validate", "pro", "license", "enable"},
			Description:   "Google Play Services internal methods",
			Dampening:     &d30,
		},
		{
			LibraryPrefix: "okhttp",
			SafeKeywords:  []string{"verify", "check", "certificate", "pin", "validate"},
			Description:   "OkHttp SSL verification and certificate pinning",
			Dampening:     &d30,
		},
		{
			LibraryPrefix: "com/admob/",
			SafeKeywords:  []string{"check", "verify", "enable", "expire"},
			Description:   "Old AdMob SDK internal methods",
			Dampening:     &d30,
		},
		{
			LibraryPrefix: "com/mobclix/",
			SafeKeywords:  []string{"pro", "check", "verify", "enable", "expire"},
			Description:   "Mobclix ad SDK (isProviderEnabled = GPS check, not premium!)",
			Dampening:     &d30,
		},
		{
			LibraryPrefix: "com/codecarpet/",
			SafeKeywords:  []string{"token", "expire", "validate", "verify", "activate"},
			Description:   "Old Facebook Connect SDK (token management)",
			Dampening:     &d30,
		},
		{
			LibraryPrefix: "kotlin/",
			SafeKeywords:  []string{"check", "validate", "verify", "enable"},
			Description:   "Kotlin standard library",
			Dampening:     &d30,
		},
		{
			LibraryPrefix: "retrofit2/",
			SafeKeywords:  []string{"validate", "verify", "check"},
			Description:   "Retrofit HTTP client",
			Dampening:     &d30,
		},
		{
			LibraryPrefix: "com/squareup/",
			SafeKeywords:  []string{"validate", "verify", "check"},
			Description:   "Square libraries",
			Dampening:     &d30,
		},
		{
			LibraryPrefix: "org/bouncycastle/",
			SafeKeywords:  []string{"verify", "validate", "check", "serial"},
			Description:   "BouncyCastle crypto (verify = signature verification)",
			Dampening:     &d30,
		},
		{
			LibraryPrefix: "org/conscrypt/",
			SafeKeywords:  []string{"verify", "validate", "check"},
			Description:   "Conscrypt TLS provider",
			Dampening:     &d30,
		},
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// EXPLAINABILITY CONTROL
// ═══════════════════════════════════════════════════════════════════════════════

func (c *Classifier) EnableExplain()           { c.explainEnabled = true }
func (c *Classifier) DisableExplain()          { c.explainEnabled = false }
func (c *Classifier) LastTrace() *ExplainTrace { return c.lastTrace }

// ═══════════════════════════════════════════════════════════════════════════════
// SET APP PACKAGE
// ═══════════════════════════════════════════════════════════════════════════════

func (c *Classifier) SetAppPackage(pkg string) {
	c.appPackage = strings.ReplaceAll(pkg, ".", "/")
	c.cache.Clear()
}

// ═══════════════════════════════════════════════════════════════════════════════
// CLASSIFY — основной метод
// ═══════════════════════════════════════════════════════════════════════════════

func (c *Classifier) Classify(path string) *ClassificationResult {
	if cached, ok := c.cache.Get(path); ok {
		return cached
	}

	result := c.classifyInternal(path)
	c.cache.Put(path, result)
	return result
}

func (c *Classifier) ClassifyWithTrace(path string) (*ClassificationResult, *ExplainTrace) {
	wasEnabled := c.explainEnabled
	c.explainEnabled = true
	result := c.classifyInternal(path)
	trace := c.lastTrace
	c.explainEnabled = wasEnabled
	return result, trace
}

func (c *Classifier) classifyInternal(path string) *ClassificationResult {
	// Multidex roots (smali_classesN/) must look like canonical smali paths,
	// otherwise known-library prefix rules never match classes2+.dex code.
	pathInfo := NormalizePath(CanonicalSmaliPath(path))
	dampening := newDampeningTracker()

	var trace *ExplainTrace
	if c.explainEnabled {
		trace = newExplainTrace(path)
	}

	result := &ClassificationResult{
		Path:           path,
		IsAppCode:      true,
		TotalDampening: 1.0,
	}

	// ── Pipeline ─────────────────────────────────────────────────
	c.checkHighValuePaths(pathInfo, result, trace)
	c.checkStandardLibraries(pathInfo, result, dampening, trace)
	c.checkKeywords(pathInfo, result, dampening, trace)
	c.checkObfuscation(pathInfo, result, trace)
	c.checkAppPackage(pathInfo, result, trace)
	c.checkCorrelations(pathInfo, result, dampening, trace) // 🆕
	c.calculateImportance(result, dampening, trace)
	c.calculateConfidence(result, dampening, trace) // 🆕 dampening передаётся!

	// ── Финализация ──────────────────────────────────────────────
	result.TotalDampening = dampening.total
	result.DampeningSources = dampening.sources()

	if trace != nil {
		trace.finalize(result)
		c.lastTrace = trace
	}

	return result
}

// ═══════════════════════════════════════════════════════════════════════════════
// STEP 1: HIGH-VALUE PATHS
// ═══════════════════════════════════════════════════════════════════════════════

func (c *Classifier) checkHighValuePaths(pathInfo PathInfo, result *ClassificationResult, trace *ExplainTrace) {
	for i := range c.compiledHighValue {
		chv := &c.compiledHighValue[i]

		if !MatchesPattern(pathInfo.Lower, chv.patternLow, chv.original.MatchType) {
			continue
		}

		result.MatchedHighValue = append(result.MatchedHighValue, chv.original)
		result.addReason(ClassificationReason{
			Type:        ReasonHighValuePath,
			Description: fmt.Sprintf("high_value: %s (%s)", chv.original.Pattern, chv.original.Category),
			Impact:      chv.original.Weight,
			Category:    SignalSemantic,
		})
		result.addCategory(chv.original.Category)

		trace.log("HIGH_VALUE", "matched", chv.original.Pattern,
			fmt.Sprintf("category=%s weight=%d — file protected from library filtering",
				chv.original.Category, chv.original.Weight))
	}

	if len(result.MatchedHighValue) == 0 {
		trace.log("HIGH_VALUE", "no_match", "", "No high-value patterns found")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// STEP 2: STANDARD LIBRARIES — мягкое гашение
// ═══════════════════════════════════════════════════════════════════════════════

func (c *Classifier) checkStandardLibraries(pathInfo PathInfo, result *ClassificationResult, dampening *dampeningTracker, trace *ExplainTrace) {
	libTarget := strings.TrimPrefix(pathInfo.Lower, "smali/")

	for i := range c.compiledLibs {
		cl := &c.compiledLibs[i]

		if !MatchesPattern(libTarget, cl.patternLow, cl.original.MatchType) {
			continue
		}

		// Exceptions
		isException := false
		for _, excLow := range cl.exceptionsLow {
			if strings.Contains(libTarget, excLow) {
				isException = true
				result.addReason(ClassificationReason{
					Type:        ReasonException,
					Description: fmt.Sprintf("exception: %s in %s", excLow, cl.original.Pattern),
					Impact:      5,
					Category:    SignalStructural,
				})
				trace.log("LIBRARY", "exception", excLow,
					fmt.Sprintf("Exception matched in %s — treating as app code!", cl.original.Pattern))
				break
			}
		}
		if isException {
			continue
		}

		// High-value override
		if len(result.MatchedHighValue) > 0 {
			trace.log("LIBRARY", "override_by_high_value", cl.original.Pattern,
				fmt.Sprintf("Library pattern matched, but %d high-value patterns take priority",
					len(result.MatchedHighValue)))
			continue
		}

		// Мягкая классификация
		result.IsLibrary = true
		result.IsAppCode = false
		result.MatchedLibrary = &cl.original

		dampening.apply("library:"+cl.original.Category, 0.4)

		result.addReason(ClassificationReason{
			Type:        ReasonStandardLibrary,
			Description: fmt.Sprintf("standard_library: %s (%s)", cl.original.Description, cl.original.Category),
			Impact:      -10,
			Category:    SignalStructural,
		})

		trace.logWithImpact("LIBRARY", "dampened", cl.original.Pattern,
			fmt.Sprintf("Library match: %s (%s) → dampening ×0.4 (keywords still checked!)",
				cl.original.Description, cl.original.Category),
			0, 0, 0.4)

		return
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// STEP 3: KEYWORDS — safe-check, context, dampening
// ═══════════════════════════════════════════════════════════════════════════════

func (c *Classifier) checkKeywords(pathInfo PathInfo, result *ClassificationResult, dampening *dampeningTracker, trace *ExplainTrace) {
	// 🆕 Определяем надёжность пути ОДИН раз
	pathReliability := c.assessPathReliability(pathInfo)

	switch pathReliability {
	case PathUnreliable:
		trace.log("KEYWORD", "path_unreliable", "",
			"Path is fully obfuscated — context adjustments disabled")
	case PathPartial:
		trace.log("KEYWORD", "path_partial", "",
			"Path partially obfuscated — context limited to filename only")
	}

	for i := range c.compiledKeywords {
		ck := &c.compiledKeywords[i]
		matched := false

		if strings.Contains(pathInfo.Lower, ck.keyword) {
			matched = true
		}

		if !matched {
			for _, alias := range ck.aliasesLow {
				if strings.Contains(pathInfo.Lower, alias) {
					matched = true
					break
				}
			}
		}

		if !matched {
			continue
		}

		match := KeywordMatch{
			Keyword: ck.keyword,
			Config:  ck.config,
			Bonus:   ck.config.Weight,
		}

		// ── Safe keyword check ───────────────────────────────────
		if c.isSafeLibraryKeyword(pathInfo.Lower, ck.keyword) {
			originalBonus := match.Bonus
			match.Bonus = intMax(int(float64(match.Bonus)*0.3), 1)
			match.Dampened = true

			result.addReason(ClassificationReason{
				Type: ReasonSafeKeyword,
				Description: fmt.Sprintf("safe_keyword: '%s' in known library path — bonus %d→%d",
					ck.keyword, originalBonus, match.Bonus),
				Impact:   match.Bonus - originalBonus,
				Category: SignalStructural,
			})

			trace.logWithImpact("KEYWORD", "safe_dampened", ck.keyword,
				fmt.Sprintf("Safe library keyword '%s' — bonus %d→%d (×0.3, min 1)",
					ck.keyword, originalBonus, match.Bonus),
				originalBonus, match.Bonus, 0.3)
		}

		// ── Context check (с учётом PathReliability!) ────────────
		switch pathReliability {
		case PathReliable:
			// Полный контекст
			context := c.detectKeywordContext(pathInfo, ck.keyword, result)
			match.Context = context
			c.applyContextBonus(context, &match, pathInfo, dampening, result, trace)

		case PathPartial:
			// Контекст ТОЛЬКО для filename
			baseNameLower := strings.ToLower(pathInfo.BaseName)
			if strings.Contains(baseNameLower, strings.ToLower(ck.keyword)) {
				match.Context = ContextFileName
				beforeBonus := match.Bonus
				match.Bonus += 3

				trace.logWithImpact("KEYWORD", "partial_context", ck.keyword,
					fmt.Sprintf("Partially obfuscated path, but keyword '%s' in FILENAME '%s' — bonus %d→%d",
						ck.keyword, pathInfo.BaseName, beforeBonus, match.Bonus),
					beforeBonus, match.Bonus, 0)
			} else {
				match.Context = ContextUnknown
			}

		case PathUnreliable:
			match.Context = ContextUnknown
		}

		// ── Combinators ──────────────────────────────────────────
		for _, combLow := range ck.combsLow {
			if strings.Contains(pathInfo.Lower, combLow) {
				match.Combinators = append(match.Combinators, combLow)
			}
		}

		if len(match.Combinators) > 0 {
			comboBonus := int(float64(len(match.Combinators)) * c.rules.Scoring.GetCombinationMultiplier())
			beforeBonus := match.Bonus
			match.Bonus = Clamp(match.Bonus+comboBonus, ck.config.MinBonus, ck.config.MaxBonus)

			result.addReason(ClassificationReason{
				Type:        ReasonKeywordCombo,
				Description: fmt.Sprintf("keyword_combo: %s + [%s]", ck.keyword, strings.Join(match.Combinators, ", ")),
				Impact:      comboBonus,
				Category:    SignalSemantic,
			})

			trace.logWithImpact("KEYWORD", "combo_boost", ck.keyword,
				fmt.Sprintf("Combo: %s + [%s] → bonus %d→%d",
					ck.keyword, strings.Join(match.Combinators, ", "), beforeBonus, match.Bonus),
				beforeBonus, match.Bonus, 0)
		}

		// ── Signal strength ──────────────────────────────────────
		match.Strength = strengthFromScore(match.Bonus)

		// ── Finalize keyword ─────────────────────────────────────
		result.MatchedKeywords = append(result.MatchedKeywords, match)
		result.addReason(ClassificationReason{
			Type: ReasonKeyword,
			Description: fmt.Sprintf("keyword: %s (cat=%s bonus=%d ctx=%s dampened=%v str=%s)",
				ck.keyword, ck.config.Category, match.Bonus,
				match.Context, match.Dampened, match.Strength),
			Impact:   match.Bonus,
			Category: SignalSemantic,
		})
		result.addCategory(ck.config.Category)

		trace.log("KEYWORD", "matched", ck.keyword,
			fmt.Sprintf("✓ cat=%s bonus=%d ctx=%s dampened=%v str=%s combos=%d",
				ck.config.Category, match.Bonus, match.Context,
				match.Dampened, match.Strength, len(match.Combinators)))
	}

	// ═══════════════════════════════════════════════════════════
	// 🆕 COMBO BONUS: множественные keywords в имени файла
	// ═══════════════════════════════════════════════════════════
	//
	// "LicenseChecker" содержит "License" + "Checker" → 2 разных keyword
	// → даём бонус за комбинацию!
	//
	// Защита от дубликатов: "license" и "licence" = одно слово (alias)

	if len(result.MatchedKeywords) >= 2 {
		baseNameLower := strings.ToLower(pathInfo.BaseName)
		uniqueKeywordsInFilename := make(map[string]bool)

		for _, match := range result.MatchedKeywords {
			kwLower := strings.ToLower(match.Keyword)

			// Проверяем, что keyword действительно в имени файла
			if !strings.Contains(baseNameLower, kwLower) {
				continue
			}

			// Добавляем keyword и все его alias'ы под одним "корневым" именем
			// чтобы "license" и "licence" считались за одно слово
			rootKey := kwLower
			if ck, ok := c.keywordByName[kwLower]; ok {
				// Используем первый keyword как "корневой"
				rootKey = ck.keyword
			}

			uniqueKeywordsInFilename[rootKey] = true
		}

		// Если в имени файла 2+ РАЗНЫХ keywords → бонус!
		if len(uniqueKeywordsInFilename) >= 2 {
			comboBonus := (len(uniqueKeywordsInFilename) - 1) * 2 // +2 за каждый дополнительный

			result.addReason(ClassificationReason{
				Type: ReasonKeywordCombo,
				Description: fmt.Sprintf("filename_multi_keyword: %d different keywords in '%s'",
					len(uniqueKeywordsInFilename), pathInfo.BaseName),
				Impact:   comboBonus,
				Category: SignalSemantic,
			})

			trace.log("KEYWORD", "filename_combo", pathInfo.BaseName,
				fmt.Sprintf("Filename '%s' contains %d DIFFERENT keywords → bonus +%d",
					pathInfo.BaseName, len(uniqueKeywordsInFilename), comboBonus))

			// Добавляем виртуальный match для учёта в importance
			result.MatchedKeywords = append(result.MatchedKeywords, KeywordMatch{
				Keyword:  "__filename_combo__",
				Bonus:    comboBonus,
				Strength: strengthFromScore(comboBonus),
				Context:  ContextFileName,
			})
		}
	}
}

// applyContextBonus применяет контекстный бонус/гашение для reliable paths
func (c *Classifier) applyContextBonus(
	context KeywordContext,
	match *KeywordMatch,
	pathInfo PathInfo,
	dampening *dampeningTracker,
	result *ClassificationResult,
	trace *ExplainTrace,
) {
	switch context {
	case ContextFileName:
		beforeBonus := match.Bonus
		match.Bonus += 3

		result.addReason(ClassificationReason{
			Type:        ReasonContextAdjust,
			Description: fmt.Sprintf("context: '%s' in FILENAME — extra important! +3", match.Keyword),
			Impact:      3,
			Category:    SignalContextual,
		})

		trace.logWithImpact("KEYWORD", "context_boost", match.Keyword,
			fmt.Sprintf("Keyword '%s' found in FILENAME '%s' — bonus %d→%d",
				match.Keyword, pathInfo.BaseName, beforeBonus, match.Bonus),
			beforeBonus, match.Bonus, 0)

	case ContextPackagePath:
		match.Bonus += 1
		trace.log("KEYWORD", "context_minor", match.Keyword,
			fmt.Sprintf("Keyword '%s' in package path — minor boost +1", match.Keyword))

	case ContextLibraryPath:
		dampening.apply("context:"+match.Keyword, 0.7)

		trace.logWithImpact("KEYWORD", "context_dampened", match.Keyword,
			fmt.Sprintf("Keyword '%s' in library path — dampening ×0.7", match.Keyword),
			match.Bonus, match.Bonus, 0.7)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// STEP 4: OBFUSCATION
// ═══════════════════════════════════════════════════════════════════════════════

func (c *Classifier) checkObfuscation(pathInfo PathInfo, result *ClassificationResult, trace *ExplainTrace) {
	for _, pattern := range c.rules.ObfuscationPatterns {
		if pattern.Matches(pathInfo.BaseName) {
			result.ObfuscationType = pattern.Name
			result.addReason(ClassificationReason{
				Type:        ReasonObfuscation,
				Description: fmt.Sprintf("obfuscation: %s (%s)", pattern.Name, pattern.Description),
				Impact:      c.rules.Scoring.ObfuscationBonus,
				Category:    SignalStructural,
			})

			trace.log("OBFUSCATION", "matched", pattern.Name,
				fmt.Sprintf("File '%s' is obfuscated: %s — %s",
					pathInfo.BaseName, pattern.Name, pattern.Description))
			break
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// STEP 5: APP PACKAGE
// ═══════════════════════════════════════════════════════════════════════════════

func (c *Classifier) checkAppPackage(pathInfo PathInfo, result *ClassificationResult, trace *ExplainTrace) {
	if c.appPackage == "" {
		return
	}

	if strings.Contains(pathInfo.Normalized, c.appPackage) {
		result.IsAppCode = true
		result.addReason(ClassificationReason{
			Type:        ReasonAppPackage,
			Description: fmt.Sprintf("app_package: %s", c.appPackage),
			Impact:      c.rules.Scoring.AppPackageBonus,
			Category:    SignalContextual,
		})

		trace.log("APP_PACKAGE", "matched", c.appPackage,
			"File is in app's own package — marked as app code")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// STEP 5.5: CORRELATION BOOST 🆕
// ═══════════════════════════════════════════════════════════════════════════════
//
// Исправлена логика: буст только если В ОДНОМ сегменте встречаются РАЗНЫЕ слова
// (keyword ≠ high-value pattern). “license” + “license” в одном сегменте — шум.

func (c *Classifier) checkCorrelations(pathInfo PathInfo, result *ClassificationResult, dampening *dampeningTracker, trace *ExplainTrace) {
	if len(result.MatchedHighValue) == 0 || len(result.MatchedKeywords) == 0 {
		return
	}

	segments := strings.Split(pathInfo.Lower, "/")

	type hvInSegment struct {
		segment    string
		patternLow string
	}
	hvSegments := make([]hvInSegment, 0, 4)

	for _, hv := range result.MatchedHighValue {
		patLow := strings.ToLower(hv.Pattern)
		for _, seg := range segments {
			if strings.Contains(seg, patLow) {
				hvSegments = append(hvSegments, hvInSegment{seg, patLow})
			}
		}
	}

	if len(hvSegments) == 0 {
		return
	}

	for _, match := range result.MatchedKeywords {
		kwLow := strings.ToLower(match.Keyword)

		for _, hvSeg := range hvSegments {
			if !strings.Contains(hvSeg.segment, kwLow) {
				continue
			}

			// 🆕 Fix #1: сравниваем keyword с high-value, не с самим собой
			if kwLow == hvSeg.patternLow {
				trace.log("CORRELATION", "same_word_skip", kwLow,
					fmt.Sprintf("Keyword '%s' == high-value '%s' in segment '%s' — skip boost",
						kwLow, hvSeg.patternLow, hvSeg.segment))
				continue
			}

			dampening.apply("correlation", 1.2)

			result.addReason(ClassificationReason{
				Type: ReasonCorrelation,
				Description: fmt.Sprintf("correlation: keyword '%s' + high-value '%s' in segment '%s'",
					match.Keyword, hvSeg.patternLow, hvSeg.segment),
				Impact:   2,
				Category: SignalSemantic,
			})

			trace.log("CORRELATION", "correlation_boost", match.Keyword,
				fmt.Sprintf("REAL correlation: keyword '%s' + high-value '%s' in segment '%s' → boost ×1.2",
					match.Keyword, hvSeg.patternLow, hvSeg.segment))

			return // один boost достаточно
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// STEP 6: IMPORTANCE — raw + dampening + smart penalties
// ═══════════════════════════════════════════════════════════════════════════════

func (c *Classifier) calculateImportance(result *ClassificationResult, dampening *dampeningTracker, trace *ExplainTrace) {
	// Чистая библиотека без сигналов
	if result.IsLibrary && len(result.MatchedHighValue) == 0 && len(result.MatchedKeywords) == 0 {
		result.RawImportance = c.rules.Scoring.StandardLibraryScore
		result.Importance = c.rules.Scoring.StandardLibraryScore
		result.RawStrength = strengthFromScore(result.RawImportance)
		result.EffectiveStrength = result.RawStrength

		trace.logWithImpact("IMPORTANCE", "library_base", "",
			fmt.Sprintf("Pure library, no signals → base score %d", c.rules.Scoring.StandardLibraryScore),
			0, c.rules.Scoring.StandardLibraryScore, dampening.total)
		return
	}

	importance := c.rules.Scoring.BaseImportance

	// Keyword bonuses
	for _, match := range result.MatchedKeywords {
		if match.Bonus <= 0 {
			continue
		}
		scaled := int(float64(match.Bonus) * 0.4)
		if scaled < 1 {
			scaled = 1
		}
		importance += scaled
	}

	// 🛡️ Избегаем двойного учёта: high-value = тот же keyword
	matchedKeywords := make(map[string]bool, len(result.MatchedKeywords)*2)
	for _, match := range result.MatchedKeywords {
		kwLow := strings.ToLower(match.Keyword)
		matchedKeywords[kwLow] = true
		for _, alias := range match.Config.Aliases {
			matchedKeywords[strings.ToLower(alias)] = true
		}
	}

	// High-value bonuses
	for _, hv := range result.MatchedHighValue {
		hvLow := strings.ToLower(hv.Pattern)
		if matchedKeywords[hvLow] {
			trace.log("IMPORTANCE", "same_word_skip", hv.Pattern,
				fmt.Sprintf("High-value '%s' already counted as keyword — skip double bonus", hv.Pattern))
			continue
		}

		importance += hv.Weight
	}

	// 🪢 Single-keyword soft cap — чтобы комбинации выигрывали
	if len(result.MatchedKeywords) == 1 && len(result.MatchedHighValue) <= 1 {
		importance -= 1
		if importance < 0 {
			importance = 0
		}

		trace.log("IMPORTANCE", "single_keyword_soft_cap", "",
			"Only one keyword detected — apply -1 to let multi-keyword combos rank higher")
	}

	// Multi high-value boost
	if len(result.MatchedHighValue) > 2 {
		importance += 2
		trace.log("IMPORTANCE", "multi_high_value_boost", "",
			fmt.Sprintf("%d high-value matches → bonus +2", len(result.MatchedHighValue)))
	}

	// Generic keyword penalty — умный минимум
	genericCount := c.countGenericKeywords(result)
	if genericCount > 0 {
		rawPenalty := genericCount
		if rawPenalty > 2 {
			rawPenalty = 2 // потолок
		}

		scaledPenalty := int(float64(rawPenalty) * dampening.total)

		// Если сильно не гасили (>=0.5) — минимум 1, иначе можем дать 0
		if scaledPenalty < 1 && rawPenalty > 0 && dampening.total >= 0.5 {
			scaledPenalty = 1
		}

		importance -= scaledPenalty

		trace.logWithImpact("IMPORTANCE", "generic_penalty", "",
			fmt.Sprintf("Generic keywords: %d → raw -%d × damp %.2f = -%d (min depends on damp)",
				genericCount, rawPenalty, dampening.total, scaledPenalty),
			importance+scaledPenalty, importance, 0)
	}

	// Obfuscation bonus
	if result.ObfuscationType != "" {
		importance += c.rules.Scoring.ObfuscationBonus
	}

	// App package bonus
	if result.IsAppCode && c.appPackage != "" {
		for _, reason := range result.Reasons {
			if reason.Type == ReasonAppPackage {
				importance += c.rules.Scoring.AppPackageBonus
				break
			}
		}
	}

	// Raw strength ДО dampening
	rawClamped := Clamp(importance,
		c.rules.Scoring.MinImportance,
		c.rules.Scoring.MaxImportance)
	result.RawImportance = rawClamped
	result.RawStrength = strengthFromScore(rawClamped)

	// Dampening/boost
	beforeDampening := importance

	if dampening.total < 1.0 {
		importance = int(float64(importance) * dampening.total)

		if importance < 1 && beforeDampening > 0 {
			importance = 1
		}

		trace.logWithImpact("IMPORTANCE", "dampened", "",
			fmt.Sprintf("Dampening: %d × %.2f = %d (floor=%.2f, ceiling=%.2f, sources: [%s])",
				beforeDampening, dampening.total, importance, dampeningFloor, dampeningCeiling,
				strings.Join(dampening.sources(), ", ")),
			beforeDampening, importance, dampening.total)
	} else if dampening.total > 1.0 {
		importance = int(float64(importance) * dampening.total)

		trace.logWithImpact("IMPORTANCE", "boosted", "",
			fmt.Sprintf("Boost: %d × %.2f = %d (ceiling=%.2f, sources: [%s])",
				beforeDampening, dampening.total, importance, dampeningCeiling,
				strings.Join(dampening.sources(), ", ")),
			beforeDampening, importance, dampening.total)
	}

	// Final clamp
	result.Importance = Clamp(importance,
		c.rules.Scoring.MinImportance,
		c.rules.Scoring.MaxImportance)

	// Effective strength ПОСЛЕ dampening
	result.EffectiveStrength = strengthFromScore(result.Importance)

	trace.logWithImpact("IMPORTANCE", "final", "",
		fmt.Sprintf("Final: importance=%d (raw=%d) rawStr=%s effStr=%s range=[%d-%d]",
			result.Importance, result.RawImportance,
			result.RawStrength, result.EffectiveStrength,
			c.rules.Scoring.MinImportance, c.rules.Scoring.MaxImportance),
		result.RawImportance, result.Importance, dampening.total)
}

// ═══════════════════════════════════════════════════════════════════════════════
// STEP 7: CONFIDENCE — плавная деградация через dampening!
// ═══════════════════════════════════════════════════════════════════════════════
//
// 🆕 Fix #3: Confidence использует dampening для плавной деградации
//
// БЫЛО:
//   conf -= 0.3 (library) → все библиотеки = 0.05 (одинаковые!)
//
// СТАЛО:
//   conf *= dampening.total → разные библиотеки = разная confidence!
//   library ×0.4 → conf ×0.4
//   library ×0.4 + safe ×0.3 → conf ×0.2 (но floor!)
//   library ×0.4 + correlation ×1.2 → conf ×0.48 (чуть выше!)

func (c *Classifier) calculateConfidence(result *ClassificationResult, dampening *dampeningTracker, trace *ExplainTrace) {
	conf := 0.5 // Базовая уверенность

	// ── Повышаем уверенность ─────────────────────────────────────
	if result.IsAppCode && !result.IsLibrary {
		conf += 0.15
	}

	hvCount := len(result.MatchedHighValue)
	if hvCount > 0 {
		hvBoost := 0.1 * float64(hvCount)
		if hvBoost > 0.3 { // cap at +0.3
			hvBoost = 0.3
		}
		conf += hvBoost
	}

	if result.ObfuscationType != "" {
		conf += 0.1
	}

	// Filename context → очень высокая уверенность
	for _, match := range result.MatchedKeywords {
		if match.Context == ContextFileName && !match.Dampened {
			conf += 0.15
			break // один бонус достаточно
		}
	}

	// ── 🆕 Плавная деградация через dampening! ──────────────────
	// Вместо жёстких шагов (-0.3) используем dampening total
	// Это даёт разные confidence для разных библиотек!
	if dampening.total < 1.0 {
		conf *= dampening.total

		// 🛡️ Confidence floor (аналогично importance floor)
		if conf < 0.05 {
			conf = 0.05
		}
	}

	// ── Dampened keywords снижают уверенность (мягко) ─────────────
	dampenedCount := 0
	for _, match := range result.MatchedKeywords {
		if match.Dampened {
			dampenedCount++
		}
	}
	if dampenedCount > 0 {
		// Мягкое снижение: -0.05 за каждый dampened keyword, max -0.15
		dampenedPenalty := float64(dampenedCount) * 0.05
		if dampenedPenalty > 0.15 {
			dampenedPenalty = 0.15
		}
		conf -= dampenedPenalty
	}

	// ── Clamp ────────────────────────────────────────────────────
	result.Confidence = clampFloat(conf, 0.05, 0.99)

	trace.logWithImpact("CONFIDENCE", "calculated", "",
		fmt.Sprintf("Confidence: %.0f%% (base=50%% app=%v hv=%d obf=%v damp=%.2f dampenedKW=%d)",
			result.Confidence*100,
			result.IsAppCode, hvCount,
			result.ObfuscationType != "",
			dampening.total, dampenedCount),
		0, int(result.Confidence*100), dampening.total)
}

// ═══════════════════════════════════════════════════════════════════════════════
// SAFE KEYWORD CHECK
// ═══════════════════════════════════════════════════════════════════════════════

func (c *Classifier) isSafeLibraryKeyword(pathLower, keyword string) bool {
	keywordLower := strings.ToLower(keyword)

	for i := range c.compiledSafe {
		csp := &c.compiledSafe[i]

		if !strings.Contains(pathLower, csp.prefixLow) {
			continue
		}

		for _, safeKW := range csp.safeKeywordsLow {
			if keywordLower == safeKW {
				return true
			}
		}
	}

	return false
}

// ═══════════════════════════════════════════════════════════════════════════════
// KEYWORD CONTEXT DETECTION
// ═══════════════════════════════════════════════════════════════════════════════

func (c *Classifier) detectKeywordContext(pathInfo PathInfo, keyword string, result *ClassificationResult) KeywordContext {
	keywordLower := strings.ToLower(keyword)
	baseNameLower := strings.ToLower(pathInfo.BaseName)

	if strings.Contains(baseNameLower, keywordLower) {
		return ContextFileName
	}

	if result.IsLibrary {
		return ContextLibraryPath
	}

	return ContextPackagePath
}

// ═══════════════════════════════════════════════════════════════════════════════
// PATH RELIABILITY ASSESSMENT 🆕
// ═══════════════════════════════════════════════════════════════════════════════
//
// 🆕 Fix #4: Трёхуровневая надёжность вместо бинарной!
//
// БЫЛО:
//   obfuscatedRatio > 0.6 → ВЕСЬ путь ненадёжен (бинарно!)
//   a/b/c/LicenseManager.smali → контекст ВЫКЛЮЧЕН! ❌
//
// СТАЛО:
//   Reliable:    > 40% читаемых сегментов → полный контекст ✅
//   Partial:     хотя бы 1 длинный сегмент (>6 символов) → контекст для filename ✅
//   Unreliable:  всё обфусцировано → контекст отключён ❌
//
// Пример:
//   a/b/c/LicenseManager.smali
//   3 обфусцированных + 1 читаемый (14 символов!)
//   → PathPartial → контекст для "LicenseManager" работает! ✅

func (c *Classifier) assessPathReliability(pathInfo PathInfo) PathReliability {
	parts := strings.Split(pathInfo.Normalized, "/")
	if len(parts) < 2 {
		return PathReliable
	}

	obfuscatedSegments := 0
	totalSegments := 0
	hasLongReadable := false

	for _, part := range parts {
		if part == "" || part == "smali" {
			continue
		}

		clean := strings.TrimSuffix(part, ".smali")
		if clean == "" {
			continue
		}

		totalSegments++

		if isObfuscatedName(clean) {
			obfuscatedSegments++
		} else if len(clean) > 6 {
			// 🆕 Хотя бы один длинный читаемый сегмент → частично надёжен!
			hasLongReadable = true
		}
	}

	if totalSegments == 0 {
		return PathReliable
	}

	obfuscatedRatio := float64(obfuscatedSegments) / float64(totalSegments)

	switch {
	case obfuscatedRatio <= 0.6:
		// Большинство сегментов читаемые → полный контекст
		return PathReliable

	case hasLongReadable:
		// Много обфусцированных, НО есть хотя бы один длинный читаемый
		// a/b/c/LicenseManager.smali → "LicenseManager" спасает!
		return PathPartial

	default:
		// Всё обфусцировано
		return PathUnreliable
	}
}

// isObfuscatedName проверяет ProGuard/R8 обфускацию
func isObfuscatedName(name string) bool {
	if idx := strings.IndexByte(name, '$'); idx > 0 {
		name = name[:idx]
	}

	nameLen := len(name)

	// Одна буква: a, b, c
	if nameLen == 1 {
		r := rune(name[0])
		return unicode.IsLower(r)
	}

	// Короткие имена (2-3 символа): ab, a1, aa
	if nameLen <= 3 {
		letters := 0
		digits := 0
		for _, r := range name {
			switch {
			case unicode.IsLower(r):
				letters++
			case unicode.IsDigit(r):
				digits++
			default:
				return false // CamelCase, uppercase → НЕ обфускация
			}
		}
		return letters > 0 && letters+digits == nameLen
	}

	return false
}

// ═══════════════════════════════════════════════════════════════════════════════
// GENERIC KEYWORD DETECTION
// ═══════════════════════════════════════════════════════════════════════════════

var genericKeywords = map[string]bool{
	"check":    true,
	"validate": true,
	"verify":   true,
	"enable":   true,
	"disable":  true,
	"flag":     true,
}

func (c *Classifier) countGenericKeywords(result *ClassificationResult) int {
	count := 0
	for _, match := range result.MatchedKeywords {
		if genericKeywords[match.Keyword] {
			count++
		}
	}
	return count
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
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

func intMax(a, b int) int {
	if a > b {
		return a
	}
	return b
}
