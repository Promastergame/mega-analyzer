package ml

import (
	"regexp"
	"strings"
	"unicode"
)

// ═══════════════════════════════════════════════════════════════════════════════
// OBFUSCATION DETECTION AND STRUCTURAL MATCHING (Enhanced v2)
//
// Расширенное сопоставление паттернов для обфусцированного кода.
// Поддержка: ProGuard, R8, DexGuard, Allatori, кастомные обфускаторы.
// Requirements: 11.1-11.5, 21.1-21.5
// Task 12: Enhance obfuscation-resistant pattern matching
// ═══════════════════════════════════════════════════════════════════════════════

// ───────────────────────────── Constants & Thresholds ─────────────────────────

const (
	// Пороги обнаружения обфускации
	obfThresholdMinimal = 0.30 // считается обфусцированным
	obfThresholdMedium  = 0.45 // переход на гибрид
	obfThresholdHeavy   = 0.65 // переход на структурный

	// Пороги уверенности по стратегиям
	confidenceNameBased  = 0.92
	confidenceHybrid     = 0.74
	confidenceStructural = 0.61

	// Сложность для DexGuard-эвристики
	dexguardMinIfChecks     = 5
	dexguardMinInstructions = 30

	// Длины подозрительных идентификаторов
	maxRandomNameLen   = 3
	maxObfClassNameLen = 2
)

// Множества для быстрого lookup
var (
	vowelSet = map[rune]struct{}{
		'a': {}, 'e': {}, 'i': {}, 'o': {}, 'u': {}, 'y': {},
		'A': {}, 'E': {}, 'I': {}, 'O': {}, 'U': {}, 'Y': {},
	}

	// Регулярки компилируем один раз
	reProGuardPath = regexp.MustCompile(`/[a-z]{1,2}/[a-z]{1,2}(/|$)`)
	reHexLikeName  = regexp.MustCompile(`^[a-f0-9]{6,}$`)
	reUnicodeObf   = regexp.MustCompile(`[\x{0400}-\x{04FF}\x{4E00}-\x{9FFF}]`) // кириллица/CJK в именах
)

// ───────────────────────────── Types ──────────────────────────────────────────

type ObfuscationType string

const (
	ObfuscationNone     ObfuscationType = "none"
	ObfuscationProGuard ObfuscationType = "proguard"
	ObfuscationR8       ObfuscationType = "r8"
	ObfuscationDexGuard ObfuscationType = "dexguard"
	ObfuscationAllatori ObfuscationType = "allatori"
	ObfuscationCustom   ObfuscationType = "custom"
)

type MatchStrategy string

const (
	StrategyNameBased  MatchStrategy = "name_based"
	StrategyStructural MatchStrategy = "structural"
	StrategyHybrid     MatchStrategy = "hybrid"
)

// ObfuscationInfo — детальная информация о найденной обфускации
type ObfuscationInfo struct {
	IsObfuscated        bool
	ObfuscationType     ObfuscationType
	Confidence          float64  // [0..1] уверенность в факте обфускации
	Score               float64  // сырой накопленный балл
	Indicators          []string // человекочитаемые маркеры
	RecommendedStrategy MatchStrategy
}

// indicator — внутренняя структура с весом, чтобы не дублировать литералы
type indicator struct {
	tag    string
	weight float64
	otype  ObfuscationType // если != "" — задаёт/уточняет тип
}

// ───────────────────────────── DetectObfuscation ──────────────────────────────

// DetectObfuscation анализирует метод и возвращает подробный отчёт об обфускации.
func DetectObfuscation(mi *MethodInfo) ObfuscationInfo {
	info := ObfuscationInfo{
		ObfuscationType:     ObfuscationNone,
		Indicators:          make([]string, 0, 8),
		RecommendedStrategy: StrategyNameBased,
	}
	if mi == nil {
		return info
	}

	className := ShortClassName(mi.ClassName)
	pathLower := strings.ToLower(mi.FilePath)

	// Кандидаты-индикаторы (порядок не важен)
	checks := []indicator{
		// — имя метода —
		{"single_letter_method_name", 0.40, ""},
		{"synthetic_accessor", 0.30, ""},
		{"short_consonant_only_name", 0.30, ""},
		{"hex_like_method_name", 0.35, ObfuscationCustom},
		{"unicode_obfuscated_name", 0.40, ObfuscationAllatori},

		// — имя класса —
		{"single_letter_class_name", 0.30, ""},
		{"short_class_name", 0.20, ""},

		// — структура пакета —
		{"obfuscated_package_structure", 0.20, ""},
		{"proguard_package_pattern", 0.25, ObfuscationProGuard},

		// — маркеры тулзы —
		{"r8_marker", 0.20, ObfuscationR8},
		{"dexguard_complexity", 0.20, ObfuscationDexGuard},
	}

	add := func(tag string, w float64, t ObfuscationType) {
		info.Score += w
		info.Indicators = append(info.Indicators, tag)
		if t != "" && info.ObfuscationType == ObfuscationNone {
			info.ObfuscationType = t
		}
	}

	// Применяем проверки
	name := mi.Name
	switch {
	case len(name) == 1 && unicode.IsLower(rune(name[0])):
		add(checks[0].tag, checks[0].weight, "")
	case strings.HasPrefix(name, "access$"):
		add(checks[1].tag, checks[1].weight, "")
	case len(name) >= 2 && len(name) <= maxRandomNameLen && !hasVowels(name):
		add(checks[2].tag, checks[2].weight, "")
	case reHexLikeName.MatchString(strings.ToLower(name)):
		add(checks[3].tag, checks[3].weight, ObfuscationCustom)
	}

	if reUnicodeObf.MatchString(name) {
		add(checks[4].tag, checks[4].weight, ObfuscationAllatori)
	}

	// Класс
	switch {
	case len(className) == 1:
		add(checks[5].tag, checks[5].weight, "")
	case len(className) <= maxObfClassNameLen && allLowerASCII(className):
		add(checks[6].tag, checks[6].weight, "")
	}

	// Пакет
	if hasObfuscatedPackageStructure(mi.ClassName) {
		add(checks[7].tag, checks[7].weight, "")
	}
	if reProGuardPath.MatchString(pathLower) {
		add(checks[8].tag, checks[8].weight, ObfuscationProGuard)
	}

	// Маркеры тулзов
	if strings.Contains(pathLower, "r8") {
		add(checks[9].tag, checks[9].weight, ObfuscationR8)
	}
	if hasComplexControlFlow(mi) && len(name) <= 2 {
		add(checks[10].tag, checks[10].weight, ObfuscationDexGuard)
	}

	// Финал
	info.Score = clampScore(info.Score)
	info.IsObfuscated = info.Score >= obfThresholdMinimal
	info.Confidence = info.Score // здесь Confidence = насколько мы уверены, что это обфускация

	switch {
	case info.Score >= obfThresholdHeavy:
		info.RecommendedStrategy = StrategyStructural
	case info.Score >= obfThresholdMedium:
		info.RecommendedStrategy = StrategyHybrid
	default:
		info.RecommendedStrategy = StrategyNameBased
	}

	return info
}

// ───────────────────────────── Helpers ────────────────────────────────────────

func hasVowels(s string) bool {
	for _, c := range s {
		if _, ok := vowelSet[c]; ok {
			return true
		}
	}
	return false
}

func allLowerASCII(s string) bool {
	for _, c := range s {
		if c < 'a' || c > 'z' {
			return false
		}
	}
	return s != ""
}

func hasObfuscatedPackageStructure(className string) bool {
	if className == "" {
		return false
	}
	parts := strings.Split(className, "/")
	count := 0
	for _, p := range parts {
		if len(p) == 1 && unicode.IsLower(rune(p[0])) {
			count++
			if count >= 2 {
				return true
			}
		}
	}
	return false
}

func hasComplexControlFlow(mi *MethodInfo) bool {
	return mi.IfCheckCount > dexguardMinIfChecks &&
		mi.InstructionCount > dexguardMinInstructions
}

func clampScore(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

// ───────────────────────────── Structural Rules ───────────────────────────────

type StructuralRuleType string

const (
	RuleDualReturn       StructuralRuleType = "dual_return"
	RuleAPISequence      StructuralRuleType = "api_sequence"
	RuleExceptionPattern StructuralRuleType = "exception_pattern"
	RuleLoopPattern      StructuralRuleType = "loop_pattern"
	RuleDataFlow         StructuralRuleType = "data_flow"
	RuleCryptoPattern    StructuralRuleType = "crypto_pattern"
	RuleReflection       StructuralRuleType = "reflection"
	RuleNativeCall       StructuralRuleType = "native_call"
)

type StructuralRule struct {
	Type        StructuralRuleType
	Description string
	Weight      float64
}

// ruleCatalog — единый каталог правил с весами (избегаем дублей)
var ruleCatalog = map[StructuralRuleType]StructuralRule{
	RuleDualReturn:       {RuleDualReturn, "Dual return path (true/false branches)", 15.0},
	RuleAPISequence:      {RuleAPISequence, "Security API call sequence", 20.0},
	RuleExceptionPattern: {RuleExceptionPattern, "Try-catch around security check", 12.0},
	RuleLoopPattern:      {RuleLoopPattern, "Iteration over packages/classes", 10.0},
	RuleDataFlow:         {RuleDataFlow, "SharedPreferences → comparison → return", 18.0},
	RuleCryptoPattern:    {RuleCryptoPattern, "Crypto/hashing API usage pattern", 14.0},
	RuleReflection:       {RuleReflection, "Reflection-based access pattern", 11.0},
	RuleNativeCall:       {RuleNativeCall, "JNI/native bridge invocation", 16.0},
}

// StructuralRules сохраняет публичный срез для совместимости.
var StructuralRules = func() []StructuralRule {
	out := make([]StructuralRule, 0, len(ruleCatalog))
	for _, r := range ruleCatalog {
		out = append(out, r)
	}
	return out
}()

// MatchStructuralRules применяет все правила и возвращает суммарный вес.
func MatchStructuralRules(mi *MethodInfo) (matches []StructuralRule, totalScore float64) {
	matches = make([]StructuralRule, 0, 6)
	if mi == nil {
		return
	}

	// Заранее подготовим кэш lower-case вызовов — экономим аллокации
	callsLower := lowerCallList(mi)

	type detector struct {
		t  StructuralRuleType
		ok bool
	}
	detectors := []detector{
		{RuleDualReturn, detectDualReturnPath(mi)},
		{RuleAPISequence, detectSecurityAPISequence(callsLower)},
		{RuleExceptionPattern, detectExceptionHandlingPattern(mi)},
		{RuleLoopPattern, detectLoopPattern(mi, callsLower)},
		{RuleDataFlow, detectDataFlowPattern(mi, callsLower)},
		{RuleCryptoPattern, detectCryptoPattern(callsLower)},
		{RuleReflection, detectReflectionPattern(callsLower)},
		{RuleNativeCall, detectNativeCallPattern(mi, callsLower)},
	}

	for _, d := range detectors {
		if !d.ok {
			continue
		}
		if r, ok := ruleCatalog[d.t]; ok {
			matches = append(matches, r)
			totalScore += r.Weight
		}
	}
	return
}

// lowerCallList кэширует lower-case полные сигнатуры вызовов
func lowerCallList(mi *MethodInfo) []string {
	out := make([]string, len(mi.Calls))
	for i, c := range mi.Calls {
		out[i] = strings.ToLower(c.FullCall)
	}
	return out
}

// ───────────────────────────── Detectors ──────────────────────────────────────

func detectDualReturnPath(mi *MethodInfo) bool {
	return mi.HasDualReturn && mi.ReturnsBoolean
}

func detectSecurityAPISequence(calls []string) bool {
	if len(calls) < 2 {
		return false
	}

	var (
		hasPkgInfo, hasSig, hasMD bool
		hasPM, hasInstaller       bool
		hasExec, hasFileExists    bool
	)
	for _, c := range calls {
		switch {
		case strings.Contains(c, "getpackageinfo"):
			hasPkgInfo = true
		case strings.Contains(c, "signature"):
			hasSig = true
		case strings.Contains(c, "messagedigest"):
			hasMD = true
		case strings.Contains(c, "packagemanager"):
			hasPM = true
		case strings.Contains(c, "installerpackage"):
			hasInstaller = true
		case strings.Contains(c, "runtime") && strings.Contains(c, "exec"):
			hasExec = true
		case strings.Contains(c, "file") && strings.Contains(c, "exists"):
			hasFileExists = true
		}
	}

	return (hasPkgInfo && hasSig && hasMD) ||
		(hasPM && hasInstaller) ||
		(hasExec && hasFileExists)
}

func detectExceptionHandlingPattern(mi *MethodInfo) bool {
	if !(mi.HasSecurityAPI || len(mi.SecurityCalls) > 0) {
		return false
	}
	for _, line := range mi.RawBody {
		l := strings.ToLower(strings.TrimSpace(line))
		if strings.HasPrefix(l, ".catch") || strings.HasPrefix(l, ":try_start") {
			return true
		}
	}
	return false
}

func detectLoopPattern(mi *MethodInfo, calls []string) bool {
	hasLoop := false
	for _, line := range mi.RawBody {
		l := strings.ToLower(strings.TrimSpace(line))
		if strings.HasPrefix(l, "goto") || strings.Contains(l, ":cond_") {
			hasLoop = true
			break
		}
	}
	if !hasLoop {
		return false
	}
	for _, c := range calls {
		if strings.Contains(c, "getinstalledpackages") ||
			strings.Contains(c, "getloadedclasses") ||
			strings.Contains(c, "iterator") ||
			strings.Contains(c, "runningapps") {
			return true
		}
	}
	return false
}

func detectDataFlowPattern(mi *MethodInfo, calls []string) bool {
	if mi.IfCheckCount == 0 || mi.ReturnCount == 0 {
		return false
	}
	for _, c := range calls {
		if strings.Contains(c, "sharedpreferences") &&
			(strings.Contains(c, "getboolean") ||
				strings.Contains(c, "getint") ||
				strings.Contains(c, "getstring") ||
				strings.Contains(c, "getlong")) {
			return true
		}
	}
	return false
}

func detectCryptoPattern(calls []string) bool {
	hits := 0
	for _, c := range calls {
		if strings.Contains(c, "cipher") ||
			strings.Contains(c, "messagedigest") ||
			strings.Contains(c, "mac/getinstance") ||
			strings.Contains(c, "secretkey") {
			hits++
			if hits >= 2 {
				return true
			}
		}
	}
	return false
}

func detectReflectionPattern(calls []string) bool {
	for _, c := range calls {
		if strings.Contains(c, "java/lang/reflect") ||
			strings.Contains(c, "getdeclaredmethod") ||
			strings.Contains(c, "getdeclaredfield") ||
			strings.Contains(c, "class/forname") {
			return true
		}
	}
	return false
}

func detectNativeCallPattern(mi *MethodInfo, calls []string) bool {
	for _, line := range mi.RawBody {
		l := strings.ToLower(line)
		if strings.Contains(l, "loadlibrary") || strings.Contains(l, "system/load") {
			return true
		}
	}
	for _, c := range calls {
		if strings.Contains(c, "loadlibrary") {
			return true
		}
	}
	return false
}

// ───────────────────────────── Hybrid Matching ────────────────────────────────

type HybridMatchResult struct {
	NameMatchScore       float64
	StructuralMatchScore float64
	TotalScore           float64
	Confidence           float64
	Strategy             MatchStrategy
	ObfuscationInfo      ObfuscationInfo
	StructuralMatches    []StructuralRule
}

// ApplyHybridMatching выбирает стратегию сопоставления исходя из степени обфускации.
func ApplyHybridMatching(mi *MethodInfo, nameMatchScore float64) HybridMatchResult {
	result := HybridMatchResult{NameMatchScore: nameMatchScore}
	if mi == nil {
		return result
	}

	result.ObfuscationInfo = DetectObfuscation(mi)
	matches, sScore := MatchStructuralRules(mi)
	result.StructuralMatches = matches
	result.StructuralMatchScore = sScore
	result.Strategy = result.ObfuscationInfo.RecommendedStrategy

	switch result.Strategy {
	case StrategyNameBased:
		result.TotalScore = nameMatchScore + sScore*0.30
		result.Confidence = confidenceNameBased
	case StrategyHybrid:
		result.TotalScore = nameMatchScore*0.50 + sScore*0.50
		result.Confidence = confidenceHybrid
	case StrategyStructural:
		result.TotalScore = nameMatchScore*0.20 + sScore*0.80
		result.Confidence = confidenceStructural
	}

	// Бустим уверенность, если структурных правил найдено много
	if len(matches) >= 3 {
		result.Confidence = clampScore(result.Confidence + 0.05)
	}
	return result
}

// GetObfuscationAdjustedScore возвращает скорректированный с учётом обфускации балл.
func GetObfuscationAdjustedScore(mi *MethodInfo, baseScore float64) float64 {
	obf := DetectObfuscation(mi)
	if !obf.IsObfuscated {
		return baseScore
	}
	_, sScore := MatchStructuralRules(mi)

	// Чем сильнее обфускация — тем больше вес структурного скоринга
	w := obf.Score // [0..1]
	return baseScore*(1-w*0.5) + sScore*(0.5+w*0.3)
}
