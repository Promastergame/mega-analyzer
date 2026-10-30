package ml

import (
	"strings"
	"sync"
)

// ═══════════════════════════════════════════════════════════════════════════════
// NOISE FILTER COMPONENT — PHASE 5 UPGRADE
//
// Полностью переработанный фильтр шума. Ключевые улучшения:
//
//   • WHITELIST: security-related методы (isPremium, isLicensed, etc.)
//     НИКОГДА не фильтруются, даже если совпадают с "generic" паттерном.
//   • CONTEXT-AWARE: методы в security-классах получают иммунитет от фильтрации.
//   • SMARTER GENERIC DETECTION: учитывает body (invoke/const-string) перед
//     тем как пометить метод как "generic getter/setter".
//   • REDUCED FALSE POSITIVES: infrastructure-фильтр проверяет количество
//     security-сигналов перед отклонением.
// ═══════════════════════════════════════════════════════════════════════════════

// NoiseFilter filters out library code and generic methods
type NoiseFilter interface {
	ShouldFilter(mi *MethodInfo, score *InterestingScore) (bool, string)
	GetStatistics() map[string]int
	Reset()
}

// DefaultNoiseFilter implements NoiseFilter interface
type DefaultNoiseFilter struct {
	mu         sync.RWMutex
	statistics map[string]int

	// Enhanced filtering with interesting score integration
	enableInterestingScoreFilter bool
	minInterestingThreshold      float64
}

func NewNoiseFilter() NoiseFilter {
	return &DefaultNoiseFilter{
		statistics:                   make(map[string]int),
		enableInterestingScoreFilter: true,
		minInterestingThreshold:      20.0, // Minimum interesting score to pass filter (synced with InterestingScorer)
	}
}

func (nf *DefaultNoiseFilter) recordStat(key string) {
	nf.mu.Lock()
	nf.statistics[key]++
	nf.mu.Unlock()
}

func (nf *DefaultNoiseFilter) ShouldFilter(mi *MethodInfo, score *InterestingScore) (bool, string) {
	return nf.ShouldFilterEnhanced(mi, score)
}

func (nf *DefaultNoiseFilter) GetStatistics() map[string]int {
	nf.mu.RLock()
	defer nf.mu.RUnlock()
	res := make(map[string]int, len(nf.statistics))
	for k, v := range nf.statistics {
		res[k] = v
	}
	return res
}

func (nf *DefaultNoiseFilter) Reset() {
	nf.mu.Lock()
	nf.statistics = make(map[string]int)
	nf.mu.Unlock()
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECURITY-AWARE WHITELIST
//
// Методы с этими ключевыми словами в имени НИКОГДА не фильтруются,
// даже если они выглядят как "generic getter/setter".
// Это решает проблему когда isPremium, isLicensed, getCoins фильтровались
// как "generic is*/get*" методы.
//
// DEPRECATED: Use SecurityWhitelistKeywords from security_keywords.go for new code.
// This variable is kept for backward compatibility.
// ═══════════════════════════════════════════════════════════════════════════════

var securityWhitelistKeywords = SecurityWhitelistKeywords

// securityClassKeywords — если класс содержит эти слова, все методы внутри
// получают "иммунитет" от generic-фильтрации
//
// DEPRECATED: Use SecurityClassKeywords from security_keywords.go for new code.
// This variable is kept for backward compatibility.
var securityClassKeywords = SecurityClassKeywords

// isSecurityRelatedMethod проверяет является ли метод security-related
// и должен ли он быть защищён от фильтрации
func isSecurityRelatedMethod(mi *MethodInfo) bool {
	if mi == nil {
		return false
	}
	if isEconomyCandidate(economyForMethod(mi)) { return true }

	// 1. Быстрые O(1) проверки по флагам безопасности
	if mi.HasSecurityAPI || mi.HasSecurityStrings || mi.HasSecurityName {
		return true
	}

	nameLower := strings.ToLower(mi.Name)

	// 2. Прямое совпадение имени метода с whitelist
	for _, keyword := range securityWhitelistKeywords {
		if strings.Contains(nameLower, keyword) {
			return true
		}
	}

	// 3. Метод в security-related классе
	classLower := strings.ToLower(mi.ClassName)
	pathLower := strings.ToLower(mi.FilePath)
	for _, keyword := range securityClassKeywords {
		if strings.Contains(classLower, keyword) || strings.Contains(pathLower, keyword) {
			return true
		}
	}

	return false
}

// Enhanced noise filter implementation with interesting score integration
func (nf *DefaultNoiseFilter) ShouldFilterEnhanced(mi *MethodInfo, score *InterestingScore) (bool, string) {
	if mi == nil {
		nf.recordStat("nil_method")
		return true, "nil_method"
	}

	// Filter library code (highest priority filter)
	if !mi.IsAppCode {
		nf.recordStat("library_code")
		return true, "library_code"
	}

	// ═══════════════════════════════════════════════════════════════════
	// PHASE 5 FIX: SECURITY WHITELIST CHECK
	//
	// Если метод security-related — НИКОГДА не фильтруем, даже если
	// InterestingScore низкий или имя выглядит "generic".
	// ═══════════════════════════════════════════════════════════════════
	if isSecurityRelatedMethod(mi) {
		nf.recordStat("whitelisted_security")
		return false, "" // ПРОПУСКАЕМ — это потенциальная уязвимость
	}

	// PHASE 5+: Body opcode rescue — если в теле метода >=2 security-relevant
	// опкодов, спасаем его от фильтрации независимо от score.
	if bodyOpcodeSecurityScore(mi) >= 2 {
		nf.recordStat("rescued_by_opcodes")
		return false, ""
	}

	// Enhanced filtering with interesting score integration
	if score != nil && nf.enableInterestingScoreFilter {
		// Filter if interesting score indicates library penalty
		if score.LibraryCodePenalty > 0 {
			nf.recordStat("library_penalty")
			return true, "library_penalty"
		}

		// Filter generic methods with high penalty
		// 🔥 PHASE 5: увеличен порог с 20 до 30 — меньше ложных срабатываний
		if score.GenericMethodPenalty > 30.0 {
			nf.recordStat("generic_method")
			return true, "generic_method"
		}

		// Filter methods with no I/O operations and low interesting score
		if score.NoIOPenalty > 10.0 && score.TotalScore < nf.minInterestingThreshold {
			nf.recordStat("no_io_low_interest")
			return true, "no_io_low_interest"
		}

		// Filter if not interesting and below threshold
		if !score.IsInteresting && score.TotalScore < nf.minInterestingThreshold {
			nf.recordStat("not_interesting")
			return true, "not_interesting"
		}
	}

	// 🔥 Infrastructure filter — теперь с double-check на security context
	if isInfra, reason := nf.isInfrastructureCode(mi); isInfra {
		// Only filter if it's NOT a high-value security method (triple check)
		if !mi.HasSecurityAPI && !mi.HasSecurityStrings && !mi.HasSecurityName {
			nf.recordStat("infrastructure_" + reason)
			return true, "infrastructure_" + reason
		}
	}

	// 🔥 Generic UI Handlers — но НЕ если это security callback
	if strings.HasSuffix(mi.FullSignature, ")V") && nf.isGenericMethodName(mi.Name) {
		nf.recordStat("ui_handler")
		return true, "ui_handler"
	}

	// Additional heuristic filters for methods without interesting score
	if score == nil {
		// Filter obvious generic methods by name
		// 🔥 PHASE 5: isGenericMethodName больше НЕ фильтрует is*/get*/set* с security контекстом
		if nf.isGenericMethodName(mi.Name) {
			nf.recordStat("generic_method_name")
			return true, "generic_method_name"
		}

		// Filter very short methods (likely getters/setters or empty)
		totalLen := 0
		for _, line := range mi.RawBody {
			totalLen += len(strings.TrimSpace(line))
		}
		if totalLen > 0 && totalLen <= 10 {
			nf.recordStat("short_method")
			return true, "short_method"
		}
	}

	return false, ""
}

// isGenericMethodName checks if method name indicates a generic method
// 🔥 PHASE 5: ПОЛНОСТЬЮ ПЕРЕРАБОТАНО
// Больше НЕ фильтрует is*/get*/set* — эти методы часто являются уязвимостями!
// Фильтрует только ДЕЙСТВИТЕЛЬНО бесполезные методы (toString, lifecycle, etc.)
func (nf *DefaultNoiseFilter) isGenericMethodName(methodName string) bool {
	// Жёстко бесполезные методы — ВСЕГДА фильтруем
	hardcodeFilter := []string{
		"toString", "hashCode", "equals", "clone", "finalize",
		"getClass", "notify", "notifyAll", "wait",
		"<init>", "<clinit>", // Constructor patterns
		"writeToParcel", "createFromParcel", "describeContents",
	}

	for _, pattern := range hardcodeFilter {
		if strings.EqualFold(methodName, pattern) {
			return true
		}
	}

	methodLower := strings.ToLower(methodName)

	// Lifecycle callbacks — фильтруем только если ТОЧНО lifecycle
	lifecycleExact := []string{
		"onactivityresult", "onfragmentresult",
		"onattach", "ondetach",
		"onstart", "onstop", "onresume", "onpause",
		"oncreate", "ondestroy",
		"onmeasure", "onlayout", "ondraw",
		"onbackpressed",
		"ondismiss", "oncancel", "onshow",
		"onsaveinstancestate", "onrestoreinstancestate",
		"oncontentchanged", "onwindowfocuschanged",
		"ontrimemory", "onlowmemory",
		"onconfigurationchanged",
	}

	for _, lc := range lifecycleExact {
		if methodLower == lc {
			return true
		}
	}

	// 🔥 УБРАНО: фильтрация is*/get*/set* — это были ложные срабатывания!
	// isPremium, isLicensed, getCoins, setBalance — всё это уязвимости.
	// Фильтрация этих методов была ГЛАВНОЙ причиной пропуска уязвимостей.

	return false
}

// libraryPackagePrefixes lists Dalvik class prefixes that are always third-party
// library code and should never surface as interesting findings.
// These are checked against mi.ClassName and mi.FilePath.
var libraryPackagePrefixes = []string{
	// HTTP clients
	"Lokhttp3/", "Lcom/squareup/okhttp/", "Lretrofit2/", "Lokio/",
	// JSON / serialization
	"Lcom/google/gson/", "Lorg/json/", "Lcom/fasterxml/jackson/",
	"Lkotlinx/serialization/",
	// DI frameworks
	"Ldagger/", "Ljavax/inject/", "Lcom/google/dagger/",
	// Image loading
	"Lcom/bumptech/glide/", "Lcom/squareup/picasso/", "Lcoil/",
	// Reactive
	"Lio/reactivex/", "Lkotlinx/coroutines/",
	// Analytics / Crashlytics (boilerplate, not security logic)
	"Lcom/google/firebase/analytics/", "Lcom/crashlytics/",
	"Lcom/google/firebase/crashlytics/",
	// UI / layout
	"Landroidx/recyclerview/", "Landroidx/viewpager/",
	"Landroidx/constraintlayout/", "Landroidx/coordinatorlayout/",
	"Lcom/google/android/material/",
	// Networking infra
	"Lcom/google/android/gms/tasks/", "Lcom/google/android/gms/common/",
	// Kotlin stdlib
	"Lkotlin/jvm/internal/", "Lkotlin/collections/", "Lkotlin/text/",
	// Apache Commons
	"Lorg/apache/commons/",
	// Guava
	"Lcom/google/common/",
	// Logging
	"Lorg/slf4j/", "Lch/qos/logback/",
}

// isDalvikLibraryClass returns true when the class path matches a known
// third-party library prefix, meaning the method is definitely not app code.
func isDalvikLibraryClass(mi *MethodInfo) (bool, string) {
	classPath := strings.ReplaceAll(mi.ClassName, ".", "/")
	// Normalise to Dalvik format if not already prefixed with 'L'
	if !strings.HasPrefix(classPath, "L") {
		classPath = "L" + classPath + "/"
	}
	for _, pfx := range libraryPackagePrefixes {
		if strings.HasPrefix(classPath, pfx) {
			return true, pfx
		}
	}
	// Also check file path (smali files often keep full package path)
	fp := strings.ToLower(mi.FilePath)
	libPathSigns := []string{
		"/okhttp3/", "/retrofit2/", "/glide/", "/picasso/", "/gson/",
		"/dagger/", "/rxjava/", "/coroutines/", "/commons/", "/guava/",
	}
	for _, sign := range libPathSigns {
		if strings.Contains(fp, sign) {
			return true, sign
		}
	}
	return false, ""
}

// bodyOpcodeSecurityScore returns a quick heuristic score (>0 = interesting)
// based on how many security-relevant Dalvik opcodes appear in the method body.
// This is used to rescue methods that would otherwise be discarded as generic.
func bodyOpcodeSecurityScore(mi *MethodInfo) int {
	score := 0
	securityOpcodes := []string{
		// Crypto
		"Ljavax/crypto/", "Ljava/security/", "Landroid/security/",
		// Reflection
		"Ljava/lang/reflect/", "Ljava/lang/Class;->forName",
		// IPC / Binder (security boundary)
		"Landroid/os/IBinder;", "Landroid/os/Binder;",
		// Native calls (JNI — often hides security logic)
		"invoke-virtual {", "native",
		// File I/O on sensitive paths
		"/proc/", "/sys/", "/data/data/",
		// Network
		"Ljava/net/URL;", "Landroid/webkit/WebView;",
		// Intent extras (common attack surface)
		"Landroid/content/Intent;->getStringExtra",
		"Landroid/content/Intent;->getIntExtra",
		// Shared Preferences (credential storage)
		"Landroid/content/SharedPreferences;->getString",
		"Landroid/content/SharedPreferences;->getInt",
		// Package manager (anti-tamper checks)
		"Landroid/content/pm/PackageManager;",
		// Signature verification
		"Landroid/content/pm/Signature;",
	}
	for _, line := range mi.RawBody {
		for _, op := range securityOpcodes {
			if strings.Contains(line, op) {
				score++
				break // count once per line to avoid skewing on dense lines
			}
		}
	}
	return score
}

// isInfrastructureCode checks if method body or strings indicate infrastructure code (boilerplate)
func (nf *DefaultNoiseFilter) isInfrastructureCode(mi *MethodInfo) (bool, string) {
	// Phase 5+: reject known third-party library classes first
	if isLib, reason := isDalvikLibraryClass(mi); isLib {
		return true, "dalvik_library_" + reason
	}

	// Patterns for common "noise" infrastructure
	infraStrings := map[string]string{
		"com.google.android.gms":   "google_play_services",
		"TypefaceCompatUtil":       "android_utils",
		"ConnectionTracker":        "bind_service_infra",
		"FirebaseApp":              "firebase_infra",
		"SharedPreferences$Editor": "prefs_boilerplate",
	}

	// Scan method strings
	for _, s := range mi.StringConsts {
		for pattern, reason := range infraStrings {
			if strings.Contains(s, pattern) {
				return true, reason
			}
		}
	}

	// Scan method body for boilerplate calls
	for _, line := range mi.RawBody {
		if strings.Contains(line, "Landroid/os/StrictMode;->") {
			return true, "android_boilerplate"
		}
	}

	return false, ""
}

// GetTotalFiltered возвращает общее количество отфильтрованных методов
func (nf *DefaultNoiseFilter) GetTotalFiltered() int {
	nf.mu.RLock()
	defer nf.mu.RUnlock()
	total := 0
	for _, count := range nf.statistics {
		total += count
	}
	return total
}

// GetFilterReasons возвращает список причин фильтрации
func (nf *DefaultNoiseFilter) GetFilterReasons() map[string]int {
	return nf.GetStatistics()
}

// SetMinInterestingThreshold устанавливает минимальный порог interesting score
func (nf *DefaultNoiseFilter) SetMinInterestingThreshold(threshold float64) {
	nf.minInterestingThreshold = threshold
}

// EnableInterestingScoreFilter включает/выключает фильтрацию по interesting score
func (nf *DefaultNoiseFilter) EnableInterestingScoreFilter(enable bool) {
	nf.enableInterestingScoreFilter = enable
}
