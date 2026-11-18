package filter

import (
	"strings"
	"sync"
	"sync/atomic"
)

// ═══════════════════════════════════════════════════════════════════════════════
// FILTER — основной API для классификации файлов
// ═══════════════════════════════════════════════════════════════════════════════
//
// v7.2 Улучшения:
//
//   1. УМНЫЙ FAST-PATH: проверяет critical keywords ПЕРЕД пропуском файла
//      "smali/org/apache/.../CipherStorage.smali" → содержит интересное → НЕ fast-path!
//
//   2. ГРАНУЛЯРНЫЕ ПРЕФИКСЫ: вместо "org/apache/" → "org/apache/commons/lang/" и т.д.
//      Слишком широкие префиксы убраны, интересные подпути теперь проходят полный анализ
//
//   3. КАТЕГОРИЙНЫЕ РЕЗУЛЬТАТЫ: разный importance для разных типов библиотек
//      SDK=0, ads_sdk=2, crypto=3 — а не одинаковый importance=1 для всех!
//
//   4. ClassifyWithTrace: полный дебаг-лог для любого файла
//
//   5. savedFromFastPath: счётчик файлов спасённых от fast-path critical keyword check'ом
//
// Thread-safety: потокобезопасен (кеш в Classifier + atomic stats)

type Filter struct {
	classifier *Classifier
	profile    ProfileType

	// structuralLibs holds package prefixes identified as vendored libraries
	// by structure (obfuscated names, no manifest components) rather than by
	// path. Marked once per run by the pipeline's structural pass, read by the
	// fast path for the rest of the run.
	structuralMu sync.RWMutex
	structural   []structuralLib

	// ── Счётчики для мониторинга ─────────────────────────────────────────
	classifyCalls      atomic.Int64
	fastPathHits       atomic.Int64
	cacheInvalidations atomic.Int64
	savedFromFastPath  atomic.Int64 // 🆕 файлы спасённые critical keyword check'ом
}

// structuralLib is one runtime-marked library prefix. The result is
// precomputed so the fast path stays allocation-free.
type structuralLib struct {
	prefix string
	result *ClassificationResult
}

// structuralLibraryResult mirrors defaultCategoryResult: low importance,
// library damping, never app code.
var structuralLibraryResult = &ClassificationResult{
	IsAppCode:         false,
	IsLibrary:         true,
	Importance:        1,
	RawImportance:     1,
	Confidence:        0.6,
	RawStrength:       SignalWeak,
	EffectiveStrength: SignalWeak,
	TotalDampening:    1.0,
	Categories:        []string{"library", "obfuscated_library"},
}

// MarkStructuralLibrary registers a canonical smali package prefix (e.g.
// "smali/z/") as a vendored obfuscated library. Paths under it classify as
// library code with IsAppCode=false from that point on. The prefix must
// already be lowercase with a trailing slash.
func (f *Filter) MarkStructuralLibrary(prefix string) {
	if prefix == "" {
		return
	}
	f.structuralMu.Lock()
	defer f.structuralMu.Unlock()
	for _, lib := range f.structural {
		if lib.prefix == prefix {
			return
		}
	}
	f.structural = append(f.structural, structuralLib{prefix: prefix, result: structuralLibraryResult})
}

// lookupStructural returns the precomputed result for a structural library
// prefix covering path (already canonical and lowercased).
func (f *Filter) lookupStructural(normalizedLower string) *ClassificationResult {
	f.structuralMu.RLock()
	defer f.structuralMu.RUnlock()
	for _, lib := range f.structural {
		if strings.HasPrefix(normalizedLower, lib.prefix) {
			return lib.result
		}
	}
	return nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONSTRUCTORS
// ═══════════════════════════════════════════════════════════════════════════════

func NewFilter() *Filter {
	return NewFilterWithProfile(ProfileBalanced)
}

func NewFilterWithProfile(profile ProfileType) *Filter {
	rules := GetProfile(profile)
	return &Filter{
		classifier: NewClassifier(rules),
		profile:    profile,
	}
}

func NewFilterWithRules(rules FilterRules) *Filter {
	return &Filter{
		classifier: NewClassifier(rules),
		profile:    "custom",
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════════

// SetAppPackage устанавливает пакет приложения.
// ВАЖНО: инвалидирует кеш, т.к. IsAppCode зависит от пакета!
func (f *Filter) SetAppPackage(pkg string) {
	if pkg == "" {
		return
	}
	f.classifier.SetAppPackage(pkg)
	f.classifier.cache.Clear()
	f.cacheInvalidations.Add(1)
}

func (f *Filter) Profile() ProfileType {
	return f.profile
}

// ═══════════════════════════════════════════════════════════════════════════════
// CRITICAL KEYWORDS — слова которые ЗАПРЕЩАЮТ fast-path
// ═══════════════════════════════════════════════════════════════════════════════
//
// Если путь к файлу содержит critical keyword — файл ОБЯЗАН пройти
// полную классификацию, даже если лежит внутри известной библиотеки.
//
// Пример:
//   "smali/com/android/billingclient/api/Purchase.smali"
//   Префикс "com/android/billingclient/" → известная библиотека
//   НО "purchase" → critical keyword!
//   → НЕ fast-path → полный анализ с dampening
//
// Почему "pro" НЕ в списке:
//   Слишком много false positives (isProxy, Protocol, Provider...)
//   Обрабатывается через SafeLibraryPatterns в classifier.go

var criticalKeywords = []string{
	// License / Registration
	"license", "licence",

	// Monetization
	"billing", "purchase", "subscription",
	"premium", "paid",

	// Activation / Trial
	"unlock", "trial", "activate",

	// Ad-free
	"adfree", "noads", "removeads",

	// Security / Piracy
	"crack", "keygen", "pirate", "hack", "cheat",
}

// containsCriticalKeywordBoundary — всегда проверяет границы слов (v7.3.1)
func containsCriticalKeywordBoundary(pathLower string) (bool, string) {
	for _, kw := range criticalKeywords {
		idx := strings.Index(pathLower, kw)
		if idx < 0 {
			continue
		}

		// Всегда требует boundary: consistency > эвристика длины
		if isAtWordBoundary(pathLower, idx, len(kw)) {
			return true, kw
		}
	}
	return false, ""
}

// isAtWordBoundary проверяет, находится ли подстрока на границе слова.
// Допустимые границы: / . $ _ - или начало/конец строки.
func isAtWordBoundary(s string, idx, length int) bool {
	// Перед
	if idx > 0 {
		before := s[idx-1]
		beforeOk := before == '/' || before == '.' || before == '$' ||
			before == '_' || before == '-'
		if !beforeOk {
			afterIdx := idx + length
			if afterIdx < len(s) {
				after := s[afterIdx]
				afterOk := after == '/' || after == '.' || after == '$' ||
					after == '_' || after == '-'
				return afterOk
			}
			return true // конец строки
		}
	}

	// После
	afterIdx := idx + length
	if afterIdx < len(s) {
		after := s[afterIdx]
		return after == '/' || after == '.' || after == '$' ||
			after == '_' || after == '-'
	}

	return true
}

// toLowerFast — zero-alloc, если строка уже lowercase
func toLowerFast(s string) string {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			return strings.ToLower(s)
		}
	}
	return s
}

// ═══════════════════════════════════════════════════════════════════════════════
// KNOWN LIBRARY ENTRIES — с категориями
// ═══════════════════════════════════════════════════════════════════════════════
//
// v7.2 изменения:
//
// УБРАНО (слишком широкие):
//   "smali/org/apache/"     → заменён на гранулярные подпути
//   "smali/com/facebook/"   → заменён на гранулярные подпути
//
// ДОБАВЛЕНО:
//   Гранулярные Apache подпути (commons/lang, commons/codec и т.д.)
//   Гранулярные Facebook подпути (internal, share, login и т.д.)
//   Категории для каждого префикса (sdk, ads_sdk, crypto и т.д.)
//
// ПОРЯДОК ВАЖЕН: более специфичные префиксы ПЕРЕД более общими!
//   "gms/ads/" ПЕРЕД "gms/" → иначе ads-файлы получат категорию "google" вместо "ads_sdk"

type knownLibEntry struct {
	prefix   string // полный smali-путь
	category string // sdk, google, kotlin, network, common, engine, ads_sdk, analytics, social, crypto, billing_lib
}

// knownLibEntries — все префиксы уже lowercase!
var knownLibEntries = []knownLibEntry{
	// ═══════════════════════════════════════════════════════════════
	// ANDROID SDK
	// ═══════════════════════════════════════════════════════════════
	{prefix: "smali/android/", category: "sdk"},
	{prefix: "smali/androidx/", category: "sdk"},
	{prefix: "smali/com/android/internal/", category: "sdk"},
	// APK signing library (v1/v2/v3 signature verification helpers). Vendored
	// by build tools into otherwise unrelated apps; its verifyIntegrity* chunk
	// helpers are signing plumbing, not app anti-tamper protection.
	{prefix: "smali/com/android/apksig/", category: "sdk"},

	// ═══════════════════════════════════════════════════════════════
	// GOOGLE — специфичные ПЕРЕД общими!
	// ═══════════════════════════════════════════════════════════════
	{prefix: "smali/com/google/android/gms/internal/play_billing/", category: "billing_lib"}, // billing internal
	{prefix: "smali/com/google/android/gms/ads/", category: "ads_sdk"},                       // AdMob
	{prefix: "smali/com/google/android/gms/internal/ads/", category: "ads_sdk"},              // AdMob internal
	{prefix: "smali/com/google/android/gms/", category: "google"},                            // GMS общий
	{prefix: "smali/com/google/android/material/", category: "google"},
	{prefix: "smali/com/google/firebase/", category: "google"},
	{prefix: "smali/com/google/android/play/", category: "google"},
	{prefix: "smali/com/google/android/ump/", category: "google"},
	{prefix: "smali/com/google/android/datatransport/", category: "google"},
	{prefix: "smali/com/google/protobuf/", category: "google"},
	{prefix: "smali/com/google/gson/", category: "google"},
	{prefix: "smali/com/google/common/", category: "google"},

	// ═══════════════════════════════════════════════════════════════
	// KOTLIN
	// ═══════════════════════════════════════════════════════════════
	{prefix: "smali/kotlin/", category: "kotlin"},
	{prefix: "smali/kotlinx/", category: "kotlin"},

	// ═══════════════════════════════════════════════════════════════
	// NETWORKING
	// ═══════════════════════════════════════════════════════════════
	{prefix: "smali/okhttp3/", category: "network"},
	{prefix: "smali/okhttp/", category: "network"},
	{prefix: "smali/okio/", category: "network"},
	{prefix: "smali/retrofit2/", category: "network"},
	{prefix: "smali/com/squareup/", category: "network"},

	// ═══════════════════════════════════════════════════════════════
	// REACTIVE
	// ═══════════════════════════════════════════════════════════════
	{prefix: "smali/io/reactivex/", category: "reactive"},
	{prefix: "smali/rx/", category: "reactive"},
	{prefix: "smali/org/reactivestreams/", category: "reactive"},

	// ═══════════════════════════════════════════════════════════════
	// APACHE — ГРАНУЛЯРНЫЙ! Не "org/apache/" целиком!
	// ═══════════════════════════════════════════════════════════════
	//
	// ✅ Безопасные подпути (utility-код, НЕ security):
	{prefix: "smali/org/apache/commons/lang/", category: "common"},
	{prefix: "smali/org/apache/commons/codec/", category: "common"},
	{prefix: "smali/org/apache/commons/io/", category: "common"},
	{prefix: "smali/org/apache/commons/logging/", category: "common"},
	{prefix: "smali/org/apache/commons/collections/", category: "common"},
	{prefix: "smali/org/apache/commons/math/", category: "common"},
	{prefix: "smali/org/apache/commons/compress/", category: "common"},
	{prefix: "smali/org/apache/commons/pool/", category: "common"},
	{prefix: "smali/org/apache/commons/dbcp/", category: "common"},
	//
	// ❌ НЕ включаем (проходят полный анализ!):
	//   org/apache/http/       — auth, SSL, proxy (isProxy → ложный "pro")
	//   org/apache/james/      — CipherStorage (шифрование!)
	//   org/apache/commons/cli — может содержать интересные парсеры
	//   org/apache/harmony/    — crypto provider

	// ═══════════════════════════════════════════════════════════════
	// COMMON LIBRARIES
	// ═══════════════════════════════════════════════════════════════
	{prefix: "smali/com/fasterxml/", category: "common"},
	{prefix: "smali/com/bumptech/glide/", category: "common"},
	{prefix: "smali/com/airbnb/", category: "common"},
	{prefix: "smali/dagger/", category: "common"},
	{prefix: "smali/javax/inject/", category: "common"},
	{prefix: "smali/com/jakewharton/", category: "common"},
	{prefix: "smali/org/json/", category: "common"},
	{prefix: "smali/com/github/", category: "common"},
	{prefix: "smali/de/greenrobot/", category: "common"},
	{prefix: "smali/org/greenrobot/", category: "common"},
	{prefix: "smali/com/journeyapps/", category: "common"},
	{prefix: "smali/com/google/zxing/", category: "common"},
	{prefix: "smali/pl/droidsonroids/", category: "common"},
	{prefix: "smali/com/caverock/", category: "common"},
	{prefix: "smali/com/nineoldandroids/", category: "common"},

	// ═══════════════════════════════════════════════════════════════
	// CRYPTO PROVIDERS
	// ═══════════════════════════════════════════════════════════════
	{prefix: "smali/org/bouncycastle/", category: "crypto"},
	{prefix: "smali/org/conscrypt/", category: "crypto"},
	{prefix: "smali/org/spongycastle/", category: "crypto"},

	// ═══════════════════════════════════════════════════════════════
	// GAME ENGINES
	// ═══════════════════════════════════════════════════════════════
	{prefix: "smali/com/unity3d/player/", category: "engine"},
	{prefix: "smali/com/unity3d/services/", category: "engine"},
	{prefix: "smali/bitter/jnibridge/", category: "engine"},
	{prefix: "smali/org/cocos2dx/", category: "engine"},
	{prefix: "smali/org/libsdl/", category: "engine"},
	{prefix: "smali/org/godotengine/", category: "engine"},

	// ═══════════════════════════════════════════════════════════════
	// BILLING API (библиотека, не использование!)
	// ═══════════════════════════════════════════════════════════════
	{prefix: "smali/com/android/billingclient/", category: "billing_lib"},
	{prefix: "smali/com/android/vending/billing/", category: "billing_lib"},

	// ═══════════════════════════════════════════════════════════════
	// AD NETWORKS — библиотеки!
	// ═══════════════════════════════════════════════════════════════
	{prefix: "smali/com/applovin/", category: "ads_sdk"},
	{prefix: "smali/com/mbridge/", category: "ads_sdk"},
	{prefix: "smali/com/bytedance/", category: "ads_sdk"},
	{prefix: "smali/com/pangle/", category: "ads_sdk"},
	{prefix: "smali/com/ironsource/", category: "ads_sdk"},
	{prefix: "smali/com/unity3d/ads/", category: "ads_sdk"},
	{prefix: "smali/com/vungle/", category: "ads_sdk"},
	{prefix: "smali/com/adcolony/", category: "ads_sdk"},
	{prefix: "smali/com/chartboost/", category: "ads_sdk"},
	{prefix: "smali/com/startapp/", category: "ads_sdk"},
	{prefix: "smali/com/inmobi/", category: "ads_sdk"},
	{prefix: "smali/com/fyber/", category: "ads_sdk"},
	{prefix: "smali/com/inneractive/", category: "ads_sdk"},
	{prefix: "smali/com/tapjoy/", category: "ads_sdk"},
	{prefix: "smali/com/ogury/", category: "ads_sdk"},
	{prefix: "smali/io/presage/", category: "ads_sdk"},
	{prefix: "smali/com/smaato/", category: "ads_sdk"},
	{prefix: "smali/io/bidmachine/", category: "ads_sdk"},
	{prefix: "smali/com/criteo/", category: "ads_sdk"},
	{prefix: "smali/net/pubnative/", category: "ads_sdk"},
	{prefix: "smali/com/digitalturbine/", category: "ads_sdk"},
	{prefix: "smali/com/amazon/device/ads/", category: "ads_sdk"},
	{prefix: "smali/com/yandex/mobile/ads/", category: "ads_sdk"},
	{prefix: "smali/com/my/target/", category: "ads_sdk"},
	{prefix: "smali/com/moloco/", category: "ads_sdk"},
	{prefix: "smali/tv/superawesome/", category: "ads_sdk"},
	{prefix: "smali/com/kpadplayer/", category: "ads_sdk"},
	{prefix: "smali/com/kidoz/", category: "ads_sdk"},
	{prefix: "smali/com/mopub/", category: "ads_sdk"},
	{prefix: "smali/com/safedk/", category: "ads_sdk"},
	{prefix: "smali/com/liftoff/", category: "ads_sdk"},
	{prefix: "smali/com/facebook/ads/", category: "ads_sdk"},

	// ═══════════════════════════════════════════════════════════════
	// ANALYTICS SDKs — библиотеки!
	// ═══════════════════════════════════════════════════════════════
	{prefix: "smali/com/appsflyer/", category: "analytics"},
	{prefix: "smali/com/adjust/", category: "analytics"},
	{prefix: "smali/com/amplitude/", category: "analytics"},
	{prefix: "smali/com/mixpanel/", category: "analytics"},
	{prefix: "smali/com/flurry/", category: "analytics"},
	{prefix: "smali/com/segment/", category: "analytics"},
	{prefix: "smali/io/branch/", category: "analytics"},
	{prefix: "smali/com/singular/", category: "analytics"},
	{prefix: "smali/com/kochava/", category: "analytics"},
	{prefix: "smali/com/tenjin/", category: "analytics"},
	{prefix: "smali/com/crashlytics/", category: "analytics"},
	{prefix: "smali/io/sentry/", category: "analytics"},
	{prefix: "smali/com/newrelic/", category: "analytics"},
	{prefix: "smali/com/bugsnag/", category: "analytics"},
	{prefix: "smali/ly/count/", category: "analytics"},
	{prefix: "smali/com/clevertap/", category: "analytics"},
	{prefix: "smali/com/braze/", category: "analytics"},
	{prefix: "smali/com/appboy/", category: "analytics"},
	{prefix: "smali/com/onesignal/", category: "analytics"},
	{prefix: "smali/com/urbanairship/", category: "analytics"},
	{prefix: "smali/com/batch/", category: "analytics"},
	{prefix: "smali/com/leanplum/", category: "analytics"},

	// ═══════════════════════════════════════════════════════════════
	// FACEBOOK — ГРАНУЛЯРНЫЙ! Не "com/facebook/" целиком!
	// ═══════════════════════════════════════════════════════════════
	//
	// ✅ Безопасные подпути:
	{prefix: "smali/com/facebook/internal/", category: "social"},
	{prefix: "smali/com/facebook/share/", category: "social"},
	{prefix: "smali/com/facebook/login/", category: "social"},
	{prefix: "smali/com/facebook/appevents/", category: "social"},
	{prefix: "smali/com/facebook/react/", category: "social"},
	{prefix: "smali/com/facebook/drawee/", category: "social"},
	{prefix: "smali/com/facebook/imagepipeline/", category: "social"},
	{prefix: "smali/com/facebook/soloader/", category: "social"},
	{prefix: "smali/com/facebook/yoga/", category: "social"},
	{prefix: "smali/com/facebook/flipper/", category: "social"},
	{prefix: "smali/com/facebook/hermes/", category: "social"},
	//
	// ❌ НЕ включаем (проходят полный анализ!):
	//   com/facebook/ads/       → уже в ads_sdk!
	//   com/facebook/android/   → старый SDK, может содержать интересное
	//   com/facebook/          → корневые классы, могут быть важными

	// ═══════════════════════════════════════════════════════════════
	// SOCIAL SDKs
	// ═══════════════════════════════════════════════════════════════
	{prefix: "smali/com/twitter/", category: "social"},
	{prefix: "smali/com/vk/", category: "social"},
	{prefix: "smali/com/kakao/", category: "social"},
	{prefix: "smali/com/linecorp/", category: "social"},
}

// ═══════════════════════════════════════════════════════════════════════════════
// PREFIX INDEX — быстрый lookup по первым сегментам пути (v7.3)
// ═══════════════════════════════════════════════════════════════════════════════

type prefixIndex struct {
	entries map[string][]indexedEntry // key → entries
}

type indexedEntry struct {
	entry *knownLibEntry
	idx   int // индекс в knownLibEntries (для дебага)
}

// multiSegmentRoots — корневые сегменты с множеством подпутей, индексируем по 2 сегментам.
var multiSegmentRoots = map[string]bool{
	"com": true,
	"org": true,
	"io":  true,
	"net": true,
	"ly":  true,
}

var prefixIdx = buildPrefixIndex()

func buildPrefixIndex() *prefixIndex {
	idx := &prefixIndex{
		entries: make(map[string][]indexedEntry, 32),
	}

	for i := range knownLibEntries {
		entry := &knownLibEntries[i]
		key := extractIndexKeyFromPrefix(entry.prefix)
		idx.entries[key] = append(idx.entries[key], indexedEntry{entry: entry, idx: i})
	}

	return idx
}

// extractIndexKeyFromPrefix извлекает ключ из полного префикса библиотеки.
func extractIndexKeyFromPrefix(prefix string) string {
	rest := strings.TrimPrefix(prefix, "smali/")
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) == 0 {
		return ""
	}

	if len(parts) >= 2 && multiSegmentRoots[parts[0]] {
		return parts[0] + "/" + parts[1]
	}
	return parts[0]
}

// extractIndexKeyFromPath — быстрый разбор пути файла (вызывается на каждый файл!)
func extractIndexKeyFromPath(pathLower string) (key string, ok bool) {
	rest := strings.TrimPrefix(pathLower, "smali/")
	if rest == pathLower {
		return "", false // не smali-файл
	}

	firstSlash := strings.IndexByte(rest, '/')
	if firstSlash < 0 {
		return "", false
	}

	firstSegment := rest[:firstSlash]

	if multiSegmentRoots[firstSegment] {
		afterFirst := rest[firstSlash+1:]
		secondSlash := strings.IndexByte(afterFirst, '/')
		if secondSlash >= 0 {
			return firstSegment + "/" + afterFirst[:secondSlash], true
		}
		return firstSegment, true
	}

	return firstSegment, true
}

// lookup возвращает список кандидатов по индексу.
func (pi *prefixIndex) lookup(pathLower string) []indexedEntry {
	key, ok := extractIndexKeyFromPath(pathLower)
	if !ok {
		return nil
	}

	if candidates := pi.entries[key]; len(candidates) > 0 {
		return candidates
	}

	// Fallback: только первый сегмент (например, нет com/unknown, но есть com/)
	if idx := strings.IndexByte(key, '/'); idx > 0 {
		return pi.entries[key[:idx]]
	}

	return nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// CATEGORY-BASED RESULTS
// ═══════════════════════════════════════════════════════════════════════════════
//
// Разные типы библиотек получают разный importance:
//   SDK/Kotlin = 0      → неинтересно
//   Common libs = 1     → чуть интереснее
//   Ad SDKs = 2         → ещё интереснее (ad-related endpoints)
//   Crypto = 3          → всегда интересно (шифрование!)
//   Billing lib = 2     → интересно (покупки!)
//
// Все результаты read-only! Не модифицировать!

var categoryResults = buildCategoryResults()

// defaultCategoryResult — fallback если категория не найдена
var defaultCategoryResult = &ClassificationResult{
	IsAppCode:         false,
	IsLibrary:         true,
	Importance:        1,
	RawImportance:     1,
	Confidence:        0.10,
	RawStrength:       SignalWeak,
	EffectiveStrength: SignalWeak,
	TotalDampening:    1.0,
	Categories:        []string{"library"},
}

func buildCategoryResults() map[string]*ClassificationResult {
	type catDef struct {
		importance int
		confidence float64
	}

	defs := map[string]catDef{
		"sdk":         {importance: 0, confidence: 0.05},
		"kotlin":      {importance: 0, confidence: 0.05},
		"google":      {importance: 0, confidence: 0.05},
		"reactive":    {importance: 0, confidence: 0.05},
		"engine":      {importance: 0, confidence: 0.05},
		"network":     {importance: 1, confidence: 0.10},
		"common":      {importance: 1, confidence: 0.10},
		"analytics":   {importance: 1, confidence: 0.10},
		"social":      {importance: 1, confidence: 0.10},
		"ads_sdk":     {importance: 2, confidence: 0.15},
		"billing_lib": {importance: 2, confidence: 0.15},
		"crypto":      {importance: 3, confidence: 0.20},
	}

	results := make(map[string]*ClassificationResult, len(defs))
	for cat, def := range defs {
		results[cat] = &ClassificationResult{
			IsAppCode:         false,
			IsLibrary:         true,
			Importance:        def.importance,
			RawImportance:     def.importance,
			Confidence:        def.confidence,
			RawStrength:       strengthFromScore(def.importance),
			EffectiveStrength: strengthFromScore(def.importance),
			TotalDampening:    1.0,
			Categories:        []string{"library", cat},
		}
	}
	return results
}

func getCategoryResult(category string) *ClassificationResult {
	if r, ok := categoryResults[category]; ok {
		return r
	}
	return defaultCategoryResult
}

// init проверяет, что все категории из knownLibEntries определены.
func init() {
	for i := range knownLibEntries {
		cat := knownLibEntries[i].category
		if _, ok := categoryResults[cat]; !ok {
			categoryResults[cat] = defaultCategoryResult
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// INIT — проверка конфигурации при старте
// ═══════════════════════════════════════════════════════════════════════════════
//
// ⚠️ THREAD SAFETY:
// - categoryResults модифицируется ТОЛЬКО в init()
// - После init() = read-only (safe for concurrent access)
// - prefixIdx строится один раз, затем immutable
// Go гарантирует, что все init() завершаются ДО main(), поэтому первые вызовы
// Classify уже видят полностью инициализированные структуры.

// ═══════════════════════════════════════════════════════════════════════════════
// FAST-PATH — умная проверка известных библиотек
// ═══════════════════════════════════════════════════════════════════════════════
//
// Алгоритм:
//   1. Нормализуем путь (\ → /)
//   2. Проверяем каждый known prefix
//   3. Если совпал — проверяем critical keywords
//   4. Если critical keyword найден → НЕ fast-path! (файл важен!)
//   5. Если нет critical keywords → возвращаем category result
//
// БЫЛО (v6):
//   "smali/org/apache/.../CipherStorage.smali" → fast-path → importance=1 → ПОТЕРЯН!
//
// СТАЛО (v7.2):
//   "smali/org/apache/.../CipherStorage.smali"
//   → org/apache/ НЕ в fast-path (убран)
//   → полный анализ → importance=6, confidence=70% → НАЙДЕН! ✅
//
// БЫЛО (v6):
//   "smali/com/android/billingclient/api/Purchase.smali" → fast-path → importance=1 → ПОТЕРЯН!
//
// СТАЛО (v7.2):
//   → matches "com/android/billingclient/" prefix
//   → containsCriticalKeyword("purchase") → true!
//   → НЕ fast-path → полный анализ → НАЙДЕН! ✅

// tryFastPath пытается классифицировать файл через fast-path.
// Возвращает (result, true) если fast-path сработал.
// Возвращает (nil, false) если нужна полная классификация.
func (f *Filter) tryFastPath(path string) (*ClassificationResult, bool) {
	// Canonicalize multidex roots (smali_classesN/ -> smali/) so known-library
	// prefixes match code from every dex, not only classes.dex.
	normalized := CanonicalSmaliPath(path)

	// ToLower только при необходимости (оптимизация)
	normalizedLower := toLowerFast(normalized)

	// Runtime-marked structural libraries first: the static prefix index is
	// built once at init and cannot know about per-run fingerprints.
	if lib := f.lookupStructural(normalizedLower); lib != nil {
		// Same critical-keyword guard as the static table: a structural
		// library must not swallow files whose name carries a strong signal.
		if matched, _ := containsCriticalKeywordBoundary(normalizedLower); matched {
			f.savedFromFastPath.Add(1)
			return nil, false
		}
		f.fastPathHits.Add(1)
		return lib, true
	}

	// Индексированный lookup: сначала сужаем список до кандидатов
	candidates := prefixIdx.lookup(normalizedLower)
	if len(candidates) == 0 {
		return nil, false // нет совпадающих префиксов → полный анализ
	}

	for _, candidate := range candidates {
		entry := candidate.entry

		if !strings.HasPrefix(normalizedLower, entry.prefix) {
			continue
		}

		// Совпал prefix! Проверяем boundary-aware critical keywords
		if matched, _ := containsCriticalKeywordBoundary(normalizedLower); matched {
			f.savedFromFastPath.Add(1)
			return nil, false
		}

		// Безопасно → fast-path
		f.fastPathHits.Add(1)
		return getCategoryResult(entry.category), true
	}

	return nil, false
}

// ═══════════════════════════════════════════════════════════════════════════════
// CORE API — горячий путь pipeline
// ═══════════════════════════════════════════════════════════════════════════════

// IsAppCode проверяет, является ли путь кодом приложения.
// Hot path — вызывается на КАЖДЫЙ файл.
func (f *Filter) IsAppCode(path string) bool {
	if result, ok := f.tryFastPath(path); ok {
		return result.IsAppCode // всегда false для библиотек
	}
	f.classifyCalls.Add(1)
	return f.classifier.Classify(path).IsAppCode
}

// GetImportance возвращает важность файла (0-10).
func (f *Filter) GetImportance(path string) int {
	if result, ok := f.tryFastPath(path); ok {
		return result.Importance
	}
	f.classifyCalls.Add(1)
	return f.classifier.Classify(path).Importance
}

// IsStandardLibrary проверяет, является ли путь стандартной библиотекой.
// Дополнительная safety-проверка: даже для fast-path файлов проверяем high-value.
func (f *Filter) IsStandardLibrary(path string) bool {
	if _, ok := f.tryFastPath(path); ok {
		// Fast-path уже проверил critical keywords и они не найдены.
		// Но high-value паттерны шире чем critical keywords
		// ("pro", "vip", "gold" не в critical, но в high-value).
		// Делаем дополнительную проверку через полную классификацию.
		result := f.classifier.Classify(path)
		if len(result.MatchedHighValue) > 0 {
			return false // high-value pattern → НЕ стандартная библиотека!
		}
		return true
	}
	return f.classifier.Classify(path).IsLibrary
}

// ═══════════════════════════════════════════════════════════════════════════════
// OPTIMIZED API — один вызов вместо двух
// ═══════════════════════════════════════════════════════════════════════════════

// FileClassification — результат для горячего пути pipeline.
type FileClassification struct {
	IsAppCode        bool
	IsLibrary        bool
	Importance       int
	SkipFullAnalysis bool // known safe library; critical paths never set this
}

// ClassifyForPipeline — ОПТИМИЗИРОВАННЫЙ метод для workers.go.
//
// Раньше в workers.go:
//
//	isAppCode := p.filter.IsAppCode(path)      ← Classify() #1
//	importance := p.filter.GetImportance(path)  ← Classify() #2
//	= 2 вызова Classify на КАЖДЫЙ файл!
//
// Теперь:
//
//	fc := p.filter.ClassifyForPipeline(path)    ← 1 вызов!
//	= 50% экономия
func (f *Filter) ClassifyForPipeline(path string) FileClassification {
	if result, ok := f.tryFastPath(path); ok {
		return FileClassification{
			IsAppCode:        result.IsAppCode,
			IsLibrary:        result.IsLibrary,
			Importance:       result.Importance,
			SkipFullAnalysis: true,
		}
	}

	f.classifyCalls.Add(1)
	result := f.classifier.Classify(path)
	return FileClassification{
		IsAppCode:  result.IsAppCode,
		IsLibrary:  result.IsLibrary,
		Importance: result.Importance,
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// EXTENDED API — полная классификация
// ═══════════════════════════════════════════════════════════════════════════════

// Classify возвращает полную классификацию файла.
func (f *Filter) Classify(path string) *ClassificationResult {
	if result, ok := f.tryFastPath(path); ok {
		return result
	}
	f.classifyCalls.Add(1)
	return f.classifier.Classify(path)
}

// 🆕 ClassifyWithTrace возвращает полную классификацию + ExplainTrace.
// Всегда выполняет полный анализ (обходит fast-path и кеш).
// Используй для дебага: ПОЧЕМУ файл получил такой score?
//
// Пример:
//
//	result, trace := filter.ClassifyWithTrace("smali/org/apache/http/impl/auth/AuthSchemeBase.smali")
//	fmt.Println(trace.String())
//
//	═══ EXPLAIN: org/apache/http/impl/auth/AuthSchemeBase.smali ═══
//	Step 1: [HIGH_VALUE] no_match | No high-value patterns found
//	Step 2: [LIBRARY] dampened | pattern=org/apache/ | dampening=0.40
//	Step 3: [KEYWORD] safe_dampened | pattern=pro | 7→2
//	...
func (f *Filter) ClassifyWithTrace(path string) (*ClassificationResult, *ExplainTrace) {
	f.classifyCalls.Add(1)
	return f.classifier.ClassifyWithTrace(path)
}

// ClassifyBatch классифицирует несколько путей.
func (f *Filter) ClassifyBatch(paths []string) []*ClassificationResult {
	results := make([]*ClassificationResult, len(paths))
	for i, path := range paths {
		results[i] = f.Classify(path)
	}
	return results
}

// ═══════════════════════════════════════════════════════════════════════════════
// EXPLAINABILITY API 🆕
// ═══════════════════════════════════════════════════════════════════════════════

// EnableExplain включает ExplainTrace для ВСЕХ последующих Classify вызовов.
// Полезно для отладки. Добавляет ~5% overhead.
func (f *Filter) EnableExplain() {
	f.classifier.EnableExplain()
}

// DisableExplain выключает ExplainTrace (zero-cost когда выключен).
func (f *Filter) DisableExplain() {
	f.classifier.DisableExplain()
}

// LastTrace возвращает trace последнего Classify вызова.
// nil если explain выключен или последний вызов был fast-path.
func (f *Filter) LastTrace() *ExplainTrace {
	return f.classifier.LastTrace()
}

// ═══════════════════════════════════════════════════════════════════════════════
// QUERY HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

func (f *Filter) IsHighValue(path string) bool {
	result := f.Classify(path)
	return len(result.MatchedHighValue) > 0
}

// IsLibraryPath проверяет, является ли путь частью известной библиотеки.
func (f *Filter) IsLibraryPath(path string) bool {
	if _, ok := f.tryFastPath(path); ok {
		return true
	}
	res := f.classifier.Classify(path)
	return res.IsLibrary
}

// LibraryNameFor возвращает имя библиотеки для пути.
func (f *Filter) LibraryNameFor(path string) string {
	normalized := path
	if strings.ContainsRune(path, '\\') {
		normalized = strings.ReplaceAll(path, "\\", "/")
	}
	normalizedLower := toLowerFast(normalized)

	candidates := prefixIdx.lookup(normalizedLower)
	for _, candidate := range candidates {
		if strings.HasPrefix(normalizedLower, candidate.entry.prefix) {
			return candidate.entry.category
		}
	}
	return ""
}

func (f *Filter) GetCategories(path string) []string {
	return f.Classify(path).Categories
}

func (f *Filter) Summary(path string) string {
	result := f.Classify(path)
	return formatSummary(result)
}

// ═══════════════════════════════════════════════════════════════════════════════
// STATS
// ═══════════════════════════════════════════════════════════════════════════════

type CacheStats struct {
	Hits               int64
	Misses             int64
	Size               int
	MaxSize            int
	HitRate            float64
	ClassifyCalls      int64
	FastPathHits       int64
	CacheInvalidations int64
	SavedFromFastPath  int64 // 🆕 файлы спасённые critical keyword check'ом
}

func (f *Filter) CacheStats() (hits, misses int64, hitRate float64) {
	return f.classifier.cache.Stats()
}

func (f *Filter) GetCacheStats() CacheStats {
	hits, misses, hitRate := f.classifier.cache.Stats()
	return CacheStats{
		Hits:               hits,
		Misses:             misses,
		Size:               f.classifier.cache.Len(),
		MaxSize:            10000,
		HitRate:            hitRate,
		ClassifyCalls:      f.classifyCalls.Load(),
		FastPathHits:       f.fastPathHits.Load(),
		CacheInvalidations: f.cacheInvalidations.Load(),
		SavedFromFastPath:  f.savedFromFastPath.Load(),
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// INTERNAL HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

func formatSummary(result *ClassificationResult) string {
	if result == nil {
		return "unknown"
	}

	hasHighValue := len(result.MatchedHighValue) > 0
	hasObf := result.ObfuscationType != ""
	hasCats := len(result.Categories) > 0

	if !result.IsLibrary && !result.IsAppCode && !hasHighValue && !hasObf && !hasCats {
		return "normal"
	}

	estimatedLen := 32
	if hasCats {
		for _, c := range result.Categories {
			estimatedLen += len(c) + 1
		}
	}

	var sb strings.Builder
	sb.Grow(estimatedLen)
	needSep := false

	writePart := func(s string) {
		if needSep {
			sb.WriteString("; ")
		}
		sb.WriteString(s)
		needSep = true
	}

	// Тип
	if result.IsLibrary {
		writePart("library")
	} else if result.IsAppCode {
		writePart("app_code")
	}

	// High-value
	if hasHighValue {
		writePart("high_value")
	}

	// Обфускация
	if hasObf {
		writePart("obfuscated:" + result.ObfuscationType)
	}

	// 🆕 Strength (показываем если effective ≠ raw)
	if result.RawStrength != result.EffectiveStrength {
		writePart("str:" + result.EffectiveStrength.String() +
			"(raw:" + result.RawStrength.String() + ")")
	} else if result.EffectiveStrength >= SignalStrong {
		writePart("str:" + result.EffectiveStrength.String())
	}

	// Категории
	if hasCats {
		writePart(strings.Join(result.Categories, ","))
	}

	if sb.Len() == 0 {
		return "normal"
	}

	return sb.String()
}
