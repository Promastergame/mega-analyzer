// pkg/internal/matcher/matcher_v2.go
// Mega Analyzer v6.1 — Ultra Low-Noise Matcher
// Ожидаемый результат: 62K → ~3-5K матчей

package matcher

import (
	"strings"
	"sync"
	"sync/atomic"

	"mega-analyzer/pkg/internal/config"
	"mega-analyzer/pkg/internal/types"
)

// ═══════════════════════════════════════════════════════════════════════════════
// SDK PATH DETECTION — расширенный список для максимальной фильтрации
// ═══════════════════════════════════════════════════════════════════════════════

var sdkPathPrefixes = []string{
	// ── Ad Networks ──────────────────────────────────────────────────────────
	"com/mbridge/", "com/applovin/", "com/ironsource/",
	"com/bytedance/sdk/", "com/facebook/ads/", "com/vungle/",
	"com/hyprmx/", "com/fyber/", "com/safedk/",
	"com/unity3d/ads/", "com/unity3d/services/",
	"com/google/android/gms/ads/",
	"com/chartboost/", "com/startapp/", "com/adcolony/",
	"com/inmobi/", "com/tapjoy/", "com/smaato/", "com/ogury/",
	"com/inneractive/", "com/flurry/ads/",

	// ── Analytics & Attribution ──────────────────────────────────────────────
	"com/appsflyer/", "com/google/firebase/",
	"com/adjust/sdk/", "com/segment/",
	"com/amplitude/", "com/mixpanel/",
	"com/google/android/gms/measurement/",
	"com/google/android/gms/analytics/",

	// ── Platform & Core Libraries ────────────────────────────────────────────
	"androidx/", "android/support/",
	"com/google/protobuf/", "com/squareup/wire/",
	"com/google/android/gms/", "com/google/android/play/",
	"com/google/gson/", "com/google/common/",

	// ── Network Libraries ────────────────────────────────────────────────────
	"okhttp3/", "okio/", "retrofit2/",
	"com/squareup/okhttp/", "com/android/volley/",
	"com/koushikdutta/async/", "com/loopj/",

	// ── Unity Engine ─────────────────────────────────────────────────────────
	"com/unity3d/player/", "com/unity/",

	// ── Crash & Monitoring ───────────────────────────────────────────────────
	"com/crashlytics/", "com/google/firebase/crashlytics/",
	"com/newrelic/", "com/bugsnag/", "io/sentry/",
	"com/apm/insight/",

	// ── IAB & Measurement ────────────────────────────────────────────────────
	"com/iab/omid/",

	// ── Media & Players ──────────────────────────────────────────────────────
	"com/google/android/exoplayer/", "com/google/android/exoplayer2/",

	// ── Kotlin & Common ──────────────────────────────────────────────────────
	"kotlin/", "kotlinx/",
	"org/apache/", "org/json/",

	// ── Obfuscator Artifacts ─────────────────────────────────────────────────
	"a/a/a/", "b/b/b/", "c/c/c/",
}

// ═══════════════════════════════════════════════════════════════════════════════
// SDK NOISE CATEGORIES — полностью пропускаем в SDK-путях
// ═══════════════════════════════════════════════════════════════════════════════

var sdkNoiseCategories map[types.Category]bool

func init() {
	sdkNoiseCategories = map[types.Category]bool{
		// Ads — все варианты
		types.CategoryAdShow:      true,
		types.CategoryAdLoad:      true,
		types.CategoryAdNetwork:   true,
		types.CategoryAdResource:  true,
		types.CategoryAdCheck:     true,
		types.CategoryAdMob:       true,
		types.CategoryAppLovin:    true,
		types.CategoryMintegral:   true,
		types.CategoryPangle:      true,
		types.CategoryFacebookAds: true,
		types.CategoryIronSource:  true,
		types.CategoryUnityAds:    true,
		types.CategoryAdColony:    true,
		types.CategoryVungle:      true,
		types.CategoryChartboost:  true,
		types.CategoryStartApp:    true,

		// Analytics — все варианты
		types.CategoryAnalytics:         true,
		types.CategoryAppsFlyer:         true,
		types.CategoryFirebaseAnalytics: true,
		types.CategoryGoogleAnalytics:   true,
		types.CategoryFacebookAnalytics: true,
		types.CategoryAmplitude:         true,
		types.CategoryMixpanel:          true,
		types.CategoryAdjust:            true,
		types.CategoryFlurry:            true,
		types.CategoryCrashlytics:       true,
		types.CategoryCrashReporting:    true,

		// Network noise в SDK
		types.CategoryNetworkCall:      true,
		types.CategoryObfuscator:       true,
		types.CategoryTimeCheck:        true,
		types.CategoryObfuscatedString: true,
	}
}

func isSDKPath(filePath string) bool {
	normalized := strings.ReplaceAll(filePath, "\\", "/")
	// Убираем smali_classesN/ или smali/ prefix
	if idx := strings.Index(normalized, "/"); idx >= 0 {
		prefix := normalized[:idx]
		if strings.HasPrefix(prefix, "smali") {
			normalized = normalized[idx+1:]
		}
	}
	for _, pfx := range sdkPathPrefixes {
		if strings.Contains(normalized, pfx) {
			return true
		}
	}
	return false
}

// ═══════════════════════════════════════════════════════════════════════════════
// AGGRESSIVE CATEGORY LIMITS — минимум шума
// ═══════════════════════════════════════════════════════════════════════════════

var maxPerCategoryPerFile = map[types.Category]int{
	// High-value — показываем больше
	types.CategoryBillingClient:     5,
	types.CategoryPremiumCheck:      3,
	types.CategoryProFeature:        3,
	types.CategorySubscription:      3,
	types.CategorySubscriptionCheck: 3,
	types.CategoryLicenseCheck:      5,
	types.CategorySignatureCheck:    3,
	types.CategoryRootDetection:     3,
	types.CategoryTamperDetection:   3,
	types.CategoryFeatureFlags:      3,
	types.CategoryServerCheck:       3,
	types.CategoryPurchaseToken:     3,
	types.CategoryDynamicLoad:       3,
	types.CategoryPiracy:            3,
	types.CategoryWebViewRemoteJS:   2,

	// Medium-value
	types.CategorySecurity:          2,
	types.CategorySSLPinning:        2,
	types.CategoryEncryptedData:     2,
	types.CategoryEmulatorDetection: 2,
	types.CategoryDebugDetection:    2,
	types.CategoryTrialExpiry:       2,
	types.CategoryHardcodedIP:       3,
	types.CategoryNetworkEndpoint:   3,
	types.CategorySuspiciousURL:     3,

	// Low-value / noise — минимум
	types.CategoryAdShow:            1,
	types.CategoryAdLoad:            1,
	types.CategoryAdNetwork:         1,
	types.CategoryAdResource:        1,
	types.CategoryAdMob:             1,
	types.CategoryAppLovin:          1,
	types.CategoryMintegral:         1,
	types.CategoryPangle:            1,
	types.CategoryFacebookAds:       1,
	types.CategoryIronSource:        1,
	types.CategoryUnityAds:          1,
	types.CategoryAnalytics:         2,
	types.CategoryAppsFlyer:         1,
	types.CategoryFirebaseAnalytics: 1,
	types.CategoryNetworkCall:       2,
	types.CategoryObfuscator:        2,
	types.CategoryObfuscatedString:  2,
	types.CategoryTimeCheck:         2,
	types.CategoryCustomKeyword:     3,
}

const defaultMaxPerCatFile = 3

// Global caps — жёсткие лимиты
var globalCategoryCaps = map[types.Category]int{
	// Ads — достаточно знать что есть
	types.CategoryAdShow:      10,
	types.CategoryAdLoad:      10,
	types.CategoryAdNetwork:   15,
	types.CategoryAdResource:  10,
	types.CategoryAdMob:       5,
	types.CategoryAppLovin:    5,
	types.CategoryUnityAds:    5,
	types.CategoryIronSource:  5,
	types.CategoryFacebookAds: 5,
	types.CategoryMintegral:   5,
	types.CategoryPangle:      5,
	types.CategoryAdColony:    5,
	types.CategoryVungle:      5,
	types.CategoryChartboost:  5,
	types.CategoryStartApp:    5,
	types.CategoryAdCheck:     5,

	// Analytics
	types.CategoryAnalytics:         15,
	types.CategoryAppsFlyer:         5,
	types.CategoryFirebaseAnalytics: 5,
	types.CategoryGoogleAnalytics:   5,

	// Network noise
	types.CategoryNetworkCall:     15,
	types.CategoryNetworkEndpoint: 20,
	types.CategoryHardcodedIP:     20,

	// Obfuscation noise
	types.CategoryTimeCheck:        10,
	types.CategoryObfuscatedString: 10,
	types.CategoryEncryptedData:    15,
	types.CategoryObfuscator:       10,

	// Security в SDK
	types.CategorySSLPinning:        15,
	types.CategoryEmulatorDetection: 15,
	types.CategoryDebugDetection:    10,
	types.CategorySecurity:          30,
	types.CategorySignatureCheck:    20,

	// Custom keywords
	types.CategoryCustomKeyword: 30,

	// Premium — реальные матчи, лимит выше
	types.CategoryPremiumCheck:  20,
	types.CategoryBillingClient: 50,
	types.CategorySubscription:  30,
	types.CategoryLicenseCheck:  20,
}

const defaultGlobalCap = 30

// ═══════════════════════════════════════════════════════════════════════════════
// FALSE POSITIVE PATTERNS — слова которые НЕ означают premium/piracy
// ═══════════════════════════════════════════════════════════════════════════════

var premiumFalsePositives = []string{
	"isprocessed", "isprojected", "isprotobuf", "isproxyclass",
	"isprovisioned", "ispropagationstopped", "ispropersubsetof",
	"isproduction", "isprogress", "ispromise", "isproperty",
	"isprotected", "isprovisional", "isprofile", "isprofiled",
	"isprop", "isprops", "ispropagate", "ispropagating",
	"isprogrammatic", "isprogram", "isprofiler", "isprofiling",
	"isprotectedcontent", "isprovisionalheader", "isprotobufmessage",
	"hasprovider", "hasproto3optional", "hasprotowrapper",
	"premium/",
}

var piracyFalsePositiveContexts = []string{
	"event", "analytics", "log", "firebase", "reward",
	"achievement", "level", "unlock_content", "progression",
	"game_state", "player_data", "measurement",
}

func isPremiumFalsePositive(matchText string) bool {
	textLower := strings.ToLower(matchText)
	for _, fp := range premiumFalsePositives {
		if strings.Contains(textLower, fp) {
			return true
		}
	}
	return false
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONTEXTUAL SUPPRESSION RULES — расширенный набор
// ═══════════════════════════════════════════════════════════════════════════════

type suppressionRule struct {
	category    types.Category
	keyword     string
	pathMust    []string
	contextAnti []string
}

var suppressionRules = []suppressionRule{
	// ── Piracy false positives ───────────────────────────────────────────────

	// "xposed" в SDK anti-tamper = ЗАЩИТА
	{
		category: types.CategoryPiracy,
		keyword:  "xposed",
		pathMust: []string{
			"com/unity3d/", "com/appsflyer/", "com/ironsource/",
			"com/google/android/gms/", "androidx/",
		},
	},
	// "unlocked" в analytics = game events
	{
		category:    types.CategoryPiracy,
		keyword:     "unlocked",
		contextAnti: piracyFalsePositiveContexts,
	},
	{
		category: types.CategoryPiracy,
		keyword:  "unlocked",
		pathMust: []string{
			"com/google/firebase/", "com/appsflyer/",
			"com/google/android/gms/measurement/", "com/iab/",
			"com/ironsource/", "com/vungle/", "com/fyber/",
		},
	},
	// "no_ads" в ad SDK config = легитимный флаг
	{
		category: types.CategoryPiracy,
		keyword:  "no_ads",
		pathMust: []string{
			"com/applovin/", "com/mbridge/", "com/ironsource/",
			"com/google/android/gms/ads/", "com/bytedance/",
			"com/unity3d/", "res/values/", "com/facebook/ads/",
		},
	},
	// "keygen" = KeyGenerator в crypto
	{
		category:    types.CategoryPiracy,
		keyword:     "keygen",
		contextAnti: []string{"KeyGenerator", "javax/crypto", "generateKey", "secretKey", "cipher"},
	},
	{
		category: types.CategoryPiracy,
		keyword:  "keygen",
		pathMust: []string{"javax/crypto/", "com/google/crypto/", "androidx/security/"},
	},
	// "xmanager" в Firebase = нормальный класс
	{
		category: types.CategoryPiracy,
		keyword:  "xmanager",
		pathMust: []string{"com/google/firebase/", "t1/", "com/google/android/"},
	},
	// "5play" в SafeDK
	{
		category: types.CategoryPiracy,
		keyword:  "5play",
		pathMust: []string{"com/safedk/"},
	},
	// Huawei/Xiaomi markets — легитимные сторы
	{
		category: types.CategoryPiracy,
		keyword:  "com.huawei.appmarket",
		pathMust: []string{}, // везде suppress
	},
	{
		category: types.CategoryPiracy,
		keyword:  "com.xiaomi.market",
		pathMust: []string{},
	},
	// com.tencent.* — китайские SDK, не пиратство
	{
		category: types.CategoryPiracy,
		keyword:  "com.tencent.",
		pathMust: []string{"com/mbridge/", "com/bytedance/"},
	},

	// ── Custom Keyword false positives ───────────────────────────────────────

	// "setAccessible" — universal reflection plumbing. AndroidX, Play Services
	// and app glue alike call setAccessible(true) for every reflective access,
	// so as a standalone finding it carries no triage value in any file
	// (including R8-obfuscated classes where the original package is hidden).
	// Reflective crack-point evidence is tracked separately by the CFG-based
	// detectors, which keep their own context.
	{
		category: types.CategoryCustomKeyword,
		keyword:  "setaccessible",
		pathMust: []string{}, // везде suppress
	},
	// "getDeviceId" в analytics SDK
	{
		category: types.CategoryCustomKeyword,
		keyword:  "getdeviceid",
		pathMust: []string{
			"com/appsflyer/", "com/adjust/", "com/google/android/gms/",
			"com/facebook/", "com/unity3d/", "com/ironsource/",
		},
	},

	// ── Vendored billing SDK internals ───────────────────────────────────────

	// Google Play Billing ships as a vendored library inside the APK, so any
	// match against the library's own classes (Purchase/SkuDetails field and
	// .param boilerplate, play_billing internals) describes the SDK, not app
	// behavior. App-side billing wrappers (obfuscated or smellymoo/sand/**)
	// stay visible: they are the actual integration evidence.
	{
		category: types.CategoryBillingClient,
		pathMust: []string{
			"com/android/billingclient/", "com/android/vending/billing/",
			"com/google/android/gms/internal/play_billing/",
		},
	},
	{
		category: types.CategoryPurchaseToken,
		pathMust: []string{
			"com/android/billingclient/", "com/android/vending/billing/",
			"com/google/android/gms/internal/play_billing/",
		},
	},
	{
		category: types.CategoryBillingCallback,
		pathMust: []string{
			"com/android/billingclient/", "com/android/vending/billing/",
			"com/google/android/gms/internal/play_billing/",
		},
	},
	{
		category: types.CategorySubscription,
		pathMust: []string{
			"com/android/billingclient/", "com/android/vending/billing/",
			"com/google/android/gms/internal/play_billing/",
		},
	},
	{
		category: types.CategoryPremiumCheck,
		pathMust: []string{
			"com/android/billingclient/", "com/android/vending/billing/",
			"com/google/android/gms/internal/play_billing/",
		},
	},
	{
		category: types.CategoryPremiumUnlock,
		pathMust: []string{
			"com/android/billingclient/", "com/android/vending/billing/",
			"com/google/android/gms/internal/play_billing/",
		},
	},

	// ── Ad patterns в SDK ────────────────────────────────────────────────────
	// "banner" в ad SDK — шум
	{
		category: types.CategoryAdShow,
		keyword:  "banner",
		pathMust: []string{
			"com/applovin/", "com/mbridge/", "com/google/android/gms/ads/",
			"com/ironsource/", "com/unity3d/ads/", "com/facebook/ads/",
			"com/bytedance/", "com/vungle/", "com/chartboost/",
		},
	},
	// "interstitial" в ad SDK
	{
		category: types.CategoryAdShow,
		keyword:  "interstitial",
		pathMust: []string{
			"com/applovin/", "com/mbridge/", "com/google/android/gms/ads/",
			"com/ironsource/", "com/unity3d/ads/", "com/facebook/ads/",
		},
	},
	// "rewarded" в ad SDK
	{
		category: types.CategoryAdShow,
		keyword:  "rewarded",
		pathMust: []string{
			"com/applovin/", "com/mbridge/", "com/google/android/gms/ads/",
			"com/ironsource/", "com/unity3d/ads/",
		},
	},

	// ── SSL Pinning в network libs ───────────────────────────────────────────

	{
		category: types.CategorySSLPinning,
		keyword:  "certificatepinner",
		pathMust: []string{"okhttp3/", "com/squareup/okhttp/"},
	},
	{
		category: types.CategorySSLPinning,
		keyword:  "trustmanager",
		pathMust: []string{"okhttp3/", "retrofit2/", "com/android/volley/", "javax/net/ssl/"},
	},
	{
		category: types.CategorySSLPinning,
		keyword:  "hostnameverifier",
		pathMust: []string{"okhttp3/", "retrofit2/", "javax/net/ssl/"},
	},

	// ── Premium false positives ──────────────────────────────────────────────

	// Protobuf "hasXxx" methods
	{
		category: types.CategoryPremiumCheck,
		keyword:  "haspro",
		pathMust: []string{"com/google/protobuf/"},
	},
	{
		category: types.CategoryProFeature,
		keyword:  "hasfeature",
		pathMust: []string{"android/view/Window", "androidx/core/view/"},
	},
	// Security noise in common SDKs
	{
		category: types.CategorySecurity,
		pathMust: []string{"com/google/android/gms/", "androidx/", "com/facebook/", "com/unity3d/"},
	},
}

// ShouldSuppressCustomKeyword lets the custom-keyword detector apply the same
// false-positive table as the built-in pattern scan. Custom keywords are
// user-configurable, so their hits previously bypassed suppression entirely
// and flooded reports with framework boilerplate (46 setAccessible findings on
// a clean app).
func ShouldSuppressCustomKeyword(category types.Category, matchText, filePath, context string) bool {
	return shouldSuppress(category, matchText, filePath, context)
}

func shouldSuppress(category types.Category, matchText, filePath, context string) bool {
	filePathLower := strings.ToLower(strings.ReplaceAll(filePath, "\\", "/"))
	contextLower := strings.ToLower(context)
	matchTextLower := strings.ToLower(matchText)

	// Специальная проверка для Premium false positives
	if category == types.CategoryPremiumCheck && isPremiumFalsePositive(matchText) {
		return true
	}

	for _, rule := range suppressionRules {
		if rule.category != category {
			continue
		}
		if rule.keyword != "" && !strings.Contains(matchTextLower, rule.keyword) {
			continue
		}

		// pathMust пустой = suppress везде (для keyword match)
		if len(rule.pathMust) == 0 && rule.keyword != "" {
			return true
		}

		if len(rule.pathMust) > 0 {
			for _, p := range rule.pathMust {
				if strings.Contains(filePathLower, strings.ToLower(p)) {
					return true
				}
			}
		}
		if len(rule.contextAnti) > 0 {
			for _, anti := range rule.contextAnti {
				antiL := strings.ToLower(anti)
				if strings.Contains(contextLower, antiL) || strings.Contains(matchTextLower, antiL) {
					return true
				}
			}
		}
	}
	return false
}

// ═══════════════════════════════════════════════════════════════════════════════
// LINE INDEX — O(1) доступ
// ═══════════════════════════════════════════════════════════════════════════════

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

type lineIndex struct {
	starts []int
}

func buildLineIndex(content string) *lineIndex {
	estimated := len(content)/40 + 1
	starts := make([]int, 0, estimated)
	starts = append(starts, 0)
	for i := 0; i < len(content); i++ {
		if content[i] == '\n' && i+1 < len(content) {
			starts = append(starts, i+1)
		}
	}
	return &lineIndex{starts: starts}
}

func (li *lineIndex) lineCount() int {
	return len(li.starts)
}

// ═══════════════════════════════════════════════════════════════════════════════
// PREFILTER INDEX
// ═══════════════════════════════════════════════════════════════════════════════

type prefilterIndex struct {
	uniqueKeywords    []string
	keywordToPatterns map[string][]*CompiledPattern
	noKeywordPatterns []*CompiledPattern
	automaton         *AhoCorasick
}

func buildPrefilterIndex(patterns *CompiledPatterns) *prefilterIndex {
	idx := &prefilterIndex{
		keywordToPatterns: make(map[string][]*CompiledPattern, 64),
	}
	for gi := range patterns.Groups {
		group := &patterns.Groups[gi]
		for _, pat := range group.Patterns {
			if len(pat.KeywordsLower) == 0 {
				idx.noKeywordPatterns = append(idx.noKeywordPatterns, pat)
				continue
			}
			for _, kw := range pat.KeywordsLower {
				idx.keywordToPatterns[kw] = append(idx.keywordToPatterns[kw], pat)
			}
		}
	}
	idx.uniqueKeywords = make([]string, 0, len(idx.keywordToPatterns))
	for kw := range idx.keywordToPatterns {
		idx.uniqueKeywords = append(idx.uniqueKeywords, kw)
	}
	if len(idx.uniqueKeywords) > 0 {
		idx.automaton = NewAhoCorasick(idx.uniqueKeywords)
	}
	return idx
}

// ═══════════════════════════════════════════════════════════════════════════════
// MATCHER
// ═══════════════════════════════════════════════════════════════════════════════

type Matcher struct {
	patterns     *CompiledPatterns
	pfIndex      *prefilterIndex
	config       *config.Config
	mu           sync.Mutex
	stats        map[types.Category]int
	totalMatched atomic.Int64
	totalScanned atomic.Int64

	globalCatCounts sync.Map
	catCounts       []atomic.Int64 // indexed by dense category id (catindex.go)
	suppressedCount atomic.Int64
	sdkSkippedCount atomic.Int64
}

func NewMatcher(cfg *config.Config) (*Matcher, error) {
	patterns, err := Compile()
	if err != nil {
		return nil, err
	}
	return &Matcher{
		patterns:  patterns,
		pfIndex:   buildPrefilterIndex(patterns),
		config:    cfg,
		stats:     make(map[types.Category]int, 32),
		catCounts: make([]atomic.Int64, numCategories()),
	}, nil
}

func (m *Matcher) getGlobalCount(cat types.Category) *atomic.Int64 {
	if v, ok := m.globalCatCounts.Load(cat); ok {
		return v.(*atomic.Int64)
	}
	counter := &atomic.Int64{}
	actual, _ := m.globalCatCounts.LoadOrStore(cat, counter)
	return actual.(*atomic.Int64)
}

func (m *Matcher) isGlobalCapReached(cat types.Category) bool {
	if m.catCounts != nil {
		if id := categoryID(cat); id >= 0 && int(id) < len(m.catCounts) {
			return m.catCounts[id].Load() >= catGlobalCapByID[id]
		}
	}
	capVal, ok := globalCategoryCaps[cat]
	if !ok {
		capVal = defaultGlobalCap
	}
	return m.getGlobalCount(cat).Load() >= int64(capVal)
}

// capReachedID is the hot-loop form: the pattern already carries its dense
// category id, so the check is one slice load instead of hashing a string.
func (m *Matcher) capReachedID(id int32, cat types.Category) bool {
	if m.catCounts != nil && id >= 0 && int(id) < len(m.catCounts) {
		return m.catCounts[id].Load() >= catGlobalCapByID[id]
	}
	return m.isGlobalCapReached(cat)
}

// addGlobalCount records one accepted match against the global category cap.
func (m *Matcher) addGlobalCount(cat types.Category) {
	if m.catCounts != nil {
		if id := categoryID(cat); id >= 0 && int(id) < len(m.catCounts) {
			m.catCounts[id].Add(1)
			return
		}
	}
	m.getGlobalCount(cat).Add(1)
}

// ═══════════════════════════════════════════════════════════════════════════════
// PUBLIC API
// ═══════════════════════════════════════════════════════════════════════════════

func (m *Matcher) MatchContentWithFilter(content string, filePath string, isAppCode bool) []types.Match {
	contentLower := strings.ToLower(content)
	return m.matchInternal(content, contentLower, filePath, isAppCode)
}

func (m *Matcher) MatchContentWithFilterLower(content, contentLower string, filePath string, isAppCode bool) []types.Match {
	return m.matchInternal(content, contentLower, filePath, isAppCode)
}

func (m *Matcher) MatchContent(content string, filePath string) []types.Match {
	return m.MatchContentWithFilter(content, filePath, true)
}

func (m *Matcher) GetStats() map[types.Category]int {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make(map[types.Category]int, len(m.stats))
	for k, v := range m.stats {
		cp[k] = v
	}
	return cp
}

func (m *Matcher) TotalMatched() int64    { return m.totalMatched.Load() }
func (m *Matcher) TotalScanned() int64    { return m.totalScanned.Load() }
func (m *Matcher) SuppressedCount() int64 { return m.suppressedCount.Load() }
func (m *Matcher) SDKSkippedCount() int64 { return m.sdkSkippedCount.Load() }

// ═══════════════════════════════════════════════════════════════════════════════
// INTERNAL
// ═══════════════════════════════════════════════════════════════════════════════

// isUIResourceXML reports whether a path is a pure UI-resource XML file
// (layout, color, animation, drawable, dimens, styles, …). These contain no
// executable code, so running code-oriented detection patterns against them
// only produces noise — hundreds of bogus "Security" hits on layouts and
// colors. AndroidManifest.xml is explicitly NOT a UI resource and is still
// scanned. See plan §1.7.
func isUIResourceXML(filePath string) bool {
	p := strings.ToLower(filePath)
	p = strings.ReplaceAll(p, "\\", "/")
	if strings.HasSuffix(p, "androidmanifest.xml") {
		return false
	}
	if !strings.HasSuffix(p, ".xml") {
		return false
	}
	uiResDirs := []string{
		"res/layout", "res/color", "res/anim", "res/animator",
		"res/drawable", "res/mipmap", "res/menu", "res/font",
		"res/transition", "res/values", "res/interpolator",
		"res/navigation",
	}
	for _, d := range uiResDirs {
		if strings.Contains(p, d) {
			return true
		}
	}
	return false
}

func (m *Matcher) matchInternal(content, contentLower, filePath string, isAppCode bool) []types.Match {
	m.totalScanned.Add(1)

	if len(content) == 0 {
		return []types.Match{}
	}

	// Skip code-pattern matching on pure UI-resource XML — plan §1.7.
	if isUIResourceXML(filePath) {
		return nil
	}

	contentIsASCII := isASCII(content)
	fileIsSDK := isSDKPath(filePath)

	candidates := m.prefilterPatterns(contentLower, isAppCode, fileIsSDK)
	if len(candidates) == 0 {
		return nil
	}

	// CPU governor: bound total concurrent CPU-bound matching to GOMAXPROCS.
	// Each file holds exactly one token while it is scanned; large files may
	// borrow extra tokens inside MatchContentParallel. This stops the pipeline's
	// per-core file workers from EACH additionally fanning out to NumCPU chunk
	// workers (NumCPU*NumCPU goroutines -> scheduler/cache thrashing). Findings
	// are identical; only scheduling changes.
	gov := cpuBudget()
	gov.acquire()
	defer gov.releaseOne()

	if ShouldUseParallel(len(content), len(candidates)) {
		return m.MatchContentParallel(content, contentLower, filePath, isAppCode, 0)
	}

	li := buildLineIndex(content)
	matches := m.scanLines(content, contentLower, filePath, isAppCode, candidates, contentIsASCII, li, fileIsSDK)

	if len(matches) > 0 {
		m.batchUpdateStats(matches)
		m.totalMatched.Add(int64(len(matches)))
		for i := range matches {
			m.addGlobalCount(matches[i].Category)
		}
	}

	return matches
}

// ═══════════════════════════════════════════════════════════════════════════════
// PHASE 1: PREFILTER
// ═══════════════════════════════════════════════════════════════════════════════

func (m *Matcher) prefilterPatterns(contentLower string, isAppCode bool, fileIsSDK bool) []*CompiledPattern {
	idx := m.pfIndex
	candidates := make([]*CompiledPattern, 0, 32)

	for _, pat := range idx.noKeywordPatterns {
		if !pat.MustBeAppCode || isAppCode {
			if fileIsSDK && sdkNoiseCategories[pat.Category] {
				m.sdkSkippedCount.Add(1)
				continue
			}
			if m.capReachedID(pat.CatIdx, pat.Category) {
				continue
			}
			candidates = append(candidates, pat)
		}
	}

	if idx.automaton == nil {
		return candidates
	}

	seen := make(map[*CompiledPattern]struct{}, 32)
	hits := idx.automaton.Search(contentLower)

	for _, hitIdx := range hits {
		kw := idx.automaton.Pattern(hitIdx)
		for _, pat := range idx.keywordToPatterns[kw] {
			if pat.MustBeAppCode && !isAppCode {
				continue
			}
			if _, ok := seen[pat]; ok {
				continue
			}
			if fileIsSDK && sdkNoiseCategories[pat.Category] {
				m.sdkSkippedCount.Add(1)
				continue
			}
			if m.capReachedID(pat.CatIdx, pat.Category) {
				continue
			}
			seen[pat] = struct{}{}
			candidates = append(candidates, pat)
		}
	}

	return candidates
}

// ═══════════════════════════════════════════════════════════════════════════════
// PHASE 2: LINE SCANNING
// ═══════════════════════════════════════════════════════════════════════════════

func (m *Matcher) scanLines(
	content, contentLower, filePath string,
	isAppCode bool,
	candidates []*CompiledPattern,
	contentIsASCII bool,
	li *lineIndex,
	fileIsSDK bool,
) []types.Match {
	_ = isAppCode

	matches := make([]types.Match, 0, 16)
	maxMatches := m.config.MaxMatchesPerFile
	maxStrLen := m.config.MaxStringLength
	contextLines := m.config.ContextLines
	totalLines := li.lineCount()

	scratch := newCatScratch()

	for lineIdx := 0; lineIdx < totalLines; lineIdx++ {
		lineNum := lineIdx + 1

		start := li.starts[lineIdx]
		var end int
		if lineIdx+1 < totalLines {
			end = li.starts[lineIdx+1]
			if end > start && content[end-1] == '\n' {
				end--
			}
		} else {
			end = len(content)
		}

		if start >= end {
			continue
		}

		line := content[start:end]

		if isSkippableLine(line) {
			continue
		}

		if len(matches) >= maxMatches {
			break
		}

		var lineLower string
		if contentIsASCII || len(content) == len(contentLower) {
			lineLower = contentLower[start:end]
		} else {
			lineLower = strings.ToLower(line)
		}

		scratch.nextLine()

		for _, pat := range candidates {
			if scratch.blocked(pat.CatIdx, pat.Category) {
				continue
			}

			if m.capReachedID(pat.CatIdx, pat.Category) {
				continue
			}

			if len(pat.KeywordsLower) > 0 {
				hasKW := false
				for _, kw := range pat.KeywordsLower {
					if strings.Contains(lineLower, kw) {
						hasKW = true
						break
					}
				}
				if !hasKW {
					continue
				}
			}

			if pat.GateLiteral != "" {
				if pat.GateFold {
					if !strings.Contains(lineLower, pat.GateLiteral) {
						continue
					}
				} else if !strings.Contains(line, pat.GateLiteral) {
					continue
				}
			}

			if pat.Regex != nil && pat.Regex.MatchString(line) {
				ctx := extractContextFast(content, li, lineNum, contextLines)

				if shouldSuppress(pat.Category, line, filePath, ctx) {
					m.suppressedCount.Add(1)
					continue
				}

				// Premium/subscription vocabulary (isUnlocked, hasPro, ...)
				// only means a real paywall when the file also references
				// billing/licensing machinery. In games these identifiers are
				// badges/achievements — suppress them otherwise.
				if isPremiumVocabularyCategory(pat.Category) && !fileHasBillingMachinery(contentLower) {
					m.suppressedCount.Add(1)
					continue
				}

				info := types.GetCategoryInfo(pat.Category)

				score := float64(info.Priority)
				// Critical only when BOTH the category default and the specific
				// pattern say so — a pattern marked IsCritical: false (e.g.
				// getPackageInfo) must never be escalated by its category.
				isCritical := info.IsCritical && pat.IsCritical
				if fileIsSDK {
					score *= 0.1
					isCritical = false
				}

				matches = append(matches, types.Match{
					SourceLocation: types.SourceLocation{
						File: filePath,
						Line: lineNum,
					},
					Categorized: types.Categorized{Category: pat.Category},
					Scored:      types.Scored{Score: score},
					Text:        types.TruncateString(line, maxStrLen),
					Pattern:     pat.Description,
					Context:     ctx,
					IsCritical:  isCritical,
				})

				scratch.record(pat.CatIdx, pat.Category)

				if len(matches) >= maxMatches {
					break
				}
			}
		}
	}

	return matches
}

// ═══════════════════════════════════════════════════════════════════════════════
// PHASE 3: BATCH STATS
// ═══════════════════════════════════════════════════════════════════════════════

func (m *Matcher) batchUpdateStats(matches []types.Match) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range matches {
		m.stats[matches[i].Category]++
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONTEXT EXTRACTION
// ═══════════════════════════════════════════════════════════════════════════════

func extractContextFast(content string, li *lineIndex, lineNum, contextLines int) string {
	if contextLines <= 0 || li == nil {
		return ""
	}
	totalLines := li.lineCount()
	startIdx := lineNum - contextLines - 1
	endIdx := lineNum + contextLines - 1
	if startIdx < 0 {
		startIdx = 0
	}
	if endIdx >= totalLines {
		endIdx = totalLines - 1
	}
	startPos := li.starts[startIdx]
	var endPos int
	if endIdx+1 < totalLines {
		endPos = li.starts[endIdx+1]
		if endPos > 0 && content[endPos-1] == '\n' {
			endPos--
		}
	} else {
		endPos = len(content)
	}
	if startPos >= endPos || startPos >= len(content) {
		return ""
	}
	ctx := content[startPos:endPos]
	const maxContextLen = 500
	if len(ctx) > maxContextLen {
		ctx = ctx[:maxContextLen] + "..."
	}
	return ctx
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

func isSkippableLine(line string) bool {
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case ' ', '\t', '\r':
			continue
		case '#':
			return true
		default:
			return false
		}
	}
	return true
}

func extractContext(content string, lineNum, contextLines int) string {
	if contextLines <= 0 {
		return ""
	}
	targetStart := lineNum - contextLines - 1
	targetEnd := lineNum + contextLines
	if targetStart < 0 {
		targetStart = 0
	}
	currentLine := 0
	startPos := 0
	endPos := len(content)
	for i := 0; i < len(content); i++ {
		if content[i] == '\n' {
			currentLine++
			if currentLine == targetStart {
				startPos = i + 1
			}
			if currentLine == targetEnd {
				endPos = i
				break
			}
		}
	}
	if startPos >= endPos || startPos >= len(content) {
		return ""
	}
	ctx := content[startPos:endPos]
	const maxContextLen = 500
	if len(ctx) > maxContextLen {
		ctx = ctx[:maxContextLen] + "..."
	}
	return ctx
}

// isPremiumVocabularyCategory reports categories built from generic
// identifier vocabulary (isUnlocked, hasPro, isPremium, ...). Such names
// are only meaningful next to billing machinery; alone they are ordinary
// app/game logic (badge unlocks, feature flags).
func isPremiumVocabularyCategory(c types.Category) bool {
	switch c {
	case types.CategoryPremiumCheck, types.CategoryPremiumUnlock,
		types.CategoryProFeature, types.CategorySubscription,
		types.CategorySubscriptionCheck:
		return true
	}
	return false
}

// fileHasBillingMachinery reports whether the file references real
// billing/licensing APIs — required corroboration for premium vocabulary.
func fileHasBillingMachinery(contentLower string) bool {
	for _, kw := range []string{
		"billing", "com/android/vending", "skudetails", "productdetails",
		"licens", "purchase", "subscription", "paywall", "entitlement",
	} {
		if strings.Contains(contentLower, kw) {
			return true
		}
	}
	return false
}
