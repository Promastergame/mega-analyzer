// pkg/internal/pipeline/detectors.go
package pipeline

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"mega-analyzer/pkg/internal/matcher"
	"mega-analyzer/pkg/internal/piracy"
	"mega-analyzer/pkg/internal/types"
)

// ═══════════════════════════════════════════════════════════════════════════════
// DETECTOR INTERFACE & CONTEXT
// ═══════════════════════════════════════════════════════════════════════════════

// FileDetectContext — контекст для детекторов.
type FileDetectContext struct {
	Ctx          context.Context
	Path         string
	Content      []byte
	ContentLower []byte
	LineOffsets  *types.LineOffsets
	IsAppCode    bool
	FileType     types.FileType
	Job          FileJob

	// Class — parsed Smali AST for FileTypeSmali inputs (nil for compact
	// detector streams and non-smali files). Lets detectors reason about
	// methods, invokes and register-level constants instead of raw bytes.
	Class *types.SmaliClass

	// Results of the independent browser helper; nil selects the local path.
	PrecomputedPiracy    *[]types.Match
	PiracyDuration       time.Duration
	PrecomputedDetectors map[string]FileDetectorResult

	// ── Кешированные вычисления (lazy) ───────────────────────────────────
	hasDigits     *bool
	hasDotClass   *bool
	isTextContent *bool
}

func (ctx *FileDetectContext) HasDigits() bool {
	if ctx.hasDigits == nil {
		result := hasAnyDigit(ctx.Content)
		ctx.hasDigits = &result
	}
	return *ctx.hasDigits
}

func (ctx *FileDetectContext) HasDotClass() bool {
	if ctx.hasDotClass == nil {
		result := bytes.Contains(ctx.ContentLower, []byte(".class"))
		ctx.hasDotClass = &result
	}
	return *ctx.hasDotClass
}

// IsTextContent — кешированная проверка "это текстовый файл?"
// Вызывается многими детекторами. Без кеша = повторный анализ 4KB на каждый детектор.
func (ctx *FileDetectContext) IsTextContent() bool {
	if ctx.isTextContent == nil {
		result := isLikelyTextContent(ctx.Content)
		ctx.isTextContent = &result
	}
	return *ctx.isTextContent
}

// FileDetector — интерфейс для подключаемых детекторов.
type FileDetector interface {
	Name() string
	Detect(ctx *FileDetectContext, analysis *types.FileAnalysis)
}

// FileTypeAwareDetector lets a detector opt out before it is invoked for file
// kinds it cannot understand. Detectors without this interface retain the
// previous behaviour and receive every scannable file.
type FileTypeAwareDetector interface {
	FileDetector
	SupportsFile(fileType types.FileType, path string) bool
}

type ResettableDetector interface {
	FileDetector
	Reset()
}

type AggregatingDetector interface {
	FileDetector
	Finalize() []types.Match
}

// ═══════════════════════════════════════════════════════════════════════════════
// DETECTOR INDEX — Fast-path indexing by FileType
// ═══════════════════════════════════════════════════════════════════════════════

type detectorIndex struct {
	byType        [256][]FileDetector
	pathSensitive []FileDetector
	generic       []FileDetector
}

func buildDetectorIndex(detectors []FileDetector) *detectorIndex {
	idx := &detectorIndex{}

	samplePaths := []string{
		"",
		"AndroidManifest.xml",
		"res/values/strings.xml",
		"smali/com/example/Foo.smali",
		"lib/arm64-v8a/libfoo.so",
		"assets/global-metadata.dat",
		"classes.dex",
		"res/drawable/icon.png",
	}

	for _, d := range detectors {
		selective, ok := d.(FileTypeAwareDetector)
		if !ok {
			idx.generic = append(idx.generic, d)
			continue
		}

		pathSensitive := false
		for ft := types.FileType(0); ft.IsValid(); ft++ {
			baseResult := selective.SupportsFile(ft, samplePaths[0])
			for _, path := range samplePaths[1:] {
				if selective.SupportsFile(ft, path) != baseResult {
					pathSensitive = true
					break
				}
			}
			if pathSensitive {
				break
			}
		}

		if pathSensitive {
			idx.pathSensitive = append(idx.pathSensitive, d)
		} else {
			for ft := types.FileType(0); ft.IsValid(); ft++ {
				if selective.SupportsFile(ft, "") {
					idx.byType[ft] = append(idx.byType[ft], d)
				}
			}
		}
	}

	return idx
}

// ═══════════════════════════════════════════════════════════════════════════════
// DETECTOR AC — Aho-Corasick хелпер для детекторов
// ═══════════════════════════════════════════════════════════════════════════════
//
// Раньше: каждый детектор делал K × bytes.Index по всему файлу = O(N × K)
// Теперь: AC.SearchBytes за ОДИН проход = O(N), потом bytes.Index только для найденных
//
// Для файла 100KB с 20 паттернами, из которых 2 найдены:
//   Раньше:  20 × 100KB = 2 000 000 байт-сравнений
//   Теперь:  AC(100KB) + 2 × 100KB = 300 000 переходов
//   Ускорение: ~7x
//
// Для файла БЕЗ совпадений (90% случаев):
//   Раньше:  20 × 100KB = 2 000 000
//   Теперь:  AC(100KB) = 100 000
//   Ускорение: ~20x

type detectorACEntry struct {
	patternLower []byte         // lowercase паттерн для поиска
	group        string         // ключ дедупликации (пустой = без дедупа)
	desc         string         // описание для Match
	category     types.Category // категория Match
	critical     bool           // IsCritical флаг
}

type detectorAC struct {
	ac      *matcher.AhoCorasick
	entries []detectorACEntry
}

// newDetectorAC строит AC из списка записей. Вызывается ОДИН раз при init.
func newDetectorAC(entries []detectorACEntry) *detectorAC {
	if len(entries) == 0 {
		return nil
	}
	patterns := make([]string, len(entries))
	for i, e := range entries {
		patterns[i] = string(e.patternLower)
	}
	return &detectorAC{
		ac:      matcher.NewAhoCorasick(patterns),
		entries: entries,
	}
}

// findMatches — двухфазный поиск:
//
//	Phase 1: AC.SearchBytes → какие паттерны ЕСТЬ в файле (O(N))
//	Phase 2: bytes.Index только для найденных → позиции (O(M×N), M << K)
//
// Дедуплицирует по group (один match на группу).
func (d *detectorAC) findMatches(contentLower []byte, ctx *FileDetectContext, analysis *types.FileAnalysis) {
	d.findMatchesCriticalIf(contentLower, ctx, analysis, 0)
}

// findMatchesCriticalIf is findMatches with a LOCAL evidence requirement: when
// evidenceWindow > 0, a match is only marked critical if billing/licensing
// machinery (hasBillingMachinery) appears within evidenceWindow bytes of the
// match itself -- not merely anywhere in the file. A whole-file signal misfires
// on classes that reference billing machinery for unrelated reasons elsewhere
// in the same class (e.g. a shared base Activity).
func (d *detectorAC) findMatchesCriticalIf(contentLower []byte, ctx *FileDetectContext, analysis *types.FileAnalysis, evidenceWindow int) {
	if d == nil || d.ac == nil {
		return
	}

	// Phase 1: O(N) — один проход, ВСЕ паттерны сразу
	found := d.ac.SearchBytes(contentLower)
	if len(found) == 0 {
		return
	}

	// Phase 2: только для найденных паттернов
	var seenGroups map[string]bool

	for _, patIdx := range found {
		if patIdx < 0 || patIdx >= len(d.entries) {
			continue
		}
		e := &d.entries[patIdx]

		// Получаем позицию для номера строки
		idx := bytes.Index(contentLower, e.patternLower)
		if idx < 0 {
			continue
		}
		if e.category == types.CategoryObfuscator {
			for idx >= 0 && !isWholeWord(contentLower, idx, len(e.patternLower)) {
				next := bytes.Index(contentLower[idx+1:], e.patternLower)
				if next < 0 {
					idx = -1
					break
				}
				idx += next + 1
			}
			if idx < 0 {
				continue
			}
		}
		if e.group != "" {
			if seenGroups == nil {
				seenGroups = make(map[string]bool, 4)
			}
			if seenGroups[e.group] {
				continue
			}
			seenGroups[e.group] = true
		}

		line := lineAt(ctx.LineOffsets, idx)
		critical := e.critical
		if critical && evidenceWindow > 0 {
			critical = hasBillingMachinery(getSurrounding(contentLower, idx, evidenceWindow))
		}
		analysis.Matches = append(analysis.Matches, newMatch(
			e.category, analysis.Path, line,
			e.desc, string(e.patternLower),
			critical,
		))
	}
}

// containsAny — быстрая проверка "есть хоть одно совпадение?" O(N).
// Для раннего выхода из детектора.
func (d *detectorAC) containsAny(contentLower []byte) bool {
	if d == nil || d.ac == nil {
		return false
	}
	return d.ac.ContainsAnyBytes(contentLower)
}

// ═══════════════════════════════════════════════════════════════════════════════
// DETECTOR METRICS
// ═══════════════════════════════════════════════════════════════════════════════

type DetectorMetrics struct {
	FilesProcessed   atomic.Int64
	MatchesFound     atomic.Int64
	ProcessingTimeNs atomic.Int64
	detectorStats    sync.Map
}

type DetectorStat struct {
	Calls   atomic.Int64
	Matches atomic.Int64
	TimeNs  atomic.Int64
}

func NewDetectorMetrics() *DetectorMetrics {
	return &DetectorMetrics{}
}

func (m *DetectorMetrics) Record(name string, matches int, timeNs int64) {
	m.FilesProcessed.Add(1)
	m.MatchesFound.Add(int64(matches))
	m.ProcessingTimeNs.Add(timeNs)

	statI, _ := m.detectorStats.LoadOrStore(name, &DetectorStat{})
	stat := statI.(*DetectorStat)
	stat.Calls.Add(1)
	stat.Matches.Add(int64(matches))
	stat.TimeNs.Add(timeNs)
}

// ═══════════════════════════════════════════════════════════════════════════════
// DETECTOR REGISTRY
// ═══════════════════════════════════════════════════════════════════════════════

type DetectorRegistry struct {
	detectors      []FileDetector
	threatDetector *ThreatIndicatorsDetector
	metrics        *DetectorMetrics
	mu             sync.RWMutex
}

func NewDetectorRegistry(opts ...DetectorOption) *DetectorRegistry {
	r := &DetectorRegistry{
		metrics: NewDetectorMetrics(),
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

type DetectorOption func(*DetectorRegistry)

func WithPiracyDetector(d *piracy.Detector) DetectorOption {
	return func(r *DetectorRegistry) {
		if d != nil {
			r.detectors = append(r.detectors, NewPiracyDetectorAdapter(d))
		}
	}
}

func WithThreatDetector(d *ThreatIndicatorsDetector) DetectorOption {
	return func(r *DetectorRegistry) {
		r.threatDetector = d
		r.detectors = append(r.detectors, d)
	}
}

func NewBuiltinDetectors(piracyDet *piracy.Detector) []FileDetector {
	threat := NewThreatIndicatorsDetector()

	detectors := []FileDetector{
		// ═══════════════════════════════════════════════════════════
		// НОВЫЕ ДЕТЕКТОРЫ — добавь в начало для приоритета
		// ═══════════════════════════════════════════════════════════
		NewLibraryCallDetector(),    // ⭐ Вызовы библиотек из app-code
		NewSemanticMethodDetector(), // ⭐ Семантический анализ методов

		// Vulnerability detectors (plan §3) — combination-of-signals
		NewVulnCryptoDetector(),            // ECB, static IV, MD5 for passwords
		NewVulnSecretDetector(),            // hardcoded API keys & PEM blocks
		NewVulnNetworkDetector(),           // cleartext HTTP, insecure TLS
		NewVulnManifestDetector(),          // exported components, deep links, cleartext flag, StrandHogg
		NewConveyorManifestDetector(),      // LEANBACK-only launcher, account authenticators, conveyor Svc-process template
		NewVulnPendingIntentDetector(),     // mutable PendingIntent
		NewVulnWebViewDetector(),           // addJavascriptInterface + JS + remote URL
		NewSVGDetector(),                   // SVG scripts, event handlers and encoded payload indicators
		NewVulnAndroidSurfaceDetector(),    // JS bridge inventory + provider openFile traversal
		NewVulnZipSlipDetector(),           // ZipEntry.getName() written without traversal filter
		NewVulnDlopenObfuscationDetector(), // StringBuilder-assembled loadLibrary() argument
		NewVulnDynamicLoadDetector(),       // DexClassLoader/System.load operand resolution (audit P2-10)
		NewVulnInsecureStorageDetector(),   // MODE_WORLD_* prefs + external-storage writes (audit P2-11)
		NewVulnResourceIntegrityDetector(), // CA/trust store shipped as a modifiable asset (repackaging enables MITM)
		NewVulnStagingEndpointDetector(),   // staging/pre-prod/UAT host shipped in a release build
		NewVulnIl2cppMetadataDetector(),    // unencrypted IL2CPP global-metadata.dat
		NewVulnWeakSaveIntegrityDetector(), // plaintext / weakly-obfuscated save files
		NewVulnDataPlaintextIDDetector(),   // plaintext persistent IDs + analytics defaults
		NewVulnModMenuInjectionDetector(),

		// Существующие детекторы
		NewAdsDetector(),
		NewAnalyticsDetector(),
		NewPaymentDetector(),
		NewSubscriptionDetector(),
		NewResourceDetector(),
		NewObfuscationDetector(),
		NewCryptoDetector(),
		NewEndpointDetector(),
		NewManifestInfoDetector(),
		NewCustomKeywordDetector(),
		threat,
		NewAccessibilityAbuseDetector(),
		NewPermissionRiskEngine(),
		NewOverlayDetector(),
		NewTyposquattingDetector(),
	}

	if piracyDet != nil {
		detectors = append(detectors, NewPiracyDetectorAdapter(piracyDet))
	}

	return detectors
}

// ═══════════════════════════════════════════════════════════════════════════════
// ADS DETECTOR — AC-powered
// ═══════════════════════════════════════════════════════════════════════════════

type AdsDetector struct {
	acNetworks *detectorAC // сети рекламы (с дедупом по имени)
	acMethods  *detectorAC // методы показа рекламы
	acKeywords *detectorAC // ключевые слова (для smali с контекстной проверкой)
	networks   []AdNetwork // оригинальные данные для описаний
}

func NewAdsDetector() *AdsDetector {
	d := &AdsDetector{
		networks: DefaultAdNetworks,
	}

	// ── AC для сетей ─────────────────────────────────────────────────────
	var networkEntries []detectorACEntry
	for i := range d.networks {
		net := &d.networks[i]
		net.Compile()
		for _, pat := range net.classPatternsBytes {
			networkEntries = append(networkEntries, detectorACEntry{
				patternLower: bytes.ToLower(pat),
				group:        net.Name,
				desc:         fmt.Sprintf("Ad Network: %s", net.Name),
				category:     types.CategoryAdNetwork,
				critical:     false,
			})
		}
	}
	d.acNetworks = newDetectorAC(networkEntries)

	// ── AC для методов ───────────────────────────────────────────────────
	methods := [][]byte{
		[]byte("->loadad("), []byte("->showad("),
		[]byte("->showinterstitial("), []byte("->showrewarded("),
		[]byte("->loadrewardedad("), []byte("->loadinterstitialad("),
		[]byte("->requestbannerad("),
	}
	var methodEntries []detectorACEntry
	for _, m := range methods {
		methodEntries = append(methodEntries, detectorACEntry{
			patternLower: m,
			desc:         "Ad display method",
			category:     types.CategoryAdShow,
			critical:     false,
		})
	}
	d.acMethods = newDetectorAC(methodEntries)

	// ── AC для keywords ──────────────────────────────────────────────────
	keywords := [][]byte{
		[]byte("showad"), []byte("loadad"), []byte("displayad"),
		[]byte("interstitialad"), []byte("rewardedad"),
		[]byte("bannerad"), []byte("nativead"),
		[]byte("adview"), []byte("adrequest"),
		[]byte("adlistener"), []byte("adloader"),
		[]byte("onadloaded"), []byte("onadclicked"),
		[]byte("onadclosed"), []byte("onadshown"),
		[]byte("onadimpression"), []byte("onrewardearned"),
	}
	var kwEntries []detectorACEntry
	for _, kw := range keywords {
		kwEntries = append(kwEntries, detectorACEntry{
			patternLower: kw,
			desc:         "Ad keyword in code",
			category:     types.CategoryAdShow,
			critical:     false,
		})
	}
	d.acKeywords = newDetectorAC(kwEntries)

	return d
}

func (d *AdsDetector) Name() string { return "ads" }

func (d *AdsDetector) Detect(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	if !ctx.IsAppCode && ctx.FileType == types.FileTypeSmali {
		return
	}

	// 1. Ad networks (group dedup по имени сети)
	d.acNetworks.findMatches(ctx.ContentLower, ctx, analysis)

	// 2. Ad methods
	d.acMethods.findMatches(ctx.ContentLower, ctx, analysis)

	// 3. Ad keywords (с smali контекстной проверкой)
	if ctx.FileType == types.FileTypeSmali && d.acKeywords != nil {
		found := d.acKeywords.ac.SearchBytes(ctx.ContentLower)
		for _, patIdx := range found {
			if patIdx < 0 || patIdx >= len(d.acKeywords.entries) {
				continue
			}
			e := &d.acKeywords.entries[patIdx]
			idx := bytes.Index(ctx.ContentLower, e.patternLower)
			if idx < 0 {
				continue
			}
			// Контекстная проверка: это строковая константа?
			surrounding := getSurrounding(ctx.Content, idx, 50)
			if bytes.Contains(surrounding, []byte("const-string")) ||
				bytes.Contains(surrounding, []byte("\"")) {
				line := lineAt(ctx.LineOffsets, idx)
				analysis.Matches = append(analysis.Matches, newMatch(
					e.category, analysis.Path, line, e.desc,
					string(e.patternLower), e.critical,
				))
				return // одного keyword достаточно
			}
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// ANALYTICS DETECTOR — AC-powered
// ═══════════════════════════════════════════════════════════════════════════════

type AnalyticsDetector struct {
	acProviders *detectorAC
	acMethods   *detectorAC
	acKeywords  *detectorAC
	providers   []AnalyticsProvider
}

func NewAnalyticsDetector() *AnalyticsDetector {
	d := &AnalyticsDetector{
		providers: DefaultAnalyticsProviders,
	}

	// Providers
	var provEntries []detectorACEntry
	for i := range d.providers {
		prov := &d.providers[i]
		prov.Compile()
		cat := prov.Category()
		desc := "Analytics: " + prov.Name
		if prov.CrashReporting {
			desc = "Crash Reporting: " + prov.Name
		}
		for _, pat := range prov.classPatternsBytes {
			provEntries = append(provEntries, detectorACEntry{
				patternLower: bytes.ToLower(pat),
				group:        prov.Name,
				desc:         desc,
				category:     cat,
			})
		}
	}
	d.acProviders = newDetectorAC(provEntries)

	// Methods
	methods := [][]byte{
		[]byte("->logevent("), []byte("->trackevent("),
		[]byte("->setuserproperty("), []byte("->setuserid("),
		[]byte("->trackpurchase("), []byte("->trackscreen("),
		[]byte("->logcustomevent("), []byte("->recordevent("),
	}
	var mEntries []detectorACEntry
	for _, m := range methods {
		mEntries = append(mEntries, detectorACEntry{
			patternLower: m,
			desc:         "Analytics tracking method",
			category:     types.CategoryAnalytics,
		})
	}
	d.acMethods = newDetectorAC(mEntries)

	// Keywords
	keywords := [][]byte{
		// Only unambiguous SDK identifiers here. Generic English words
		// (adjust, branch, segment, amplitude, flurry, singular) matched
		// ordinary app/game vocabulary as bare substrings, so they are
		// package-qualified now. Real SDKs are still caught via these paths
		// and via provider ClassPatterns.
		[]byte("firebase_analytics"), []byte("appsflyer"),
		[]byte("com/adjust/sdk"), []byte("mixpanel"),
		[]byte("com/amplitude/"),
		[]byte("com/flurry/"), []byte("com/segment/analytics"),
		// "braze" alone matches Czech "obraze" and similar words —
		// require the SDK package instead.
		[]byte("clevertap"), []byte("com/braze"), []byte("com/appboy"),
		[]byte("moengage"), []byte("onesignal"),
		[]byte("io/branch/"), []byte("com/singular/sdk"),
		[]byte("kochava"), []byte("com/tenjin/"),
	}
	var kwEntries []detectorACEntry
	for _, kw := range keywords {
		kwEntries = append(kwEntries, detectorACEntry{
			patternLower: kw,
			desc:         "Analytics SDK reference",
			category:     types.CategoryAnalytics,
		})
	}
	// Crash-reporting keywords are categorised separately (plan §1.3).
	crashKeywords := [][]byte{
		// "sentry" alone matches game vocabulary (e.g. Crystal Sentry in
		// Shattered PD); require the SDK package or domain instead.
		[]byte("crashlytics"), []byte("io/sentry"),
		[]byte("sentry.io"), []byte("bugsnag"),
		[]byte("newrelic"),
	}
	for _, kw := range crashKeywords {
		kwEntries = append(kwEntries, detectorACEntry{
			patternLower: kw,
			desc:         "Crash Reporting SDK reference",
			category:     types.CategoryCrashReporting,
		})
	}
	d.acKeywords = newDetectorAC(kwEntries)

	return d
}

func (d *AnalyticsDetector) Name() string { return "analytics" }

func (d *AnalyticsDetector) Detect(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	if ctx.FileType == types.FileTypeXML || ctx.FileType == types.FileTypeNative {
		return
	}
	if !ctx.IsTextContent() {
		return
	}

	d.acProviders.findMatches(ctx.ContentLower, ctx, analysis)
	d.acMethods.findMatches(ctx.ContentLower, ctx, analysis)

	// Keywords — one match is enough
	if d.acKeywords.containsAny(ctx.ContentLower) {
		found := d.acKeywords.ac.SearchBytes(ctx.ContentLower)
		if len(found) > 0 && found[0] >= 0 && found[0] < len(d.acKeywords.entries) {
			e := &d.acKeywords.entries[found[0]]
			analysis.Matches = append(analysis.Matches, newMatch(
				e.category, analysis.Path, 0, e.desc,
				string(e.patternLower), false,
			))
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// PAYMENT DETECTOR — AC-powered
// ═══════════════════════════════════════════════════════════════════════════════

type PaymentDetector struct {
	acProviders *detectorAC
	acAPIs      *detectorAC
	acMethods   *detectorAC
}

type PaymentProvider struct {
	Name          string
	ClassPatterns []string
	patternsBytes [][]byte
	// Category is the finding category for this provider. Payment SDK presence
	// is inventory, not a malware signal: every monetized app ships billing
	// code, so providers default to non-critical. A confirmed abuse pattern
	// (overlay, premium bypass) is reported by its own detector instead.
	Category   types.Category
	IsCritical bool
}

func (p *PaymentProvider) Compile() {
	p.patternsBytes = make([][]byte, len(p.ClassPatterns))
	for i, s := range p.ClassPatterns {
		p.patternsBytes[i] = []byte(strings.ToLower(s))
	}
}

// Payment SDKs are inventory, never CRITICAL on their own. Flagging a
// `billingclient` import as critical turned every Play-Billing app into a
// false positive (44 CRITICAL hits on a clean paid game). The category still
// records what the app uses; abuse is proven by behaviour, not by an import.
var DefaultPaymentProviders = []PaymentProvider{
	{Name: "Google Play Billing", ClassPatterns: []string{"Lcom/android/vending/billing/", "Lcom/android/billingclient/api/"}, Category: types.CategoryBillingClient},
	{Name: "PayPal", ClassPatterns: []string{"Lcom/paypal/android/sdk/", "Lcom/paypal/checkout/"}, Category: types.CategoryBillingClient},
	{Name: "Stripe", ClassPatterns: []string{"Lcom/stripe/android/", "Lcom/stripe/"}, Category: types.CategoryBillingClient},
	{Name: "Braintree", ClassPatterns: []string{"Lcom/braintreepayments/", "Lcom/braintree/"}, Category: types.CategoryBillingClient},
	{Name: "Square", ClassPatterns: []string{"Lcom/squareup/sdk/"}, Category: types.CategoryBillingClient},
	{Name: "RevenueCat", ClassPatterns: []string{"Lcom/revenuecat/purchases/"}, Category: types.CategoryBillingClient},
	{Name: "Qonversion", ClassPatterns: []string{"Lio/qonversion/android/"}, Category: types.CategoryBillingClient},
	{Name: "Adapty", ClassPatterns: []string{"Lcom/adapty/android/"}, Category: types.CategoryBillingClient},
	{Name: "BuyMeACoffee", ClassPatterns: []string{"buymeacoffee"}, Category: types.CategoryDonation},
	{Name: "Ko-fi", ClassPatterns: []string{"ko-fi.com"}, Category: types.CategoryDonation},
}

func NewPaymentDetector() *PaymentDetector {
	d := &PaymentDetector{}

	// Providers
	var provEntries []detectorACEntry
	for i := range DefaultPaymentProviders {
		prov := &DefaultPaymentProviders[i]
		prov.Compile()
		cat := prov.Category
		if cat == "" {
			cat = types.CategoryBillingClient
		}
		for _, pat := range prov.patternsBytes {
			provEntries = append(provEntries, detectorACEntry{
				patternLower: pat,
				group:        prov.Name,
				desc:         fmt.Sprintf("Payment Provider: %s", prov.Name),
				category:     cat,
				critical:     prov.IsCritical,
			})
		}
	}
	d.acProviders = newDetectorAC(provEntries)

	// Billing APIs
	apis := [][]byte{
		[]byte("lcom/android/vending/billing/iinappbillingservice;"),
		[]byte("billingclient;->"), []byte("billingflowparams"),
		[]byte("purchasesresult"), []byte("skudetails"),
		[]byte("productdetails"), []byte("billingresult"),
	}
	var apiEntries []detectorACEntry
	for _, api := range apis {
		apiEntries = append(apiEntries, detectorACEntry{
			patternLower: api,
			desc:         "Billing API usage",
			category:     types.CategoryBillingClient,
			// Import/API presence is inventory; see DefaultPaymentProviders.
			critical: false,
		})
	}
	d.acAPIs = newDetectorAC(apiEntries)

	// Purchase methods
	methods := [][]byte{
		[]byte("->launchbillingflow("), []byte("->querypurchases("),
		[]byte("->queryskudetails("), []byte("->queryproductdetails("),
		[]byte("->acknowledgepurchase("), []byte("->consumepurchase("),
		[]byte("->startconnection("),
	}
	var mEntries []detectorACEntry
	for _, m := range methods {
		mEntries = append(mEntries, detectorACEntry{
			patternLower: m,
			desc:         "Purchase method call",
			category:     types.CategoryBillingClient,
			// A real purchase flow is legitimate app behaviour.
			critical: false,
		})
	}
	d.acMethods = newDetectorAC(mEntries)

	return d
}

func (d *PaymentDetector) Name() string { return "payment" }

func (d *PaymentDetector) Detect(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	// Skip library files — we want app-code usage only
	if !ctx.IsAppCode && ctx.FileType == types.FileTypeSmali {
		return
	}
	d.acProviders.findMatches(ctx.ContentLower, ctx, analysis)
	d.acAPIs.findMatches(ctx.ContentLower, ctx, analysis)
	d.acMethods.findMatches(ctx.ContentLower, ctx, analysis)
}

// ═══════════════════════════════════════════════════════════════════════════════
// SUBSCRIPTION DETECTOR — AC-powered
// ═══════════════════════════════════════════════════════════════════════════════

type SubscriptionDetector struct {
	acPatterns *detectorAC
	acState    *detectorAC // state keywords (с контекстной проверкой)
	acVerify   *detectorAC
	patterns   []SubscriptionPattern

	// Lowercase state keywords для контекстной проверки
	stateKeywordsLower [][]byte
}

func NewSubscriptionDetector() *SubscriptionDetector {
	d := &SubscriptionDetector{
		patterns: DefaultSubscriptionPatterns,
	}

	// Subscription patterns
	var patEntries []detectorACEntry
	for i := range d.patterns {
		pat := &d.patterns[i]
		pat.Compile()
		for j, patLower := range pat.patternsLower {
			patEntries = append(patEntries, detectorACEntry{
				patternLower: patLower,
				group:        pat.Name,
				desc:         fmt.Sprintf("Subscription: %s", pat.Name),
				category:     types.CategorySubscription,
				critical:     true,
			})
			_ = j
		}
	}
	d.acPatterns = newDetectorAC(patEntries)

	// State keywords
	stateKWs := [][]byte{
		[]byte("ispremium"), []byte("isvip"), []byte("ispro"),
		[]byte("issubscribed"), []byte("hassubscription"),
		[]byte("ispurchased"), []byte("isunlocked"),
		[]byte("haspremium"), []byte("haslicense"),
		[]byte("isentitled"),
		[]byte("subscriptionstatus"), []byte("premiumstatus"),
		[]byte("showpaywall"), []byte("displaypaywall"),
		[]byte("openpaywall"), []byte("launchpaywall"),
		[]byte("checkfeature"), []byte("getentitlement"),
	}
	d.stateKeywordsLower = stateKWs

	var stateEntries []detectorACEntry
	for _, kw := range stateKWs {
		stateEntries = append(stateEntries, detectorACEntry{
			patternLower: kw,
			desc:         "Subscription state check",
			category:     types.CategorySubscriptionCheck,
			critical:     true,
		})
	}
	d.acState = newDetectorAC(stateEntries)

	// Verify methods
	verifyMethods := [][]byte{
		[]byte("->verifysubscription("), []byte("->checksubscription("),
		[]byte("->validatepurchase("), []byte("->checkentitlement("),
		[]byte("->getsubscriptionstatus("),
	}
	var vEntries []detectorACEntry
	for _, m := range verifyMethods {
		vEntries = append(vEntries, detectorACEntry{
			patternLower: m,
			desc:         "Subscription verification",
			category:     types.CategorySubscriptionCheck,
			critical:     true,
		})
	}
	d.acVerify = newDetectorAC(vEntries)

	return d
}

func (d *SubscriptionDetector) Name() string { return "subscription" }

func (d *SubscriptionDetector) Detect(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	defer normalizeSubscriptionVocabulary(ctx, analysis)
	// Skip library files — we want app-code usage only
	if !ctx.IsAppCode && ctx.FileType == types.FileTypeSmali {
		return
	}
	if ctx.FileType != types.FileTypeSmali {
		return
	}

	// Bare subscription/trial vocabulary is critical evidence only when
	// billing/licensing machinery appears NEAR this specific occurrence (not
	// merely anywhere in the file -- SPD classes reference IAP machinery
	// broadly for unrelated donation features).
	// 1. Subscription patterns (простой поиск)
	d.acPatterns.findMatchesCriticalIf(ctx.ContentLower, ctx, analysis, billingEvidenceWindow)

	// 2. State keywords (с контекстной проверкой smali)
	if d.acState != nil {
		found := d.acState.ac.SearchBytes(ctx.ContentLower)
		seenKW := make(map[string]bool, len(found))

		for _, patIdx := range found {
			if patIdx < 0 || patIdx >= len(d.acState.entries) {
				continue
			}
			e := &d.acState.entries[patIdx]
			kwStr := string(e.patternLower)
			if seenKW[kwStr] {
				continue
			}

			idx := bytes.Index(ctx.ContentLower, e.patternLower)
			if idx < 0 {
				continue
			}

			// Контекстная проверка: это метод или поле?
			surrounding := getSurrounding(ctx.Content, idx, 30)
			if bytes.Contains(surrounding, []byte("->")) ||
				bytes.Contains(surrounding, []byte(".method")) ||
				bytes.Contains(surrounding, []byte(".field")) {

				seenKW[kwStr] = true
				// Bare state vocabulary (isUnlocked, isPremium, ...) with no
				// billing/licensing machinery nearby is ordinary app logic
				// (game badges, feature flags) — not a subscription check.
				if !hasBillingMachinery(getSurrounding(ctx.ContentLower, idx, billingEvidenceWindow)) {
					continue
				}
				line := lineAt(ctx.LineOffsets, idx)
				analysis.Matches = append(analysis.Matches, newMatch(
					e.category, analysis.Path, line,
					e.desc, kwStr, e.critical,
				))
			}
		}
	}

	// 3. Verify methods
	d.acVerify.findMatches(ctx.ContentLower, ctx, analysis)
}

// ═══════════════════════════════════════════════════════════════════════════════
// OBFUSCATION DETECTOR — AC-powered
// ═══════════════════════════════════════════════════════════════════════════════

type ObfuscationDetector struct {
	acPackers     *detectorAC
	acObfuscators *detectorAC
}

func NewObfuscationDetector() *ObfuscationDetector {
	d := &ObfuscationDetector{}

	// Packers (case-sensitive patterns, lowercased for AC)
	packers := []struct {
		name     string
		patterns []string
	}{
		{"Qihoo 360", []string{"libjiagu", "jiagu", "com.qihoo", "libprotectclass"}},
		{"Baidu", []string{"libbaiduprotect", "baiduprotect"}},
		{"Bangcle/SecNeo", []string{"libsecexe", "libsecmain", "secneo", "bangcle"}},
		{"Tencent Legu", []string{"liblbs"}},
		{"iJiami", []string{"ijiami"}},
		{"APKProtect", []string{"apkprotect", "libapkprotect"}},
		{"DexProtector", []string{"dexprotector", "lirusern"}},
		{"DexGuard", []string{"dexguard"}},
	}
	var packerEntries []detectorACEntry
	for _, p := range packers {
		for _, pat := range p.patterns {
			packerEntries = append(packerEntries, detectorACEntry{
				patternLower: []byte(strings.ToLower(pat)),
				group:        p.name,
				desc:         fmt.Sprintf("Packer detected: %s", p.name),
				category:     types.CategoryPacker,
				critical:     true,
			})
		}
	}
	d.acPackers = newDetectorAC(packerEntries)

	// Obfuscators
	obfuscators := []struct {
		name     string
		patterns []string
	}{
		{"ProGuard", []string{"proguard"}},
		{"R8", []string{"r8:"}},
		{"Allatori", []string{"allatori"}},
		{"Zelix KlassMaster", []string{"zelix", "klassmaster"}},
		{"yGuard", []string{"yguard"}},
	}
	var obfEntries []detectorACEntry
	for _, o := range obfuscators {
		for _, pat := range o.patterns {
			obfEntries = append(obfEntries, detectorACEntry{
				patternLower: []byte(strings.ToLower(pat)),
				group:        o.name,
				desc:         fmt.Sprintf("Obfuscator: %s", o.name),
				category:     types.CategoryObfuscator,
			})
		}
	}
	d.acObfuscators = newDetectorAC(obfEntries)

	return d
}

func (d *ObfuscationDetector) Name() string { return "obfuscation" }

func (d *ObfuscationDetector) Detect(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	if ctx.FileType == types.FileTypeNative {
		// Для нативных бинарей — только packers
		d.acPackers.findMatches(ctx.ContentLower, ctx, analysis)
		return
	}
	if !ctx.IsTextContent() {
		return
	}

	d.acPackers.findMatches(ctx.ContentLower, ctx, analysis)
	d.acObfuscators.findMatches(ctx.ContentLower, ctx, analysis)

	// Heavy obfuscation check
	if ctx.FileType == types.FileTypeSmali && ctx.IsAppCode {
		d.detectHeavyObfuscation(ctx, analysis)
	}
}

func (d *ObfuscationDetector) detectHeavyObfuscation(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	if bytes.Contains(ctx.Content, []byte(".class public La/a/a;")) ||
		bytes.Contains(ctx.Content, []byte(".class public final La/a;")) {

		shortPaths := bytes.Count(ctx.ContentLower, []byte("la/"))
		if shortPaths > 10 {
			analysis.Matches = append(analysis.Matches, newMatch(
				types.CategoryObfuscator,
				analysis.Path, 0,
				"Heavy obfuscation (short class names)",
				fmt.Sprintf("%d short paths", shortPaths),
				false,
			))
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// CRYPTO DETECTOR — AC-powered
// ═══════════════════════════════════════════════════════════════════════════════

type CryptoDetector struct {
	acAll *detectorAC // все паттерны в одном AC
}

func NewCryptoDetector() *CryptoDetector {
	var entries []detectorACEntry

	// Wallet patterns
	for _, pat := range []string{
		"walletaddress", "cryptowallet", "bitcoinwallet", "ethereumwallet",
		"wallet_address", "btc_address", "eth_address", "crypto_address",
	} {
		entries = append(entries, detectorACEntry{
			patternLower: []byte(pat),
			desc:         "Crypto wallet reference",
			category:     types.CategoryCrypto,
		})
	}

	// API patterns
	for _, pat := range []string{
		"coinbase.com", "blockchain.info", "binance.com", "kraken.com",
		"api.coingecko", "api.coinmarketcap", "etherscan.io", "blockstream.info",
		"web3j", "bitcoinj",
	} {
		entries = append(entries, detectorACEntry{
			patternLower: []byte(pat),
			group:        "crypto_api", // одного API match достаточно
			desc:         "Crypto API/service",
			category:     types.CategoryCrypto,
		})
	}

	// Keywords
	for _, pat := range []string{
		"cryptocurrency", "cryptopayment", "miningpool", "blockchain",
		"ethereum", "bitcoin", "monero", "litecoin",
		"metamask", "trustwallet",
	} {
		entries = append(entries, detectorACEntry{
			patternLower: []byte(pat),
			group:        "crypto_kw", // одного keyword достаточно
			desc:         "Crypto keyword",
			category:     types.CategoryCrypto,
		})
	}

	return &CryptoDetector{
		acAll: newDetectorAC(entries),
	}
}

func (d *CryptoDetector) Name() string { return "crypto" }

func (d *CryptoDetector) Detect(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	// Esperanto "monero" (= coin) and similar natural-language collisions:
	// never scan translation bundles for crypto vocabulary.
	if isLocalizationAsset(ctx.Path) {
		return
	}
	d.acAll.findMatches(ctx.ContentLower, ctx, analysis)
}

// ═══════════════════════════════════════════════════════════════════════════════
// RESOURCE DETECTOR
// ═══════════════════════════════════════════════════════════════════════════════

type ResourceDetector struct {
	pathPatterns []resourcePathPattern
	acValues     *detectorAC
}

type resourcePathPattern struct {
	keyword  string
	desc     string
	category types.Category
	critical bool
}

func NewResourceDetector() *ResourceDetector {
	d := &ResourceDetector{
		pathPatterns: []resourcePathPattern{
			{"premium", "Premium resource", types.CategoryResource, false},
			{"pro_", "Pro version resource", types.CategoryResource, false},
			{"vip_", "VIP resource", types.CategoryResource, false},
			{"gold_", "Gold/Premium resource", types.CategoryResource, false},
			{"unlock", "Unlock resource", types.CategoryResource, false},
			{"paid", "Paid content resource", types.CategoryResource, false},
			{"ad_banner", "Ad banner resource", types.CategoryAdResource, false},
			{"ad_layout", "Ad layout resource", types.CategoryAdResource, false},
			{"admob_", "AdMob resource", types.CategoryAdResource, false},
			{"interstitial", "Interstitial ad resource", types.CategoryAdResource, false},
			{"rewarded", "Rewarded ad resource", types.CategoryAdResource, false},
			{"banner_ad", "Banner ad resource", types.CategoryAdResource, false},
			// A resource NAME alone is weak evidence; only the unambiguous
			// "paywall" stays critical.
			{"subscription", "Subscription resource", types.CategorySubscription, false},
			{"paywall", "Paywall resource", types.CategorySubscription, true},
			{"purchase", "Purchase resource", types.CategorySubscription, false},
		},
	}

	// AC для XML value patterns
	var valEntries []detectorACEntry
	for _, v := range []struct {
		pat  string
		desc string
		cat  types.Category
	}{
		{"premium_feature", "Premium feature string", types.CategoryResource},
		{"upgrade_to_pro", "Upgrade prompt", types.CategoryResource},
		{"unlock_all", "Unlock all string", types.CategoryResource},
		{"remove_ads", "Remove ads string", types.CategoryAdResource},
		{"no_ads", "No ads string", types.CategoryAdResource},
		{"ad_free", "Ad-free string", types.CategoryAdResource},
	} {
		valEntries = append(valEntries, detectorACEntry{
			patternLower: []byte(v.pat),
			desc:         v.desc,
			category:     v.cat,
		})
	}
	d.acValues = newDetectorAC(valEntries)

	return d
}

func (d *ResourceDetector) Name() string { return "resource" }

func (d *ResourceDetector) Detect(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	pathLower := strings.ToLower(ctx.Path)

	// 1. Path patterns. Library smali is skipped with the same convention as
	// the payment/subscription detectors: "purchase" in the vendored
	// com/android/billingclient/api/Purchase.smali filename produced a
	// "Resource: Purchase resource" finding on the SDK's own class.
	skipLibrarySmali := !ctx.IsAppCode && ctx.FileType == types.FileTypeSmali
	if !skipLibrarySmali {
		for _, rp := range d.pathPatterns {
			if strings.Contains(pathLower, rp.keyword) {
				analysis.Matches = append(analysis.Matches, newMatch(
					rp.category, analysis.Path, 0,
					fmt.Sprintf("Resource: %s", rp.desc),
					ctx.Job.RelPath, rp.critical,
				))
			}
		}
	}

	// 2. Value patterns (для XML ресурсов)
	if ctx.FileType == types.FileTypeXML && strings.Contains(pathLower, "res/values") {
		d.acValues.findMatches(ctx.ContentLower, ctx, analysis)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// PIRACY DETECTOR ADAPTER
// ═══════════════════════════════════════════════════════════════════════════════

type PiracyDetectorAdapter struct {
	detector *piracy.Detector
}

func NewPiracyDetectorAdapter(d *piracy.Detector) *PiracyDetectorAdapter {
	return &PiracyDetectorAdapter{detector: d}
}

func (d *PiracyDetectorAdapter) Name() string { return "piracy" }

func (d *PiracyDetectorAdapter) Detect(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	// A runtime-looking path alone must never suppress findings.
	result, err := d.detector.Analyze(ctx.Ctx, ctx.Path, ctx.Content, ctx.FileType)
	if err != nil || result == nil || len(result.Findings) == 0 {
		return
	}

	// Corroboration context: weak single-token signals (a bare `lp_…` symbol or
	// the word `no_ads`) are NOT evidence of piracy on their own — `lp_` is a
	// common R8-obfuscation prefix and `no_ads` is an ordinary config flag. They
	// are only escalated when a second, independent piracy signal is present in
	// the same file. See plan §1.4 / §1.5.
	hasStrongLuckyPatcher := fileHasStrongLuckyPatcher(result.Findings)
	hasOtherPiracySignal := fileHasIndependentPiracySignal(result.Findings)

	for _, f := range result.Findings {
		if shouldSkipPiracyFinding(ctx.Path, f) {
			continue
		}

		category := piracyFindingCategory(f)

		critical := isCriticalPiracyFinding(f)

		// Demote uncorroborated weak signals to a non-critical generic Piracy
		// hint so they stay visible for analysts but never land in the critical
		// "Piracy Tool" bucket.
		if isBareLuckyPatcherRegex(f) && !hasStrongLuckyPatcher {
			category = types.CategoryPiracy
			critical = false
		}
		if isWeakModToken(f) && !hasOtherPiracySignal {
			// Weak mod vocabulary with no corroborating crack/site/tool
			// signal in the file is a false positive on legitimate apps —
			// drop it entirely instead of emitting noise.
			continue
		}

		analysis.Matches = append(analysis.Matches, newPiracyMatch(
			category, analysis.Path, f, critical,
		))
	}
}

const (
	piracyMetaType       = "piracy_type"
	piracyMetaSource     = "piracy_source"
	piracyMetaSiteName   = "piracy_site_name"
	piracyMetaSiteDomain = "piracy_site_domain"
	piracyMetaRiskTags   = "piracy_risk_tags"
	piracyMetaStrength   = "piracy_strength"
)

// piracyFindingCategory keeps the detector's semantic finding type visible to
// downstream scoring and reporting instead of flattening every hit to PIRACY.
func piracyFindingCategory(f piracy.Finding) types.Category {
	switch strings.ToLower(f.Type) {
	case "site":
		return types.CategoryPiracySite
	case "mod", "path_mod":
		return types.CategoryModDetection
	case "crack", "crack_tool":
		return types.CategoryCrackTool
	}
	if strings.Contains(strings.ToLower(f.Description), "lucky patcher") {
		return types.CategoryPiracyTool
	}
	if strings.Contains(strings.ToLower(f.Description), "license") {
		return types.CategoryLicenseCheck
	}
	return types.CategoryPiracy
}

// newPiracyMatch preserves the evidence produced by the dedicated detector.
// Legacy Match remains the transport type, while Metadata carries the fields
// required to build the typed PiracyAnalysis section after parallel scanning.
func newPiracyMatch(category types.Category, file string, f piracy.Finding, critical bool) types.Match {
	info := types.GetCategoryInfo(category)
	metadata := map[string]string{
		"detector":           "piracy",
		piracyMetaType:       f.Type,
		piracyMetaSource:     f.Source,
		piracyMetaSiteName:   f.SiteName,
		piracyMetaSiteDomain: f.SiteDomain,
		piracyMetaRiskTags:   strings.Join(f.RiskTags, ","),
		piracyMetaStrength:   string(f.Strength),
	}
	return types.Match{
		SourceLocation: types.SourceLocation{File: file, Line: f.Line},
		Categorized:    types.Categorized{Category: category},
		Scored: types.Scored{
			Score:      float64(info.Priority),
			Confidence: f.Confidence,
		},
		Pattern:    f.Pattern,
		Text:       f.Pattern,
		Context:    fmt.Sprintf("Piracy: %s", f.Description),
		IsCritical: critical,
		Metadata:   metadata,
	}
}

// isBareLuckyPatcherRegex reports whether a finding is the generic `lp_\w+`
// regex match (which alone is just an obfuscated-symbol prefix, not proof of
// Lucky Patcher).
func isBareLuckyPatcherRegex(f piracy.Finding) bool {
	return strings.Contains(strings.ToLower(f.Pattern), "lp_")
}

// fileHasStrongLuckyPatcher reports whether the file carries an unambiguous
// Lucky Patcher signal (the tool's name or its `chelpus` marker), which makes a
// co-located `lp_…` match trustworthy.
func fileHasStrongLuckyPatcher(findings []piracy.Finding) bool {
	for _, f := range findings {
		p := strings.ToLower(f.Pattern)
		if strings.Contains(p, "luckypatcher") ||
			strings.Contains(p, "lucky_patcher") ||
			strings.Contains(p, "chelpus") {
			return true
		}
	}
	return false
}

// isWeakModToken reports whether a finding is a broad feature/configuration
// term. These strings occur in legitimate games, root-management and ad-free
// builds, so they require independent corroboration before becoming a threat.
func isWeakModToken(f piracy.Finding) bool {
	if strings.ToLower(f.Type) != "mod" {
		return false
	}
	switch strings.ToLower(f.Pattern) {
	case "no_ads", "ad_free", "adfree", "headshot", "aimbot", "aim_bot",
		"autoaim", "auto_aim", "root_hide", "no_root", "антибан", "anti_ban", "antiban", "взлом",
		// Ordinary game/app vocabulary: badge "unlocked", "cracked" walls,
		// "instakill" game mechanics, changelog text. Meaningless without
		// an independent piracy signal in the same file.
		"unlocked", "unlock", "instakill", "insta_kill", "cracked", "crack",
		"godmode", "god_mode", "wallhack", "wall_hack", "speedhack",
		"speed_hack", "modmenu", "mod_menu", "unlimited", "premium_unlocked":
		return true
	}
	return false
}

// fileHasIndependentPiracySignal reports whether the file contains at least one
// piracy signal beyond the weak single-word mod flags — a crack pattern, a
// known site/tool reference, or a strong/medium mod indicator.
func fileHasIndependentPiracySignal(findings []piracy.Finding) bool {
	for _, f := range findings {
		switch strings.ToLower(f.Type) {
		case "crack", "site":
			return true
		case "mod":
			if !isWeakModToken(f) {
				return true
			}
		}
	}
	return false
}

// ═══════════════════════════════════════════════════════════════════════════════
// DETECTION HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

func detectBytesPattern(
	ctx *FileDetectContext, analysis *types.FileAnalysis,
	patterns [][]byte, category types.Category, desc string, critical bool,
) bool {
	for _, pat := range patterns {
		if idx := bytes.Index(ctx.Content, pat); idx >= 0 {
			line := lineAt(ctx.LineOffsets, idx)
			analysis.Matches = append(analysis.Matches, newMatch(
				category, analysis.Path, line, desc,
				types.TruncateString(string(pat), 100), critical,
			))
			return true
		}
	}
	return false
}

func detectBytesPatternLower(
	ctx *FileDetectContext, analysis *types.FileAnalysis,
	patternsLower [][]byte, category types.Category, desc string, critical bool,
) bool {
	for _, pat := range patternsLower {
		if idx := bytes.Index(ctx.ContentLower, pat); idx >= 0 {
			line := lineAt(ctx.LineOffsets, idx)
			analysis.Matches = append(analysis.Matches, newMatch(
				category, analysis.Path, line, desc, string(pat), critical,
			))
			return true
		}
	}
	return false
}

func lineAt(offsets *types.LineOffsets, idx int) int {
	if offsets != nil && idx >= 0 {
		return offsets.LineAt(idx)
	}
	return 0
}

func getSurrounding(content []byte, idx, window int) []byte {
	start := idx - window
	if start < 0 {
		start = 0
	}
	end := idx + window
	if end > len(content) {
		end = len(content)
	}
	return content[start:end]
}

func isLikelyTextContent(content []byte) bool {
	if len(content) == 0 {
		return true
	}
	sample := content
	if len(sample) > 4096 {
		sample = sample[:4096]
	}
	if bytes.IndexByte(sample, 0x00) >= 0 {
		return false
	}
	printable := 0
	for _, b := range sample {
		switch {
		case b == '\n' || b == '\r' || b == '\t':
			printable++
		case b >= 0x20 && b <= 0x7E:
			printable++
		case b >= 0xC2:
			printable++
		}
	}
	return float64(printable)/float64(len(sample)) >= 0.65
}

func shouldSkipPiracyFinding(path string, f piracy.Finding) bool {
	switch strings.ToLower(f.Type) {
	case "path", "path_mod", "watermark", "warning":
		return true
	}
	base := strings.ToLower(filepath.Base(path))
	if base == "apktool.yml" || base == "apktool.yaml" {
		return true
	}
	return false
}

func isCriticalPiracyFinding(f piracy.Finding) bool {
	// A bare word is ambiguous (including the standard HTML <keygen> element).
	// Other corroborating findings remain independently visible.
	if strings.EqualFold(f.Pattern, "keygen") {
		return false
	}
	ft := strings.ToLower(f.Type)
	desc := strings.ToLower(f.Description)

	if strings.Contains(desc, "lucky patcher") {
		return true
	}
	switch ft {
	case "crack", "mod":
		if ft == "mod" && f.Strength != "" {
			return f.Strength == piracy.StrengthStrong || f.Strength == piracy.StrengthCritical
		}
		return true
	case "site":
		return f.Confidence >= 0.95
	default:
		return false
	}
}

// billingEvidenceWindow bounds how close billing/licensing machinery must
// appear to a subscription/premium/access keyword to corroborate criticality.
// Wide enough to cover an enclosing smali method, narrow enough to exclude
// unrelated machinery elsewhere in the same class.
const billingEvidenceWindow = 400

// hasBillingMachinery reports whether class content references real
// billing/licensing machinery. Premium/subscription vocabulary alone is
// ordinary app/game code; it is critical evidence only alongside this.
func hasBillingMachinery(contentLower []byte) bool {
	return bytes.Contains(contentLower, []byte("billing")) ||
		bytes.Contains(contentLower, []byte("com/android/vending")) ||
		bytes.Contains(contentLower, []byte("skudetails")) ||
		bytes.Contains(contentLower, []byte("productdetails")) ||
		bytes.Contains(contentLower, []byte("licens")) ||
		bytes.Contains(contentLower, []byte("purchase"))
}

// DetectorStatSnapshot is an immutable view of one detector's accounting.
type DetectorStatSnapshot struct {
	Name    string
	Calls   int64
	Matches int64
	TimeNs  int64
}

// Snapshot returns per-detector stats sorted by descending total time.
func (m *DetectorMetrics) Snapshot() []DetectorStatSnapshot {
	out := make([]DetectorStatSnapshot, 0, 48)
	m.detectorStats.Range(func(k, v any) bool {
		name, _ := k.(string)
		stat, ok := v.(*DetectorStat)
		if !ok {
			return true
		}
		out = append(out, DetectorStatSnapshot{
			Name:    name,
			Calls:   stat.Calls.Load(),
			Matches: stat.Matches.Load(),
			TimeNs:  stat.TimeNs.Load(),
		})
		return true
	})
	sort.Slice(out, func(i, j int) bool { return out[i].TimeNs > out[j].TimeNs })
	return out
}
