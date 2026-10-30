package pipeline

import (
	"bytes"
	"fmt"
	"strings"

	"mega-analyzer/pkg/internal/types"
)

type LibraryCallDetector struct {
	libraryPrefixes []libraryPrefix
	acInvoke        *detectorAC
}

type libraryPrefix struct {
	prefix      string
	prefixLower []byte
	name        string
	category    types.Category
	critical    bool
	methods     []targetMethod
}

type targetMethod struct {
	name        string
	description string
	critical    bool
}

func NewLibraryCallDetector() *LibraryCallDetector {
	d := &LibraryCallDetector{}

	d.libraryPrefixes = []libraryPrefix{
		{
			prefix:   "Lcom/android/billingclient/api/",
			name:     "Google Play Billing",
			category: types.CategoryBillingClient,
			critical: true,
			methods: []targetMethod{
				{"queryPurchases", "Queries user purchases", true},
				{"queryProductDetails", "Queries product details", false},
				{"launchBillingFlow", "Launches purchase flow", true},
				{"acknowledgePurchase", "Acknowledges purchase", true},
				{"consumeAsync", "Consumes purchase", true},
			},
		},
		{
			prefix:   "Lcom/android/vending/billing/",
			name:     "Legacy Billing",
			category: types.CategoryBillingClient,
			critical: true,
		},
		{
			prefix:   "Lcom/revenuecat/purchases/",
			name:     "RevenueCat",
			category: types.CategoryBillingClient,
			critical: true,
			methods: []targetMethod{
				{"getCustomerInfo", "Gets subscription status", true},
				{"purchase", "Makes purchase", true},
				{"restorePurchases", "Restores purchases", true},
			},
		},
		{
			prefix:   "Lcom/google/android/gms/ads/",
			name:     "AdMob",
			category: types.CategoryAdShow,
			critical: false,
			methods: []targetMethod{
				{"show", "Shows advertisement", true},
				{"loadAd", "Loads advertisement", false},
			},
		},
		{
			prefix:   "Lcom/applovin/",
			name:     "AppLovin",
			category: types.CategoryAdShow,
			critical: false,
			methods: []targetMethod{
				{"showAd", "Shows advertisement", true},
				{"loadAd", "Loads advertisement", false},
			},
		},
		{
			prefix:   "Lcom/unity3d/ads/",
			name:     "Unity Ads",
			category: types.CategoryAdShow,
			critical: false,
			methods: []targetMethod{
				{"show", "Shows advertisement", true},
				{"load", "Loads advertisement", false},
			},
		},
		{
			prefix:   "Lcom/ironsource/mediationsdk/IronSource;",
			name:     "IronSource",
			category: types.CategoryAdShow,
			critical: false,
			methods: []targetMethod{
				{"showInterstitial", "Shows interstitial ad", true},
				{"showRewardedVideo", "Shows rewarded video", true},
				{"loadInterstitial", "Loads interstitial", false},
			},
		},
		{
			prefix:   "Lcom/google/firebase/remoteconfig/FirebaseRemoteConfig;",
			name:     "Firebase Remote Config",
			category: types.CategoryRemoteConfig,
			critical: true,
			methods: []targetMethod{
				{"getBoolean", "Gets remote boolean flag", true},
				{"getString", "Gets remote string", false},
				{"getLong", "Gets remote number", false},
				{"fetch", "Fetches remote config", false},
			},
		},
		{
			prefix:   "Lcom/google/firebase/firestore/FirebaseFirestore;",
			name:     "Firestore",
			category: types.CategoryServerCheck,
			critical: true,
			methods: []targetMethod{
				{"collection", "Accesses Firestore collection", true},
				{"document", "Accesses Firestore document", true},
			},
		},
		{
			prefix:   "Lcom/google/firebase/functions/",
			name:     "Firebase Functions",
			category: types.CategoryServerCheck,
			critical: true,
		},
		{
			prefix:   "Lokhttp3/OkHttpClient;",
			name:     "OkHttp",
			category: types.CategoryNetworkCall,
			critical: false,
			methods: []targetMethod{
				{"newCall", "Makes HTTP request", false},
			},
		},
		{
			prefix:   "Lretrofit2/Retrofit;",
			name:     "Retrofit",
			category: types.CategoryNetworkCall,
			critical: false,
		},
		{
			prefix:   "Lcom/google/android/play/core/integrity/",
			name:     "Play Integrity",
			category: types.CategoryPlayIntegrity,
			critical: true,
		},
		{
			prefix:   "Lcom/google/android/gms/safetynet/",
			name:     "SafetyNet",
			category: types.CategorySafetyNet,
			critical: true,
		},
	}

	for i := range d.libraryPrefixes {
		d.libraryPrefixes[i].prefixLower = []byte(strings.ToLower(d.libraryPrefixes[i].prefix))
	}

	var entries []detectorACEntry
	for _, lp := range d.libraryPrefixes {
		entries = append(entries, detectorACEntry{
			patternLower: bytes.ToLower([]byte(lp.prefix)),
			desc:         fmt.Sprintf("Calls %s", lp.name),
			category:     lp.category,
			critical:     lp.critical,
		})
	}
	d.acInvoke = newDetectorAC(entries)

	return d
}

func (d *LibraryCallDetector) Name() string { return "library_calls" }

func (d *LibraryCallDetector) SupportsFile(fileType types.FileType, _ string) bool {
	return fileType == types.FileTypeSmali
}

func (d *LibraryCallDetector) Detect(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	if !ctx.IsAppCode {
		return
	}
	if ctx.FileType != types.FileTypeSmali {
		return
	}
	if !bytes.Contains(ctx.ContentLower, []byte("invoke-")) {
		return
	}
	d.detectLibraryCalls(ctx, analysis)
}

func (d *LibraryCallDetector) detectLibraryCalls(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	lines := bytes.Split(ctx.Content, []byte("\n"))

	for lineNum, line := range lines {
		lineLower := bytes.ToLower(line)

		if !bytes.Contains(lineLower, []byte("invoke-")) {
			continue
		}

		className := extractClassName(line)
		if className == nil {
			continue
		}
		classNameLower := bytes.ToLower(className)

		for _, lp := range d.libraryPrefixes {
			if !bytes.HasPrefix(classNameLower, lp.prefixLower) {
				continue
			}

			methodName := d.extractMethodName(line)
			matchDesc := fmt.Sprintf("App code calls %s.%s", lp.name, methodName)

			for _, tm := range lp.methods {
				if strings.EqualFold(methodName, tm.name) {
					matchDesc = fmt.Sprintf("Calls %s.%s - %s", lp.name, tm.name, tm.description)
					break
				}
			}

			analysis.Matches = append(analysis.Matches, types.Match{
				SourceLocation: types.SourceLocation{
					File: analysis.Path,
					Line: lineNum + 1,
				},
				Categorized: types.Categorized{Category: lp.category},
				Pattern:     matchDesc,
				Text:        types.TruncateString(string(line), 200),
				IsCritical:  lp.critical,
				Context:     fmt.Sprintf("Library: %s, Method: %s", lp.name, methodName),
			})

			break
		}
	}
}

func (d *LibraryCallDetector) extractMethodName(line []byte) string {
	arrowIdx := bytes.Index(line, []byte("->"))
	if arrowIdx < 0 {
		return ""
	}
	afterArrow := line[arrowIdx+2:]
	parenIdx := bytes.IndexByte(afterArrow, '(')
	if parenIdx < 0 {
		return string(afterArrow)
	}
	return string(afterArrow[:parenIdx])
}

func extractClassName(line []byte) []byte {
	arrowIdx := bytes.Index(line, []byte("->"))
	if arrowIdx < 0 {
		return nil
	}
	start := arrowIdx - 1
	for start >= 0 {
		c := line[start]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '/' || c == '$' || c == ';' || c == '_' || c == '-') {
			start++
			break
		}
		start--
	}
	if start < 0 {
		start = 0
	}
	if start < len(line) && line[start] == 'L' {
		return line[start:arrowIdx]
	}
	return nil
}
