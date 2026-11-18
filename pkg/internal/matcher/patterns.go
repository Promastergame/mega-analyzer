// Package matcher — паттерн-матчер v4.0
//
// Архитектура:
//   - PatternDef: декларативное определение (data)
//   - CompiledPattern: скомпилированный для runtime (regex + lowercase keywords)
//   - CompiledPatterns: группы по категориям
//   - Compile(): PatternDef → CompiledPattern с предвычислением
package matcher

import (
	"regexp"
	"strings"

	"mega-analyzer/pkg/internal/types"
)

// ═══════════════════════════════════════════════════════════════════════════════
// PATTERN DEFINITION — декларативные данные
// ═══════════════════════════════════════════════════════════════════════════════

// PatternDef — определение паттерна (данные, не runtime).
type PatternDef struct {
	Category      types.Category
	Pattern       string
	Priority      int
	IsCritical    bool
	Description   string
	IsRegex       bool
	Keywords      []string
	MustBeAppCode bool
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMPILED PATTERN — runtime-структура для матчинга
// ═══════════════════════════════════════════════════════════════════════════════

// CompiledPattern — скомпилированный паттерн для быстрого matching.
type CompiledPattern struct {
	Regex         *regexp.Regexp
	Keywords      []string // оригинальные keywords
	KeywordsLower []string // предвычисленные lowercase
	Category      types.Category
	CatIdx        int32  // dense category id; -1 when unknown (see catindex.go)
	GateLiteral   string // mandatory substring; "" = no gate (see literalgate.go)
	GateFold      bool   // GateLiteral is lowercase, search the lowercased line
	Description   string
	Priority      int
	IsCritical    bool
	MustBeAppCode bool
}

// PatternGroup — группа паттернов одной категории.
type PatternGroup struct {
	Category    types.Category
	Description string
	Patterns    []*CompiledPattern
}

// CompiledPatterns — все скомпилированные паттерны.
type CompiledPatterns struct {
	Groups []PatternGroup
	Total  int // общее число паттернов
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMPILATION
// ═══════════════════════════════════════════════════════════════════════════════

// Compile компилирует все паттерны.
// Вызывается один раз при создании Matcher.
func Compile() (*CompiledPatterns, error) {
	defs := GetAllPatterns()

	// Группируем по категории
	index := make(map[types.Category]int, 64)
	groups := make([]PatternGroup, 0, 64)
	totalCompiled := 0

	for i := range defs {
		def := &defs[i]

		// Компилируем regex
		patternStr := def.Pattern
		if !def.IsRegex {
			patternStr = regexp.QuoteMeta(patternStr)
		}

		re, err := regexp.Compile(patternStr)
		if err != nil {
			continue // skip invalid patterns
		}

		gate := buildLiteralGate(patternStr)

		// Предвычисляем lowercase keywords
		kwLower := make([]string, len(def.Keywords))
		for j, kw := range def.Keywords {
			kwLower[j] = strings.ToLower(kw)
		}

		// Auto-description если пустой
		desc := def.Description
		if desc == "" {
			desc = def.Pattern
		}

		compiled := &CompiledPattern{
			Regex:         re,
			Keywords:      def.Keywords,
			KeywordsLower: kwLower,
			Category:      def.Category,
			CatIdx:        categoryID(def.Category),
			GateLiteral:   gate.literal,
			GateFold:      gate.fold,
			Description:   desc,
			Priority:      def.Priority,
			IsCritical:    def.IsCritical,
			MustBeAppCode: def.MustBeAppCode,
		}

		// Находим или создаём группу
		groupIdx, ok := index[def.Category]
		if !ok {
			info := types.GetCategoryInfo(def.Category)
			groups = append(groups, PatternGroup{
				Category:    def.Category,
				Description: info.Name,
				Patterns:    make([]*CompiledPattern, 0, 16),
			})
			groupIdx = len(groups) - 1
			index[def.Category] = groupIdx
		}

		groups[groupIdx].Patterns = append(groups[groupIdx].Patterns, compiled)
		totalCompiled++
	}

	return &CompiledPatterns{
		Groups: groups,
		Total:  totalCompiled,
	}, nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// PATTERN DEFINITIONS — ВСЕ ПАТТЕРНЫ
// ═══════════════════════════════════════════════════════════════════════════════

// GetAllPatterns возвращает все определения паттернов.
func GetAllPatterns() []PatternDef {
	patterns := make([]PatternDef, 0, 600)
	patterns = append(patterns, getLicensePatterns()...)
	patterns = append(patterns, getBillingPatterns()...)
	patterns = append(patterns, getPremiumPatterns()...)
	patterns = append(patterns, getTrialPatterns()...)
	patterns = append(patterns, getSubscriptionPatterns()...)
	patterns = append(patterns, getAdPatterns()...)
	patterns = append(patterns, getAdNetworkPatterns()...)
	patterns = append(patterns, getAnalyticsPatterns()...)
	patterns = append(patterns, getSecurityPatterns()...)
	patterns = append(patterns, getAdvancedSecurityPatterns()...)
	patterns = append(patterns, getDropperPatterns()...)
	patterns = append(patterns, getRemoteConfigPatterns()...)
	patterns = append(patterns, getObfuscationPatterns()...)
	patterns = append(patterns, getNetworkPatterns()...)
	return patterns
}

// ═══════════════════════════════════════════════════════════════════════════════
// LICENSE
// ═══════════════════════════════════════════════════════════════════════════════

func getLicensePatterns() []PatternDef {
	return []PatternDef{
		// Google LVL
		{Category: types.CategoryGoogleLVL, Pattern: `Lcom/google/android/vending/licensing/`, Priority: 10, IsCritical: true, Description: "Google LVL licensing package"},
		{Category: types.CategoryGoogleLVL, Pattern: `Lcom/android/vending/licensing/`, Priority: 10, IsCritical: true, Description: "Android vending licensing"},
		{Category: types.CategoryGoogleLVL, Pattern: `LicenseChecker`, Priority: 10, IsCritical: true, Description: "LicenseChecker class"},
		{Category: types.CategoryGoogleLVL, Pattern: `LicenseCheckerCallback`, Priority: 10, IsCritical: true, Description: "LicenseCheckerCallback"},
		{Category: types.CategoryGoogleLVL, Pattern: `->dontAllow(`, Priority: 10, IsCritical: true, Description: "License denied handler"},
		{Category: types.CategoryGoogleLVL, Pattern: `->applicationError(`, Priority: 10, IsCritical: true, Description: "License error handler"},
		{Category: types.CategoryGoogleLVL, Pattern: `->allow(`, Priority: 9, IsCritical: true, Description: "License allow handler"},
		{Category: types.CategoryGoogleLVL, Pattern: `ILicensingService`, Priority: 10, IsCritical: true, Description: "ILicensingService interface"},
		{Category: types.CategoryGoogleLVL, Pattern: `ServerManagedPolicy`, Priority: 9, IsCritical: true, Description: "Server-managed license policy"},
		{Category: types.CategoryGoogleLVL, Pattern: `StrictPolicy`, Priority: 9, IsCritical: true, Description: "Strict license policy"},

		// License checks
		{Category: types.CategoryLicenseCheck, Pattern: `isLicensed`, Priority: 10, IsCritical: true, Description: "License status check"},
		{Category: types.CategoryLicenseCheck, Pattern: `checkLicense`, Priority: 10, IsCritical: true, Description: "License verification call"},
		{Category: types.CategoryLicenseCheck, Pattern: `verifyLicense`, Priority: 10, IsCritical: true, Description: "License verification"},
		{Category: types.CategoryLicenseCheck, Pattern: `validateLicense`, Priority: 10, IsCritical: true, Description: "License validation"},
		{Category: types.CategoryLicenseCheck, Pattern: `isValidLicense`, Priority: 10, IsCritical: true, Description: "License validity check"},
		{Category: types.CategoryLicenseCheck, Pattern: `hasLicense`, Priority: 9, IsCritical: true, Description: "Has license check"},
		// isRegistered alone is ambiguous (e.g. listener registration), not a license check.
		{Category: types.CategoryLicenseCheck, Pattern: `isLicenseActivated`, Priority: 9, IsCritical: true, Description: "License activation check"},
		{Category: types.CategoryLicenseCheck, Pattern: `"license_key"`, Priority: 8, IsCritical: true, Description: "License key string"},

		// License storage
		{Category: types.CategoryLicenseStorage, Pattern: `"license_status"`, Priority: 7, IsCritical: true, Description: "License status storage key"},
		{Category: types.CategoryLicenseStorage, Pattern: `"license_valid"`, Priority: 7, IsCritical: true, Description: "License valid flag"},
		{Category: types.CategoryLicenseStorage, Pattern: `"is_licensed"`, Priority: 7, IsCritical: true, Description: "Is licensed flag"},
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// BILLING
// ═══════════════════════════════════════════════════════════════════════════════

func getBillingPatterns() []PatternDef {
	return []PatternDef{
		// Billing SDK classes are inventory. Marking them critical made every
		// Play-Billing app report CRITICAL findings for a normal purchase flow.
		{Category: types.CategoryBillingClient, Pattern: `Lcom/android/billingclient/api/BillingClient`, Priority: 9, Description: "BillingClient class"},
		{Category: types.CategoryBillingClient, Pattern: `Lcom/android/billingclient/api/Purchase`, Priority: 9, Description: "Purchase class"},
		{Category: types.CategoryBillingClient, Pattern: `Lcom/android/billingclient/api/BillingResult`, Priority: 8, Description: "BillingResult class"},
		{Category: types.CategoryBillingClient, Pattern: `Lcom/android/billingclient/api/PurchasesUpdatedListener`, Priority: 9, Description: "Purchase update listener"},
		{Category: types.CategoryBillingClient, Pattern: `Lcom/android/billingclient/api/SkuDetails`, Priority: 8, IsCritical: false, Description: "SKU details"},
		{Category: types.CategoryBillingClient, Pattern: `Lcom/android/billingclient/api/ProductDetails`, Priority: 8, IsCritical: false, Description: "Product details"},
		{Category: types.CategoryBillingClient, Pattern: `->queryPurchases`, Priority: 8, Description: "Query purchases call"},
		{Category: types.CategoryBillingClient, Pattern: `->launchBillingFlow`, Priority: 7, IsCritical: false, Description: "Launch billing flow"},

		{Category: types.CategoryPurchaseVerify, Pattern: `isPurchased`, Priority: 9, IsCritical: true, Description: "Purchase status check"},
		{Category: types.CategoryPurchaseVerify, Pattern: `hasPurchased`, Priority: 9, IsCritical: true, Description: "Has purchased check"},
		{Category: types.CategoryPurchaseVerify, Pattern: `verifyPurchase`, Priority: 9, IsCritical: true, Description: "Purchase verification"},
		{Category: types.CategoryPurchaseVerify, Pattern: `checkPurchase`, Priority: 9, IsCritical: true, Description: "Purchase check"},
		{Category: types.CategoryPurchaseVerify, Pattern: `isOwned`, Priority: 8, IsCritical: true, Description: "Ownership check"},
		{Category: types.CategoryPurchaseVerify, Pattern: `hasOwned`, Priority: 8, IsCritical: true, Description: "Has owned check"},
		{Category: types.CategoryPurchaseVerify, Pattern: `isProductPurchased`, Priority: 9, IsCritical: true, Description: "Product purchase check"},
		{Category: types.CategoryPurchaseVerify, Pattern: `getPurchaseState`, Priority: 8, IsCritical: true, Description: "Get purchase state"},

		// Purchase tokens are expected fields in any billing integration; they
		// only become interesting when they leak (hardcoded-secret detectors).
		{Category: types.CategoryPurchaseToken, Pattern: `purchaseToken`, Priority: 8, Description: "Purchase token field"},
		{Category: types.CategoryPurchaseToken, Pattern: `"purchase_token"`, Priority: 8, Description: "Purchase token string"},
		{Category: types.CategoryPurchaseToken, Pattern: `orderId`, Priority: 7, IsCritical: false, Description: "Order ID field"},
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// PREMIUM
// ═══════════════════════════════════════════════════════════════════════════════

func getPremiumPatterns() []PatternDef {
	return []PatternDef{
		{Category: types.CategoryPremiumCheck, Pattern: `isPremium`, Priority: 9, IsCritical: true, Description: "Premium status check"},
		{Category: types.CategoryPremiumCheck, Pattern: `\bisPro(?:$|[^a-zA-Z0-9]|User\b|Version\b|Active\b)`, IsRegex: true, Priority: 9, IsCritical: true, Description: "Pro status check"},
		{Category: types.CategoryPremiumCheck, Pattern: `isProUser`, Priority: 9, IsCritical: true, Description: "Pro user check"},
		{Category: types.CategoryPremiumCheck, Pattern: `isPremiumUser`, Priority: 9, IsCritical: true, Description: "Premium user check"},
		{Category: types.CategoryPremiumCheck, Pattern: `hasPremium`, Priority: 9, IsCritical: true, Description: "Has premium check"},
		{Category: types.CategoryPremiumCheck, Pattern: `\bhasPro(?:$|[^a-zA-Z0-9]|Access\b|Version\b)`, IsRegex: true, Priority: 9, IsCritical: true, Description: "Has pro check"},
		{Category: types.CategoryPremiumCheck, Pattern: `isVip`, Priority: 9, IsCritical: true, Description: "VIP status check"},
		{Category: types.CategoryPremiumCheck, Pattern: `isVipUser`, Priority: 9, IsCritical: true, Description: "VIP user check"},
		{Category: types.CategoryPremiumCheck, Pattern: `isGold`, Priority: 8, IsCritical: true, Description: "Gold status check"},
		{Category: types.CategoryPremiumCheck, Pattern: `isPlatinum`, Priority: 8, IsCritical: true, Description: "Platinum status check"},
		{Category: types.CategoryPremiumCheck, Pattern: `isFullVersion`, Priority: 9, IsCritical: true, Description: "Full version check"},
		{Category: types.CategoryPremiumCheck, Pattern: `isPaid`, Priority: 9, IsCritical: true, Description: "Paid status check"},
		{Category: types.CategoryPremiumCheck, Pattern: `isPaidUser`, Priority: 9, IsCritical: true, Description: "Paid user check"},
		{Category: types.CategoryPremiumCheck, Pattern: `isUnlocked`, Priority: 8, IsCritical: true, Description: "Unlock status check"},
		{Category: types.CategoryPremiumCheck, Pattern: `hasLifetime`, Priority: 9, IsCritical: true, Description: "Lifetime access check"},
		{Category: types.CategoryPremiumCheck, Pattern: `isLifetime`, Priority: 9, IsCritical: true, Description: "Lifetime status check"},

		{Category: types.CategoryPremiumUnlock, Pattern: `unlockPremium`, Priority: 8, IsCritical: true, Description: "Unlock premium"},
		{Category: types.CategoryPremiumUnlock, Pattern: `unlockPro`, Priority: 8, IsCritical: true, Description: "Unlock pro"},
		{Category: types.CategoryPremiumUnlock, Pattern: `activatePremium`, Priority: 8, IsCritical: true, Description: "Activate premium"},
		{Category: types.CategoryPremiumUnlock, Pattern: `setPremium`, Priority: 8, IsCritical: true, Description: "Set premium flag"},

		{Category: types.CategoryProFeature, Pattern: `isFeatureUnlocked`, Priority: 7, IsCritical: false, Description: "Feature unlock check"},
		{Category: types.CategoryProFeature, Pattern: `hasFeature`, Priority: 7, IsCritical: false, Description: "Has feature check"},
		{Category: types.CategoryProFeature, Pattern: `canUseFeature`, Priority: 7, IsCritical: false, Description: "Feature access check"},
		{Category: types.CategoryProFeature, Pattern: `isFeatureEnabled`, Priority: 7, IsCritical: false, Description: "Feature enabled check"},
		{Category: types.CategoryProFeature, Pattern: `"premium"`, Priority: 6, IsCritical: false, Description: "Premium string reference"},
		{Category: types.CategoryProFeature, Pattern: `"pro_version"`, Priority: 6, IsCritical: false, Description: "Pro version string"},
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// TRIAL
// ═══════════════════════════════════════════════════════════════════════════════

func getTrialPatterns() []PatternDef {
	return []PatternDef{
		{Category: types.CategoryTrialCheck, Pattern: `isTrialActive`, Priority: 8, IsCritical: true, Description: "Trial active check"},
		{Category: types.CategoryTrialCheck, Pattern: `isInTrial`, Priority: 8, IsCritical: true, Description: "In trial check"},
		{Category: types.CategoryTrialCheck, Pattern: `hasTrialLeft`, Priority: 8, IsCritical: true, Description: "Trial remaining check"},
		{Category: types.CategoryTrialCheck, Pattern: `checkTrial`, Priority: 8, IsCritical: true, Description: "Trial validation"},
		{Category: types.CategoryTrialCheck, Pattern: `isTrialValid`, Priority: 8, IsCritical: true, Description: "Trial validity check"},
		{Category: types.CategoryTrialCheck, Pattern: `getTrialDaysLeft`, Priority: 7, IsCritical: true, Description: "Trial days remaining"},

		{Category: types.CategoryTrialExpiry, Pattern: `isTrialExpired`, Priority: 8, IsCritical: true, Description: "Trial expired check"},
		{Category: types.CategoryTrialExpiry, Pattern: `hasTrialExpired`, Priority: 8, IsCritical: true, Description: "Has trial expired"},
		{Category: types.CategoryTrialExpiry, Pattern: `isExpired`, Priority: 8, IsCritical: true, Description: "Expiry check"},
		{Category: types.CategoryTrialExpiry, Pattern: `hasExpired`, Priority: 8, IsCritical: true, Description: "Has expired check"},
		{Category: types.CategoryTrialExpiry, Pattern: `checkExpiry`, Priority: 8, IsCritical: true, Description: "Expiry validation"},
		{Category: types.CategoryTrialExpiry, Pattern: `getExpiryDate`, Priority: 7, IsCritical: true, Description: "Get expiry date"},
		{Category: types.CategoryTrialExpiry, Pattern: `"trial_end"`, Priority: 7, IsCritical: true, Description: "Trial end key"},
		{Category: types.CategoryTrialExpiry, Pattern: `"expiry_date"`, Priority: 7, IsCritical: true, Description: "Expiry date key"},

		// NOTE: bare System->currentTimeMillis was removed — every app calls
		// it constantly (game loops, timers, animation), zero trial signal.
		{Category: types.CategoryTimeCheck, Pattern: `getRemainingDays`, Priority: 7, IsCritical: true, Description: "Remaining days getter"},
		{Category: types.CategoryTimeCheck, Pattern: `getDaysLeft`, Priority: 7, IsCritical: true, Description: "Days left getter"},
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// SUBSCRIPTION
// ═══════════════════════════════════════════════════════════════════════════════

func getSubscriptionPatterns() []PatternDef {
	return []PatternDef{
		{Category: types.CategorySubscription, Pattern: `isSubscribed`, Priority: 9, IsCritical: true, Description: "Subscription status check"},
		{Category: types.CategorySubscription, Pattern: `hasSubscription`, Priority: 9, IsCritical: true, Description: "Has subscription check"},
		{Category: types.CategorySubscription, Pattern: `isSubscriptionActive`, Priority: 9, IsCritical: true, Description: "Active subscription check"},
		{Category: types.CategorySubscription, Pattern: `checkSubscription`, Priority: 9, IsCritical: true, Description: "Subscription validation"},
		{Category: types.CategorySubscription, Pattern: `isSubscriber`, Priority: 9, IsCritical: true, Description: "Subscriber check"},
		{Category: types.CategorySubscription, Pattern: `hasActiveSubscription`, Priority: 9, IsCritical: true, Description: "Active subscription check"},
		{Category: types.CategorySubscription, Pattern: `isSubscriptionValid`, Priority: 9, IsCritical: true, Description: "Subscription validity"},
		{Category: types.CategorySubscription, Pattern: `getSubscriptionStatus`, Priority: 8, IsCritical: true, Description: "Subscription status getter"},
		{Category: types.CategorySubscription, Pattern: `SubscriptionManager`, Priority: 7, IsCritical: false, Description: "Subscription manager class"},
		{Category: types.CategorySubscription, Pattern: `"subscription"`, Priority: 6, IsCritical: false, Description: "Subscription string"},
		{Category: types.CategorySubscription, Pattern: `"monthly"`, Priority: 5, IsCritical: false, Description: "Monthly period string"},
		{Category: types.CategorySubscription, Pattern: `"yearly"`, Priority: 5, IsCritical: false, Description: "Yearly period string"},
		{Category: types.CategorySubscription, Pattern: `"weekly"`, Priority: 5, IsCritical: false, Description: "Weekly period string"},
		{Category: types.CategorySubscription, Pattern: `"lifetime"`, Priority: 6, IsCritical: false, Description: "Lifetime access string"},
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// ADS — GENERAL
// ═══════════════════════════════════════════════════════════════════════════════

func getAdPatterns() []PatternDef {
	return []PatternDef{
		{Category: types.CategoryAdRemove, Pattern: `isAdFree`, Priority: 7, IsCritical: false, Description: "Ad-free status check"},
		{Category: types.CategoryAdRemove, Pattern: `hasNoAds`, Priority: 7, IsCritical: false, Description: "No ads check"},
		{Category: types.CategoryAdRemove, Pattern: `isNoAds`, Priority: 7, IsCritical: false, Description: "No ads flag"},
		{Category: types.CategoryAdRemove, Pattern: `isAdsRemoved`, Priority: 7, IsCritical: false, Description: "Ads removed check"},
		{Category: types.CategoryAdRemove, Pattern: `hasRemoveAds`, Priority: 7, IsCritical: false, Description: "Remove ads purchased"},
		{Category: types.CategoryAdRemove, Pattern: `adsRemoved`, Priority: 7, IsCritical: false, Description: "Ads removed flag"},
		{Category: types.CategoryAdRemove, Pattern: `"remove_ads"`, Priority: 6, IsCritical: false, Description: "Remove ads SKU"},
		{Category: types.CategoryAdRemove, Pattern: `"no_ads"`, Priority: 6, IsCritical: false, Description: "No ads key"},
		{Category: types.CategoryAdRemove, Pattern: `"ad_free"`, Priority: 6, IsCritical: false, Description: "Ad-free key"},

		{Category: types.CategoryAdCheck, Pattern: `shouldShowAd`, Priority: 6, IsCritical: false, Description: "Should show ad check"},
		{Category: types.CategoryAdCheck, Pattern: `shouldShowAds`, Priority: 6, IsCritical: false, Description: "Should show ads check"},
		{Category: types.CategoryAdCheck, Pattern: `canShowAd`, Priority: 6, IsCritical: false, Description: "Can show ad check"},
		{Category: types.CategoryAdCheck, Pattern: `isAdEnabled`, Priority: 6, IsCritical: false, Description: "Ad enabled check"},
		{Category: types.CategoryAdCheck, Pattern: `hasAds`, Priority: 5, IsCritical: false, Description: "Has ads check"},
		{Category: types.CategoryAdCheck, Pattern: `isTimeToShowAd`, Priority: 6, IsCritical: false, Description: "Ad timing check"},
		{Category: types.CategoryAdCheck, Pattern: `shouldDisplayAd`, Priority: 6, IsCritical: false, Description: "Ad display decision"},

		{Category: types.CategoryAdLoad, Pattern: `loadAd`, Priority: 5, IsCritical: false, Description: "Load ad call"},
		{Category: types.CategoryAdLoad, Pattern: `loadBanner`, Priority: 5, IsCritical: false, Description: "Load banner"},
		{Category: types.CategoryAdLoad, Pattern: `loadInterstitial`, Priority: 5, IsCritical: false, Description: "Load interstitial"},
		{Category: types.CategoryAdLoad, Pattern: `loadRewardedAd`, Priority: 5, IsCritical: false, Description: "Load rewarded ad"},
		{Category: types.CategoryAdLoad, Pattern: `loadNativeAd`, Priority: 5, IsCritical: false, Description: "Load native ad"},
		{Category: types.CategoryAdLoad, Pattern: `fetchAd`, Priority: 5, IsCritical: false, Description: "Fetch ad request"},
		{Category: types.CategoryAdLoad, Pattern: `requestAd`, Priority: 5, IsCritical: false, Description: "Request ad"},

		{Category: types.CategoryAdShow, Pattern: `\bshowAd(?:$|[^a-zA-Z0-9]|s\b|vertisement\b)`, IsRegex: true, Priority: 6, IsCritical: false, Description: "Show ad call"},
		{Category: types.CategoryAdShow, Pattern: `showBanner`, Priority: 6, IsCritical: false, Description: "Show banner"},
		{Category: types.CategoryAdShow, Pattern: `showInterstitial`, Priority: 6, IsCritical: false, Description: "Show interstitial"},
		{Category: types.CategoryAdShow, Pattern: `showRewardedAd`, Priority: 6, IsCritical: false, Description: "Show rewarded ad"},
		{Category: types.CategoryAdShow, Pattern: `displayAd`, Priority: 6, IsCritical: false, Description: "Display ad"},
		{Category: types.CategoryAdShow, Pattern: `presentAd`, Priority: 6, IsCritical: false, Description: "Present ad"},

		{Category: types.CategoryAdInit, Pattern: `initAds`, Priority: 5, IsCritical: false, Description: "Initialize ads"},
		{Category: types.CategoryAdInit, Pattern: `initializeAds`, Priority: 5, IsCritical: false, Description: "Ads initialization"},
		{Category: types.CategoryAdInit, Pattern: `setupAds`, Priority: 5, IsCritical: false, Description: "Ads setup"},
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// AD NETWORKS
// ═══════════════════════════════════════════════════════════════════════════════

func getAdNetworkPatterns() []PatternDef {
	return []PatternDef{
		// AdMob
		{Category: types.CategoryAdMob, Pattern: `Lcom/google/android/gms/ads/AdView;`, Priority: 6, Description: "AdMob AdView"},
		{Category: types.CategoryAdMob, Pattern: `Lcom/google/android/gms/ads/InterstitialAd;`, Priority: 6, Description: "AdMob InterstitialAd"},
		{Category: types.CategoryAdMob, Pattern: `Lcom/google/android/gms/ads/rewarded/RewardedAd;`, Priority: 6, Description: "AdMob RewardedAd"},
		{Category: types.CategoryAdMob, Pattern: `Lcom/google/android/gms/ads/MobileAds;`, Priority: 6, Description: "AdMob SDK init"},
		{Category: types.CategoryAdMob, Pattern: `Lcom/google/android/gms/ads/nativead/`, Priority: 6, Description: "AdMob NativeAd"},
		{Category: types.CategoryAdMob, Pattern: `Lcom/google/android/gms/ads/AdRequest;`, Priority: 5, Description: "AdMob AdRequest"},
		{Category: types.CategoryAdMob, Pattern: `Lcom/google/android/gms/ads/interstitial/InterstitialAd;`, Priority: 6, Description: "AdMob Interstitial v2"},

		// Unity Ads
		{Category: types.CategoryUnityAds, Pattern: `Lcom/unity3d/ads/UnityAds;`, Priority: 6, Description: "Unity Ads SDK"},
		{Category: types.CategoryUnityAds, Pattern: `Lcom/unity3d/ads/IUnityAdsListener;`, Priority: 6, Description: "Unity Ads listener"},
		{Category: types.CategoryUnityAds, Pattern: `Lcom/unity3d/services/ads/`, Priority: 6, Description: "Unity Ads services"},

		// Facebook Ads
		{Category: types.CategoryFacebookAds, Pattern: `Lcom/facebook/ads/Ad;`, Priority: 6, Description: "Facebook Ad interface"},
		{Category: types.CategoryFacebookAds, Pattern: `Lcom/facebook/ads/InterstitialAd;`, Priority: 6, Description: "Facebook InterstitialAd"},
		{Category: types.CategoryFacebookAds, Pattern: `Lcom/facebook/ads/RewardedVideoAd;`, Priority: 6, Description: "Facebook RewardedVideoAd"},
		{Category: types.CategoryFacebookAds, Pattern: `Lcom/facebook/ads/NativeAd;`, Priority: 6, Description: "Facebook NativeAd"},

		// IronSource
		{Category: types.CategoryIronSource, Pattern: `Lcom/ironsource/mediationsdk/IronSource;`, Priority: 6, Description: "IronSource SDK"},
		{Category: types.CategoryIronSource, Pattern: `Lcom/ironsource/mediationsdk/sdk/`, Priority: 6, Description: "IronSource mediation"},

		// AppLovin
		{Category: types.CategoryAppLovin, Pattern: `Lcom/applovin/sdk/AppLovinAd;`, Priority: 6, Description: "AppLovin Ad"},
		{Category: types.CategoryAppLovin, Pattern: `Lcom/applovin/mediation/`, Priority: 6, Description: "AppLovin mediation"},
		{Category: types.CategoryAppLovin, Pattern: `Lcom/applovin/sdk/AppLovinSdk;`, Priority: 6, Description: "AppLovin SDK"},

		// Others
		{Category: types.CategoryAdColony, Pattern: `Lcom/adcolony/sdk/AdColony;`, Priority: 6, Description: "AdColony SDK"},
		{Category: types.CategoryVungle, Pattern: `Lcom/vungle/warren/Vungle;`, Priority: 6, Description: "Vungle SDK"},
		{Category: types.CategoryChartboost, Pattern: `Lcom/chartboost/sdk/Chartboost;`, Priority: 6, Description: "Chartboost SDK"},
		{Category: types.CategoryStartApp, Pattern: `Lcom/startapp/sdk/`, Priority: 6, Description: "StartApp SDK"},
		{Category: types.CategoryMintegral, Pattern: `Lcom/mbridge/msdk/`, Priority: 6, Description: "Mintegral SDK"},
		{Category: types.CategoryPangle, Pattern: `Lcom/bytedance/sdk/openadsdk/`, Priority: 6, Description: "Pangle SDK"},
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// ANALYTICS
// ═══════════════════════════════════════════════════════════════════════════════

func getAnalyticsPatterns() []PatternDef {
	return []PatternDef{
		{Category: types.CategoryFirebaseAnalytics, Pattern: `Lcom/google/firebase/analytics/FirebaseAnalytics;`, Priority: 4, Description: "Firebase Analytics"},
		{Category: types.CategoryFirebaseAnalytics, Pattern: `->logEvent(`, Priority: 4, Description: "Firebase logEvent"},
		{Category: types.CategoryFirebaseAnalytics, Pattern: `->setUserProperty(`, Priority: 4, Description: "Firebase setUserProperty"},
		{Category: types.CategoryGoogleAnalytics, Pattern: `Lcom/google/android/gms/analytics/`, Priority: 4, Description: "Google Analytics"},
		{Category: types.CategoryFacebookAnalytics, Pattern: `Lcom/facebook/appevents/AppEventsLogger;`, Priority: 4, Description: "Facebook App Events"},
		{Category: types.CategoryAmplitude, Pattern: `Lcom/amplitude/api/Amplitude;`, Priority: 4, Description: "Amplitude SDK"},
		{Category: types.CategoryMixpanel, Pattern: `Lcom/mixpanel/android/`, Priority: 4, Description: "Mixpanel SDK"},
		{Category: types.CategoryAppsFlyer, Pattern: `Lcom/appsflyer/AppsFlyerLib;`, Priority: 4, Description: "AppsFlyer SDK"},
		{Category: types.CategoryAdjust, Pattern: `Lcom/adjust/sdk/Adjust;`, Priority: 4, Description: "Adjust SDK"},
		{Category: types.CategoryFlurry, Pattern: `Lcom/flurry/android/FlurryAgent;`, Priority: 4, Description: "Flurry SDK"},
		{Category: types.CategoryCrashlytics, Pattern: `Lcom/google/firebase/crashlytics/`, Priority: 3, Description: "Firebase Crashlytics"},
		{Category: types.CategoryCrashlytics, Pattern: `Lcom/crashlytics/android/`, Priority: 3, Description: "Crashlytics SDK"},
		{Category: types.CategoryCrashlytics, Pattern: `->recordException(`, Priority: 3, Description: "Crashlytics recordException"},
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECURITY
// ═══════════════════════════════════════════════════════════════════════════════

func getSecurityPatterns() []PatternDef {
	return []PatternDef{
		// getPackageInfo alone is benign (version display, update checks) —
		// only GET_SIGNATURES / signature comparison patterns stay critical.
		{Category: types.CategorySignatureCheck, Pattern: `->getPackageInfo(`, Priority: 5, IsCritical: false, Description: "PackageInfo retrieval"},
		{Category: types.CategorySignatureCheck, Pattern: `GET_SIGNATURES`, Priority: 9, IsCritical: true, Description: "GET_SIGNATURES flag"},
		{Category: types.CategorySignatureCheck, Pattern: `GET_SIGNING_CERTIFICATES`, Priority: 9, IsCritical: true, Description: "GET_SIGNING_CERTIFICATES flag"},
		{Category: types.CategorySignatureCheck, Pattern: `checkSignature`, Priority: 9, IsCritical: true, Description: "Signature check call"},
		{Category: types.CategorySignatureCheck, Pattern: `verifySignature`, Priority: 9, IsCritical: true, Description: "Signature verification"},
		{Category: types.CategorySignatureCheck, Pattern: `isSignatureValid`, Priority: 9, IsCritical: true, Description: "Signature validity check"},
		{Category: types.CategorySignatureCheck, Pattern: `validateSignature`, Priority: 9, IsCritical: true, Description: "Signature validation"},

		{Category: types.CategoryIntegrityCheck, Pattern: `checkIntegrity`, Priority: 9, IsCritical: true, Description: "Integrity check"},
		{Category: types.CategoryIntegrityCheck, Pattern: `verifyIntegrity`, Priority: 9, IsCritical: true, Description: "Integrity verification"},
		{Category: types.CategoryIntegrityCheck, Pattern: `isIntegrityOk`, Priority: 9, IsCritical: true, Description: "Integrity status"},

		{Category: types.CategoryTamperDetection, Pattern: `isTampered`, Priority: 9, IsCritical: true, Description: "Tamper check"},
		{Category: types.CategoryTamperDetection, Pattern: `detectTampering`, Priority: 9, IsCritical: true, Description: "Tamper detection"},
		{Category: types.CategoryTamperDetection, Pattern: `checkTamper`, Priority: 9, IsCritical: true, Description: "Tamper validation"},
		{Category: types.CategoryTamperDetection, Pattern: `isModified`, Priority: 8, IsCritical: true, Description: "Modification check"},
		{Category: types.CategoryTamperDetection, Pattern: `isApkModified`, Priority: 9, IsCritical: true, Description: "APK modification check"},
		{Category: types.CategoryTamperDetection, Pattern: `isRepackaged`, Priority: 9, IsCritical: true, Description: "Repackage detection"},

		{Category: types.CategoryRootDetection, Pattern: `isRooted`, Priority: 8, IsCritical: true, Description: "Root detection"},
		{Category: types.CategoryRootDetection, Pattern: `isDeviceRooted`, Priority: 8, IsCritical: true, Description: "Device root check"},
		{Category: types.CategoryRootDetection, Pattern: `checkRoot`, Priority: 8, IsCritical: true, Description: "Root check"},
		{Category: types.CategoryRootDetection, Pattern: `detectRoot`, Priority: 8, IsCritical: true, Description: "Root detection call"},
		{Category: types.CategoryRootDetection, Pattern: `hasRoot`, Priority: 8, IsCritical: true, Description: "Has root check"},
		{Category: types.CategoryRootDetection, Pattern: `isSuAvailable`, Priority: 8, IsCritical: true, Description: "SU binary check"},
		{Category: types.CategoryRootDetection, Pattern: `checkSuBinary`, Priority: 8, IsCritical: true, Description: "SU binary validation"},
		{Category: types.CategoryRootDetection, Pattern: `"/system/bin/su"`, Priority: 7, Description: "SU path string"},
		{Category: types.CategoryRootDetection, Pattern: `"/system/xbin/su"`, Priority: 7, Description: "SU xbin path string"},
		{Category: types.CategoryRootDetection, Pattern: `hasSuperuser`, Priority: 8, IsCritical: true, Description: "Superuser check"},
		{Category: types.CategoryRootDetection, Pattern: `isMagiskPresent`, Priority: 8, IsCritical: true, Description: "Magisk detection"},
		{Category: types.CategoryRootDetection, Pattern: `checkMagisk`, Priority: 8, IsCritical: true, Description: "Magisk check"},

		{Category: types.CategoryEmulatorDetection, Pattern: `isEmulator`, Priority: 7, Description: "Emulator check"},
		{Category: types.CategoryEmulatorDetection, Pattern: `isRunningOnEmulator`, Priority: 7, Description: "Running on emulator"},
		{Category: types.CategoryEmulatorDetection, Pattern: `detectEmulator`, Priority: 7, Description: "Emulator detection"},
		{Category: types.CategoryEmulatorDetection, Pattern: `checkEmulator`, Priority: 7, Description: "Emulator validation"},
		{Category: types.CategoryEmulatorDetection, Pattern: `isVirtualDevice`, Priority: 7, Description: "Virtual device check"},
		{Category: types.CategoryEmulatorDetection, Pattern: `isGenymotion`, Priority: 7, Description: "Genymotion check"},
		{Category: types.CategoryEmulatorDetection, Pattern: `isBluestacks`, Priority: 7, Description: "BlueStacks check"},
		// NOTE: bare "generic" / "sdk" string patterns were removed — they match
		// almost any resource/XML and produced thousands of false positives with
		// no real signal. Emulator detection now relies on the method-name and
		// dedicated-string patterns above. See plan §1.7.
		{Category: types.CategoryEmulatorDetection, Pattern: `Build.FINGERPRINT`, Priority: 6, Description: "Build.FINGERPRINT emulator probe"},
		{Category: types.CategoryEmulatorDetection, Pattern: `"goldfish"`, Priority: 7, Description: "Goldfish emulator kernel string"},
		{Category: types.CategoryEmulatorDetection, Pattern: `"ranchu"`, Priority: 7, Description: "Ranchu emulator string"},

		{Category: types.CategoryDebugDetection, Pattern: `isDebuggable`, Priority: 7, Description: "Debuggable check"},
		{Category: types.CategoryDebugDetection, Pattern: `isDebugBuild`, Priority: 7, Description: "Debug build check"},
		{Category: types.CategoryDebugDetection, Pattern: `isDebugMode`, Priority: 7, Description: "Debug mode check"},
		{Category: types.CategoryDebugDetection, Pattern: `detectDebug`, Priority: 7, Description: "Debug detection"},
		{Category: types.CategoryDebugDetection, Pattern: `checkDebugger`, Priority: 7, Description: "Debugger check"},
		{Category: types.CategoryDebugDetection, Pattern: `isBeingDebugged`, Priority: 7, Description: "Being debugged check"},
		{Category: types.CategoryDebugDetection, Pattern: `Landroid/os/Debug;->isDebuggerConnected`, Priority: 8, IsCritical: true, Description: "Debug.isDebuggerConnected"},
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// DROPPER / SECOND-STAGE TOOLING
// ═══════════════════════════════════════════════════════════════════════════════

func getDropperPatterns() []PatternDef {
	return []PatternDef{
		// Payload-container markers. These appear in plaintext in builds that
		// do not obfuscate string constants; StringFog builds are covered by
		// the stringfog evaluator feeding the rule engine.
		{Category: types.CategoryMalware, Pattern: `__wombat_payload__`, Priority: 10, IsCritical: true,
			Description: "Second-stage payload container marker"},
		{Category: types.CategoryMalware, Pattern: `Provider missing in decoy mode`, Priority: 9, IsCritical: true,
			Description: "Decoy-mode hidden application loader"},
		// Injection tooling — non-critical standalone (QA tooling exists);
		// the toolkit combo raises it with corroboration.
		{Category: types.CategoryDexNetworkLoad, Pattern: `linjector`, Priority: 7, Description: "Native injection helper"},
		{Category: types.CategoryDexNetworkLoad, Pattern: `libreality_transport`, Priority: 7, Description: "REALITY TLS-camouflaged transport"},
		{Category: types.CategoryDexNetworkLoad, Pattern: `libldssfve`, Priority: 8, IsCritical: true,
			Description: "Known packed-loader native library"},
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// ADVANCED SECURITY
// ═══════════════════════════════════════════════════════════════════════════════

func getAdvancedSecurityPatterns() []PatternDef {
	return []PatternDef{
		{Category: types.CategorySafetyNet, Pattern: `Lcom/google/android/gms/safetynet/SafetyNet;`, Priority: 10, IsCritical: true, Description: "SafetyNet API"},
		{Category: types.CategorySafetyNet, Pattern: `SafetyNetClient`, Priority: 10, IsCritical: true, Description: "SafetyNet client"},
		{Category: types.CategorySafetyNet, Pattern: `SafetyNetApi`, Priority: 10, IsCritical: true, Description: "SafetyNet API call"},
		{Category: types.CategorySafetyNet, Pattern: `AttestationResponse`, Priority: 10, IsCritical: true, Description: "Attestation response"},
		{Category: types.CategorySafetyNet, Pattern: `attest(`, Priority: 9, IsCritical: true, Description: "Attestation call"},

		{Category: types.CategoryPlayIntegrity, Pattern: `Lcom/google/android/play/core/integrity/`, Priority: 10, IsCritical: true, Description: "Play Integrity API"},
		{Category: types.CategoryPlayIntegrity, Pattern: `IntegrityManager`, Priority: 10, IsCritical: true, Description: "Integrity manager"},
		{Category: types.CategoryPlayIntegrity, Pattern: `IntegrityTokenRequest`, Priority: 9, IsCritical: true, Description: "Integrity token request"},

		{Category: types.CategorySSLPinning, Pattern: `CertificatePinner`, Priority: 8, IsCritical: true, Description: "OkHttp certificate pinner"},
		{Category: types.CategoryNetwork, Pattern: `TrustManager`, Priority: 2, Description: "TLS trust manager reference; pinning not established"},
		{Category: types.CategoryNetwork, Pattern: `X509TrustManager`, Priority: 2, Description: "X.509 trust manager reference; pinning not established"},
		{Category: types.CategoryNetwork, Pattern: `HostnameVerifier`, Priority: 2, Description: "TLS hostname verifier reference; pinning not established"},
		{Category: types.CategoryNetwork, Pattern: `->checkServerTrusted(`, Priority: 2, Description: "Server certificate validation API reference; pinning not established"},

		{Category: types.CategoryAntiXposed, Pattern: `"de.robv.android.xposed"`, Priority: 9, IsCritical: true, Description: "Xposed package check"},
		{Category: types.CategoryAntiXposed, Pattern: `XposedBridge`, Priority: 9, IsCritical: true, Description: "XposedBridge reference"},
		{Category: types.CategoryAntiXposed, Pattern: `XposedHelpers`, Priority: 9, IsCritical: true, Description: "XposedHelpers reference"},
		{Category: types.CategoryAntiXposed, Pattern: `detectXposed`, Priority: 9, IsCritical: true, Description: "Xposed detection"},
		{Category: types.CategoryAntiXposed, Pattern: `isXposedActive`, Priority: 9, IsCritical: true, Description: "Xposed active check"},

		{Category: types.CategoryAntiHook, Pattern: `"substrate"`, Priority: 8, IsCritical: true, Description: "Substrate framework check"},
		{Category: types.CategoryAntiHook, Pattern: `"cydia"`, Priority: 8, IsCritical: true, Description: "Cydia Substrate check"},
		{Category: types.CategoryAntiHook, Pattern: `detectHook`, Priority: 8, IsCritical: true, Description: "Hook detection"},
		{Category: types.CategoryAntiHook, Pattern: `isHooked`, Priority: 8, IsCritical: true, Description: "Hook status check"},
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// REMOTE CONFIG
// ═══════════════════════════════════════════════════════════════════════════════

func getRemoteConfigPatterns() []PatternDef {
	return []PatternDef{
		// NOTE: Avoid generic method-name patterns like "->getBoolean(" because they explode with false positives.
		// We match full owner type so the signal actually means Firebase Remote Config.
		{Category: types.CategoryRemoteConfig, Pattern: `Lcom/google/firebase/remoteconfig/FirebaseRemoteConfig;`, Priority: 7, IsCritical: true, Description: "Firebase Remote Config", MustBeAppCode: true},
		{Category: types.CategoryRemoteConfig, Pattern: `Lcom/google/firebase/remoteconfig/FirebaseRemoteConfig;->getBoolean(`, Priority: 6, Description: "Remote config getBoolean", MustBeAppCode: true},
		{Category: types.CategoryRemoteConfig, Pattern: `Lcom/google/firebase/remoteconfig/FirebaseRemoteConfig;->getString(`, Priority: 5, Description: "Remote config getString", MustBeAppCode: true},
		{Category: types.CategoryRemoteConfig, Pattern: `Lcom/google/firebase/remoteconfig/FirebaseRemoteConfig;->getLong(`, Priority: 5, Description: "Remote config getLong", MustBeAppCode: true},
		{Category: types.CategoryRemoteConfig, Pattern: `Lcom/google/firebase/remoteconfig/FirebaseRemoteConfig;->fetch(`, Priority: 6, Description: "Remote config fetch", MustBeAppCode: true},
		{Category: types.CategoryRemoteConfig, Pattern: `Lcom/google/firebase/remoteconfig/FirebaseRemoteConfig;->activate(`, Priority: 6, Description: "Remote config activate", MustBeAppCode: true},

		{Category: types.CategoryFeatureFlags, Pattern: `"feature_`, Priority: 6, Description: "Feature flag key"},
		{Category: types.CategoryFeatureFlags, Pattern: `"is_enabled"`, Priority: 6, Description: "Enabled flag key"},
		{Category: types.CategoryFeatureFlags, Pattern: `FeatureFlag`, Priority: 6, Description: "FeatureFlag class"},
		{Category: types.CategoryFeatureFlags, Pattern: `isFeatureEnabled`, Priority: 7, IsCritical: true, Description: "Feature enabled check"},
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// OBFUSCATION
// ═══════════════════════════════════════════════════════════════════════════════

func getObfuscationPatterns() []PatternDef {
	return []PatternDef{
		{Category: types.CategoryObfuscatedString, Pattern: `decryptString`, Priority: 5, Description: "String decryption"},
		{Category: types.CategoryObfuscatedString, Pattern: `deobfuscate`, Priority: 5, Description: "Deobfuscation call"},
		{Category: types.CategoryObfuscatedString, Pattern: `decode(`, Priority: 4, Description: "Decode call"},
		{Category: types.CategoryObfuscatedString, Pattern: `xor(`, Priority: 5, Description: "XOR operation"},

		{Category: types.CategoryEncryptedData, Pattern: `Ljavax/crypto/Cipher;`, Priority: 6, Description: "Cipher class usage"},
		{Category: types.CategoryEncryptedData, Pattern: `AES`, Priority: 5, Description: "AES encryption"},
		{Category: types.CategoryEncryptedData, Pattern: `SecretKeySpec`, Priority: 6, Description: "Secret key spec"},

		{Category: types.CategoryDynamicLoad, Pattern: `DexClassLoader`, Priority: 7, IsCritical: true, Description: "Dynamic DEX loading"},
		{Category: types.CategoryDynamicLoad, Pattern: `PathClassLoader`, Priority: 6, Description: "Path class loader"},
		{Category: types.CategoryDynamicLoad, Pattern: `InMemoryDexClassLoader`, Priority: 8, IsCritical: true, Description: "In-memory DEX loading"},
		{Category: types.CategoryDynamicLoad, Pattern: `dalvik.system.DexFile`, Priority: 7, IsCritical: true, Description: "DexFile access"},
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// NETWORK
// ═══════════════════════════════════════════════════════════════════════════════

func getNetworkPatterns() []PatternDef {
	return []PatternDef{
		{Category: types.CategoryAPIKey, Pattern: `"api_key"`, Priority: 6, Description: "API key string"},
		{Category: types.CategoryAPIKey, Pattern: `"apiKey"`, Priority: 6, Description: "API key camelCase"},
		{Category: types.CategoryAPIKey, Pattern: `"API_KEY"`, Priority: 6, Description: "API key constant"},
		{Category: types.CategoryAPIKey, Pattern: `"secret_key"`, Priority: 7, IsCritical: true, Description: "Secret key string"},
		{Category: types.CategoryAPIKey, Pattern: `"client_secret"`, Priority: 7, IsCritical: true, Description: "Client secret string"},

		{Category: types.CategoryServerCheck, Pattern: `verifyWithServer`, Priority: 7, IsCritical: true, Description: "Server verification call"},
		{Category: types.CategoryServerCheck, Pattern: `checkWithServer`, Priority: 7, IsCritical: true, Description: "Server check call"},
		{Category: types.CategoryServerCheck, Pattern: `validateOnServer`, Priority: 7, IsCritical: true, Description: "Server validation"},

		{Category: types.CategoryNetworkCall, Pattern: `Lokhttp3/OkHttpClient;`, Priority: 4, Description: "OkHttp client"},
		{Category: types.CategoryNetworkCall, Pattern: `Lretrofit2/Retrofit;`, Priority: 4, Description: "Retrofit client"},
		{Category: types.CategoryNetworkCall, Pattern: `Ljava/net/HttpURLConnection;`, Priority: 4, Description: "HttpURLConnection"},
	}
}
