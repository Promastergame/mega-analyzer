// pkg/internal/pipeline/providers.go
// Все провайдеры/сети вынесены из pipeline.go — данные отдельно от логики.
package pipeline

import (
	"strings"

	"mega-analyzer/pkg/internal/types"
)

// ═══════════════════════════════════════════════════════════════════════════════
// AD NETWORKS
// ═══════════════════════════════════════════════════════════════════════════════

type AdNetwork struct {
	Name           string
	ID             string
	Type           string
	ClassPatterns  []string
	StringPatterns []string
	Confidence     float64

	classPatternsBytes  [][]byte
	stringPatternsLower [][]byte
}

func (a *AdNetwork) Compile() {
	if len(a.classPatternsBytes) > 0 {
		return
	}
	a.classPatternsBytes = toBytes(a.ClassPatterns)
	a.stringPatternsLower = toBytesLower(a.StringPatterns)
}

var DefaultAdNetworks = []AdNetwork{
	{Name: "Google AdMob", ID: "admob", ClassPatterns: []string{"com/google/android/gms/ads/", "com/google/ads/"}, StringPatterns: []string{"ca-app-pub-", "admob"}, Confidence: 0.95},
	{Name: "Facebook Audience Network", ID: "facebook", ClassPatterns: []string{"com/facebook/ads/"}, StringPatterns: []string{"audience_network"}, Confidence: 0.9},
	{Name: "Unity Ads", ID: "unity", ClassPatterns: []string{"com/unity3d/ads/", "com/unity3d/services/ads/"}, StringPatterns: []string{"unityads"}, Confidence: 0.9},
	{Name: "IronSource", ID: "ironsource", ClassPatterns: []string{"com/ironsource/"}, StringPatterns: []string{"ironsource"}, Confidence: 0.85},
	{Name: "AppLovin", ID: "applovin", ClassPatterns: []string{"com/applovin/"}, StringPatterns: []string{"applovin"}, Confidence: 0.85},
	{Name: "Vungle", ID: "vungle", ClassPatterns: []string{"com/vungle/"}, StringPatterns: []string{"vungle"}, Confidence: 0.85},
	{Name: "AdColony", ID: "adcolony", ClassPatterns: []string{"com/adcolony/"}, StringPatterns: []string{"adcolony"}, Confidence: 0.85},
	{Name: "Chartboost", ID: "chartboost", ClassPatterns: []string{"com/chartboost/"}, StringPatterns: []string{"chartboost"}, Confidence: 0.85},
	{Name: "Yandex Ads", ID: "yandex", ClassPatterns: []string{"com/yandex/mobile/ads/"}, StringPatterns: []string{"yandex_mobile_ads"}, Confidence: 0.85},
	{Name: "Pangle (TikTok)", ID: "pangle", ClassPatterns: []string{"com/bytedance/sdk/openadsdk/"}, StringPatterns: []string{"pangle"}, Confidence: 0.85},
}

// ═══════════════════════════════════════════════════════════════════════════════
// ANALYTICS PROVIDERS
// ═══════════════════════════════════════════════════════════════════════════════

type AnalyticsProvider struct {
	Name          string
	ID            string
	ClassPatterns []string
	Confidence    float64
	Privacy       string
	// CrashReporting marks providers that are crash/error monitoring tools
	// (Sentry, Crashlytics, …) rather than user-tracking analytics. They are
	// categorised as Crash Reporting (low severity) instead of Analytics so
	// they don't inflate the privacy-tracker count. See plan §1.3.
	CrashReporting bool

	classPatternsBytes [][]byte
}

// Category returns the finding category for this provider — Crash Reporting
// for monitoring SDKs, Analytics otherwise.
func (a *AnalyticsProvider) Category() types.Category {
	if a.CrashReporting {
		return types.CategoryCrashReporting
	}
	return types.CategoryAnalytics
}

func (a *AnalyticsProvider) Compile() {
	if len(a.classPatternsBytes) > 0 {
		return
	}
	a.classPatternsBytes = toBytes(a.ClassPatterns)
}

var DefaultAnalyticsProviders = []AnalyticsProvider{
	{Name: "Firebase Analytics", ID: "firebase", ClassPatterns: []string{"com/google/firebase/analytics/"}, Confidence: 0.95, Privacy: "high"},
	{Name: "Facebook Analytics", ID: "facebook_analytics", ClassPatterns: []string{"com/facebook/appevents/"}, Confidence: 0.9, Privacy: "high"},
	{Name: "Amplitude", ID: "amplitude", ClassPatterns: []string{"com/amplitude/"}, Confidence: 0.9, Privacy: "medium"},
	{Name: "Mixpanel", ID: "mixpanel", ClassPatterns: []string{"com/mixpanel/"}, Confidence: 0.9, Privacy: "medium"},
	{Name: "AppsFlyer", ID: "appsflyer", ClassPatterns: []string{"com/appsflyer/"}, Confidence: 0.9, Privacy: "high"},
	{Name: "Adjust", ID: "adjust", ClassPatterns: []string{"com/adjust/"}, Confidence: 0.9, Privacy: "high"},
	{Name: "Crashlytics", ID: "crashlytics", ClassPatterns: []string{"com/crashlytics/", "com/google/firebase/crashlytics/"}, Confidence: 0.9, Privacy: "low", CrashReporting: true},
	{Name: "Sentry", ID: "sentry", ClassPatterns: []string{"io/sentry/"}, Confidence: 0.85, Privacy: "low", CrashReporting: true},
	{Name: "Bugsnag", ID: "bugsnag", ClassPatterns: []string{"com/bugsnag/"}, Confidence: 0.85, Privacy: "low", CrashReporting: true},
	{Name: "New Relic", ID: "newrelic", ClassPatterns: []string{"com/newrelic/"}, Confidence: 0.85, Privacy: "low", CrashReporting: true},
	{Name: "Datadog", ID: "datadog", ClassPatterns: []string{"com/datadog/"}, Confidence: 0.85, Privacy: "low", CrashReporting: true},
	{Name: "AppMetrica", ID: "appmetrica", ClassPatterns: []string{"com/yandex/metrica/"}, Confidence: 0.85, Privacy: "high"},
}

// ═══════════════════════════════════════════════════════════════════════════════
// DONATION PROVIDERS
// ═══════════════════════════════════════════════════════════════════════════════

type DonationProvider struct {
	Name       string
	ID         string
	Patterns   []string
	Confidence float64

	patternsBytes [][]byte
}

func (d *DonationProvider) Compile() {
	if len(d.patternsBytes) > 0 {
		return
	}
	d.patternsBytes = toBytes(d.Patterns)
}

var DefaultDonationProviders = []DonationProvider{
	{Name: "Google Play Billing", ID: "google", Patterns: []string{"com/android/vending/billing/", "com/android/billingclient/"}, Confidence: 0.95},
	{Name: "PayPal", ID: "paypal", Patterns: []string{"com/paypal/"}, Confidence: 0.9},
	{Name: "Stripe", ID: "stripe", Patterns: []string{"com/stripe/"}, Confidence: 0.9},
	{Name: "Patreon", ID: "patreon", Patterns: []string{"patreon"}, Confidence: 0.8},
	{Name: "Ko-fi", ID: "kofi", Patterns: []string{"ko-fi", "kofi"}, Confidence: 0.8},
	{Name: "Buy Me A Coffee", ID: "buymeacoffee", Patterns: []string{"buymeacoffee"}, Confidence: 0.8},
	{Name: "Boosty", ID: "boosty", Patterns: []string{"boosty"}, Confidence: 0.8},
}

// ═══════════════════════════════════════════════════════════════════════════════
// SUBSCRIPTION PATTERNS
// ═══════════════════════════════════════════════════════════════════════════════

type SubscriptionPattern struct {
	Name     string
	Type     string
	Patterns []string
	Methods  []string

	patternsLower [][]byte
	methodsLower  [][]byte
}

func (s *SubscriptionPattern) Compile() {
	if len(s.patternsLower) > 0 {
		return
	}
	s.patternsLower = toBytesLower(s.Patterns)
	s.methodsLower = toBytesLower(s.Methods)
}

var DefaultSubscriptionPatterns = []SubscriptionPattern{
	{Name: "Google Play Subscription", Type: "google_play", Patterns: []string{"SkuType.SUBS", "BillingClient.SkuType.SUBS", "subscription"}, Methods: []string{"querySubscriptions", "isSubscribed", "checkSubscription"}},
	{Name: "Premium Subscription", Type: "premium", Patterns: []string{"isPremium", "hasPremium", "premiumUser"}, Methods: []string{"isPremiumUser", "checkPremium", "getPremiumStatus"}},
	{Name: "Trial Period", Type: "trial", Patterns: []string{"trial", "trialPeriod", "trialDays"}, Methods: []string{"isTrialActive", "getTrialDaysLeft", "startTrial"}},
	{Name: "Recurring Payment", Type: "recurring", Patterns: []string{"recurring", "autoRenew", "renewSubscription"}, Methods: []string{"isAutoRenewEnabled", "getNextBillingDate"}},
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

func toBytes(ss []string) [][]byte {
	result := make([][]byte, len(ss))
	for i, s := range ss {
		result[i] = []byte(s)
	}
	return result
}

func toBytesLower(ss []string) [][]byte {
	result := make([][]byte, len(ss))
	for i, s := range ss {
		result[i] = []byte(strings.ToLower(s))
	}
	return result
}
