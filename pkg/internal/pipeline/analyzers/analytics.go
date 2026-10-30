//go:build legacy_pipeline
// +build legacy_pipeline

// pkg/internal/pipeline/analyzers/analytics.go
package analyzers

import (
	"context"
	"fmt"
	"strings"

	"mega-analyzer/pkg/internal/pipeline"
)

// ═══════════════════════════════════════════════════════════════════════════════
// ANALYTICS ANALYZER
// ═══════════════════════════════════════════════════════════════════════════════

// AnalyticsProvider провайдер аналитики
type AnalyticsProvider struct {
	Name           string
	ID             string
	ClassPatterns  []string
	MethodPatterns []string
	EventPatterns  []string
	Confidence     float64
	Privacy        string // low, medium, high (privacy concern level)
}

// DefaultAnalyticsProviders список провайдеров аналитики
var DefaultAnalyticsProviders = []AnalyticsProvider{
	{
		Name: "Google Analytics / Firebase",
		ID:   "firebase",
		ClassPatterns: []string{
			"com/google/firebase/analytics/",
			"com/google/android/gms/analytics/",
			"Lcom/google/firebase/analytics/FirebaseAnalytics",
		},
		MethodPatterns: []string{
			"logEvent", "setUserProperty", "setUserId",
			"setCurrentScreen", "setAnalyticsCollectionEnabled",
		},
		EventPatterns: []string{
			"screen_view", "user_engagement", "app_open",
		},
		Confidence: 0.95,
		Privacy:    "high",
	},
	{
		Name: "Facebook Analytics",
		ID:   "facebook_analytics",
		ClassPatterns: []string{
			"com/facebook/appevents/",
			"Lcom/facebook/appevents/AppEventsLogger",
		},
		MethodPatterns: []string{
			"logEvent", "logPurchase", "setUserID",
			"activateApp", "deactivateApp",
		},
		Confidence: 0.9,
		Privacy:    "high",
	},
	{
		Name: "Amplitude",
		ID:   "amplitude",
		ClassPatterns: []string{
			"com/amplitude/",
			"Lcom/amplitude/api/Amplitude",
		},
		MethodPatterns: []string{
			"logEvent", "setUserId", "setUserProperties",
			"uploadEvents", "initialize",
		},
		Confidence: 0.9,
		Privacy:    "medium",
	},
	{
		Name: "Mixpanel",
		ID:   "mixpanel",
		ClassPatterns: []string{
			"com/mixpanel/",
			"Lcom/mixpanel/android/mpmetrics/MixpanelAPI",
		},
		MethodPatterns: []string{
			"track", "identify", "getPeople",
			"timeEvent", "flush",
		},
		Confidence: 0.9,
		Privacy:    "medium",
	},
	{
		Name: "Flurry",
		ID:   "flurry",
		ClassPatterns: []string{
			"com/flurry/",
			"Lcom/flurry/android/FlurryAgent",
		},
		MethodPatterns: []string{
			"logEvent", "setUserId", "onStartSession",
			"onEndSession", "setVersionName",
		},
		Confidence: 0.85,
		Privacy:    "medium",
	},
	{
		Name: "AppsFlyer",
		ID:   "appsflyer",
		ClassPatterns: []string{
			"com/appsflyer/",
			"Lcom/appsflyer/AppsFlyerLib",
		},
		MethodPatterns: []string{
			"trackEvent", "setCustomerUserId", "start",
			"logEvent", "sendPushNotificationData",
		},
		Confidence: 0.9,
		Privacy:    "high",
	},
	{
		Name: "Adjust",
		ID:   "adjust",
		ClassPatterns: []string{
			"com/adjust/",
			"Lcom/adjust/sdk/Adjust",
		},
		MethodPatterns: []string{
			"trackEvent", "onCreate", "onResume",
			"addSessionCallbackParameter", "setEnabled",
		},
		Confidence: 0.9,
		Privacy:    "high",
	},
	{
		Name: "Branch.io",
		ID:   "branch",
		ClassPatterns: []string{
			"io/branch/",
			"Lio/branch/referral/Branch",
		},
		MethodPatterns: []string{
			"initSession", "trackEvent", "setIdentity",
			"getShortUrl", "logout",
		},
		Confidence: 0.85,
		Privacy:    "medium",
	},
	{
		Name: "Crashlytics",
		ID:   "crashlytics",
		ClassPatterns: []string{
			"com/crashlytics/",
			"com/google/firebase/crashlytics/",
			"Lcom/crashlytics/android/Crashlytics",
		},
		MethodPatterns: []string{
			"log", "logException", "setUserIdentifier",
			"recordException", "setCustomKey",
		},
		Confidence: 0.9,
		Privacy:    "low",
	},
	{
		Name: "Sentry",
		ID:   "sentry",
		ClassPatterns: []string{
			"io/sentry/",
			"Lio/sentry/Sentry",
		},
		MethodPatterns: []string{
			"captureException", "captureMessage", "setUser",
			"addBreadcrumb", "setTag",
		},
		Confidence: 0.85,
		Privacy:    "low",
	},
	{
		Name: "Yandex AppMetrica",
		ID:   "appmetrica",
		ClassPatterns: []string{
			"com/yandex/metrica/",
			"Lcom/yandex/metrica/YandexMetrica",
		},
		MethodPatterns: []string{
			"reportEvent", "setUserProfileID", "activate",
			"reportError", "reportRevenue",
		},
		Confidence: 0.85,
		Privacy:    "high",
	},
	{
		Name: "Countly",
		ID:   "countly",
		ClassPatterns: []string{
			"ly/count/",
			"Lly/count/android/sdk/Countly",
		},
		MethodPatterns: []string{
			"recordEvent", "setUserData", "init",
			"changeDeviceId", "setLoggingEnabled",
		},
		Confidence: 0.8,
		Privacy:    "medium",
	},
	{
		Name: "Segment",
		ID:   "segment",
		ClassPatterns: []string{
			"com/segment/",
			"Lcom/segment/analytics/Analytics",
		},
		MethodPatterns: []string{
			"track", "identify", "screen",
			"group", "flush",
		},
		Confidence: 0.85,
		Privacy:    "medium",
	},
}

// AnalyticsAnalyzer анализатор аналитики
type AnalyticsAnalyzer struct {
	providers []AnalyticsProvider
}

// NewAnalyticsAnalyzer создаёт новый анализатор
func NewAnalyticsAnalyzer() *AnalyticsAnalyzer {
	return &AnalyticsAnalyzer{
		providers: DefaultAnalyticsProviders,
	}
}

// Analyze анализирует файл
func (a *AnalyticsAnalyzer) Analyze(ctx context.Context, file *pipeline.FileData, parseResult *pipeline.ParseResult) (*pipeline.AnalysisResult, error) {
	result := &pipeline.AnalysisResult{
		File:        file,
		ParseResult: parseResult,
		Categories:  make(map[pipeline.Category]pipeline.CategoryResult),
	}

	findings := make([]pipeline.LegacyFinding, 0)

	if parseResult == nil {
		return result, nil
	}

	// Check class name
	className := ""
	if parseResult.Class != nil {
		className = parseResult.Class.RawName
		if className == "" {
			className = parseResult.Class.Name
		}
	}

	for _, provider := range a.providers {
		// Check class patterns
		for _, pattern := range provider.ClassPatterns {
			if strings.Contains(className, pattern) {
				findings = append(findings, pipeline.LegacyFinding{
					ID:          fmt.Sprintf("analytics_%s_%s", provider.ID, hashString(file.RelativePath)),
					Title:       fmt.Sprintf("%s Analytics", provider.Name),
					Description: fmt.Sprintf("%s SDK detected (Privacy concern: %s)", provider.Name, provider.Privacy),
					Location: pipeline.Location{
						Path:      file.RelativePath,
						ClassName: className,
					},
					Severity:   getSeverityByPrivacy(provider.Privacy),
					Category:   pipeline.CategoryAnalytics,
					Confidence: provider.Confidence,
				})
			}
		}

		// Check methods
		if parseResult.Class != nil && len(parseResult.Class.Methods) > 0 {
			for _, method := range parseResult.Class.Methods {
				for _, pattern := range provider.MethodPatterns {
					if strings.EqualFold(method.Name, pattern) {
						findings = append(findings, pipeline.LegacyFinding{
							ID:          fmt.Sprintf("analytics_%s_%s_%s", provider.ID, method.Name, hashString(file.RelativePath)),
							Title:       fmt.Sprintf("%s Tracking", provider.Name),
							Description: fmt.Sprintf("Analytics method: %s", method.Name),
							Location: pipeline.Location{
								Path:       file.RelativePath,
								MethodName: method.Name,
							},
							Severity:   getSeverityByPrivacy(provider.Privacy),
							Category:   pipeline.CategoryAnalytics,
							Confidence: provider.Confidence * 0.8,
						})
					}
				}
			}
		}
	}

	if len(findings) > 0 {
		result.Categories[pipeline.CategoryAnalytics] = pipeline.CategoryResult{
			Category:   pipeline.CategoryAnalytics,
			Score:      calculateCategoryScore(findings),
			Confidence: calculateAverageConfidence(findings),
			MatchCount: len(findings),
			Severity:   getMaxSeverity(findings),
			Findings:   deduplicateFindings(findings),
		}
	}

	return result, nil
}

// getSeverityByPrivacy возвращает severity по уровню privacy concern
func getSeverityByPrivacy(privacy string) pipeline.Severity {
	switch privacy {
	case "high":
		return pipeline.SeverityMedium
	case "medium":
		return pipeline.SeverityLow
	default:
		return pipeline.SeverityInfo
	}
}

func (a *AnalyticsAnalyzer) Name() string                  { return "AnalyticsAnalyzer" }
func (a *AnalyticsAnalyzer) Phase() pipeline.AnalysisPhase { return pipeline.PhaseQuickScan }
