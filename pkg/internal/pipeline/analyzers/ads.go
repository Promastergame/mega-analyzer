//go:build legacy_pipeline
// +build legacy_pipeline

// pkg/internal/pipeline/analyzers/ads.go
package analyzers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"mega-analyzer/pkg/internal/pipeline"
)

// ═══════════════════════════════════════════════════════════════════════════════
// ADS ANALYZER - Расширенный анализатор рекламы
// ═══════════════════════════════════════════════════════════════════════════════

// AdNetwork рекламная сеть
type AdNetwork struct {
	Name           string   `json:"name"`
	ID             string   `json:"id"`
	Type           string   `json:"type"`
	ClassPatterns  []string `json:"class_patterns"`
	MethodPatterns []string `json:"method_patterns"`
	StringPatterns []string `json:"string_patterns"`
	Confidence     float64
	Revenue        string `json:"revenue"`
}

// DefaultAdNetworks список рекламных сетей
var DefaultAdNetworks = []AdNetwork{
	{
		Name: "Google AdMob", ID: "admob", Type: "all",
		ClassPatterns: []string{
			"com/google/android/gms/ads/", "com/google/ads/",
			"Lcom/google/android/gms/ads/AdView",
			"Lcom/google/android/gms/ads/InterstitialAd",
			"Lcom/google/android/gms/ads/rewarded/RewardedAd",
		},
		MethodPatterns: []string{
			"loadAd", "show", "isLoaded", "setAdListener",
			"onAdLoaded", "onAdFailedToLoad", "onAdOpened",
			"onAdClosed", "onAdClicked", "onAdImpression",
		},
		StringPatterns: []string{"ca-app-pub-", "admob", "gads"},
		Confidence:     0.95, Revenue: "cpm",
	},
	{
		Name: "Facebook Audience Network", ID: "facebook", Type: "all",
		ClassPatterns: []string{
			"com/facebook/ads/", "Lcom/facebook/ads/AdView",
			"Lcom/facebook/ads/InterstitialAd", "Lcom/facebook/ads/RewardedVideoAd",
		},
		MethodPatterns: []string{
			"loadAd", "show", "isAdLoaded", "setAdListener",
			"buildLoadAdConfig", "loadAdFromBid",
		},
		StringPatterns: []string{"audience_network", "facebook_ads"},
		Confidence:     0.9, Revenue: "cpm",
	},
	{
		Name: "Unity Ads", ID: "unity", Type: "rewarded",
		ClassPatterns: []string{
			"com/unity3d/ads/", "com/unity3d/services/ads/",
			"Lcom/unity3d/ads/UnityAds", "Lcom/unity3d/ads/IUnityAdsListener",
		},
		MethodPatterns: []string{"show", "isReady", "initialize", "load", "addListener", "removeListener"},
		StringPatterns: []string{"unityads", "unity_ads"},
		Confidence:     0.9, Revenue: "cpm",
	},
	{
		Name: "IronSource", ID: "ironsource", Type: "all",
		ClassPatterns: []string{"com/ironsource/", "Lcom/ironsource/mediationsdk/IronSource"},
		MethodPatterns: []string{
			"showRewardedVideo", "loadInterstitial", "showInterstitial",
			"isRewardedVideoAvailable", "isInterstitialReady",
		},
		StringPatterns: []string{"ironsource", "supersonic"},
		Confidence:     0.85, Revenue: "cpm",
	},
	{
		Name: "AppLovin", ID: "applovin", Type: "all",
		ClassPatterns:  []string{"com/applovin/", "Lcom/applovin/sdk/AppLovinSdk", "Lcom/applovin/mediation/MaxAd"},
		MethodPatterns: []string{"showAd", "loadAd", "isAdReadyToDisplay", "loadNextAd", "showAdForPlacement"},
		StringPatterns: []string{"applovin", "max_ads"},
		Confidence:     0.85, Revenue: "cpm",
	},
	{
		Name: "Vungle", ID: "vungle", Type: "rewarded",
		ClassPatterns:  []string{"com/vungle/", "Lcom/vungle/warren/Vungle"},
		MethodPatterns: []string{"playAd", "loadAd", "isAdPlayable", "canPlayAd", "init"},
		StringPatterns: []string{"vungle"},
		Confidence:     0.85, Revenue: "cpm",
	},
	{
		Name: "AdColony", ID: "adcolony", Type: "rewarded",
		ClassPatterns:  []string{"com/adcolony/", "Lcom/adcolony/sdk/AdColony"},
		MethodPatterns: []string{"show", "requestInterstitial", "configure", "requestAdView", "isRequestPending"},
		StringPatterns: []string{"adcolony"},
		Confidence:     0.85, Revenue: "cpm",
	},
	{
		Name: "Chartboost", ID: "chartboost", Type: "interstitial",
		ClassPatterns: []string{"com/chartboost/", "Lcom/chartboost/sdk/Chartboost"},
		MethodPatterns: []string{
			"showInterstitial", "cacheInterstitial", "hasInterstitial",
			"showRewardedVideo", "hasRewardedVideo",
		},
		StringPatterns: []string{"chartboost"},
		Confidence:     0.85, Revenue: "cpm",
	},
	{
		Name: "MoPub", ID: "mopub", Type: "all",
		ClassPatterns:  []string{"com/mopub/", "Lcom/mopub/mobileads/MoPubView"},
		MethodPatterns: []string{"loadAd", "show", "isReady", "forceRefresh"},
		StringPatterns: []string{"mopub"},
		Confidence:     0.85, Revenue: "cpm",
	},
	{
		Name: "StartApp", ID: "startapp", Type: "interstitial",
		ClassPatterns:  []string{"com/startapp/", "Lcom/startapp/sdk/adsbase/StartAppAd"},
		MethodPatterns: []string{"showAd", "loadAd", "isReady"},
		StringPatterns: []string{"startapp", "startio"},
		Confidence:     0.8, Revenue: "cpm",
	},
	{
		Name: "InMobi", ID: "inmobi", Type: "all",
		ClassPatterns:  []string{"com/inmobi/", "Lcom/inmobi/ads/InMobiBanner", "Lcom/inmobi/ads/InMobiInterstitial"},
		MethodPatterns: []string{"load", "show", "isReady"},
		StringPatterns: []string{"inmobi"},
		Confidence:     0.8, Revenue: "cpm",
	},
	{
		Name: "Yandex Ads", ID: "yandex", Type: "all",
		ClassPatterns:  []string{"com/yandex/mobile/ads/", "Lcom/yandex/mobile/ads/banner/BannerAdView"},
		MethodPatterns: []string{"loadAd", "show", "isLoaded"},
		StringPatterns: []string{"yandex_mobile_ads"},
		Confidence:     0.85, Revenue: "cpm",
	},
	{
		Name: "Tapjoy", ID: "tapjoy", Type: "rewarded",
		ClassPatterns:  []string{"com/tapjoy/", "Lcom/tapjoy/TJPlacement"},
		MethodPatterns: []string{"showContent", "requestContent", "isContentReady"},
		StringPatterns: []string{"tapjoy"},
		Confidence:     0.8, Revenue: "cpi",
	},
	{
		Name: "Fyber/Digital Turbine", ID: "fyber", Type: "rewarded",
		ClassPatterns:  []string{"com/fyber/", "com/digitalturbine/"},
		MethodPatterns: []string{"show", "load", "isAvailable"},
		StringPatterns: []string{"fyber", "digital_turbine"},
		Confidence:     0.8, Revenue: "cpm",
	},
	{
		Name: "Pangle (TikTok)", ID: "pangle", Type: "all",
		ClassPatterns:  []string{"com/bytedance/sdk/openadsdk/", "Lcom/bytedance/sdk/openadsdk/TTAdNative"},
		MethodPatterns: []string{"loadAd", "showAd", "loadRewardVideoAd"},
		StringPatterns: []string{"pangle", "bytedance_ads"},
		Confidence:     0.85, Revenue: "cpm",
	},
}

// ═══════════════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════════════

// AdsAnalyzer анализатор рекламы
type AdsAnalyzer struct {
	networks []AdNetwork
}

// NewAdsAnalyzer создаёт новый анализатор
func NewAdsAnalyzer() *AdsAnalyzer {
	return &AdsAnalyzer{networks: DefaultAdNetworks}
}

// AdFinding находка рекламы
type AdFinding struct {
	Network     string
	NetworkID   string
	Type        string
	FilePath    string
	Line        int
	Method      string
	Pattern     string
	Confidence  float64
	Revenue     string
	Description string
}

// ═══════════════════════════════════════════════════════════════════════════════
// PRIVATE HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

func adsHashID(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:8])
}

func adsCalcScore(findings []pipeline.LegacyFinding) float64 {
	if len(findings) == 0 {
		return 0
	}
	total := 0.0
	for _, f := range findings {
		total += f.Confidence
	}
	score := total / float64(len(findings)) * 100
	if score > 100 {
		score = 100
	}
	return score
}

func adsCalcConfidence(findings []pipeline.LegacyFinding) float64 {
	if len(findings) == 0 {
		return 0
	}
	total := 0.0
	for _, f := range findings {
		total += f.Confidence
	}
	return total / float64(len(findings))
}

func adsDedup(findings []AdFinding) []AdFinding {
	seen := make(map[string]bool)
	out := make([]AdFinding, 0, len(findings))
	for _, f := range findings {
		key := f.NetworkID + "|" + f.FilePath + "|" + f.Pattern
		if !seen[key] {
			seen[key] = true
			out = append(out, f)
		}
	}
	return out
}

// ═══════════════════════════════════════════════════════════════════════════════
// ANALYZE — главный метод
// ═══════════════════════════════════════════════════════════════════════════════

func (a *AdsAnalyzer) Analyze(
	ctx context.Context,
	file *pipeline.FileData,
	parseResult *pipeline.ParseResult,
) (*pipeline.AnalysisResult, error) {

	result := &pipeline.AnalysisResult{
		File:        file,
		ParseResult: parseResult,
		Categories:  make(map[pipeline.Category]pipeline.CategoryResult),
	}

	var raw []AdFinding

	switch file.Type {
	case pipeline.FileTypeSmali:
		raw = a.analyzeSmali(file, parseResult)
	case pipeline.FileTypeXML:
		raw = a.analyzeXML(file)
	default:
		return result, nil
	}

	if len(raw) == 0 {
		return result, nil
	}

	pf := make([]pipeline.LegacyFinding, 0, len(raw))
	for _, f := range raw {
		pf = append(pf, pipeline.LegacyFinding{
			ID:          fmt.Sprintf("ads_%s_%s", f.NetworkID, adsHashID(f.FilePath+f.Pattern)),
			Title:       fmt.Sprintf("%s Advertisement", f.Network),
			Description: f.Description,
			Location: pipeline.Location{
				Path:       file.RelativePath,
				Line:       f.Line,
				MethodName: f.Method,
			},
			Severity:   pipeline.SeverityMedium,
			Category:   pipeline.CategoryAds,
			Confidence: f.Confidence,
		})
	}

	result.Categories[pipeline.CategoryAds] = pipeline.CategoryResult{
		Category:   pipeline.CategoryAds,
		Score:      adsCalcScore(pf),
		Confidence: adsCalcConfidence(pf),
		MatchCount: len(pf),
		Severity:   pipeline.SeverityMedium,
		Findings:   pf,
	}

	return result, nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// SMALI ANALYSIS
//
// ParseResult = parser.ParseResult, содержит:
//   Class *SmaliClass
//     .RawName, .Name string
//     .Methods []SmaliMethod
//       SmaliMethod has embedded SourceRange {Start SourceLocation, End SourceLocation}
//         SourceLocation.Line int
//       .Name string
//       .Invokes []Invoke
//         Invoke.SourceLocation.Line, .Class, .Method string
//       .StringConsts []StringConstant
//         StringConstant.SourceLocation.Line, .Value string
// ═══════════════════════════════════════════════════════════════════════════════

func (a *AdsAnalyzer) analyzeSmali(file *pipeline.FileData, pr *pipeline.ParseResult) []AdFinding {
	var findings []AdFinding

	// --- Structured analysis via ParseResult ---
	if pr != nil && pr.Class != nil {
		cls := pr.Class

		className := cls.RawName
		if className == "" {
			className = cls.Name
		}

		for _, net := range a.networks {
			// Check class name against patterns
			for _, pat := range net.ClassPatterns {
				if strings.Contains(className, pat) {
					findings = append(findings, AdFinding{
						Network: net.Name, NetworkID: net.ID, Type: net.Type,
						FilePath: file.RelativePath, Pattern: pat,
						Confidence: net.Confidence, Revenue: net.Revenue,
						Description: fmt.Sprintf("%s SDK class: %s", net.Name, className),
					})
				}
			}

			// Check each method
			for mi := range cls.Methods {
				m := &cls.Methods[mi]

				// Method name match
				for _, pat := range net.MethodPatterns {
					if strings.EqualFold(m.Name, pat) {
						findings = append(findings, AdFinding{
							Network: net.Name, NetworkID: net.ID, Type: net.Type,
							FilePath:   file.RelativePath,
							Line:       m.Start.Line, // embedded SourceRange → Start.Line
							Method:     m.Name,
							Pattern:    pat,
							Confidence: net.Confidence * 0.9, Revenue: net.Revenue,
							Description: fmt.Sprintf("%s method: %s", net.Name, m.Name),
						})
					}
				}

				// Invokes inside method body
				for ii := range m.Invokes {
					inv := &m.Invokes[ii]
					ref := inv.Class + "->" + inv.Method
					for _, pat := range net.ClassPatterns {
						if strings.Contains(ref, pat) {
							findings = append(findings, AdFinding{
								Network: net.Name, NetworkID: net.ID, Type: net.Type,
								FilePath:   file.RelativePath,
								Line:       inv.SourceLocation.Line,
								Method:     m.Name,
								Pattern:    pat,
								Confidence: net.Confidence, Revenue: net.Revenue,
								Description: fmt.Sprintf("%s invoke: %s", net.Name, ref),
							})
						}
					}
				}

				// String constants
				for si := range m.StringConsts {
					sc := &m.StringConsts[si]
					for _, pat := range net.StringPatterns {
						if strings.Contains(strings.ToLower(sc.Value), strings.ToLower(pat)) {
							findings = append(findings, AdFinding{
								Network: net.Name, NetworkID: net.ID, Type: net.Type,
								FilePath:   file.RelativePath,
								Line:       sc.SourceLocation.Line,
								Method:     m.Name,
								Pattern:    pat,
								Confidence: net.Confidence * 0.8, Revenue: net.Revenue,
								Description: fmt.Sprintf("%s const-string: %q", net.Name, sc.Value),
							})
						}
					}
				}
			}
		}
	}

	// --- Fallback: raw content scan ---
	if len(findings) == 0 {
		findings = a.scanRawContent(file)
	}

	return adsDedup(findings)
}

// scanRawContent — поиск по тексту файла когда ParseResult недоступен
func (a *AdsAnalyzer) scanRawContent(file *pipeline.FileData) []AdFinding {
	content, err := file.Content()
	if err != nil {
		return nil
	}

	contentStr := string(content)
	lines := strings.Split(contentStr, "\n")
	var findings []AdFinding

	for _, net := range a.networks {
		for _, pat := range net.ClassPatterns {
			for i, line := range lines {
				if strings.Contains(line, pat) {
					findings = append(findings, AdFinding{
						Network: net.Name, NetworkID: net.ID, Type: net.Type,
						FilePath: file.RelativePath, Line: i + 1,
						Pattern: pat, Confidence: net.Confidence, Revenue: net.Revenue,
						Description: fmt.Sprintf("%s SDK reference", net.Name),
					})
					break
				}
			}
		}

		for _, pat := range net.StringPatterns {
			if strings.Contains(strings.ToLower(contentStr), strings.ToLower(pat)) {
				findings = append(findings, AdFinding{
					Network: net.Name, NetworkID: net.ID, Type: net.Type,
					FilePath: file.RelativePath, Pattern: pat,
					Confidence: net.Confidence * 0.7, Revenue: net.Revenue,
					Description: fmt.Sprintf("%s string: %q", net.Name, pat),
				})
			}
		}
	}

	return findings
}

// ═══════════════════════════════════════════════════════════════════════════════
// XML ANALYSIS
// ═══════════════════════════════════════════════════════════════════════════════

func (a *AdsAnalyzer) analyzeXML(file *pipeline.FileData) []AdFinding {
	content, err := file.Content()
	if err != nil {
		return nil
	}

	contentStr := string(content)
	var findings []AdFinding

	xmlPatterns := map[string]string{
		"com.google.android.gms.ads.AdView":         "admob",
		"com.facebook.ads.AdView":                   "facebook",
		"com.mopub.mobileads.MoPubView":             "mopub",
		"com.startapp.sdk.ads.banner.Banner":        "startapp",
		"com.applovin.adview.AppLovinAdView":        "applovin",
		"com.inmobi.ads.InMobiBanner":               "inmobi",
		"com.yandex.mobile.ads.banner.BannerAdView": "yandex",
	}

	for pat, netID := range xmlPatterns {
		if strings.Contains(contentStr, pat) {
			net := a.findNetwork(netID)
			if net != nil {
				findings = append(findings, AdFinding{
					Network: net.Name, NetworkID: net.ID, Type: "banner",
					FilePath: file.RelativePath, Pattern: pat,
					Confidence: 0.95, Revenue: net.Revenue,
					Description: fmt.Sprintf("%s banner in layout", net.Name),
				})
			}
		}
	}

	return findings
}

// ═══════════════════════════════════════════════════════════════════════════════
// UTILS
// ═══════════════════════════════════════════════════════════════════════════════

func (a *AdsAnalyzer) findNetwork(id string) *AdNetwork {
	for i := range a.networks {
		if a.networks[i].ID == id {
			return &a.networks[i]
		}
	}
	return nil
}

// Name возвращает имя анализатора
func (a *AdsAnalyzer) Name() string { return "AdsAnalyzer" }

// Phase возвращает фазу анализа
func (a *AdsAnalyzer) Phase() pipeline.AnalysisPhase { return pipeline.PhaseQuickScan }
