package ml

import "strings"

// SDKOwnership describes who owns the matched class. SDK internals are useful
// for audit, but must not become automatic application patch targets.
type SDKOwnership string

const (
	SDKOwnershipUnknown SDKOwnership = "unknown"
	SDKOwnershipLibrary SDKOwnership = "sdk_library"
	SDKOwnershipApp     SDKOwnership = "app_code"
	SDKOwnershipWrapper SDKOwnership = "app_wrapper"
)

type SDKVersion struct {
	ID      string   `json:"id"`
	MinAPI  int      `json:"min_api,omitempty"`
	MaxAPI  int      `json:"max_api,omitempty"`
	Signals []string `json:"signals,omitempty"`
}

// SDKDescriptor is the normalized registry entry for SDK families. Existing
// per-SDK pattern files remain the source of patterns; this registry adds a
// common inventory and ownership contract around them.
type SDKDescriptor struct {
	ID              string       `json:"id"`
	DisplayName     string       `json:"display_name"`
	Family          string       `json:"family"`
	PackagePrefixes []string     `json:"package_prefixes"`
	Versions        []SDKVersion `json:"versions,omitempty"`
}

type SDKMatch struct {
	SDK            SDKDescriptor    `json:"sdk"`
	Version        string           `json:"version,omitempty"`
	Confidence     float64          `json:"confidence"`
	Ownership      SDKOwnership     `json:"ownership"`
	Evidence       []string         `json:"evidence,omitempty"`
	Dependency     ServerDependency `json:"dependency"`
	NativeSignals  []string         `json:"native_signals,omitempty"`
	WrapperMethods []string         `json:"wrapper_methods,omitempty"`
}

var sdkRegistry = []SDKDescriptor{
	{ID: "admob", DisplayName: "Google AdMob", Family: "ads", PackagePrefixes: []string{"com/google/android/gms/ads", "com/google/ads"}},
	{ID: "unity_ads", DisplayName: "Unity Ads", Family: "ads", PackagePrefixes: []string{"com/unity3d/ads", "com/unity3d/services"}},
	{ID: "ironsource", DisplayName: "IronSource", Family: "ads", PackagePrefixes: []string{"com/ironsource", "com/ironsource/mediationsdk"}},
	{ID: "applovin", DisplayName: "AppLovin MAX", Family: "ads", PackagePrefixes: []string{"com/applovin"}},
	{ID: "facebook_audience", DisplayName: "Facebook Audience Network", Family: "ads", PackagePrefixes: []string{"com/facebook/ads"}},
	{ID: "vungle", DisplayName: "Vungle", Family: "ads", PackagePrefixes: []string{"com/vungle"}},
	{ID: "adcolony", DisplayName: "AdColony", Family: "ads", PackagePrefixes: []string{"com/adcolony"}},
	{ID: "superawesome", DisplayName: "SuperAwesome", Family: "ads", PackagePrefixes: []string{"tv/superawesome"}},
	{ID: "kpadplayer", DisplayName: "KPAdPlayer (Kidoz)", Family: "ads", PackagePrefixes: []string{"com/kpadplayer", "com/kidoz"}},
	{ID: "play_billing", DisplayName: "Google Play Billing", Family: "billing", PackagePrefixes: []string{"com/android/billingclient"}, Versions: []SDKVersion{{ID: "v7+", Signals: []string{"queryproductdetailsasync", "isexternalofferavailable"}}, {ID: "v6", Signals: []string{"queryproductdetailsasync", "productdetails"}}, {ID: "v5", Signals: []string{"sku", "querysku"}}}},
}

func SDKRegistry() []SDKDescriptor {
	return append([]SDKDescriptor(nil), sdkRegistry...)
}

// DetectSDKInventory reports confidence and ownership for every registered
// SDK. It intentionally scans class paths and method calls instead of relying
// only on a package-name boolean.
func DetectSDKInventory(classInfo *ClassInfo) []SDKMatch {
	if classInfo == nil {
		return nil
	}
	classText := strings.ToLower(classInfo.ClassName + "\n" + classInfo.FilePath)
	for _, method := range classInfo.Methods {
		classText += "\n" + strings.ToLower(method.ClassName+" "+method.FullSignature)
		for _, call := range method.Calls {
			classText += "\n" + strings.ToLower(call.FullCall)
		}
	}
	results := make([]SDKMatch, 0, len(sdkRegistry))
	for _, descriptor := range sdkRegistry {
		var evidence []string
		for _, prefix := range descriptor.PackagePrefixes {
			if strings.Contains(classText, strings.ToLower(prefix)) {
				evidence = append(evidence, "package:"+prefix)
			}
		}
		if len(evidence) == 0 {
			continue
		}
		match := SDKMatch{SDK: descriptor, Confidence: 0.65, Ownership: SDKOwnershipLibrary, Evidence: evidence}
		match.Dependency = ServerDependencyUnknown
		match.Version = inferSDKVersion(descriptor, classText)
		// A class outside a known SDK namespace is an app wrapper candidate. It
		// is still review-only until a concrete call/data-flow is available.
		if !isSDKOwnedReference(classInfo.ClassName) && !isSDKOwnedReference(classInfo.FilePath) {
			match.Ownership = SDKOwnershipWrapper
			match.Confidence += 0.1
		}
		for _, method := range classInfo.Methods {
			if !isSDKOwnedReference(method.ClassName) && len(method.Calls) > 0 {
				match.WrapperMethods = append(match.WrapperMethods, method.Name)
			}
			for _, call := range method.Calls {
				callText := strings.ToLower(call.FullCall)
				if strings.Contains(callText, "jni") || strings.Contains(callText, "native") {
					match.NativeSignals = append(match.NativeSignals, call.FullCall)
				}
			}
		}
		if len(evidence) > 1 {
			match.Confidence += 0.1
		}
		if match.Confidence > 1 {
			match.Confidence = 1
		}
		results = append(results, match)
	}
	return results
}

func inferSDKVersion(descriptor SDKDescriptor, text string) string {
	for _, version := range descriptor.Versions {
		for _, signal := range version.Signals {
			if strings.Contains(text, strings.ToLower(signal)) {
				return version.ID
			}
		}
	}
	return "unknown"
}

func isSDKOwnedReference(value string) bool {
	value = strings.ToLower(strings.ReplaceAll(value, "\\", "/"))
	for _, descriptor := range sdkRegistry {
		for _, prefix := range descriptor.PackagePrefixes {
			if strings.Contains(value, strings.ToLower(prefix)) {
				return true
			}
		}
	}
	return false
}
