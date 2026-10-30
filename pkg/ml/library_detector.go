package ml

import (
	"path"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// LIBRARY DETECTOR — PHASE 5 MEGA UPGRADE
//
// Расширенная база известных библиотек (70+ записей).
// Дополняет IsLibraryPath() для более точной классификации.
// Используется для "deprioritize" библиотечных findings, а не полного скрытия.
//
// 🔥 PHASE 5 изменения:
//   • +25 новых библиотечных путей (Sentry, AppsFlyer, Adjust, Kochava, etc.)
//   • Отдельный targetSDKPrefixes — SDK которые НУЖНО сканировать (billing, licensing)
//   • Улучшенная логика LibraryName() — более точные имена
// ═══════════════════════════════════════════════════════════════════════════════

// knownLibraryPrefixes — известные префиксы библиотек/SDK,
// которые НЕ должны попадать в HIGH RISK как user code
//
// ВАЖНО: сюда НЕ включаем Google Play Billing/Licensing — это целевой код для патчинга!
var knownLibraryPrefixes = []string{
	// ═══════════════════════════════════════════════════════════════════
	// CRYPTO (PRIORITY — самый частый шум!)
	// ═══════════════════════════════════════════════════════════════════
	"org/spongycastle/", "org/bouncycastle/",
	"org/jose4j/",
	"org/simpleframework/",
	"com/nimbusds/jose/", "com/nimbusds/jwt/",
	"org/conscrypt/",

	// ═══════════════════════════════════════════════════════════════════
	// MICROSOFT
	// ═══════════════════════════════════════════════════════════════════
	"com/microsoft/xbox/", "com/microsoft/xal/",
	"com/microsoft/identity/", "com/microsoft/appcenter/",
	"com/microsoft/aad/",

	// ═══════════════════════════════════════════════════════════════════
	// ANALYTICS / MARKETING / ATTRIBUTION
	// ═══════════════════════════════════════════════════════════════════
	"com/braze/", "bo/app/",
	"com/google/firebase/", "com/google/analytics/",
	"com/google/android/gms/",
	"com/appsflyer/", "com/adjust/sdk/",
	"com/amplitude/", "com/mixpanel/",
	"com/segment/analytics/",
	"com/kochava/", "com/singular/sdk/",
	"com/clevertap/", "com/moengage/",
	"com/onesignal/", "com/pushwoosh/",
	"com/tenjin/", "com/branch/",

	// ═══════════════════════════════════════════════════════════════════
	// ERROR REPORTING / MONITORING
	// ═══════════════════════════════════════════════════════════════════
	"io/sentry/", "com/bugsnag/",
	"com/newrelic/", "com/datadog/",
	"com/instabug/", "com/embrace/",

	// ═══════════════════════════════════════════════════════════════════
	// AD NETWORKS (шум — мы сканируем SDK отдельно через ad SDK patterns)
	// ═══════════════════════════════════════════════════════════════════
	"com/google/android/gms/ads/",
	"com/facebook/ads/", "com/facebook/audiencenetwork/",
	"com/applovin/", "com/applovin/mediation/",
	"com/vungle/", "com/adcolony/",
	"com/chartboost/", "com/inmobi/",
	"com/mopub/", "com/tapjoy/",
	"com/ironsource/", "com/ironsource/mediationsdk/",
	// Older SDK namespaces still shipped by games, including shaded dependencies.
	"com/millennialmedia/", "com/applifier/", "com/supersonicads/",
	"com/adsdk/", "com/jumptap/", "com/bda/",
	"com/madvertise/", "de/madvertise/",
	"com/startapp/", "com/fyber/",
	"com/ogury/", "com/pangle/",
	"com/pgl/",            // Pangle SDK internals
	"com/apm/",            // ByteDance APM Insight (performance/analytics)
	"com/safedk/",         // SafeDK ad-fraud SDK
	"com/bykv/",           // VK attribution SDK
	"com/bytedance/sdk/",
	"com/bytedance/",      // all TikTok/Pangle SDK trees (events, pcc, embed)
	"com/tiktok/",         // TikTok event/attribution SDK
	"com/mbridge/",        // Mintegral (incl. its bundled exoplayer copy)
	"com/iab/",            // OMID wrappers (vungle/ironsource/unity3d under omid/)
	"com/digitalturbine/", // Ignite
	"tv/superawesome/",  // SuperAwesome kids-safe ads (Epic Games)
	"com/kpadplayer/",   // KPAdPlayer (Kidoz) kids-safe ads SDK
	"com/kidoz/",        // Kidoz SDK family
	"gatewayprotocol/",    // app-bundled protobuf generated code (builders/Dsl)

	// ═══════════════════════════════════════════════════════════════════
	// GAME ENGINES / SDKS
	// ═══════════════════════════════════════════════════════════════════
	"org/fmod/", "com/unity3d/", "com/epicgames/",
	"com/mojang/minecraftpe/",
	"org/cocos2d/", "org/cocos2dx/",
	"org/libsdl/",

	// ═══════════════════════════════════════════════════════════════════
	// CORE ANDROID / JETPACK / KOTLIN
	// ═══════════════════════════════════════════════════════════════════
	"androidx/", "android/support/",
	"kotlin/", "kotlinx/",

	// ═══════════════════════════════════════════════════════════════════
	// NETWORKING / HTTP
	// ═══════════════════════════════════════════════════════════════════
	"com/squareup/", "okhttp3/", "okio/",
	"retrofit2/",
	"com/android/volley/",

	// ═══════════════════════════════════════════════════════════════════
	// SERIALIZATION / JSON / PROTOBUF
	// ═══════════════════════════════════════════════════════════════════
	"com/google/gson/", "com/google/protobuf/",
	"org/json/", "com/fasterxml/jackson/",
	"com/google/flatbuffers/",

	// ═══════════════════════════════════════════════════════════════════
	// TESTING / REFLECTION / BUILD
	// ═══════════════════════════════════════════════════════════════════
	"org/junit/", "junit/", "org/mockito/", "org/hamcrest/",

	// ═══════════════════════════════════════════════════════════════════
	// REACTIVE / COROUTINES
	// ═══════════════════════════════════════════════════════════════════
	"io/reactivex/", "rx/",

	// ═══════════════════════════════════════════════════════════════════
	// SOCIAL / AUTH PROVIDERS
	// ═══════════════════════════════════════════════════════════════════
	"com/facebook/", "com/twitter/",
	"com/kakao/", "com/linecorp/",
	"com/vk/sdk/",

	// ═══════════════════════════════════════════════════════════════════
	// DATABASE / STORAGE
	// ═══════════════════════════════════════════════════════════════════
	"net/sqlcipher/", "io/realm/",

	// ═══════════════════════════════════════════════════════════════════
	// WEBVIEW / CHROMIUM
	// ═══════════════════════════════════════════════════════════════════
	"org/chromium/",

	// ═══════════════════════════════════════════════════════════════════
	// IMAGE LOADING
	// ═══════════════════════════════════════════════════════════════════
	"com/bumptech/glide/", "com/squareup/picasso/",
	"com/facebook/fresco/",

	// ═══════════════════════════════════════════════════════════════════
	// LOGGING / DEBUGGING
	// ═══════════════════════════════════════════════════════════════════
	"timber/log/", "com/jakewharton/timber/",

	// ═══════════════════════════════════════════════════════════════════
	// DEPENDENCY INJECTION
	// ═══════════════════════════════════════════════════════════════════
	"dagger/", "javax/inject/",
	"com/google/dagger/", "hilt_aggregated_deps/",

	// ═══════════════════════════════════════════════════════════════════
	// OTHER
	// ═══════════════════════════════════════════════════════════════════
	"org/intellij/", "org/jetbrains/",
	"org/apache/",
	"com/crashlytics/", "com/flurry/",
	"com/google/common/", // Guava
	"com/google/android/material/",
	"com/airbnb/lottie/",

	// ═══════════════════════════════════════════════════════════════════
	// ADDITIONAL LIBRARIES (Phase 6 fix — false positive reduction)
	// ═══════════════════════════════════════════════════════════════════
	"tv/teads/android/exoplayer2/",
	"com/reactnativemmkv/",
	"com/zmxv/rnsound/",
	"com/caverock/androidsvg/",
	"io/invertase/",
	"com/brentvatne/",
	"coil/", "io/coil/",
	"com/horcrux/svg/",
	"com/th3rdwave/safeareacontext/",
	"com/swmansion/",
	"com/facebook/react/",
	"com/reactnativecommunity/",
	"org/chromium/",
	"org/bouncycastle/", "org/spongycastle/",
	"com/nimbusds/",
	"okio/",
	"com/google/protobuf/",
	"com/google/flatbuffers/",
	"com/fasterxml/jackson/",
	"com/amplitude/", "com/mixpanel/",
	"com/segment/", "com/braze/",
	"com/appsflyer/", "com/adjust/",
	"com/onesignal/",
	"io/sentry/", "com/bugsnag/",
	"com/newrelic/", "com/datadog/",
	"com/kochava/", "com/clevertap/",
	"com/moengage/", "com/startapp/",
	"com/bytedance/sdk/",
	"com/epicgames/",
	"org/cocos2d/", "org/libsdl/",
	"net/sqlcipher/", "io/realm/",
	"com/jakewharton/",
	"com/facebook/fresco/",
	"com/facebook/audiencenetwork/",
	"com/google/ads/",
	"org/jacoco/",
}

// ═══════════════════════════════════════════════════════════════════════════════
// TARGET SDK PREFIXES — SDK которые НУЖНО сканировать (НЕ фильтровать!)
//
// Эти пути содержат целевой код для патчинга:
//   • Google Play Billing — проверка покупок
//   • Google Play Licensing — LVL
//   • RevenueCat — подписки
//   • Qonversion — подписки
// ═══════════════════════════════════════════════════════════════════════════════

var targetSDKPrefixes = []string{
	"com/android/vending/billing/",
	"com/android/vending/licensing/",
	"com/revenuecat/",
	"com/qonversion/",
	"com/adapty/",
	"com/apphud/",
}

// IsKnownLibrary возвращает true если путь принадлежит известной библиотеке
// 🔥 PHASE 5: проверяет targetSDKPrefixes ПЕРВЫМ — целевые SDK не фильтруются!
func IsKnownLibrary(path string) bool {
	p := normalizeLibraryReference(path)

	// 🔥 PHASE 5: НЕ фильтруем целевые SDK!
	for _, prefix := range targetSDKPrefixes {
		if strings.HasPrefix(p, prefix) {
			return false // это ЦЕЛЕВОЙ код, не библиотека
		}
	}

	for _, prefix := range knownLibraryPrefixes {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}

var dangerousLibraryPatterns = map[string]bool{
	"REFLECTION_INVOKE":     true, // рефлексия — может быть эксплойт
	"CLASS_FORNAME":         true, // динамическая загрузка классов
	"REFLECTION_FIELD":      true, // доступ к приватным полям
	"PROXY_INVOKE":          true, // динамические прокси
	"DEX_CLASS_LOADER":      true, // загрузка DEX — опасно!
	"INMEMORY_DEX_LOADER":   true, // in-memory DEX — очень опасно!
	"NATIVE_LOAD":           true, // загрузка .so библиотек
	"TAMPER_DETECT":         true, // может быть антивирус в библиотеке
	"SAVE_ENCRYPTION":       true, // шифрование — может быть ransomware
	"SERVER_RESPONSE_CHECK": true, // проверка ответов — может быть C&C
}

// ShouldScanPatternInLibrary определяет нужно ли сканировать паттерн в библиотеке
//
// ЛОГИКА:
// - ОПАСНЫЕ паттерны (tamper, reflection, native_load) → СКАНИРУЕМ (могут быть вирусы/эксплойты)
// - ОБЫЧНЫЕ проверки (root_detection, premium_check) → ФИЛЬТРУЕМ (это нормально для библиотеки)
func ShouldScanPatternInLibrary(patternID string) bool {
	return dangerousLibraryPatterns[patternID]
}

// LibraryName возвращает имя библиотеки для отображения
// 🔥 PHASE 5: улучшенные имена с читаемыми названиями
func LibraryName(path string) string {
	p := normalizeLibraryReference(path)

	// 🔥 PHASE 5: Readable names для популярных библиотек
	readableNames := map[string]string{
		"com/millennialmedia/": "Millennial Media",
		"com/applifier/":      "Applifier",
		"com/supersonicads/":  "SupersonicAds",
		"com/adsdk/":          "AdSDK",
		"com/jumptap/":        "JumpTap",
		"com/bda/":            "BDA Controller",
		"com/madvertise/":     "Madvertise",
		"de/madvertise/":      "Madvertise",
		"org/spongycastle/":       "SpongyCastle",
		"org/bouncycastle/":       "BouncyCastle",
		"com/nimbusds/":           "Nimbus JOSE",
		"com/microsoft/xbox/":     "Xbox SDK",
		"com/microsoft/xal/":      "Xbox Auth",
		"com/microsoft/identity/": "Microsoft Identity",
		"com/braze/":              "Braze",
		"com/google/firebase/":    "Firebase",
		"com/appsflyer/":          "AppsFlyer",
		"com/adjust/sdk/":         "Adjust",
		"com/amplitude/":          "Amplitude",
		"com/mixpanel/":           "Mixpanel",
		"io/sentry/":              "Sentry",
		"com/bugsnag/":            "Bugsnag",
		"com/unity3d/":            "Unity",
		"com/epicgames/":          "Unreal Engine",
		"com/facebook/":           "Facebook SDK",
		"com/applovin/":           "AppLovin",
		"com/ironsource/":         "IronSource",
		"com/vungle/":             "Vungle",
		"tv/superawesome/":        "SuperAwesome",
		"com/kpadplayer/":         "KPAdPlayer",
		"com/kidoz/":              "Kidoz",
		"io/reactivex/":           "RxJava",
		"com/squareup/":           "Square (OkHttp/Retrofit)",
		"com/bumptech/glide/":     "Glide",
		"com/google/gson/":        "Gson",
		"com/segment/analytics/":  "Segment",
		"com/onesignal/":          "OneSignal",
		"com/branch/":             "Branch",
		"com/google/android/gms/": "Google Play Services",
		"org/junit/":              "JUnit",
		"org/jose4j/":             "jose4j",
	}

	// Match from the package root, never a substring of an application package.
	// Longest-prefix selection remains deterministic even if mappings overlap.
	bestPrefix, bestName := "", ""
	for prefix, name := range readableNames {
		if strings.HasPrefix(p, prefix) && len(prefix) > len(bestPrefix) {
			bestPrefix, bestName = prefix, name
		}
	}
	if bestName != "" {
		return bestName
	}

	for _, prefix := range knownLibraryPrefixes {
		if strings.HasPrefix(p, prefix) && len(prefix) > len(bestPrefix) {
			bestPrefix = prefix
		}
	}
	if bestPrefix == "" {
		return ""
	}
	parts := strings.Split(strings.TrimSuffix(bestPrefix, "/"), "/")
	return parts[len(parts)-1]
}

// normalizeLibraryReference accepts a package path, an L...; descriptor or a
// file below a smali root. Absolute Windows paths are handled on every host.
// Do not peel a smali-like component out of a relative application package.
func normalizeLibraryReference(ref string) string {
	p := strings.TrimSpace(strings.ReplaceAll(ref, "\\", "/"))
	if strings.HasPrefix(p, "L") && strings.HasSuffix(p, ";") {
		return strings.ToLower(p[1 : len(p)-1])
	}
	p = path.Clean(strings.ToLower(p))
	parts := strings.Split(p, "/")
	absolute := path.IsAbs(p) || (len(p) >= 3 && p[1] == ':' && p[2] == '/')
	for i, part := range parts {
		if i > 0 && !absolute {
			break
		}
		if isSmaliSourceRoot(part) {
			return strings.Join(parts[i+1:], "/")
		}
	}
	return p
}

func isSmaliSourceRoot(part string) bool {
	if part == "smali" {
		return true
	}
	const prefix = "smali_classes"
	if !strings.HasPrefix(part, prefix) {
		return false
	}
	number := strings.TrimPrefix(part, prefix)
	if number == "" || number[0] == '0' || number == "1" {
		return false
	}
	for _, digit := range number {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	return true
}
