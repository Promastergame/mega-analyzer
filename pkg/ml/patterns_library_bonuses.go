package ml

// ═══════════════════════════════════════════════════════════════════════════════
// LIBRARY PATHS — библиотеки где патч-точки маловероятны
// ═══════════════════════════════════════════════════════════════════════════════

var LibraryExcludePaths = []string{
	"com/google/android/gms/",
	"com/google/firebase/",
	"com/google/ads/",
	"com/facebook/",
	"com/twitter/",
	"com/squareup/",
	"androidx/",
	"android/support/",
	"org/apache/",
	"org/json/",
	"io/reactivex/",
	"okhttp3/",
	"retrofit2/",
	"com/crashlytics/",
	"com/flurry/",
	"kotlin/",
	"kotlinx/",
	"org/intellij/",
	"org/jetbrains/",
	"com/unity3d/",
	"com/applovin/",
	"com/chartboost/",
	"com/inmobi/",
	"com/mopub/",
	"com/tapjoy/",
	"com/vungle/",
	"com/ironsource/",
	"com/bumptech/glide/",
	"com/squareup/picasso/",
	"dagger/",
	"javax/inject/",
	"com/google/dagger/",
	"hilt_aggregated_deps/",
	"com/google/android/material/",
	"com/airbnb/lottie/",
	"io/flutter/",
	"androidx/media3/",
	"com/google/android/exoplayer/",
	"com/google/android/exoplayer2/",
	"tv/teads/android/exoplayer2/",
	"com/reactnativemmkv/",
	"com/zmxv/rnsound/",
	"com/caverock/androidsvg/",
	"io/invertase/",
	"com/brentvatne/",
	"coil/",
	"io/coil/",
	"org/webrtc/",
	"com/horcrux/svg/",
	"com/th3rdwave/safeareacontext/",
	"com/swmansion/",
	"com/facebook/react/",
	"com/reactnativecommunity/",
	"org/chromium/",
	"org/bouncycastle/",
	"org/spongycastle/",
	"com/nimbusds/",
	"okio/",
	"com/google/common/",
	"com/google/gson/",
	"com/google/protobuf/",
	"com/google/flatbuffers/",
	"com/fasterxml/jackson/",
	"com/amplitude/",
	"com/mixpanel/",
	"com/segment/",
	"com/braze/",
	"com/appsflyer/",
	"com/adjust/",
	"com/onesignal/",
	"io/sentry/",
	"com/bugsnag/",
	"com/newrelic/",
	"com/datadog/",
	"com/kochava/",
	"com/clevertap/",
	"com/moengage/",
	"com/startapp/",
	"com/bytedance/sdk/",
	"com/bytedance/", // all TikTok/Pangle SDK trees (events, pcc, embed) — analytics, not gates
	"com/tiktok/",    // TikTok event/attribution SDK
	"com/mbridge/",   // Mintegral (incl. its bundled exoplayer copy)
	"com/iab/",       // OMID wrappers (vungle/ironsource/unity3d under omid/)
	"com/digitalturbine/", // Ignite
	"tv/superawesome/",  // SuperAwesome kids-safe ads (Epic Games)
	"com/kpadplayer/",   // KPAdPlayer (Kidoz) kids-safe ads SDK
	"com/kidoz/",        // Kidoz SDK family
	"gatewayprotocol/",    // app-bundled protobuf generated code (builders/Dsl)
	"com/fyber/",
	"com/ogury/",
	"com/pangle/",   // Pangle (TikTok ads) — own tree next to com/bytedance
	"com/pgl/",      // Pangle SDK internals
	"com/apm/",      // ByteDance APM Insight (performance/analytics)
	"com/safedk/",   // SafeDK ad-fraud SDK
	"com/bykv/",     // VK attribution SDK
	"com/microsoft/",
	"com/epicgames/",
	"org/cocos2d/",
	"org/libsdl/",
	"net/sqlcipher/",
	"io/realm/",
	"com/android/volley/",
	"com/crashlytics/",
	"com/flurry/",
	"com/jakewharton/",
	"com/facebook/fresco/",
	"com/facebook/audiencenetwork/",
	"timber/",
	"rx/",
	"org/junit/",
	"org/mockito/",
	"org/hamcrest/",
	"org/jacoco/",
}

// LibraryPenalty — штраф за нахождение в библиотеке
const LibraryPenalty = -35.0

// ═══════════════════════════════════════════════════════════════════════════════
// STRUCTURAL BONUSES — бонусы за структуру метода
// ═══════════════════════════════════════════════════════════════════════════════

type StructuralBonus struct {
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Bonus       float64 `json:"bonus"`
}

var StructuralBonuses = []StructuralBonus{
	{
		Name:        "boolean_return",
		Description: "Method returns boolean (Z)",
		Bonus:       15,
	},
	{
		Name:        "dual_return",
		Description: "Has two return paths (true/false branches)",
		Bonus:       10,
	},
	{
		Name:        "short_method",
		Description: "Method is short (3-20 instructions) — typical for checks",
		Bonus:       8,
	},
	{
		Name:        "if_with_return",
		Description: "Has if-eqz/if-nez followed by return",
		Bonus:       12,
	},
	{
		Name:        "app_code",
		Description: "Located in application code (not library)",
		Bonus:       15,
	},
	{
		Name:        "security_context",
		Description: "File has other security-related methods nearby",
		Bonus:       10,
	},
	{
		Name:        "name_match",
		Description: "Method name matches vulnerable pattern",
		Bonus:       20,
	},
	{
		Name:        "class_match",
		Description: "Class name/path matches vulnerable pattern",
		Bonus:       15,
	},
	{
		Name:        "call_match",
		Description: "Contains security-related API calls",
		Bonus:       18,
	},
	{
		Name:        "string_match",
		Description: "Contains security-related string constants",
		Bonus:       12,
	},
}
