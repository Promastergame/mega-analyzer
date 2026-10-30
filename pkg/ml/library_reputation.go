package ml

import (
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// LIBRARY REPUTATION DB — Phase 6
//
// Решает главную проблему: semantic hallucinations.
//
// Примеры ложных срабатываний которые это фиксит:
//   • io/ktor/http/MimesKt → "app installation flow detected" (это MIME таблица!)
//   • org/jacoco/core/internal/instr/SignatureRemover → "Billing verification"
//   • com/swmansion/reanimated/sensor/ReanimatedSensor → "Premium gate"
//   • AsyncLocalStorageUtil.verifyAndForceSqliteCheckpoint → "SERVER_PREMIUM_VALIDATION"
//   • PeerConnectionFactory.initializeFieldTrials → "UNITY_ADS_INIT"
//   • io/ktor/util/NIOKt.copy() → "Crypto-mining pool URLs" (слово "pool"!)
//
// Подход:
//   1. Trusted framework prefixes → MASSIVE score reduction (÷10 или полный suppress)
//   2. Safe semantic domains → context-aware penalty
//   3. Known false-positive string patterns → suppress specific triggers
//   4. API semantics → distinguish "Signature.verify()" from "SignatureRemover"
//
// Интеграция: вызывается из PatchScorer.scoreLibrary() ПЕРЕД финальным расчётом.
// ═══════════════════════════════════════════════════════════════════════════════

// ReputationVerdict — результат проверки репутации
type ReputationVerdict struct {
	IsTrusted       bool     `json:"is_trusted"`
	Framework       string   `json:"framework,omitempty"`
	Domain          string   `json:"domain,omitempty"` // "networking", "animation", "testing", etc.
	PenaltyFactor   float64  `json:"penalty_factor"`   // 0.0 = полный suppress, 1.0 = без изменений
	Reason          string   `json:"reason,omitempty"`
	SuppressStrings []string `json:"suppress_strings,omitempty"` // строки которые НЕ должны триггерить
}

// CheckReputation проверяет метод против reputation DB.
// Возвращает nil если метод не принадлежит известному фреймворку.
func CheckReputation(mi *MethodInfo) *ReputationVerdict {
	if mi == nil {
		return nil
	}

	classLower := strings.ToLower(mi.ClassName)
	pathLower := strings.ToLower(mi.FilePath)
	// Нормализуем path separators
	pathLower = strings.ReplaceAll(pathLower, "\\", "/")
	classLower = strings.ReplaceAll(classLower, ".", "/")

	// ═══════════════════════════════════════════════════════════════════
	// TIER 1: ABSOLUTE TRUST — эти фреймворки НИКОГДА не содержат
	// security gates для патчинга. Score → ÷20 (почти полный suppress).
	// ═══════════════════════════════════════════════════════════════════
	for _, tf := range tier1AbsoluteTrust {
		if matchesPrefix(pathLower, classLower, tf.prefix) {
			return &ReputationVerdict{
				IsTrusted:     true,
				Framework:     tf.name,
				Domain:        tf.domain,
				PenaltyFactor: 0.05, // ÷20
				Reason:        tf.name + " — trusted framework, not a patch target",
			}
		}
	}

	// ═══════════════════════════════════════════════════════════════════
	// TIER 2: HIGH TRUST — библиотеки которые ОЧЕНЬ редко содержат
	// реальные security gates. Score → ÷5.
	// ═══════════════════════════════════════════════════════════════════
	for _, tf := range tier2HighTrust {
		if matchesPrefix(pathLower, classLower, tf.prefix) {
			return &ReputationVerdict{
				IsTrusted:     true,
				Framework:     tf.name,
				Domain:        tf.domain,
				PenaltyFactor: 0.2, // ÷5
				Reason:        tf.name + " — high-trust library, unlikely patch target",
			}
		}
	}

	// ═══════════════════════════════════════════════════════════════════
	// TIER 3: MEDIUM TRUST — SDK которые могут содержать security-relevant
	// код, но обычно не являются целями. Score → ÷2.
	// ═══════════════════════════════════════════════════════════════════
	for _, tf := range tier3MediumTrust {
		if matchesPrefix(pathLower, classLower, tf.prefix) {
			return &ReputationVerdict{
				IsTrusted:     true,
				Framework:     tf.name,
				Domain:        tf.domain,
				PenaltyFactor: 0.5, // ÷2
				Reason:        tf.name + " — medium-trust SDK",
			}
		}
	}

	// ═══════════════════════════════════════════════════════════════════
	// SEMANTIC DOMAIN CHECK — даже если не в prefix list, проверяем
	// по семантике класса/метода.
	// ═══════════════════════════════════════════════════════════════════
	if v := checkSemanticDomain(mi, classLower, pathLower); v != nil {
		return v
	}

	return nil
}

// CheckStringFalsePositive проверяет, является ли найденная "security string"
// ложным срабатыванием из-за контекста (MIME таблицы, codec names, etc.)
func CheckStringFalsePositive(str string, mi *MethodInfo) bool {
	strLower := strings.ToLower(str)

	// MIME types — "application/vnd.android.package-archive" содержит "package"
	// и "archive" но это просто MIME constant
	for _, safe := range safeStringContexts {
		if strings.Contains(strLower, safe) {
			return true
		}
	}

	// Проверяем контекст класса — если класс в MIME/codec/media домене,
	// строки типа "pool", "verify", "check" — это не security
	if mi != nil {
		classLower := strings.ToLower(mi.ClassName)
		pathLower := strings.ToLower(mi.FilePath)
		for _, domain := range safeClassDomains {
			if strings.Contains(classLower, domain) || strings.Contains(pathLower, domain) {
				return true
			}
		}
	}

	return false
}

// ═══════════════════════════════════════════════════════════════════════════════
// INTERNAL DATA
// ═══════════════════════════════════════════════════════════════════════════════

type trustedFramework struct {
	prefix string
	name   string
	domain string
}

func matchesPrefix(pathLower, classLower, prefix string) bool {
	p := strings.ToLower(prefix)
	return strings.Contains(pathLower, p) || strings.Contains(classLower, p)
}

// ─── TIER 1: ABSOLUTE TRUST ─────────────────────────────────────────────────
// Эти фреймворки НИКОГДА не являются целями для патчинга.
// Любой finding в них — 100% false positive.

var tier1AbsoluteTrust = []trustedFramework{
	// Google Play billing / integrity / transport — noise source in the FNaF
	// scan: isReady(), MessageDigest.getInstance() etc. are library plumbing.
	{"com/android/billingclient/", "Google Billing Library", "billing-sdk"},
	{"com/android/vending/expansion/", "Android APK Expansion Zip", "play-services"},
	{"com/google/android/play/", "Google Play Core", "play-services"},
	{"com/pairip/", "Google Play Integrity (pairip)", "integrity-sdk"},
	{"com/google/android/datatransport/", "Firebase Data Transport", "telemetry"},

	// Clickteam Fusion engine root namespaces (FNaF scan): the whole engine
	// (Runtime/MMFRuntime, Services/CServices, Sprites/CSpriteGen,
	// Expressions/CValue, Conditions/CND_*, RunLoop/CRun, Events/CEventProgram,
	// Banks/CSound, Transitions/CTrans, Movements/*, Application/CRunApp...)
	// lives at the APK root and is pure plumbing. The IAP extension
	// (Extensions/) deliberately stays OUT of this list: it is a legitimate
	// license-gate location.
	{"runtime/", "Clickteam Fusion Runtime", "game-engine"},
	{"services/", "Clickteam Fusion Services", "game-engine"},
	{"objects/", "Clickteam Fusion Objects", "game-engine"},
	{"sprites/", "Clickteam Fusion Sprites", "game-engine"},
	{"banks/", "Clickteam Fusion Banks", "game-engine"},
	{"conditions/", "Clickteam Fusion Conditions", "game-engine"},
	{"runloop/", "Clickteam Fusion Run Loop", "game-engine"},
	{"events/", "Clickteam Fusion Events", "game-engine"},
	{"expressions/", "Clickteam Fusion Expressions", "game-engine"},
	{"transitions/", "Clickteam Fusion Transitions", "game-engine"},
	{"movements/", "Clickteam Fusion Movements", "game-engine"},
	{"application/", "Clickteam Fusion Application", "game-engine"},
	{"oi/", "Clickteam Fusion Object Info", "game-engine"},
	{"frame/", "Clickteam Fusion Frame", "game-engine"},
	{"actions/", "Clickteam Fusion Actions", "game-engine"},
	{"opengl/", "Clickteam Fusion GL Renderer", "game-engine"},

	// libGDX (FNaF scan: utils/Array, Pool, LongArray hit HIGH as
	// "structurally bypassable" plumbing).
	{"com/badlogic/gdx/", "libGDX", "game-framework"},

	// Android core / Jetpack
	{"androidx/", "AndroidX", "android-framework"},
	{"android/support/", "Android Support Library", "android-framework"},

	// Kotlin stdlib / coroutines
	{"kotlin/", "Kotlin stdlib", "language-runtime"},
	{"kotlinx/", "Kotlin extensions", "language-runtime"},

	// React Native ecosystem
	{"com/facebook/react/", "React Native", "cross-platform-framework"},
	{"com/swmansion/reanimated/", "React Native Reanimated", "animation"},
	{"com/swmansion/gesturehandler/", "React Native Gesture Handler", "ui-input"},
	{"com/swmansion/rnscreens/", "React Native Screens", "navigation"},
	{"com/th3rdwave/safeareacontext/", "React Native Safe Area", "ui-layout"},
	{"com/reactnativecommunity/", "React Native Community", "cross-platform-framework"},
	{"com/horcrux/svg/", "React Native SVG", "graphics"},
	{"com/brentvatne/", "React Native Expo", "cross-platform-framework"},
	{"expo/modules/", "Expo Modules", "cross-platform-framework"},

	// WebRTC
	{"org/webrtc/", "WebRTC", "networking-media"},

	// Testing / Coverage
	{"org/jacoco/", "JaCoCo", "testing-coverage"},
	{"org/junit/", "JUnit", "testing"},
	{"org/mockito/", "Mockito", "testing"},
	{"org/hamcrest/", "Hamcrest", "testing"},

	// Networking (non-security)
	{"io/ktor/", "Ktor", "networking"},
	{"okhttp3/internal/", "OkHttp internals", "networking"},
	{"okio/", "Okio", "io-library"},

	// Serialization
	{"com/google/gson/", "Gson", "serialization"},
	{"com/google/protobuf/", "Protobuf", "serialization"},
	{"com/fasterxml/jackson/", "Jackson", "serialization"},
	{"com/google/flatbuffers/", "FlatBuffers", "serialization"},
	{"org/json/", "org.json", "serialization"},

	// Image loading
	{"com/bumptech/glide/", "Glide", "image-loading"},
	{"com/squareup/picasso/", "Picasso", "image-loading"},
	{"com/facebook/fresco/", "Fresco", "image-loading"},
	{"io/coil/", "Coil", "image-loading"},
	{"coil/", "Coil", "image-loading"},

	// Media / ExoPlayer
	{"com/google/android/exoplayer/", "ExoPlayer", "media-playback"},
	{"androidx/media3/", "Media3", "media-playback"},
	{"com/google/android/exoplayer2/", "ExoPlayer2", "media-playback"},

	// Dependency injection
	{"dagger/", "Dagger", "dependency-injection"},
	{"javax/inject/", "javax.inject", "dependency-injection"},
	{"com/google/dagger/", "Dagger/Hilt", "dependency-injection"},
	{"hilt_aggregated_deps/", "Hilt", "dependency-injection"},

	// Reactive
	{"io/reactivex/", "RxJava", "reactive"},
	{"rx/", "RxJava1", "reactive"},

	// Logging
	{"timber/log/", "Timber", "logging"},
	{"com/jakewharton/timber/", "Timber", "logging"},

	// Apache commons
	{"org/apache/", "Apache Commons", "utility"},

	// Jetbrains / IntelliJ annotations
	{"org/intellij/", "IntelliJ", "annotations"},
	{"org/jetbrains/", "JetBrains", "annotations"},

	// Google common (Guava)
	{"com/google/common/", "Guava", "utility"},

	// Material Design
	{"com/google/android/material/", "Material Design", "ui-framework"},

	// Lottie animations
	{"com/airbnb/lottie/", "Lottie", "animation"},

	// Flutter engine
	{"io/flutter/", "Flutter Engine", "cross-platform-framework"},

	// SQLite / Room (internal)
	{"androidx/sqlite/", "AndroidX SQLite", "database"},
	{"androidx/room/", "Room", "database"},

	// Crypto libraries (NOT app crypto — library internals)
	{"org/spongycastle/", "SpongyCastle", "crypto-library"},
	{"org/bouncycastle/", "BouncyCastle", "crypto-library"},
	{"org/conscrypt/", "Conscrypt", "crypto-library"},
	{"com/nimbusds/", "Nimbus JOSE+JWT", "crypto-library"},

	// Chromium internals
	{"org/chromium/", "Chromium", "webview-engine"},

	// Forked ExoPlayer (tv.teads variant)
	{"tv/teads/android/exoplayer2/", "ExoPlayer (fork)", "media-playback"},

	// MMKV storage
	{"com/reactnativemmkv/", "MMKV", "storage"},

	// React Native Sound
	{"com/zmxv/rnsound/", "RNSound", "audio"},

	// AndroidSVG
	{"com/caverock/androidsvg/", "AndroidSVG", "graphics"},

	// React Native Firebase wrapper (io.invertase)
	{"io/invertase/", "React Native Firebase", "cross-platform-framework"},

	// Coil (variant paths)
	{"io/coil/", "Coil", "image-loading"},

	// SVG (React Native)
	{"com/horcrux/svg/", "React Native SVG", "graphics"},

	// Safe Area Context
	{"com/th3rdwave/safeareacontext/", "React Native Safe Area", "ui-layout"},

	// Swmansion (Reanimated + Gesture Handler)
	{"com/swmansion/", "React Native SwMansion", "cross-platform-framework"},

	// React Native Community
	{"com/reactnativecommunity/", "React Native Community", "cross-platform-framework"},

	// Protobuf
	{"com/google/protobuf/", "Protobuf", "serialization"},
	{"com/google/flatbuffers/", "FlatBuffers", "serialization"},

	// Okio
	{"okio/", "Okio", "io-library"},

	// Fresco
	{"com/facebook/fresco/", "Fresco", "image-loading"},

	// React Native core
	{"com/facebook/react/", "React Native", "cross-platform-framework"},

	// Amplitude / Mixpanel / Segment
	{"com/amplitude/", "Amplitude", "analytics"},
	{"com/mixpanel/", "Mixpanel", "analytics"},
	{"com/segment/", "Segment", "analytics"},
}

// ─── TIER 2: HIGH TRUST ─────────────────────────────────────────────────────
// Библиотеки которые ОЧЕНЬ редко содержат реальные security gates.
// Findings в них — почти всегда false positive, но не 100%.

var tier2HighTrust = []trustedFramework{
	// OkHttp (top-level, not internals)
	{"okhttp3/", "OkHttp", "networking"},
	{"retrofit2/", "Retrofit", "networking"},
	{"com/squareup/", "Square libraries", "networking"},

	// Firebase (analytics, not auth)
	{"com/google/firebase/analytics/", "Firebase Analytics", "analytics"},
	{"com/google/firebase/messaging/", "Firebase Messaging", "push-notifications"},
	{"com/google/firebase/crashlytics/", "Firebase Crashlytics", "error-reporting"},
	{"com/google/firebase/perf/", "Firebase Performance", "monitoring"},

	// Analytics / Attribution
	{"com/appsflyer/", "AppsFlyer", "analytics"},
	{"com/adjust/sdk/", "Adjust", "analytics"},
	{"com/amplitude/", "Amplitude", "analytics"},
	{"com/mixpanel/", "Mixpanel", "analytics"},
	{"com/segment/analytics/", "Segment", "analytics"},
	{"com/braze/", "Braze", "marketing"},
	{"com/onesignal/", "OneSignal", "push-notifications"},

	// Error reporting
	{"io/sentry/", "Sentry", "error-reporting"},
	{"com/bugsnag/", "Bugsnag", "error-reporting"},
	{"com/newrelic/", "New Relic", "monitoring"},
	{"com/datadog/", "Datadog", "monitoring"},

	// Social SDKs
	{"com/facebook/", "Facebook SDK", "social"},
	{"com/twitter/", "Twitter SDK", "social"},
	{"com/kakao/", "Kakao SDK", "social"},
	{"com/linecorp/", "LINE SDK", "social"},
	{"com/vk/sdk/", "VK SDK", "social"},

	// Game engines
	{"com/unity3d/", "Unity", "game-engine"},
	{"org/cocos2d/", "Cocos2d", "game-engine"},
	{"org/libsdl/", "SDL", "game-engine"},
	{"org/fmod/", "FMOD", "audio-engine"},
	{"com/epicgames/", "Unreal Engine", "game-engine"},

	// Database
	{"net/sqlcipher/", "SQLCipher", "database"},
	{"io/realm/", "Realm", "database"},

	// Volley
	{"com/android/volley/", "Volley", "networking"},

	// GMS (non-billing)
	{"com/google/android/gms/common/", "GMS Common", "google-services"},
	{"com/google/android/gms/maps/", "Google Maps", "maps"},
	{"com/google/android/gms/location/", "Google Location", "location"},
	{"com/google/android/gms/tasks/", "GMS Tasks", "async"},
}

// ─── TIER 3: MEDIUM TRUST ───────────────────────────────────────────────────
// SDK которые МОГУТ содержать security-relevant код, но обычно не являются
// целями для патчинга. Score → ÷2.

var tier3MediumTrust = []trustedFramework{
	// Ad networks (contain ad-loading logic but not premium gates)
	{"com/google/android/gms/ads/", "Google Ads", "advertising"},
	{"com/facebook/ads/", "Facebook Ads", "advertising"},
	{"com/applovin/", "AppLovin", "advertising"},
	{"com/vungle/", "Vungle", "advertising"},
	{"com/ironsource/", "IronSource", "advertising"},
	{"com/chartboost/", "Chartboost", "advertising"},
	{"com/inmobi/", "InMobi", "advertising"},
	{"com/mopub/", "MoPub", "advertising"},
	{"com/tapjoy/", "Tapjoy", "advertising"},
	{"com/startapp/", "StartApp", "advertising"},
	{"com/bytedance/sdk/", "ByteDance SDK", "advertising"},

	// Microsoft (auth SDK — has security but not patch target)
	{"com/microsoft/identity/", "Microsoft Identity", "auth-sdk"},
	{"com/microsoft/aad/", "Microsoft AAD", "auth-sdk"},

	// Firebase Auth (has security but usually not the patch target)
	{"com/google/firebase/auth/", "Firebase Auth", "auth-sdk"},
}

// ─── SEMANTIC DOMAIN CHECK ──────────────────────────────────────────────────

func checkSemanticDomain(mi *MethodInfo, classLower, pathLower string) *ReputationVerdict {
	nameLower := strings.ToLower(mi.Name)

	// MIME tables / codec registries — слова "package", "archive", "verify"
	// в контексте MIME/codec — это НЕ security
	if isMimeOrCodecContext(classLower, pathLower, nameLower) {
		return &ReputationVerdict{
			IsTrusted:     true,
			Domain:        "mime-codec-registry",
			PenaltyFactor: 0.05,
			Reason:        "MIME/codec table — not security-relevant",
		}
	}

	// SVG/XML parsers — "path", "verify", "validate" в SVG контексте
	if isSVGOrXMLParser(classLower, pathLower) {
		return &ReputationVerdict{
			IsTrusted:     true,
			Domain:        "xml-svg-parser",
			PenaltyFactor: 0.1,
			Reason:        "SVG/XML parser internals",
		}
	}

	// EXIF/XMP/media metadata — "signature", "verify" в EXIF контексте
	if isMediaMetadata(classLower, pathLower) {
		return &ReputationVerdict{
			IsTrusted:     true,
			Domain:        "media-metadata",
			PenaltyFactor: 0.1,
			Reason:        "Media metadata processing (EXIF/XMP)",
		}
	}

	// Localization / i18n — "locale", "translation", "resource"
	if isLocalization(classLower, pathLower) {
		return &ReputationVerdict{
			IsTrusted:     true,
			Domain:        "localization",
			PenaltyFactor: 0.1,
			Reason:        "Localization/i18n infrastructure",
		}
	}

	// File extension maps / content type resolvers
	if isContentTypeResolver(classLower, pathLower, nameLower) {
		return &ReputationVerdict{
			IsTrusted:     true,
			Domain:        "content-type-resolver",
			PenaltyFactor: 0.05,
			Reason:        "Content-type/extension mapping — not security",
		}
	}

	// Connection pool / thread pool / object pool — "pool" is NOT crypto mining
	if isPoolContext(classLower, pathLower, nameLower) {
		return &ReputationVerdict{
			IsTrusted:     true,
			Domain:        "resource-pool",
			PenaltyFactor: 0.1,
			Reason:        "Resource pool (connection/thread/object) — not crypto mining",
		}
	}

	// RecyclerView / DiffUtil — areContentsTheSame, areItemsTheSame
	if isDiffUtilContext(classLower, nameLower) {
		return &ReputationVerdict{
			IsTrusted:     true,
			Domain:        "ui-diffutil",
			PenaltyFactor: 0.05,
			Reason:        "DiffUtil/RecyclerView callback — not security gate",
		}
	}

	return nil
}

// ─── SEMANTIC HELPERS ────────────────────────────────────────────────────────

func isMimeOrCodecContext(classLower, pathLower, nameLower string) bool {
	mimeIndicators := []string{
		"mime", "mimetype", "mimes", "contenttype", "mediatype",
		"codec", "codecs", "encoder", "decoder", "format",
		"w3c", "namespace", "iana", "rfc",
	}
	for _, ind := range mimeIndicators {
		if strings.Contains(classLower, ind) || strings.Contains(pathLower, ind) || strings.Contains(nameLower, ind) {
			return true
		}
	}
	// Ktor MimesKt specifically
	if strings.Contains(pathLower, "ktor") && strings.Contains(classLower, "mime") {
		return true
	}
	return false
}

func isSVGOrXMLParser(classLower, pathLower string) bool {
	indicators := []string{
		"svg", "xmlparser", "xmlpull", "saxparser", "domparser",
		"xpath", "xslt", "xmlutil", "xmlreader", "xmlwriter",
	}
	for _, ind := range indicators {
		if strings.Contains(classLower, ind) || strings.Contains(pathLower, ind) {
			return true
		}
	}
	return false
}

func isMediaMetadata(classLower, pathLower string) bool {
	indicators := []string{
		"exif", "xmp", "iptc", "metadata/image", "imagemeta",
		"mediaextractor", "mediametadata", "id3", "vorbiscomment",
	}
	for _, ind := range indicators {
		if strings.Contains(classLower, ind) || strings.Contains(pathLower, ind) {
			return true
		}
	}
	return false
}

func isLocalization(classLower, pathLower string) bool {
	indicators := []string{
		"locale", "i18n", "l10n", "translation", "localiz",
		"plurals", "icu4j", "messageformat",
	}
	for _, ind := range indicators {
		if strings.Contains(classLower, ind) || strings.Contains(pathLower, ind) {
			return true
		}
	}
	return false
}

func isContentTypeResolver(classLower, pathLower, nameLower string) bool {
	// Classes that map file extensions to MIME types
	if strings.Contains(classLower, "contenttyperesolver") ||
		strings.Contains(classLower, "mimetypemap") ||
		strings.Contains(classLower, "extensionmap") ||
		strings.Contains(classLower, "filetypemap") {
		return true
	}
	// Path-based detection
	if strings.Contains(pathLower, "contenttype") ||
		strings.Contains(pathLower, "mimetype") ||
		strings.Contains(pathLower, "extension") {
		return true
	}
	// Methods that are clearly content-type lookups
	if strings.Contains(nameLower, "getmimetype") ||
		strings.Contains(nameLower, "getcontenttype") ||
		strings.Contains(nameLower, "fromextension") {
		return true
	}
	return false
}

func isPoolContext(classLower, pathLower, nameLower string) bool {
	poolIndicators := []string{
		"connectionpool", "threadpool", "objectpool", "bufferpool",
		"pool/", "pooled", "pooling", "workerpool",
		"executorpool", "channelpool",
	}
	for _, ind := range poolIndicators {
		if strings.Contains(classLower, ind) || strings.Contains(pathLower, ind) {
			return true
		}
	}
	// NIO copy/transfer — "pool" in NIO context is buffer pool
	if (strings.Contains(classLower, "nio") || strings.Contains(pathLower, "nio")) &&
		(strings.Contains(nameLower, "copy") || strings.Contains(nameLower, "transfer") ||
			strings.Contains(nameLower, "pool")) {
		return true
	}
	return false
}

func isDiffUtilContext(classLower, nameLower string) bool {
	if strings.Contains(classLower, "diffutil") ||
		strings.Contains(classLower, "diffcallback") ||
		strings.Contains(classLower, "itemcallback") ||
		strings.Contains(classLower, "listadapter") {
		return true
	}
	if nameLower == "arecontentsthesame" || nameLower == "areitemsthesame" {
		return true
	}
	return false
}

// ─── SAFE STRING CONTEXTS ───────────────────────────────────────────────────
// Строки которые триггерят false positives когда встречаются в коде.
// Если const-string содержит эти подстроки — это НЕ security signal.

var safeStringContexts = []string{
	// MIME types that contain "package", "archive", etc.
	"application/vnd.android.package-archive",
	"application/x-tar",
	"application/zip",
	"application/gzip",
	"application/x-rar",
	"application/java-archive",
	"application/octet-stream",
	"multipart/form-data",

	// W3C / XML namespaces
	"http://www.w3.org/",
	"http://schemas.android.com/",
	"http://xmlpull.org/",
	"xmlns:",

	// Media codecs
	"video/avc", "video/hevc", "video/mp4",
	"audio/mp4a", "audio/mpeg", "audio/ogg",
	"image/webp", "image/png", "image/jpeg",

	// Common infrastructure strings that trigger "crypto mining"
	"thread pool", "connection pool", "buffer pool",
	"object pool", "worker pool",

	// SQLite maintenance
	"checkpoint", "wal_checkpoint", "pragma",
	"vacuum", "integrity_check", "journal_mode",

	// WebRTC field trials
	"fieldtrial", "field_trial", "webrtc-",

	// React Native bridge
	"__rct_export__", "rctbridgemodule",

	// OkHttp cache
	"cache-control", "if-none-match", "if-modified-since",
	"etag", "last-modified",

	// Gradle / build
	"gradle", "buildconfig", "versionname", "versioncode",
}

// ─── SAFE CLASS DOMAINS ─────────────────────────────────────────────────────
// Если класс содержит эти подстроки, его строковые константы НЕ должны
// триггерить security alerts.

var safeClassDomains = []string{
	"mimetypemap", "mimes", "contenttype", "mediatype",
	"codec", "encoder", "decoder",
	"localedata", "timezone", "calendar",
	"unittest", "testcase", "testrunner",
	"buildconfig", "r$", "r/",
	"diffutil", "diffcallback",
	"asynclocalstorage", "asyncstorage",
	"peerconnection", "webrtc", "onetimetoken",
}
