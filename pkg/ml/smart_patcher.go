package ml

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// SMART PATCHER — нормальный патчинг для реальных задач
//
// Умеет находить:
//   - URL/API endpoints (для редиректа на приватный сервер)
//   - SSL pinning methods (для отключения)
//   - Root detection (для bypass)
//   - Signature verification (для отключения проверки)
//   - License/Subscription checks
// ═══════════════════════════════════════════════════════════════════════════════

// SmartPatchTarget типы целей для патчинга
type SmartPatchTarget int

const (
	TargetUnknown             SmartPatchTarget = iota
	TargetURLRedirect                          // Изменение URL API
	TargetSSLBypass                            // Отключение SSL pinning
	TargetRootBypass                           // Отключение root detection
	TargetSignatureBypass                      // Отключение проверки подписи
	TargetLicenseBypass                        // Обход license check
	TargetSubscriptionBypass                   // Обход subscription check
	TargetLoginBypass                          // Обход login check
	TargetAdRemove                             // Удаление рекламы
	TargetJWTBypass                            // Обход проверки JWT
	TargetAntiCheatBypass                      // Обход Anti-Cheat
	TargetIntegrityBypass                      // Play Integrity / SafetyNet attestation
	TargetDebuggerBypass                       // Anti-debug (Debug.isDebuggerConnected)
	TargetFridaBypass                          // Frida / Xposed / instrumentation detection
	TargetVPNProxyBypass                       // VPN / proxy detection
	TargetTrialBypass                          // Trial / expiry / time-bomb checks
	TargetBiometricBypass                      // BiometricPrompt / FingerprintManager auth
	TargetDeviceBindingBypass                  // Device ID / IMEI binding check
	TargetHardwareAttestation                  // TEE / StrongBox / Keystore attestation
	TargetAppCloneBypass                       // Dual-space / clone app / parallel space detection
	TargetKernelSUBypass                       // KernelSU / APatch / Zygisk Next root
	TargetLSPosedBypass                        // LSPosed / Riru / EdXposed framework detection
	TargetCertTransparency                     // Certificate Transparency (OkHttp CT policy)
	TargetOAuthBypass                          // OAuth2 / OpenID Connect token validation
	TargetGeoBlockBypass                       // Geographic restriction / region lock
	TargetDeviceFarmBypass                     // Device farm / UIAutomator / automation detect
	TargetSpeedHackBypass                      // Game speed-hack / frame-time manipulation
	TargetScreenOverlayBypass                  // canDrawOverlays / TYPE_APPLICATION_OVERLAY
)

// SmartPatch описание умного патча
type SmartPatch struct {
	Target    SmartPatchTarget
	MethodSig string
	FilePath  string
	// OriginalCode and OriginalHash are populated when a SmartPatch is bound to
	// a concrete parsed method. Without them ToPatchArtifact is preview-only.
	OriginalCode string
	OriginalHash string
	OriginalURL  string // для URLRedirect
	NewURL       string // для URLRedirect
	Confidence   float64
	Explanation  string
	Strategy     SmartPatchStrategy
}

// SmartPatchStrategy стратегия применения патча
type SmartPatchStrategy struct {
	Type     string   // "redirect_url", "return_true", "nop_call", "const_replace"
	ParamIdx int      // индекс параметра для замены (для const_replace)
	NewConst string   // новое значение константы
	Preserve []string // какие проверки сохранить
}

// BindSource attaches the exact parsed method body before application. This is
// deliberately explicit so a signature-only SmartPatch cannot silently replace
// an unrelated overloaded method.
func (sp *SmartPatch) BindSource(body []string) {
	if sp == nil {
		return
	}
	sp.OriginalCode = canonicalPatchText(strings.Join(body, "\n"))
	sp.OriginalHash = sha256Hex(sp.OriginalCode)
}

// SmartPatcher анализирует код и находит реальные цели для патчинга
type SmartPatcher struct {
	urlPatterns           []URLPattern
	sslPinningPatterns    []Pattern
	rootDetectionPatterns []Pattern
	signaturePatterns     []Pattern
	licensePatterns       []Pattern
	subscriptionPatterns  []Pattern
	loginPatterns         []Pattern
	jwtPatterns           []Pattern
	antiCheatPatterns     []Pattern
	extraDetectors        []detector
	redirectURL           string // target for TargetURLRedirect patches
}

// defaultRedirectURL is used when no redirect target was configured.
const defaultRedirectURL = "http://YOUR_SERVER/"

// SetRedirectURL configures the URL that TargetURLRedirect patches rewrite API
// endpoints to (e.g. a private interception server). Empty restores the default.
func (sp *SmartPatcher) SetRedirectURL(url string) {
	sp.redirectURL = strings.TrimSpace(url)
}

// effectiveRedirectURL returns the configured redirect target or the default.
func (sp *SmartPatcher) effectiveRedirectURL() string {
	if sp.redirectURL != "" {
		return sp.redirectURL
	}
	return defaultRedirectURL
}

// detector is a table-driven bypass rule: a group of patterns mapped to a
// target, a match threshold, and a default patch polarity. The actual polarity
// is refined per-method by inferBypassStrategy.
type detector struct {
	target      SmartPatchTarget
	patterns    []Pattern
	threshold   float64
	defaultType string // "return_true" | "return_false" | "return_void"
	label       string
}

// URLPattern паттерн для поиска URL
type URLPattern struct {
	Regex       *regexp.Regexp
	ServiceName string
	IsAPI       bool
}

// Pattern generic pattern для поиска
type Pattern struct {
	Name    string
	Strings []string
	Calls   []string
	Classes []string
}

// NewSmartPatcher создает умный патчер с предустановленными паттернами
func NewSmartPatcher() *SmartPatcher {
	return &SmartPatcher{
		urlPatterns: []URLPattern{
			{regexp.MustCompile(`https?://[a-zA-Z0-9.-]+\.[a-z]{2,}(/[a-zA-Z0-9._-]+)*`), "generic_url", true},
			{regexp.MustCompile(`api\.[a-zA-Z0-9.-]+\.[a-z]{2,}`), "api_endpoint", true},
			{regexp.MustCompile(`[a-zA-Z0-9-]+\.duolingo\.com`), "duolingo_api", true},
			{regexp.MustCompile(`[a-zA-Z0-9-]+\.googleapis\.com`), "google_api", true},
			{regexp.MustCompile(`firebase\.google\.com`), "firebase", true},
			{regexp.MustCompile(`crashlytics\.com`), "crashlytics", true},
			{regexp.MustCompile(`sentry\.io`), "sentry", true},
			{regexp.MustCompile(`appsflyer\.com`), "appsflyer", true},
			{regexp.MustCompile(`adjust\.com`), "adjust", true},
			{regexp.MustCompile(`braze\.com`), "braze", true},
			{regexp.MustCompile(`onesignal\.com`), "onesignal", true},
		},
		sslPinningPatterns: []Pattern{
			{
				Name:    "certificate_pinning",
				Strings: []string{"pin", "certificate", "sha256", "sha1", "X509", "TrustManager"},
				Calls:   []string{"checkServerTrusted", "getSSLCertificate", "pinning"},
				Classes: []string{"OkHttpClient", "CertificatePinner", "TrustManager", "X509TrustManager"},
			},
			{
				Name:    "hostname_verifier",
				Strings: []string{"hostname", "verifier", "verify"},
				Calls:   []string{"setHostnameVerifier", "verify"},
				Classes: []string{"HostnameVerifier"},
			},
			{
				Name:    "ssl_socket_factory",
				Strings: []string{"ssl", "socket", "factory"},
				Calls:   []string{"setSSLSocketFactory", "createSocket"},
				Classes: []string{"SSLSocketFactory"},
			},
		},
		rootDetectionPatterns: []Pattern{
			{
				Name:    "root_detection_basic",
				Strings: []string{"su", "busybox", "superuser", "magisk", "supersu"},
				Calls:   []string{"exists", "canExecute", "isRooted"},
				Classes: []string{"RootChecker", "RootDetection", "SafetyNet"},
			},
			{
				Name:    "root_detection_advanced",
				Strings: []string{"/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su"},
				Calls:   []string{"checkRootMethod", "isDeviceRooted"},
				Classes: []string{"RootBeer", "RootCloak"},
			},
			{
				Name:    "emulator_detection",
				Strings: []string{"generic", "sdk", "emulator", "simulator"},
				Calls:   []string{"isEmulator", "isRunningOnEmulator"},
				Classes: []string{"EmulatorDetector"},
			},
		},
		signaturePatterns: []Pattern{
			{
				Name:    "signature_verification",
				Strings: []string{"signature", "getPackageSignature", "SIGNATURE"},
				Calls:   []string{"getPackageSignature", "checkSignature", "verifySignature"},
				Classes: []string{"SignatureChecker", "AppProtector"},
			},
			{
				Name:    "tamper_detection",
				Strings: []string{"tamper", "modified", "integrity"},
				Calls:   []string{"isTampered", "checkIntegrity"},
				Classes: []string{"TamperDetector", "IntegrityChecker"},
			},
		},
		licensePatterns: []Pattern{
			{
				Name:    "license_check",
				Strings: []string{"license", "licensed", "Licensing"},
				Calls:   []string{"checkLicense", "isLicensed", "verifyLicense"},
				Classes: []string{"LicenseChecker", "LicenseValidator"},
			},
			{
				Name:    "pro_license",
				Strings: []string{"pro", "premium", "unlocked", "full"},
				Calls:   []string{"isPro", "isPremium", "isFullVersion"},
				Classes: []string{"LicenseManager"},
			},
		},
		subscriptionPatterns: []Pattern{
			{
				Name:    "subscription_check",
				Strings: []string{"subscription", "subscribe", "billing"},
				Calls:   []string{"checkSubscription", "isSubscribed", "getSubscription"},
				Classes: []string{"BillingClient", "BillingFlow", "InAppPurchase"},
			},
			{
				Name:    "purchase_validation",
				Strings: []string{"purchase", "purchased", "consume", "acknowledge"},
				Calls:   []string{"consumePurchase", "acknowledgePurchase"},
				Classes: []string{"PurchaseValidator"},
			},
		},
		loginPatterns: []Pattern{
			{
				Name:    "login_check",
				Strings: []string{"logged_in", "isLoggedIn", "authenticated"},
				Calls:   []string{"isLoggedIn", "isAuthenticated", "checkLogin"},
				Classes: []string{"AuthManager", "SessionManager"},
			},
			{
				Name:    "session_validation",
				Strings: []string{"session", "token", "expired"},
				Calls:   []string{"validateSession", "isSessionValid"},
				Classes: []string{"SessionValidator"},
			},
		},
		jwtPatterns: []Pattern{
			{
				Name:    "jwt_signature_bypass",
				Strings: []string{"jwt", "signature", "verify", "token"},
				Calls:   []string{"verifySignature", "isSignatureValid", "verify"},
				Classes: []string{"JWT", "TokenValidator", "Signature"},
			},
		},
		antiCheatPatterns: []Pattern{
			{
				Name:    "anticheat_init_block",
				Strings: []string{"anticheat", "tencent", "eac", "battleye"},
				Calls:   []string{"initAntiCheat", "startAntiCheatService", "init"},
				Classes: []string{"TssSdk", "AntiCheat", "EAC"},
			},
			{
				Name:    "anticheat_heartbeat_fake",
				Strings: []string{"heartbeat"},
				Calls:   []string{"sendHeartbeat", "onHeartbeatPulse"},
				Classes: []string{"Heartbeat", "AntiCheat"},
			},
		},
		extraDetectors: []detector{
			{
				target:      TargetIntegrityBypass,
				threshold:   0.7,
				defaultType: "return_true",
				label:       "Play Integrity / SafetyNet attestation",
				patterns: []Pattern{
					{
						Name:    "play_integrity",
						Strings: []string{"integrity", "attestation", "device_integrity", "meets_device_integrity", "ctsProfileMatch", "basicIntegrity"},
						Calls:   []string{"requestIntegrityToken", "isDeviceIntegrityMet", "verifyIntegrity", "attest"},
						Classes: []string{"IntegrityManager", "SafetyNet", "PlayIntegrity", "Attestation"},
					},
				},
			},
			{
				target:      TargetDebuggerBypass,
				threshold:   0.65,
				defaultType: "return_false",
				label:       "Debugger detection",
				patterns: []Pattern{
					{
						Name:    "debugger_detection",
						Strings: []string{"isdebuggerconnected", "debug.isdebugger", "tracerpid", "/proc/self/status", "debuggable"},
						Calls:   []string{"isDebuggerConnected", "waitingForDebugger", "detectDebugger", "checkDebugger"},
						Classes: []string{"Debug", "DebuggerDetector", "AntiDebug"},
					},
				},
			},
			{
				target:      TargetFridaBypass,
				threshold:   0.65,
				defaultType: "return_false",
				label:       "Frida / Xposed instrumentation detection",
				patterns: []Pattern{
					{
						Name:    "instrumentation_detection",
						Strings: []string{"frida", "xposed", "substrate", "gum-js-loop", "re.frida.server", "/data/local/tmp/frida", "libxposed"},
						Calls:   []string{"isFridaDetected", "detectFrida", "isXposedActive", "checkInstrumentation", "isHooked"},
						Classes: []string{"FridaDetector", "XposedDetector", "AntiHook", "InstrumentationCheck"},
					},
				},
			},
			{
				target:      TargetVPNProxyBypass,
				threshold:   0.7,
				defaultType: "return_false",
				label:       "VPN / proxy detection",
				patterns: []Pattern{
					{
						Name:    "vpn_proxy_detection",
						Strings: []string{"vpn", "tun0", "ppp0", "proxy", "http.proxyhost", "networkcapabilities"},
						Calls:   []string{"isVpnActive", "isVpnConnected", "detectProxy", "isProxySet", "hasTransport"},
						Classes: []string{"VpnDetector", "ProxyDetector", "NetworkChecker"},
					},
				},
			},
			{
				target:      TargetTrialBypass,
				threshold:   0.7,
				defaultType: "return_false",
				label:       "Trial / expiry / time-bomb check",
				patterns: []Pattern{
					{
						Name:    "trial_expiry",
						Strings: []string{"trial", "expired", "expiry", "expiration", "remaining_days", "time_bomb", "evaluation"},
						Calls:   []string{"isTrialExpired", "isExpired", "getRemainingDays", "checkTrial", "isEvaluationPeriod"},
						Classes: []string{"TrialManager", "ExpiryChecker", "LicenseClock"},
					},
				},
			},
			// ── New detectors ────────────────────────────────────────────────────
			{
				target:      TargetBiometricBypass,
				threshold:   0.65,
				defaultType: "return_true",
				label:       "Biometric authentication (fingerprint / face)",
				patterns: []Pattern{{
					Name:    "biometric_auth",
					Strings: []string{"biometric", "fingerprint", "face_auth", "biometricprompt", "fingerprintmanager", "biometricmanager", "canAuthenticate"},
					Calls:   []string{"authenticate", "onAuthenticationSucceeded", "canAuthenticate", "checkBiometric"},
					Classes: []string{"BiometricPrompt", "FingerprintManager", "BiometricManager", "BiometricHelper"},
				}},
			},
			{
				target:      TargetDeviceBindingBypass,
				threshold:   0.65,
				defaultType: "return_true",
				label:       "Device ID / IMEI binding check",
				patterns: []Pattern{{
					Name:    "device_binding",
					Strings: []string{"android_id", "device_id", "imei", "devicebinding", "device_fingerprint", "hardware_id", "device_hash", "bound_device"},
					Calls:   []string{"getDeviceId", "getImei", "getImsi", "getSubscriberId", "getAndroidId", "checkDeviceBinding"},
					Classes: []string{"TelephonyManager", "DeviceBinding", "HardwareID", "DeviceID", "DeviceChecker"},
				}},
			},
			{
				target:      TargetHardwareAttestation,
				threshold:   0.7,
				defaultType: "return_true",
				label:       "Hardware attestation (TEE / StrongBox / Keystore)",
				patterns: []Pattern{{
					Name:    "hardware_attestation",
					Strings: []string{"attestation", "strongbox", "tee", "hardware_attestation", "key_attestation", "securitylevel", "trusted_execution"},
					Calls:   []string{"generateKey", "getAttestationRecord", "getCertificateChain", "checkValidity", "attestKey"},
					Classes: []string{"KeyPairGenerator", "KeyStore", "Attestation", "KeyAttestation", "StrongBox", "AndroidKeyStore"},
				}},
			},
			{
				target:      TargetAppCloneBypass,
				threshold:   0.60,
				defaultType: "return_false",
				label:       "Clone app / dual space / multi-user detection",
				patterns: []Pattern{{
					Name:    "clone_detection",
					Strings: []string{"com.lbe.parallel", "com.ludashi.dualspace", "com.excelliance.dualaid", "com.iscope.iclone", "parallel_space", "virtualapp", "island", "work_profile", "clone_app", "multi_space"},
					Calls:   []string{"getUserId", "getUsers", "createPackageContextAsUser", "isUserAGoat", "getSecondaryUsers"},
					Classes: []string{"UserManager", "CloneDetect", "DualSpace", "VirtualApp", "ParallelSpace"},
				}},
			},
			{
				target:      TargetKernelSUBypass,
				threshold:   0.60,
				defaultType: "return_false",
				label:       "KernelSU / APatch / Zygisk Next root",
				patterns: []Pattern{{
					Name:    "kernelsu_apatch",
					Strings: []string{"kernelsu", "ksud", "/data/adb/ksud", "apatch", "apd", "/data/adb/apd", "magisk_kitsune", "zygisk_next", "ksu_version", "apatch_version"},
					Calls:   []string{"checkKernelSU", "isKernelSUInstalled", "detectKernelRoot", "getKSUVersion"},
					Classes: []string{"KernelSU", "APatch", "KernelRoot", "ZygiskNext"},
				}},
			},
			{
				target:      TargetLSPosedBypass,
				threshold:   0.60,
				defaultType: "return_false",
				label:       "LSPosed / Riru / EdXposed framework detection",
				patterns: []Pattern{{
					Name:    "lsposed_riru",
					Strings: []string{"lsposed", "lspatch", "riru", "edxposed", "taichi", "virtualxposed", "rirud", "org.lsposed.lspatch", "org.lsposed.manager", "io.github.lsposed"},
					Calls:   []string{"detectLSPosed", "isRiruInstalled", "checkEdXposed", "isLSPosedActive"},
					Classes: []string{"LSPosed", "Riru", "EdXposed", "Taichi", "VirtualXposed"},
				}},
			},
			{
				target:      TargetCertTransparency,
				threshold:   0.70,
				defaultType: "return_true",
				label:       "Certificate Transparency (OkHttp CT policy)",
				patterns: []Pattern{{
					Name:    "cert_transparency",
					Strings: []string{"certificate_transparency", "ct_policy", "sct", "log_list", "certificatetransparency", "enforce_ct", "google_ct", "ctverifier"},
					Calls:   []string{"checkCertificateTransparency", "verifyCT", "validateSCT", "checkCTPolicy"},
					Classes: []string{"CertificateTransparency", "CTVerifier", "CTPolicy", "CTLog", "OkHttpCTInterceptor"},
				}},
			},
			{
				target:      TargetOAuthBypass,
				threshold:   0.65,
				defaultType: "return_true",
				label:       "OAuth2 / OpenID Connect token validation",
				patterns: []Pattern{{
					Name:    "oauth_token",
					Strings: []string{"client_id", "client_secret", "redirect_uri", "authorization_code", "id_token", "access_token", "refresh_token", "code_verifier", "pkce", "openid"},
					Calls:   []string{"exchangeCodeForToken", "validateIdToken", "refreshAccessToken", "verifyOAuthToken", "introspectToken"},
					Classes: []string{"OAuthClient", "OAuth2", "OpenIDConnect", "IdToken", "TokenValidator", "AuthorizationRequest"},
				}},
			},
			{
				target:      TargetGeoBlockBypass,
				threshold:   0.65,
				defaultType: "return_false",
				label:       "Geographic restriction / region lock",
				patterns: []Pattern{{
					Name:    "geo_restriction",
					Strings: []string{"country_code", "geo_block", "region_lock", "restricted_country", "allowed_countries", "blocked_regions", "unsupported_region", "geocheck"},
					Calls:   []string{"isRegionAllowed", "checkCountry", "isGeoBlocked", "getCountryCode", "detectRegion", "isCountryRestricted"},
					Classes: []string{"GeoChecker", "RegionLock", "CountryValidator", "LocaleFilter", "RegionDetector"},
				}},
			},
			{
				target:      TargetDeviceFarmBypass,
				threshold:   0.60,
				defaultType: "return_false",
				label:       "Device farm / UIAutomator / automation detection",
				patterns: []Pattern{{
					Name:    "device_farm",
					Strings: []string{"uiautomator", "espresso", "robotium", "appium", "monkeyrunner", "testlab", "firebase_test_lab", "automated_testing", "ui_testing"},
					Calls:   []string{"isUiAutomationEnabled", "detectAutomation", "isTestEnvironment", "checkDeviceFarm", "isInstrumentationEnabled"},
					Classes: []string{"UiAutomation", "InstrumentationRegistry", "TestFarm", "DeviceFarm", "AutomationDetect"},
				}},
			},
			{
				target:      TargetSpeedHackBypass,
				threshold:   0.65,
				defaultType: "return_false",
				label:       "Game speed-hack / frame-time manipulation",
				patterns: []Pattern{{
					Name:    "speed_hack",
					Strings: []string{"speed_hack", "game_speed", "speedhack", "timescale", "speed_multiplier", "clock_drift", "frame_time_anomaly", "speeddetect"},
					Calls:   []string{"detectSpeedHack", "checkGameSpeed", "isSpeedHackActive", "verifyFrameTime", "checkTimeDrift"},
					Classes: []string{"SpeedHackDetector", "GameSpeed", "FrameTimer", "AntiSpeedHack", "ClockChecker"},
				}},
			},
			{
				target:      TargetScreenOverlayBypass,
				threshold:   0.65,
				defaultType: "return_false",
				label:       "Screen overlay / canDrawOverlays detection",
				patterns: []Pattern{{
					Name:    "screen_overlay",
					Strings: []string{"candrawoverlays", "type_application_overlay", "system_alert_window", "overlay_detected", "draw_over_other_apps", "overlay_attack"},
					Calls:   []string{"canDrawOverlays", "checkOverlay", "detectOverlay", "isOverlayActive", "hasOverlayPermission"},
					Classes: []string{"OverlayDetect", "OverlayCheck", "WindowSecurity", "ScreenProtect"},
				}},
			},
			{
				target:      TargetAdRemove,
				threshold:   0.5,
				defaultType: "return_false",
				label:       "Advertisement SDK / ad decision point",
				patterns: []Pattern{
					{
						Name:    "ad_sdk",
						Strings: []string{"admob", "applovin", "unityads", "ironsource", "vungle", "adcolony", "mopub", "inmobi", "chartboost", "rewarded", "interstitial", "banner_ad"},
						Calls:   []string{"loadAd", "showAd", "showRewardedAd", "shouldShowAd", "isAdLoaded", "loadRewardedAd", "showInterstitial"},
						Classes: []string{"AdView", "AdLoader", "InterstitialAd", "RewardedAd", "PseudoAd", "AdController", "Admob", "Applovin", "UnityAds", "Ironsource"},
					},
					{
						Name:    "ad_decision",
						Strings: []string{"shouldshowad", "isadfree", "ad_loaded", "adfree", "no_ads", "remove_ads", "premium_no_ads"},
						Calls:   []string{"shouldShowAd", "isAdFree", "hasAds", "isAdEnabled"},
						Classes: []string{"AdController", "AdGate", "AdManager"},
					},
				},
			},
		},
	}
}

// AnalyzeMethod анализирует метод и возвращает найденные патчи
func (sp *SmartPatcher) AnalyzeMethod(method *PatchPoint) []SmartPatch {
	patches := make([]SmartPatch, 0)
	body := joinBody(method.MethodBody)

	// Анализ URL в строковых константах метода
	if urlPatches := sp.findURLPatches(method, body); len(urlPatches) > 0 {
		patches = append(patches, urlPatches...)
	}

	// Анализ SSL pinning
	if sslPatch := sp.findSSLPatch(method, body); sslPatch != nil {
		patches = append(patches, *sslPatch)
	}

	// Анализ root detection
	if rootPatch := sp.findRootPatch(method, body); rootPatch != nil {
		patches = append(patches, *rootPatch)
	}

	// Анализ signature verification
	if sigPatch := sp.findSignaturePatch(method, body); sigPatch != nil {
		patches = append(patches, *sigPatch)
	}

	// Анализ license/subscription/login
	if licensePatch := sp.findLicensePatch(method, body); licensePatch != nil {
		patches = append(patches, *licensePatch)
	}

	// Анализ JWT
	if jwtPatch := sp.findJWTPatch(method, body); jwtPatch != nil {
		patches = append(patches, *jwtPatch)
	}

	// Анализ AntiCheat
	if acPatch := sp.findAntiCheatPatch(method, body); acPatch != nil {
		patches = append(patches, *acPatch)
	}

	// Табличные детекторы: integrity / debugger / frida / vpn / trial
	for i := range sp.extraDetectors {
		if p := sp.findByDetector(method, body, &sp.extraDetectors[i]); p != nil {
			patches = append(patches, *p)
		}
	}

	return normalizeSmartCandidates(method, patches)
}

// normalizeSmartCandidates makes detector output safe for the actual Dalvik
// return descriptor, merges duplicate independent detections, and ranks the
// result deterministically. This prevents a high text-match score from
// producing an invalid object/wide/void return patch.
func normalizeSmartCandidates(method *PatchPoint, candidates []SmartPatch) []SmartPatch {
	merged := make(map[string]SmartPatch, len(candidates))
	order := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		originalStrategy := candidate.Strategy.Type
		candidate.Strategy.Type = compatibleSmartStrategy(method.MethodSignature, candidate.Strategy.Type)
		if candidate.Strategy.Type != originalStrategy {
			candidate.Confidence -= 0.05
			candidate.Explanation += fmt.Sprintf("; strategy normalized %s→%s for %s", originalStrategy, candidate.Strategy.Type, methodReturnType(method.MethodSignature))
		}
		if methodReturnType(method.MethodSignature) == "" {
			candidate.Confidence -= 0.15
			candidate.Explanation += "; unknown return descriptor requires review"
		}
		if method.IsLibraryCode && !method.IsAppCode {
			candidate.Confidence *= 0.85
			candidate.Explanation += "; library-code confidence penalty"
		}
		candidate.Confidence = clampSmartConfidence(candidate.Confidence)
		key := fmt.Sprintf("%d|%s|%s|%s", candidate.Target, candidate.Strategy.Type, candidate.OriginalURL, candidate.Strategy.NewConst)
		if previous, exists := merged[key]; exists {
			previous.Confidence = clampSmartConfidence(1 - (1-previous.Confidence)*(1-candidate.Confidence))
			if !strings.Contains(previous.Explanation, candidate.Explanation) {
				previous.Explanation += "; corroborated by " + candidate.Explanation
			}
			merged[key] = previous
			continue
		}
		merged[key] = candidate
		order = append(order, key)
	}

	result := make([]SmartPatch, 0, len(order))
	for _, key := range order {
		result = append(result, merged[key])
	}
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].Confidence == result[j].Confidence {
			if result[i].Target == result[j].Target {
				return result[i].Strategy.Type < result[j].Strategy.Type
			}
			return result[i].Target < result[j].Target
		}
		return result[i].Confidence > result[j].Confidence
	})
	return result
}

func compatibleSmartStrategy(signature, strategy string) string {
	switch strategy {
	case "const_replace", "redirect_url", "nop_call":
		return strategy
	}
	switch methodReturnType(signature) {
	case "V":
		return "return_void"
	case "Z", "B", "S", "C", "I":
		if strategy == "return_true" || strategy == "return_false" {
			return strategy
		}
		return "return_default"
	case "J", "D", "F":
		return "return_default"
	case "":
		return strategy
	default:
		return "return_null"
	}
}

func clampSmartConfidence(value float64) float64 {
	if value < 0 {
		return 0
	}
	if value > 0.99 {
		return 0.99
	}
	return value
}

// findByDetector runs a table-driven detector against a method, choosing the
// best-matching pattern and inferring the correct patch polarity from the
// method name (e.g. isRooted→return_false, isLicensed→return_true).
func (sp *SmartPatcher) findByDetector(method *PatchPoint, body string, d *detector) *SmartPatch {
	className := method.ClassName

	best := 0.0
	var bestName string
	for _, pattern := range d.patterns {
		score := sp.matchPattern(body, className, pattern)
		if nameScore := sp.matchMethodName(method.MethodName, pattern); nameScore > 0 {
			score = (score + nameScore) / 2
		}
		if score > best {
			best = score
			bestName = pattern.Name
		}
	}
	if best < d.threshold {
		return nil
	}
	return &SmartPatch{
		Target:      d.target,
		MethodSig:   method.MethodSignature,
		FilePath:    method.FilePath,
		Confidence:  best,
		Explanation: fmt.Sprintf("%s: %s", d.label, bestName),
		Strategy:    SmartPatchStrategy{Type: inferBypassStrategy(method, d.defaultType)},
	}
}

var (
	negativePolarityWords = []string{"root", "debug", "frida", "xposed", "hook", "emulator",
		"tamper", "vpn", "proxy", "expired", "expire", "trial", "cheat",
		"detect", "blocked", "pirat", "crack", "instrument", "jailbr", "magisk"}
	positivePolarityWords = []string{"licensed", "premium", "valid", "verified", "integrity",
		"authoriz", "authorised", "authorized", "safe", "genuine", "subscribed", "purchased", "trusted"}
)

// inferBypassStrategy picks the patch polarity from the return type AND the
// method's name+body, not just its name. Void methods become no-ops; object
// getters are neutralised to null; primitive predicates are forced to the value
// that disables the check — "detected-something-bad" predicates to false,
// "looks-authorised" predicates to true. The body is tallied (weight 1) on top
// of the name (weight 3) so a generically-named method is still classified from
// the keywords it actually references.
func inferBypassStrategy(method *PatchPoint, fallback string) string {
	rt := methodReturnType(method.MethodSignature)
	if rt == "V" {
		return "return_void"
	}
	isObject := strings.HasPrefix(rt, "L") || strings.HasPrefix(rt, "[")

	neg, pos := 0, 0
	name := strings.ToLower(method.MethodName)
	for _, w := range negativePolarityWords {
		if strings.Contains(name, w) {
			neg += 3
		}
	}
	for _, w := range positivePolarityWords {
		if strings.Contains(name, w) {
			pos += 3
		}
	}
	body := strings.ToLower(joinBody(method.MethodBody))
	for _, w := range negativePolarityWords {
		if strings.Contains(body, w) {
			neg++
		}
	}
	for _, w := range positivePolarityWords {
		if strings.Contains(body, w) {
			pos++
		}
	}

	switch {
	case isObject:
		// Returning a benign null typically disables an object-returning probe
		// (token providers, detector handles); we can't synthesize a valid one.
		return "return_null"
	case neg > pos:
		return "return_false"
	case pos > neg:
		return "return_true"
	default:
		return fallback
	}
}

// methodReturnType extracts the return descriptor (e.g. "Z", "V",
// "Ljava/lang/String;") from a smali method signature.
func methodReturnType(sig string) string {
	idx := strings.LastIndex(sig, ")")
	if idx < 0 || idx+1 >= len(sig) {
		return ""
	}
	return sig[idx+1:]
}

// joinBody объединяет MethodBody []string в одну строку
func joinBody(body []string) string {
	return strings.Join(body, "\n")
}

// findURLPatches ищет URL для редиректа
func (sp *SmartPatcher) findURLPatches(method *PatchPoint, body string) []SmartPatch {
	patches := make([]SmartPatch, 0)

	for _, pattern := range sp.urlPatterns {
		matches := pattern.Regex.FindAllString(body, -1)
		for _, url := range matches {
			redirect := sp.effectiveRedirectURL()
			patch := SmartPatch{
				Target:      TargetURLRedirect,
				MethodSig:   method.MethodSignature,
				FilePath:    method.FilePath,
				OriginalURL: url,
				NewURL:      redirect,
				Confidence:  0.85,
				Explanation: fmt.Sprintf("Found API URL: %s (service: %s)", url, pattern.ServiceName),
				Strategy: SmartPatchStrategy{
					Type:     "const_replace",
					NewConst: redirect,
				},
			}
			patches = append(patches, patch)
		}
	}

	return patches
}

// findSSLPatch ищет SSL pinning для отключения
func (sp *SmartPatcher) findSSLPatch(method *PatchPoint, body string) *SmartPatch {
	className := method.ClassName

	for _, pattern := range sp.sslPinningPatterns {
		score := sp.matchPattern(body, className, pattern)
		if score >= 0.7 {
			// Для TrustManager.checkServerTrusted - return void или true
			strategyType := inferBypassStrategy(method, "return_true")
			if strings.Contains(method.MethodSignature, "checkServerTrusted") {
				strategyType = "return_void"
			}

			return &SmartPatch{
				Target:      TargetSSLBypass,
				MethodSig:   method.MethodSignature,
				FilePath:    method.FilePath,
				Confidence:  score,
				Explanation: fmt.Sprintf("SSL Pinning detected: %s", pattern.Name),
				Strategy:    SmartPatchStrategy{Type: strategyType},
			}
		}
	}

	return nil
}

// findRootPatch ищет root detection для bypass
func (sp *SmartPatcher) findRootPatch(method *PatchPoint, body string) *SmartPatch {
	className := method.ClassName

	for _, pattern := range sp.rootDetectionPatterns {
		score := sp.matchPattern(body, className, pattern)
		if score >= 0.75 {
			return &SmartPatch{
				Target:      TargetRootBypass,
				MethodSig:   method.MethodSignature,
				FilePath:    method.FilePath,
				Confidence:  score,
				Explanation: fmt.Sprintf("Root detection detected: %s", pattern.Name),
				// Polarity inferred from name+body: "isRooted"-style probes →
				// return_false, "isSafeToRun"-style → return_true.
				Strategy: SmartPatchStrategy{Type: inferBypassStrategy(method, "return_false")},
			}
		}
	}

	return nil
}

// findSignaturePatch ищет signature verification
func (sp *SmartPatcher) findSignaturePatch(method *PatchPoint, body string) *SmartPatch {
	className := method.ClassName

	for _, pattern := range sp.signaturePatterns {
		score := sp.matchPattern(body, className, pattern)
		if score >= 0.8 {
			return &SmartPatch{
				Target:      TargetSignatureBypass,
				MethodSig:   method.MethodSignature,
				FilePath:    method.FilePath,
				Confidence:  score,
				Explanation: fmt.Sprintf("Signature/Tamper detection: %s", pattern.Name),
				// "verifySignature" → return_true, but a "detected-bad" probe
				// like isTampered must return FALSE — returning true would
				// confirm tampering and brick the app.
				Strategy: SmartPatchStrategy{Type: inferBypassStrategy(method, "return_true")},
			}
		}
	}

	return nil
}

// findLicensePatch ищет license/subscription/login checks
func (sp *SmartPatcher) findLicensePatch(method *PatchPoint, body string) *SmartPatch {
	className := method.ClassName
	methodName := method.MethodName

	// Проверяем license patterns
	for _, pattern := range sp.licensePatterns {
		score := sp.matchPattern(body, className, pattern)
		// Также проверяем имя метода
		if nameScore := sp.matchMethodName(methodName, pattern); nameScore > 0 {
			score = (score + nameScore) / 2
		}
		if score >= 0.7 {
			return &SmartPatch{
				Target:      TargetLicenseBypass,
				MethodSig:   method.MethodSignature,
				FilePath:    method.FilePath,
				Confidence:  score,
				Explanation: fmt.Sprintf("License check: %s", pattern.Name),
				Strategy:    SmartPatchStrategy{Type: inferBypassStrategy(method, "return_true")},
			}
		}
	}

	// Проверяем subscription patterns
	for _, pattern := range sp.subscriptionPatterns {
		score := sp.matchPattern(body, className, pattern)
		if nameScore := sp.matchMethodName(methodName, pattern); nameScore > 0 {
			score = (score + nameScore) / 2
		}
		if score >= 0.7 {
			return &SmartPatch{
				Target:      TargetSubscriptionBypass,
				MethodSig:   method.MethodSignature,
				FilePath:    method.FilePath,
				Confidence:  score,
				Explanation: fmt.Sprintf("Subscription check: %s", pattern.Name),
				Strategy:    SmartPatchStrategy{Type: inferBypassStrategy(method, "return_true")},
			}
		}
	}

	// Проверяем login patterns
	for _, pattern := range sp.loginPatterns {
		score := sp.matchPattern(body, className, pattern)
		if nameScore := sp.matchMethodName(methodName, pattern); nameScore > 0 {
			score = (score + nameScore) / 2
		}
		if score >= 0.7 {
			return &SmartPatch{
				Target:      TargetLoginBypass,
				MethodSig:   method.MethodSignature,
				FilePath:    method.FilePath,
				Confidence:  score,
				Explanation: fmt.Sprintf("Login check: %s", pattern.Name),
				Strategy:    SmartPatchStrategy{Type: inferBypassStrategy(method, "return_true")},
			}
		}
	}

	return nil
}

// findJWTPatch ищет JWT signature check для bypass
func (sp *SmartPatcher) findJWTPatch(method *PatchPoint, body string) *SmartPatch {
	className := method.ClassName

	for _, pattern := range sp.jwtPatterns {
		score := sp.matchPattern(body, className, pattern)
		if score >= 0.75 {
			return &SmartPatch{
				Target:      TargetJWTBypass,
				MethodSig:   method.MethodSignature,
				FilePath:    method.FilePath,
				Confidence:  score,
				Explanation: fmt.Sprintf("JWT validation bypass: %s", pattern.Name),
				Strategy:    SmartPatchStrategy{Type: inferBypassStrategy(method, "return_true")},
			}
		}
	}

	return nil
}

// findAntiCheatPatch ищет AntiCheat проверки
func (sp *SmartPatcher) findAntiCheatPatch(method *PatchPoint, body string) *SmartPatch {
	className := method.ClassName

	for _, pattern := range sp.antiCheatPatterns {
		score := sp.matchPattern(body, className, pattern)
		if score >= 0.7 {
			// Polarity from name+body: a "detected-cheat" probe (isCheatTool)
			// must return FALSE — returning true would flag the player; void
			// probes (heartbeat) become no-ops.
			return &SmartPatch{
				Target:      TargetAntiCheatBypass,
				MethodSig:   method.MethodSignature,
				FilePath:    method.FilePath,
				Confidence:  score,
				Explanation: fmt.Sprintf("AntiCheat detected: %s", pattern.Name),
				Strategy:    SmartPatchStrategy{Type: inferBypassStrategy(method, "return_void")},
			}
		}
	}

	return nil
}

// matchPattern оценивает соответствие паттерну.
//
// Сопоставление идёт по границам токенов: короткие маркеры ("su", "pin",
// "vpn") больше не матчатся внутри посторонних слов ("result", "spinning",
// "consume"), что раньше накручивало confidence детекторов.
func (sp *SmartPatcher) matchPattern(body, className string, pattern Pattern) float64 {
	score := 0.0
	matches := 0

	bodyLower := strings.ToLower(body)
	classLower := strings.ToLower(className)

	// Проверяем строки
	for _, s := range pattern.Strings {
		if tokenContains(bodyLower, strings.ToLower(s)) {
			matches++
		}
	}
	if len(pattern.Strings) > 0 {
		strScore := float64(matches) / float64(len(pattern.Strings))
		if strScore == 1.0 {
			score += 0.5 // Bonus for all strings matching
		} else {
			score += strScore * 0.4
		}
	}

	// Проверяем вызовы
	matches = 0
	for _, call := range pattern.Calls {
		if tokenContains(body, call) {
			matches++
		}
	}
	if len(pattern.Calls) > 0 {
		callScore := float64(matches) / float64(len(pattern.Calls))
		if callScore == 1.0 {
			score += 0.4 // Bonus for all calls matching
		} else {
			score += callScore * 0.3
		}
	}

	// Проверяем классы
	for _, cls := range pattern.Classes {
		if tokenContains(classLower, strings.ToLower(cls)) {
			score += 0.4 // Increased class weight
			break
		}
	}

	// Clamp to a valid confidence: string(0.5)+call(0.4)+class(0.4) can exceed 1.0.
	if score > 1.0 {
		score = 1.0
	}
	return score
}

// tokenContains reports whether needle occurs in haystack at token boundaries:
// the characters immediately before and after the occurrence must not be
// identifier bytes (letters/digits). Separators like '/', '.', '-', '_', '"'
// and '(' count as boundaries, so "/system/bin/su" matches "su" while
// "result" and "consumePurchase" do not.
func tokenContains(haystack, needle string) bool {
	if needle == "" {
		return false
	}
	idx := 0
	for {
		pos := strings.Index(haystack[idx:], needle)
		if pos < 0 {
			return false
		}
		pos += idx
		before := pos == 0 || !isPatternIdentByte(haystack[pos-1])
		end := pos + len(needle)
		after := end >= len(haystack) || !isPatternIdentByte(haystack[end])
		if before && after {
			return true
		}
		idx = pos + 1
	}
}

func isPatternIdentByte(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// matchMethodName проверяет имя метода на соответствие паттерну
func (sp *SmartPatcher) matchMethodName(methodName string, pattern Pattern) float64 {
	methodLower := strings.ToLower(methodName)

	for _, call := range pattern.Calls {
		if strings.Contains(methodLower, strings.ToLower(call)) {
			return 1.0
		}
	}

	for _, s := range pattern.Strings {
		if strings.Contains(methodLower, strings.ToLower(s)) {
			return 0.8
		}
	}

	return 0.0
}

// SmartPatchType для внутреннего использования
type SmartPatchType int

const (
	SmartPatchReturnTrue SmartPatchType = iota
	SmartPatchReturnFalse
	SmartPatchReturnVoid
	SmartPatchConstReplace
)

// ToPatchArtifact конвертирует SmartPatch в PatchArtifact для применения
func (sp *SmartPatch) ToPatchArtifact() *PatchArtifact {
	// Генерируем patched code
	patchedCode := sp.generatePatchedCode()

	methodName := sp.getMethodName()
	patchedCode = canonicalPatchText(patchedCode)
	validation := NewSmaliValidator().ValidateStrict(patchedCode)
	// SmartPatch only carries a signature, not the original method body. It can
	// produce a preview, but it cannot safely write an artifact until the
	// artifact is bound to a concrete source body and OriginalHash.
	canWrite := sp.Confidence >= 0.7 && patchedCode != "" && validation.Valid && sp.hasBoundSource()
	level := sp.getSafetyLevel()
	if !validation.Valid {
		level = "blocked"
	}
	reasons := []string{sp.Explanation}
	if !sp.hasBoundSource() {
		level = "blocked"
		reasons = append(reasons, "original method body is unavailable; bind artifact before apply")
	}
	if !validation.Valid {
		reasons = append(reasons, "generated smali failed strict validation")
	}
	if sp.Strategy.Type == "const_replace" && sp.NewURL == defaultRedirectURL {
		canWrite = false
		level = "blocked"
		reasons = append(reasons, "redirect target is the default placeholder; configure SetRedirectURL")
	}
	artifact := &PatchArtifact{
		SchemaVersion:   "2.0.0",
		MethodName:      methodName,
		FilePath:        sp.FilePath,
		MethodSignature: sp.MethodSig,
		OriginalCode:    sp.OriginalCode,
		PatchedCode:     patchedCode,
		OriginalHash:    sp.OriginalHash,
		PatchedHash:     sha256Hex(patchedCode),
		Validation:      validation,
		ApplySafety: ApplySafety{
			Safe:     canWrite,
			Level:    level,
			CanWrite: canWrite,
			Reasons:  reasons,
		},
	}

	artifact.PatchID = stablePatchID(artifact.FilePath, artifact.MethodName, artifact.MethodSignature, artifact.OriginalHash)
	// Заполняем UnifiedDiff
	artifact.UnifiedDiff = sp.generateUnifiedDiff(patchedCode)

	return artifact
}

func (sp *SmartPatch) hasBoundSource() bool {
	return sp != nil && strings.TrimSpace(sp.OriginalCode) != "" && strings.TrimSpace(sp.OriginalHash) != ""
}

// generatePatchedCode генерирует пропатченный код
func (sp *SmartPatch) generatePatchedCode() string {
	if sp == nil {
		return ""
	}
	// SmartPatcher used to maintain a second hand-written Smali generator with
	// fixed .registers counts. Route all return stubs through the shared typed
	// builder so instance/wide parameters and return descriptors are handled in
	// one place.
	desc := sp.getMethodDesc()
	returnType := effectiveReturnType("", desc, "")
	header := ".method public " + sp.getMethodName() + desc
	switch sp.Strategy.Type {
	case "return_true":
		if returnType != "Z" {
			return ""
		}
		return BuildTypedReturnPatch(header, desc, returnType, PatchReturnTrue)
	case "return_false":
		if returnType != "Z" {
			return ""
		}
		return BuildTypedReturnPatch(header, desc, returnType, PatchReturnFalse)
	case "return_void":
		return BuildTypedReturnPatch(header, desc, returnType, PatchReturnVoid)
	case "return_null":
		if !strings.HasPrefix(returnType, "L") && !strings.HasPrefix(returnType, "[") {
			return ""
		}
		return BuildTypedReturnPatch(header, desc, returnType, PatchReturnFalse)
	case "const_replace":
		// URL redirect: rewrite the URL occurrences inside the BOUND source
		// body. This is offset-safe — const-string is a fixed-size (21c)
		// instruction whose payload lives in the string pool, so changing the
		// literal never shifts code-unit layout. Without a bound source (or
		// when the URL does not appear verbatim) we refuse rather than
		// synthesize a fake method.
		if sp.OriginalCode == "" || sp.OriginalURL == "" || sp.NewURL == "" {
			return ""
		}
		if !strings.Contains(sp.OriginalCode, sp.OriginalURL) {
			return ""
		}
		return strings.ReplaceAll(sp.OriginalCode, sp.OriginalURL, sp.NewURL)
	default:
		return ""
	}
}

// getMethodName извлекает имя метода из сигнатуры
func (sp *SmartPatch) getMethodName() string {
	parts := strings.Split(sp.MethodSig, "->")
	if len(parts) < 2 {
		return "unknown"
	}
	nameAndDesc := strings.Split(parts[1], "(")
	return nameAndDesc[0]
}

// getMethodDesc извлекает дескриптор метода
func (sp *SmartPatch) getMethodDesc() string {
	parts := strings.Split(sp.MethodSig, "->")
	if len(parts) < 2 {
		return "()V"
	}
	idx := strings.Index(parts[1], "(")
	if idx < 0 {
		return "()V"
	}
	return parts[1][idx:]
}

// getSafetyLevel возвращает уровень безопасности
func (sp *SmartPatch) getSafetyLevel() string {
	if sp.Confidence >= 0.9 {
		return "safe"
	}
	if sp.Confidence >= 0.7 {
		return "review"
	}
	return "blocked"
}

// generateUnifiedDiff создаёт настоящий unified diff между привязанным исходником
// и сгенерированным кодом: общий префикс/суфффикс сворачиваются в контекст,
// меняется только реальный изменённый блок. Формат парсится
// extractOriginalFromUnifiedDiff / extractPatchedFromUnifiedDiff.
func (sp *SmartPatch) generateUnifiedDiff(patchedCode string) string {
	return buildSmartUnifiedDiff(sp.FilePath, sp.OriginalCode, patchedCode)
}

// buildSmartUnifiedDiff renders a minimal unified diff: lines common to both
// sides become context, only the changed middle block is emitted as -/+ lines.
func buildSmartUnifiedDiff(filePath, original, patched string) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("--- a/%s\n", filePath))
	b.WriteString(fmt.Sprintf("+++ b/%s\n", filePath))

	origLines := strings.Split(strings.TrimRight(original, "\n"), "\n")
	patchLines := strings.Split(strings.TrimRight(patched, "\n"), "\n")

	pre := 0
	for pre < len(origLines) && pre < len(patchLines) && origLines[pre] == patchLines[pre] {
		pre++
	}
	suf := 0
	for suf < len(origLines)-pre && suf < len(patchLines)-pre &&
		origLines[len(origLines)-1-suf] == patchLines[len(patchLines)-1-suf] {
		suf++
	}
	if pre+suf >= len(origLines) && pre+suf >= len(patchLines) {
		return strings.TrimRight(b.String(), "\n") // identical
	}

	const ctx = 3
	start := pre - ctx
	if start < 0 {
		start = 0
	}
	// Context after the change may only extend INTO the common suffix —
	// deeper lines may legitimately differ between the two sides.
	afterCtx := suf
	if afterCtx > ctx {
		afterCtx = ctx
	}

	countO := (pre - start) + (len(origLines) - suf - pre) + afterCtx
	countP := (pre - start) + (len(patchLines) - suf - pre) + afterCtx

	b.WriteString(fmt.Sprintf("@@ -%d,%d +%d,%d @@\n", start+1, countO, start+1, countP))

	write := func(prefix byte, line string) {
		b.WriteByte(prefix)
		b.WriteString(line)
		b.WriteByte('\n')
	}
	for _, line := range origLines[start:pre] {
		write(' ', line)
	}
	for _, line := range origLines[pre : len(origLines)-suf] {
		write('-', line)
	}
	for _, line := range patchLines[pre : len(patchLines)-suf] {
		write('+', line)
	}
	for _, line := range origLines[len(origLines)-suf : len(origLines)-suf+afterCtx] {
		write(' ', line)
	}
	return b.String()
}

// TargetName возвращает человекочитаемое имя цели
func (t SmartPatchTarget) TargetName() string {
	names := map[SmartPatchTarget]string{
		TargetURLRedirect:         "URL Redirect",
		TargetSSLBypass:           "SSL Pinning Bypass",
		TargetRootBypass:          "Root Detection Bypass",
		TargetSignatureBypass:     "Signature Verification Bypass",
		TargetLicenseBypass:       "License Check Bypass",
		TargetSubscriptionBypass:  "Subscription Bypass",
		TargetLoginBypass:         "Login Check Bypass",
		TargetAdRemove:            "Advertisement Removal",
		TargetJWTBypass:           "JWT Signature Bypass",
		TargetAntiCheatBypass:     "Anti-Cheat Bypass",
		TargetIntegrityBypass:     "Play Integrity / SafetyNet Bypass",
		TargetDebuggerBypass:      "Debugger Detection Bypass",
		TargetFridaBypass:         "Frida / Xposed Detection Bypass",
		TargetVPNProxyBypass:      "VPN / Proxy Detection Bypass",
		TargetTrialBypass:         "Trial / Expiry Bypass",
		TargetBiometricBypass:     "Biometric Auth Bypass",
		TargetDeviceBindingBypass: "Device Binding Bypass",
		TargetHardwareAttestation: "Hardware Attestation Bypass",
		TargetAppCloneBypass:      "Clone App Detection Bypass",
		TargetKernelSUBypass:      "KernelSU / APatch Bypass",
		TargetLSPosedBypass:       "LSPosed / Riru Bypass",
		TargetCertTransparency:    "Certificate Transparency Bypass",
		TargetOAuthBypass:         "OAuth2 Token Bypass",
		TargetGeoBlockBypass:      "Geo-Block Bypass",
		TargetDeviceFarmBypass:    "Device Farm Detection Bypass",
		TargetSpeedHackBypass:     "Speed Hack Detection Bypass",
		TargetScreenOverlayBypass: "Screen Overlay Detection Bypass",
	}
	if name, ok := names[t]; ok {
		return name
	}
	return "Unknown"
}
