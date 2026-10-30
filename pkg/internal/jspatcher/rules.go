package jspatcher

// AllRules is the full detection rule set — 60+ rules across all categories.
// Rules are ordered roughly by category priority (server, premium, license …).
var AllRules = []JSPatchRule{

	// ═══════════════════════════════════════════════════════════════════════════
	// SERVER — hardcoded backend addresses and WebSocket endpoints
	// ═══════════════════════════════════════════════════════════════════════════

	{
		ID:          "server_base_url",
		Category:    CategoryServer,
		Name:        "Base URL Assignment",
		Description: "Hardcoded server base URL assigned to a variable",
		Patterns: []string{
			`(?i)\b(baseURL|base_url|serverUrl|server_url|apiUrl|api_url|apiEndpoint|apiHost|serverHost|SERVER_URL|API_URL|API_BASE|API_HOST)\s*[:=]\s*["` + "`" + `'](https?://[-a-zA-Z0-9./?=&%#_~:+]{4,200})`,
		},
		ContextBoosts:    []string{`axios`, `fetch\(`, `XMLHttpRequest`, `https?://`, `config\b`},
		ContextPenalties: []string{`// mock`, `// test`, `localhost`},
		DefaultStrategy:  StrategyReplaceURL,
		BaseConfidence:   82,
		ImpactNote:       "All API requests will be redirected to the new server",
		SymbolCapture:    1,
	},
	{
		ID:          "server_websocket",
		Category:    CategoryServer,
		Name:        "WebSocket Endpoint",
		Description: "Hardcoded WebSocket (wss:// or ws://) server endpoint",
		Patterns: []string{
			`(?i)(wss?://[a-zA-Z0-9.-]+(?::\d{1,5})?(?:/[-a-zA-Z0-9./?=&%#_~:+]{0,100})?)`,
		},
		ContextBoosts:    []string{`WebSocket`, `io\.connect`, `socket\.io`, `new WebSocket`},
		ContextPenalties: []string{`// `, `\* `},
		DefaultStrategy:  StrategyReplaceURL,
		BaseConfidence:   80,
		ImpactNote:       "Real-time communication will be redirected",
	},
	{
		ID:          "server_ip_literal",
		Category:    CategoryServer,
		Name:        "Hardcoded IP Address",
		Description: "Raw IPv4 address in string (potential production server)",
		Patterns: []string{
			`["` + "`" + `']((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?))(?::\d{1,5})?["` + "`" + `']`,
		},
		ContextBoosts:    []string{`connect\(`, `host\b`, `server\b`, `endpoint\b`, `socket`},
		ContextPenalties: []string{`127\.0\.0\.1`, `0\.0\.0\.0`, `255\.255`, `192\.168`, `10\.0\.`},
		DefaultStrategy:  StrategyReplaceURL,
		BaseConfidence:   65,
		ImpactNote:       "Network connections to this IP will be redirected",
	},
	{
		ID:          "server_ssl_host",
		Category:    CategoryServer,
		Name:        "SSL/TLS Host Header",
		Description: "Hardcoded hostname used for HTTPS connections",
		Patterns: []string{
			`(?i)(hostname|host|serverHost|apiDomain|domain)\s*[:=]\s*["` + "`" + `']([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})["` + "`" + `']`,
		},
		ContextBoosts:    []string{`ssl`, `tls`, `certificate`, `pinning`, `https`, `443`},
		ContextPenalties: []string{`localhost`, `example\.com`, `test\.com`},
		DefaultStrategy:  StrategyReplaceURL,
		BaseConfidence:   60,
		ImpactNote:       "TLS/HTTPS host will be replaced",
		SymbolCapture:    1,
	},
	{
		ID:          "server_api_url_literal",
		Category:    CategoryServer,
		Name:        "Literal API URL",
		Description: "Hardcoded API URL inside a string literal",
		Patterns: []string{
			`(?i)["` + "`" + `'](https?://(?:api|graphql|v1|v2)[-a-zA-Z0-9.]*\.[a-zA-Z]{2,}(?::\d{1,5})?(?:/[-a-zA-Z0-9./?=&%#_~:+]{0,150})?)["` + "`" + `']`,
		},
		ContextBoosts:    []string{`fetch`, `axios`, `request`},
		ContextPenalties: []string{`localhost`, `example\.com`},
		DefaultStrategy:  StrategyReplaceURL,
		BaseConfidence:   65,
		ImpactNote:       "Literal API URL will be redirected",
		SymbolCapture:    1,
	},

	// ═══════════════════════════════════════════════════════════════════════════
	// PREMIUM / PRO — feature gates, paywalls, pro-only checks
	// ═══════════════════════════════════════════════════════════════════════════

	{
		ID:          "premium_is_premium_fn",
		Category:    CategoryPremium,
		Name:        "isPremium Function",
		Description: "Function that checks premium status",
		Patterns: []string{
			`(?i)\b(isPremium|checkPremium|hasPremium|getPremium|premiumCheck|verifyPremium)\s*[=:]\s*function`,
			`(?i)function\s+(isPremium|checkPremium|hasPremium|getPremium|premiumCheck|verifyPremium)\s*\(`,
			`(?i)(isPremium|checkPremium|hasPremium|getPremium)\s*=\s*\(\s*\)\s*=>`,
		},
		ContextBoosts:    []string{`return\s+(false|true)`, `subscription`, `purchase`, `billing`},
		ContextPenalties: []string{`// deprecated`, `_test`, `spec\b`},
		DefaultStrategy:  StrategyEarlyReturnTrue,
		BaseConfidence:   88,
		ImpactNote:       "All callers will receive premium=true; paywall will be bypassed",
		SymbolCapture:    1,
	},
	{
		ID:          "premium_is_pro_fn",
		Category:    CategoryPremium,
		Name:        "isPro / isProUser Function",
		Description: "Function that checks pro/vip status",
		Patterns: []string{
			`(?i)function\s+(isPro|isVIP|isProUser|isVipUser|checkVIP|checkPro)\s*\(`,
			`(?i)(isPro|isVIP|isProUser|isVipUser)\s*=\s*(?:function|\(\s*\)\s*=>)`,
		},
		ContextBoosts:   []string{`return\s+false`, `subscription`, `account`, `tier`},
		DefaultStrategy: StrategyEarlyReturnTrue,
		BaseConfidence:  86,
		ImpactNote:      "Pro/VIP status check will always return true",
		SymbolCapture:   1,
	},
	{
		ID:          "premium_variable_assign",
		Category:    CategoryPremium,
		Name:        "Premium Variable Assignment",
		Description: "Boolean variable that holds premium state",
		Patterns: []string{
			`(?i)(?:var|let|const)\s+(isPremium|hasPremium|premiumStatus|premiumUnlocked|isVip|isPro|premiumUser)\s*=\s*(?:false|null|undefined|0)`,
		},
		ContextBoosts:    []string{`subscription`, `purchase`, `billing`, `feature`, `unlock`},
		ContextPenalties: []string{`// `, `\* `, `test`},
		DefaultStrategy:  StrategyAssignTrue,
		BaseConfidence:   78,
		ImpactNote:       "Variable initialized to premium=true",
		SymbolCapture:    1,
	},
	{
		ID:          "premium_keywords",
		Category:    CategoryPremium,
		Name:        "Premium & Donation Keywords",
		Description: "String literals related to premium, donate, or subscription features",
		Patterns: []string{
			`(?i)([a-zA-Z0-9_.\-]{0,10}(?:premium|subscribe|subscription|donate|donation|vip|is_?pro|c\.ai\+|plus_?member)[a-zA-Z0-9_.\-]{0,10})`,
		},
		ContextBoosts:    []string{`true`, `false`, `buy`, `purchase`},
		ContextPenalties: []string{},
		DefaultStrategy:  StrategyInformational,
		BaseConfidence:   65,
		ImpactNote:       "Informational: Premium/Donation flag or route",
		SymbolCapture:    1,
	},
	{
		ID:          "age_verification_gate",
		Category:    CategoryAgeCheck,
		Name:        "Age Verification & Registration",
		Description: "Age gate, NSFW check, or registration logic",
		Patterns: []string{
			`(?i)([a-zA-Z0-9_.\-]{0,16}(?:age_?verification|ageCheck|verifyAge|over18|nsfw_gate|isAdult|canOpenMatureSection|parseAgeResponse|requestAge|AGE_ENDPOINT|registration|signup|register)[a-zA-Z0-9_.\-]{0,16})`,
			`(?i)\b(canOpenMatureSection|parseAgeResponse|requestAge)\s*\(`,
		},
		ContextBoosts:    []string{`true`, `false`, `required`},
		ContextPenalties: []string{},
		DefaultStrategy:  StrategyInformational,
		BaseConfidence:   70,
		ImpactNote:       "Informational: Age or Registration verification string",
		SymbolCapture:    1,
	},
	{
		ID:          "premium_paywall_show",
		Category:    CategoryPremium,
		Name:        "Paywall Display",
		Description: "Code that shows a paywall / upgrade prompt",
		Patterns: []string{
			`(?i)\b(showPaywall|displayPaywall|openPaywall|presentPaywall|showUpgradeScreen|showUpgradePrompt|showPremiumModal)\s*\(`,
		},
		ContextBoosts:   []string{`navigation`, `modal`, `screen`, `alert`},
		DefaultStrategy: StrategyNOP,
		BaseConfidence:  75,
		ImpactNote:      "Paywall display call will be suppressed",
		SymbolCapture:   1,
	},
	{
		ID:          "premium_feature_locked",
		Category:    CategoryPremium,
		Name:        "Feature Lock Check",
		Description: "isLocked / isFeatureLocked condition",
		Patterns: []string{
			`(?i)\b(isLocked|isFeatureLocked|featureLocked|isRestricted|isGated|requiresPremium)\b`,
		},
		ContextBoosts:    []string{`if\s*\(`, `return\b`, `feature`, `unlock`},
		ContextPenalties: []string{`unlock\s*=\s*true`, `// disabled`},
		DefaultStrategy:  StrategyInlineFalse,
		BaseConfidence:   72,
		ImpactNote:       "Feature lock condition replaced with false",
		SymbolCapture:    1,
	},

	// ═══════════════════════════════════════════════════════════════════════════
	// SUBSCRIPTION — recurring payment gates
	// ═══════════════════════════════════════════════════════════════════════════

	{
		ID:          "sub_is_subscribed_fn",
		Category:    CategorySubscription,
		Name:        "isSubscribed Function",
		Description: "Function that checks subscription status",
		Patterns: []string{
			`(?i)function\s+(isSubscribed|hasSubscription|checkSubscription|isSubscriptionActive|subscriptionValid)\s*\(`,
			`(?i)(isSubscribed|hasSubscription|checkSubscription)\s*=\s*(?:function|\(\s*\)\s*=>)`,
		},
		ContextBoosts:   []string{`return\s+false`, `subscription`, `billing`, `expired`},
		DefaultStrategy: StrategyEarlyReturnTrue,
		BaseConfidence:  87,
		ImpactNote:      "Subscription check always returns true",
		SymbolCapture:   1,
	},
	{
		ID:          "sub_expired_check",
		Category:    CategorySubscription,
		Name:        "Subscription Expired Check",
		Description: "Code that checks if a subscription has expired",
		Patterns: []string{
			`(?i)\b(subscriptionExpired|isExpired|subExpired|hasExpired|trialExpired)\s*[=:()]/`,
			`(?i)(?:var|let|const)\s+(subscriptionExpired|isExpired|subExpired)\s*=\s*(?:true|1)`,
		},
		ContextBoosts:   []string{`date`, `expire`, `renew`, `billing`},
		DefaultStrategy: StrategyAssignFalse,
		BaseConfidence:  78,
		ImpactNote:      "Subscription expiry flag cleared",
		SymbolCapture:   1,
	},
	{
		ID:          "sub_active_status",
		Category:    CategorySubscription,
		Name:        "Subscription Active Status",
		Description: "Property/variable tracking active subscription state",
		Patterns: []string{
			`(?i)\b(subscriptionActive|isSubscriptionActive|activeSubscription|subscriptionStatus)\s*[:=]\s*(?:false|null|"inactive"|"expired")`,
		},
		ContextBoosts:   []string{`subscription`, `payment`, `billing`},
		DefaultStrategy: StrategyAssignTrue,
		BaseConfidence:  76,
		ImpactNote:      "Subscription active status set to true",
		SymbolCapture:   1,
	},

	// ═══════════════════════════════════════════════════════════════════════════
	// LICENSE — DRM and license key checks
	// ═══════════════════════════════════════════════════════════════════════════

	{
		ID:          "license_check_fn",
		Category:    CategoryLicense,
		Name:        "License Check Function",
		Description: "Function that validates license keys or DRM",
		Patterns: []string{
			`(?i)function\s+(checkLicense|validateLicense|verifyLicense|isLicenseValid|licenseCheck|checkDRM)\s*\(`,
			`(?i)(checkLicense|validateLicense|verifyLicense|isLicenseValid)\s*=\s*(?:function|\(\s*\)\s*=>)`,
		},
		ContextBoosts:   []string{`license`, `key`, `drm`, `validate`, `return false`},
		DefaultStrategy: StrategyEarlyReturnTrue,
		BaseConfidence:  90,
		ImpactNote:      "License validation bypassed; all checks return valid",
		SymbolCapture:   1,
	},
	{
		ID:          "license_valid_variable",
		Category:    CategoryLicense,
		Name:        "License Valid Variable",
		Description: "Variable holding license validity state",
		Patterns: []string{
			`(?i)(?:var|let|const)\s+(licenseValid|isLicensed|hasLicense|licenseOk|validLicense)\s*=\s*(?:false|null|0)`,
		},
		ContextBoosts:   []string{`license`, `key`, `activation`},
		DefaultStrategy: StrategyAssignTrue,
		BaseConfidence:  82,
		ImpactNote:      "License validity variable set to true",
		SymbolCapture:   1,
	},
	{
		ID:          "license_key_verify",
		Category:    CategoryLicense,
		Name:        "License Key Verification",
		Description: "Inline license key verification call",
		Patterns: []string{
			`(?i)\b(verifyKey|validateKey|checkActivation|activationCheck|verifyActivation)\s*\(`,
		},
		ContextBoosts:   []string{`key`, `activation`, `license`, `serial`},
		DefaultStrategy: StrategyInlineTrue,
		BaseConfidence:  75,
		ImpactNote:      "Key verification call replaced with true",
		SymbolCapture:   1,
	},

	// ═══════════════════════════════════════════════════════════════════════════
	// REGISTRATION / AUTH — login / session / account checks
	// ═══════════════════════════════════════════════════════════════════════════

	{
		ID:          "auth_is_logged_in_fn",
		Category:    CategoryRegistration,
		Name:        "isLoggedIn Function",
		Description: "Function that checks login/authentication state",
		Patterns: []string{
			`(?i)function\s+(isLoggedIn|isAuthenticated|checkAuth|isSignedIn|checkLogin|hasSession)\s*\(`,
			`(?i)(isLoggedIn|isAuthenticated|checkAuth|isSignedIn)\s*=\s*(?:function|\(\s*\)\s*=>)`,
		},
		ContextBoosts:   []string{`return\s+false`, `session`, `token`, `auth`, `user`},
		DefaultStrategy: StrategyEarlyReturnTrue,
		BaseConfidence:  85,
		ImpactNote:      "Auth check always returns true; login wall bypassed",
		SymbolCapture:   1,
	},
	{
		ID:          "auth_logged_in_variable",
		Category:    CategoryRegistration,
		Name:        "Logged In Variable",
		Description: "Variable holding login/session state",
		Patterns: []string{
			`(?i)(?:var|let|const)\s+(isLoggedIn|loggedIn|isAuthenticated|authenticated|hasSession|sessionActive)\s*=\s*(?:false|null|0)`,
		},
		ContextBoosts:   []string{`session`, `user`, `token`, `login`, `auth`},
		DefaultStrategy: StrategyAssignTrue,
		BaseConfidence:  80,
		ImpactNote:      "Session state variable forced to logged-in",
		SymbolCapture:   1,
	},
	{
		ID:          "auth_requires_registration",
		Category:    CategoryRegistration,
		Name:        "Registration Required Gate",
		Description: "Code that requires user registration before proceeding",
		Patterns: []string{
			`(?i)\b(requiresRegistration|mustRegister|registrationRequired|needsAccount|loginRequired)\b`,
		},
		ContextBoosts:   []string{`if\s*\(`, `redirect`, `navigate`, `screen`},
		DefaultStrategy: StrategyInlineFalse,
		BaseConfidence:  72,
		ImpactNote:      "Registration requirement disabled",
		SymbolCapture:   1,
	},
	{
		ID:          "auth_validate_session",
		Category:    CategoryRegistration,
		Name:        "Session Validation Call",
		Description: "Explicit session/token validation call",
		Patterns: []string{
			`(?i)\b(validateSession|verifySession|checkSession|refreshSession|validateToken|verifyToken)\s*\(`,
		},
		ContextBoosts:   []string{`token`, `session`, `expire`, `refresh`},
		DefaultStrategy: StrategyInlineTrue,
		BaseConfidence:  68,
		ImpactNote:      "Session validation replaced with success",
		SymbolCapture:   1,
	},

	// ═══════════════════════════════════════════════════════════════════════════
	// AGE CHECK — age gates, adult content verifiers
	// ═══════════════════════════════════════════════════════════════════════════

	{
		ID:          "age_is_underage",
		Category:    CategoryAgeCheck,
		Name:        "isUnderage Check",
		Description: "Code that detects users below minimum age",
		Patterns: []string{
			`(?i)\b(isUnderage|checkAge|ageVerification|verifyAge|ageGate|ageCheck|isMinor)\s*\(`,
			`(?i)function\s+(isUnderage|checkAge|ageVerification|verifyAge)\s*\(`,
		},
		ContextBoosts:   []string{`18`, `21`, `age`, `dob`, `birth`, `adult`},
		DefaultStrategy: StrategyEarlyReturnFalse,
		BaseConfidence:  83,
		ImpactNote:      "Age check always returns false (not underage); gate bypassed",
		SymbolCapture:   1,
	},
	{
		ID:          "age_comparison",
		Category:    CategoryAgeCheck,
		Name:        "Age Comparison Expression",
		Description: "Inline age comparison `age < 18` or `userAge < minimumAge`",
		Patterns: []string{
			`(?i)\b(?:user)?[Aa]ge\s*<\s*(?:18|21|minimumAge|minAge|MIN_AGE)\b`,
			`(?i)\b(?:18|21|minimumAge|MIN_AGE)\s*>\s*(?:user)?[Aa]ge\b`,
		},
		ContextBoosts:   []string{`if\s*\(`, `return\b`, `block`, `restrict`},
		DefaultStrategy: StrategyConditionFalse,
		BaseConfidence:  79,
		ImpactNote:      "Age comparison always evaluates to false (adult assumed)",
	},
	{
		ID:          "age_mature_section_gate",
		Category:    CategoryAgeCheck,
		Name:        "Mature Section Gate",
		Description: "React Native function combining server adult response with native age approval",
		Patterns: []string{
			`(?i)\bcanOpenMatureSection\s*\(`,
			`(?i)\bparseAgeResponse\s*\(`,
		},
		ContextBoosts:   []string{`adult`, `age`, `NativeAgeBridge`, `serverApproved`, `return\s+serverApproved`},
		DefaultStrategy: StrategyEarlyReturnTrue,
		BaseConfidence:  88,
		ImpactNote:      "Age gate decision point identified; review server and native approval flow",
		SymbolCapture:   1,
	},
	{
		ID:          "age_gate_variable",
		Category:    CategoryAgeCheck,
		Name:        "Age Gate Variable",
		Description: "Variable that controls age-restricted content",
		Patterns: []string{
			`(?i)(?:var|let|const)\s+(ageVerified|isAdultVerified|ageConfirmed|adultContent|isAdult)\s*=\s*(?:false|null|0)`,
		},
		ContextBoosts:   []string{`age`, `adult`, `content`, `18`, `21`},
		DefaultStrategy: StrategyAssignTrue,
		BaseConfidence:  76,
		ImpactNote:      "Age verification variable set to verified",
		SymbolCapture:   1,
	},
	{
		ID:          "age_birthday_check",
		Category:    CategoryAgeCheck,
		Name:        "Birthday / DOB Check",
		Description: "Date-of-birth based age verification",
		Patterns: []string{
			`(?i)\b(checkBirthday|verifyDOB|validateAge|ageFromDOB|calculateAge)\s*\(`,
		},
		ContextBoosts:   []string{`dob`, `birth`, `birthday`, `date`, `age`},
		DefaultStrategy: StrategyInlineTrue,
		BaseConfidence:  70,
		ImpactNote:      "DOB check replaced with adult confirmation",
		SymbolCapture:   1,
	},

	// ═══════════════════════════════════════════════════════════════════════════
	// DONATE — donation prompts and payment nags
	// ═══════════════════════════════════════════════════════════════════════════

	{
		ID:          "donate_is_enabled",
		Category:    CategoryDonate,
		Name:        "Donation Enabled Flag",
		Description: "Boolean controlling whether donation UI is shown",
		Patterns: []string{
			`(?i)(?:var|let|const)\s+(donationEnabled|isDonationEnabled|canDonate|showDonation)\s*=\s*(?:true|1)`,
		},
		ContextBoosts:   []string{`donate`, `support`, `kofi`, `patreon`, `paypal`},
		DefaultStrategy: StrategyAssignFalse,
		BaseConfidence:  78,
		ImpactNote:      "Donation flag disabled; donation UI will not show",
		SymbolCapture:   1,
	},
	{
		ID:          "donate_show_banner",
		Category:    CategoryDonate,
		Name:        "Donation Banner Display",
		Description: "Call that shows a donation prompt or banner",
		Patterns: []string{
			`(?i)\b(showDonationBanner|displayDonation|showDonateScreen|openDonationPage|showSupportScreen)\s*\(`,
		},
		ContextBoosts:   []string{`banner`, `modal`, `prompt`, `screen`, `navigate`},
		DefaultStrategy: StrategyNOP,
		BaseConfidence:  80,
		ImpactNote:      "Donation banner call suppressed",
		SymbolCapture:   1,
	},
	{
		ID:          "donate_has_donated",
		Category:    CategoryDonate,
		Name:        "hasDonated Check",
		Description: "Code that checks whether user has previously donated",
		Patterns: []string{
			`(?i)\b(hasDonated|userDonated|donorStatus|isDonor|checkDonation)\b`,
		},
		ContextBoosts:   []string{`if\s*\(`, `donated`, `donor`, `thank`},
		DefaultStrategy: StrategyInlineTrue,
		BaseConfidence:  72,
		ImpactNote:      "Donor check bypassed; treated as already donated",
		SymbolCapture:   1,
	},
	{
		ID:          "donate_payment_url",
		Category:    CategoryDonate,
		Name:        "Donation Payment URL",
		Description: "Hardcoded URL to a donation/payment platform",
		Patterns: []string{
			`(?i)(https?://(?:www\.)?(?:paypal\.me|ko-fi\.com|patreon\.com|boosty\.to|buymeacoffee\.com|gofundme\.com)/[^\s"'` + "`" + `]{3,})`,
		},
		ContextBoosts:   []string{`donate`, `support`, `fund`, `coffee`},
		DefaultStrategy: StrategyNOP,
		BaseConfidence:  85,
		ImpactNote:      "Donation URL reference found",
	},
	{
		ID:          "donate_nag_counter",
		Category:    CategoryDonate,
		Name:        "Donation Nag Counter",
		Description: "Counter that triggers donation prompts after N uses",
		Patterns: []string{
			`(?i)\b(donationNagCount|nagCount|promptCount|showCount|sessionCount)\s*(?:[><!]=?\s*\d+|[+]{1,2})`,
		},
		ContextBoosts:   []string{`donate`, `prompt`, `nag`, `remind`},
		DefaultStrategy: StrategyConditionFalse,
		BaseConfidence:  65,
		ImpactNote:      "Donation nag counter condition bypassed",
		SymbolCapture:   1,
	},

	// ═══════════════════════════════════════════════════════════════════════════
	// ADS — advertisement display and removal
	// ═══════════════════════════════════════════════════════════════════════════

	{
		ID:          "ads_show_ad",
		Category:    CategoryAds,
		Name:        "Show Ad Call",
		Description: "Function call that displays an advertisement",
		Patterns: []string{
			`(?i)\b(showAd|displayAd|showInterstitial|showRewardedAd|showBannerAd|showNativeAd|presentAd|loadAndShowAd)\s*\(`,
		},
		ContextBoosts:   []string{`admob`, `unity`, `ironsource`, `applovin`, `ad`, `banner`, `interstitial`},
		DefaultStrategy: StrategyNOP,
		BaseConfidence:  80,
		ImpactNote:      "Ad display call suppressed",
		SymbolCapture:   1,
	},
	{
		ID:          "ads_enabled_flag",
		Category:    CategoryAds,
		Name:        "Ads Enabled Flag",
		Description: "Boolean variable that controls ad display",
		Patterns: []string{
			`(?i)(?:var|let|const)\s+(adsEnabled|showAds|adEnabled|enableAds|adsVisible)\s*=\s*(?:true|1)`,
		},
		ContextBoosts:   []string{`ad`, `banner`, `interstitial`, `monetiz`},
		DefaultStrategy: StrategyAssignFalse,
		BaseConfidence:  76,
		ImpactNote:      "Ads flag disabled",
		SymbolCapture:   1,
	},
	{
		ID:          "ads_is_ad_free",
		Category:    CategoryAds,
		Name:        "isAdFree Check",
		Description: "Variable or function checking ad-free status",
		Patterns: []string{
			`(?i)\b(isAdFree|noAds|adFree|adsRemoved|purchasedNoAds)\b`,
		},
		ContextBoosts:   []string{`if\s*\(`, `purchase`, `premium`, `free`},
		DefaultStrategy: StrategyInlineTrue,
		BaseConfidence:  74,
		ImpactNote:      "Ad-free status set to true",
		SymbolCapture:   1,
	},
	{
		ID:          "ads_init_sdk",
		Category:    CategoryAds,
		Name:        "Ad SDK Initialization",
		Description: "AdMob, IronSource, AppLovin, Unity Ads SDK init call",
		Patterns: []string{
			`(?i)\b(MobileAds\.initialize|IronSource\.init|AppLovinSdk\.initializeSdk|UnityAds\.initialize|FacebookAds\.setAdvertiserTrackingEnabled)\s*\(`,
		},
		ContextBoosts:   []string{`ad`, `sdk`, `init`, `app_id`},
		DefaultStrategy: StrategyNOP,
		BaseConfidence:  70,
		ImpactNote:      "Ad SDK initialization suppressed",
		SymbolCapture:   1,
	},

	// ═══════════════════════════════════════════════════════════════════════════
	// SECURITY — root, jailbreak, integrity, tamper checks
	// ═══════════════════════════════════════════════════════════════════════════

	{
		ID:          "sec_root_check",
		Category:    CategorySecurity,
		Name:        "Root / Jailbreak Check",
		Description: "Code that detects a rooted Android or jailbroken iOS device",
		Patterns: []string{
			`(?i)function\s+(isRooted|checkRoot|isJailbroken|checkJailbreak|detectRoot|rootDetected)\s*\(`,
			`(?i)(isRooted|checkRoot|isJailbroken|rootDetection|jailbreakCheck)\s*=\s*(?:function|\(\s*\)\s*=>)`,
		},
		ContextBoosts:   []string{`su\b`, `superuser`, `busybox`, `cydia`, `jailbreak`, `root`},
		DefaultStrategy: StrategyEarlyReturnFalse,
		BaseConfidence:  88,
		ImpactNote:      "Root/jailbreak detection bypassed; always returns not-rooted",
		SymbolCapture:   1,
	},
	{
		ID:          "sec_integrity_check",
		Category:    CategorySecurity,
		Name:        "Integrity / Tamper Check",
		Description: "App integrity or tamper detection",
		Patterns: []string{
			`(?i)function\s+(checkIntegrity|verifyIntegrity|integrityCheck|isTampered|detectTamper|signatureCheck)\s*\(`,
			`(?i)(checkIntegrity|verifyIntegrity|isTampered)\s*=\s*(?:function|\(\s*\)\s*=>)`,
		},
		ContextBoosts:   []string{`hash`, `checksum`, `signature`, `crc`, `tamper`, `integrity`},
		DefaultStrategy: StrategyEarlyReturnFalse,
		BaseConfidence:  85,
		ImpactNote:      "Integrity check bypassed; always returns not-tampered",
		SymbolCapture:   1,
	},
	{
		ID:          "sec_debug_check",
		Category:    CategorySecurity,
		Name:        "Debug Mode Check",
		Description: "Code that detects debugger attachment or dev mode",
		Patterns: []string{
			`(?i)\b(isDebugMode|debuggerAttached|isDebugging|detectDebugger|checkDebugger|__DEV__)\b`,
		},
		ContextBoosts:    []string{`debug`, `__DEV__`, `debugger`, `devtools`},
		ContextPenalties: []string{`console\.log`, `logger`},
		DefaultStrategy:  StrategyInlineFalse,
		BaseConfidence:   75,
		ImpactNote:       "Debug detection always returns false",
		SymbolCapture:    1,
	},
	{
		ID:          "sec_emulator_check",
		Category:    CategorySecurity,
		Name:        "Emulator Detection",
		Description: "Code that detects running in an emulator or simulator",
		Patterns: []string{
			`(?i)function\s+(isEmulator|checkEmulator|isSimulator|detectEmulator)\s*\(`,
			`(?i)\b(isEmulator|isSimulator|emulatorDetected|runningInEmulator)\b`,
		},
		ContextBoosts:   []string{`emulator`, `simulator`, `avd`, `genymotion`},
		DefaultStrategy: StrategyEarlyReturnFalse,
		BaseConfidence:  80,
		ImpactNote:      "Emulator detection bypassed",
		SymbolCapture:   1,
	},
	{
		ID:          "sec_play_integrity",
		Category:    CategorySecurity,
		Name:        "Play Integrity / SafetyNet",
		Description: "Google Play Integrity API or SafetyNet attestation call",
		Patterns: []string{
			`(?i)\b(checkPlayIntegrity|safetyNetCheck|attestationCheck|verifyAttestation|PlayIntegrity|SafetyNet)\b`,
		},
		ContextBoosts:   []string{`attest`, `integrity`, `google`, `play`},
		DefaultStrategy: StrategyInlineTrue,
		BaseConfidence:  82,
		ImpactNote:      "Play Integrity/SafetyNet bypassed",
		SymbolCapture:   1,
	},

	// ═══════════════════════════════════════════════════════════════════════════
	// TRIAL — time-limited and usage-limited features
	// ═══════════════════════════════════════════════════════════════════════════

	{
		ID:          "trial_is_trial",
		Category:    CategoryTrial,
		Name:        "isTrial Check",
		Description: "Code that checks if user is on a trial",
		Patterns: []string{
			`(?i)function\s+(isTrial|isInTrial|checkTrial|trialActive|hasActiveTrial)\s*\(`,
			`(?i)(?:var|let|const)\s+(isTrial|isInTrial|onTrial|trialUser)\s*=\s*(?:true|1)`,
		},
		ContextBoosts:   []string{`trial`, `expire`, `day`, `period`, `free`},
		DefaultStrategy: StrategyEarlyReturnFalse,
		BaseConfidence:  76,
		ImpactNote:      "Trial status cleared; treated as full version",
		SymbolCapture:   1,
	},
	{
		ID:          "trial_expired",
		Category:    CategoryTrial,
		Name:        "Trial Expired Flag",
		Description: "Code that checks if a trial period has expired",
		Patterns: []string{
			`(?i)(?:var|let|const)\s+(trialExpired|isTrialExpired|trialEnded|trialFinished)\s*=\s*(?:true|1)`,
			`(?i)\b(trialExpired|isTrialExpired|trialEnded)\b\s*(?:===?\s*true|\|\||&&)`,
		},
		ContextBoosts:   []string{`trial`, `expired`, `days`, `limit`},
		DefaultStrategy: StrategyAssignFalse,
		BaseConfidence:  82,
		ImpactNote:      "Trial expiry flag cleared",
		SymbolCapture:   1,
	},
	{
		ID:          "trial_usage_limit",
		Category:    CategoryTrial,
		Name:        "Usage Limit Check",
		Description: "Numeric limit check that gates feature access",
		Patterns: []string{
			`(?i)\b(usageCount|useCount|launchCount|sessionCount)\s*>=?\s*\d+`,
			`(?i)\b(maxUses|maxLaunches|freeUses|trialLimit)\s*[:=]\s*\d+`,
		},
		ContextBoosts:   []string{`trial`, `limit`, `exceed`, `max`},
		DefaultStrategy: StrategyConditionFalse,
		BaseConfidence:  68,
		ImpactNote:      "Usage limit condition bypassed",
		SymbolCapture:   1,
	},

	// ═══════════════════════════════════════════════════════════════════════════
	// GEO BLOCK — region-based restrictions
	// ═══════════════════════════════════════════════════════════════════════════

	{
		ID:          "geo_is_blocked",
		Category:    CategoryGeoBlock,
		Name:        "Geo Block Check",
		Description: "Code that blocks access based on user region",
		Patterns: []string{
			`(?i)\b(isGeoBlocked|regionBlocked|geoBlocked|isRegionRestricted|countryBlocked|regionLocked)\b`,
			`(?i)function\s+(checkRegion|isRegionAllowed|geoCheck|countryCheck)\s*\(`,
		},
		ContextBoosts:   []string{`country`, `region`, `geo`, `location`, `ip`},
		DefaultStrategy: StrategyInlineFalse,
		BaseConfidence:  76,
		ImpactNote:      "Geo block check always returns false (not blocked)",
		SymbolCapture:   1,
	},
	{
		ID:          "geo_country_code",
		Category:    CategoryGeoBlock,
		Name:        "Country Code Restriction",
		Description: "Hardcoded country code list or restriction check",
		Patterns: []string{
			`(?i)\b(blockedCountries|restrictedRegions|allowedCountries)\s*[:=]\s*\[`,
			`(?i)\b(countryCode|userCountry|region)\s*===?\s*["'][A-Z]{2}["']`,
		},
		ContextBoosts:   []string{`country`, `region`, `block`, `restrict`, `allow`},
		DefaultStrategy: StrategyConditionFalse,
		BaseConfidence:  65,
		ImpactNote:      "Country restriction condition bypassed",
		SymbolCapture:   1,
	},

	// ═══════════════════════════════════════════════════════════════════════════
	// SSL PINNING — certificate validation bypass in JS layer
	// ═══════════════════════════════════════════════════════════════════════════

	{
		ID:          "ssl_fetch_pin",
		Category:    CategorySSLPinning,
		Name:        "Fetch SSL Pin Config",
		Description: "SSL certificate pinning configured in fetch/axios",
		Patterns: []string{
			`(?i)(fingerprint|pinning|sslPinning|certificatePin|publicKeyPin)\s*:\s*(?:\[|true|["']{)`,
		},
		ContextBoosts:   []string{`fetch`, `axios`, `XMLHttpRequest`, `https`, `certificate`},
		DefaultStrategy: StrategyRemovePin,
		BaseConfidence:  78,
		ImpactNote:      "SSL pinning configuration removed; MITM interception enabled",
	},
	{
		ID:          "ssl_rn_ssl_pinning",
		Category:    CategorySSLPinning,
		Name:        "React Native SSL Pinning Library",
		Description: "react-native-ssl-pinning or similar library usage",
		Patterns: []string{
			`(?i)(fetch\s*\(\s*[^,]+,\s*\{[^}]*(?:sslPinning|pkPinning|pinnedCertificates))`,
			`(?i)require\s*\(\s*["']react-native-ssl-pinning["']\s*\)`,
		},
		ContextBoosts:   []string{`ssl`, `pin`, `certificate`, `fetch`},
		DefaultStrategy: StrategyRemovePin,
		BaseConfidence:  85,
		ImpactNote:      "React Native SSL pinning library usage neutralised",
	},
	{
		ID:          "ssl_axios_interceptor",
		Category:    CategorySSLPinning,
		Name:        "Axios SSL Interceptor",
		Description: "Axios interceptor performing certificate validation",
		Patterns: []string{
			`(?i)axios\.interceptors\.[^.]+\.use\([^)]*(?:ssl|cert|pin|signature)`,
		},
		ContextBoosts:   []string{`axios`, `interceptor`, `ssl`, `cert`, `verify`},
		DefaultStrategy: StrategyNOP,
		BaseConfidence:  72,
		ImpactNote:      "Axios SSL certificate interceptor removed",
	},
}
