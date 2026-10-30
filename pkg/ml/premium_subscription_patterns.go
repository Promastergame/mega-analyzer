package ml

// ═══════════════════════════════════════════════════════════════════════════════
// PREMIUM FEATURE AND SUBSCRIPTION PATTERNS
//
// Enhanced patterns for premium status checks, subscriptions, and feature gates
// Requirements: 4.1-4.6, 5.1-5.5
// ═══════════════════════════════════════════════════════════════════════════════

// PremiumFeaturePatterns — Premium feature and subscription patterns
var PremiumFeaturePatterns = []VulnerablePattern{
	// ═══════════════════════════════════════════════════════════════════════
	// PREMIUM #1 — Premium Status Check (Enhanced)
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "PREMIUM_STATUS_CHECK_ENHANCED",
		Category:    PatchCatPremium,
		Description: "Enhanced premium status check (isPremium, isPro, isVIP)",
		MethodNames: []string{
			"ispremium", "ispro", "isproversion", "isfullversion",
			"ispaid", "isvip", "isgold", "isplatinum",
			"haspremium", "haspro", "getpremiumstatus",
			"ispremiumuser", "ispremiumactive", "checkpremium",
		},
		ClassPatterns: []string{
			"premium", "proversion", "fullversion", "vip",
			"membership", "userstatus", "account",
		},
		RequiredCalls: []string{
			"getsharedpreferences",
			"getboolean",
		},
		StringPatterns: []string{
			"premium", "pro_version", "is_premium",
			"premium_status", "full_version", "vip",
			"paid_user", "premium_active",
		},
		ReturnType:    "Z",
		PatchType:     PatchReturnTrue,
		Weight:        1.3,
		MinMatchScore: 12,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// PREMIUM #2 — Feature Flag System
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "FEATURE_FLAG_CHECK",
		Category:    PatchCatFeatureGate,
		Description: "Feature flag system controlling premium functionality",
		MethodNames: []string{
			"isfeatureenabled", "hasfeature", "checkfeatureflag",
			"getfeatureflag", "isfeatureavailable",
			"canaccess feature", "isfeatureunlocked",
		},
		ClassPatterns: []string{
			"featureflag", "feature", "flag",
			"config", "remoteconfig",
		},
		RequiredCalls: []string{
			"getboolean", "getstring",
			"getsharedpreferences",
			"remoteconfig",
		},
		StringPatterns: []string{
			"feature_", "flag_", "enabled",
			"feature_flag", "remote_config",
		},
		ReturnType:    "Z",
		PatchType:     PatchReturnTrue,
		Weight:        1.2,
		MinMatchScore: 10,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// PREMIUM #3 — Entitlement Verification
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "ENTITLEMENT_VERIFICATION",
		Category:    PatchCatPremium,
		Description: "Entitlement verification for premium features",
		MethodNames: []string{
			"hasentitlement", "checkentitlement",
			"verifyentitlement", "isentitled",
			"getentitlement", "validateentitlement",
		},
		ClassPatterns: []string{
			"entitlement", "entitle", "access",
			"permission", "capability",
		},
		RequiredCalls: []string{
			"set;->contains", "list;->contains",
			"getsharedpreferences",
		},
		StringPatterns: []string{
			"entitlement", "entitled", "access",
			"permission",
		},
		ReturnType:    "Z",
		PatchType:     PatchReturnTrue,
		Weight:        1.2,
		MinMatchScore: 10,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// PREMIUM #4 — Capability Check
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "CAPABILITY_CHECK",
		Category:    PatchCatFeatureGate,
		Description: "Capability check that gates premium features",
		MethodNames: []string{
			"hascapability", "checkcapability",
			"cancapability", "iscapable",
			"getcapability", "verifycapability",
		},
		ClassPatterns: []string{
			"capability", "able", "permission",
			"access", "feature",
		},
		RequiredCalls: []string{
			"getboolean", "contains",
		},
		StringPatterns: []string{
			"capability", "can_", "able_to",
		},
		ReturnType:    "Z",
		PatchType:     PatchReturnTrue,
		Weight:        1.1,
		MinMatchScore: 10,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// PREMIUM #5 — SharedPreferences Premium Storage
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "SHAREDPREFS_PREMIUM_STORAGE",
		Category:    PatchCatPremium,
		Description: "SharedPreferences-based premium status storage",
		MethodNames: []string{
			"savepremiumstatus", "setpremium", "storepremium",
			"getpremiumstatus", "loadpremium",
		},
		ClassPatterns: []string{
			"premium", "preferences", "storage",
			"prefs", "settings",
		},
		RequiredCalls: []string{
			"getsharedpreferences",
			"edit", "putboolean", "getboolean",
			"apply", "commit",
		},
		StringPatterns: []string{
			"premium", "pro", "vip",
			"is_premium", "premium_status",
		},
		ReturnType:    "V",
		PatchType:     PatchReturnVoid,
		Weight:        1.0,
		MinMatchScore: 12,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// PREMIUM #6 — Server-Side Premium Validation
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "SERVER_PREMIUM_VALIDATION",
		Category:    PatchCatPremium,
		Description: "Server-side premium status validation indicators",
		MethodNames: []string{
			"validatepremiumonserver", "checkpremiumserver",
			"verifypremiumremote", "syncpremiumstatus",
		},
		ClassPatterns: []string{
			"premium", "server", "api",
			"remote", "sync",
		},
		RequiredCalls: []string{
			"httpurlconnection", "okhttp",
			"retrofit", "request",
		},
		StringPatterns: []string{
			"https://", "api", "premium",
			"verify", "validate",
		},
		ReturnType:    "V",
		PatchType:     PatchReturnVoid,
		Weight:        1.1,
		MinMatchScore: 12,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// SUBSCRIPTION #1 — Active Subscription Check
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "SUBSCRIPTION_ACTIVE_CHECK",
		Category:    PatchCatSubscription,
		Description: "Active subscription status check",
		MethodNames: []string{
			"issubscriptionactive", "hasactivesubscription",
			"issubscribed", "checksubscriptionactive",
			"getsubscriptionstatus",
		},
		ClassPatterns: []string{
			"subscription", "subscribe", "membership",
		},
		RequiredCalls: []string{
			"getsharedpreferences", "getboolean",
			"system;->currenttimemillis",
		},
		StringPatterns: []string{
			"subscription", "active", "subscribed",
			"subscription_active", "is_subscribed",
		},
		ReturnType:    "Z",
		PatchType:     PatchReturnTrue,
		Weight:        1.3,
		MinMatchScore: 12,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// SUBSCRIPTION #2 — Expiry Date Validation
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "SUBSCRIPTION_EXPIRY_VALIDATION",
		Category:    PatchCatSubscription,
		Description: "Subscription expiry date validation",
		MethodNames: []string{
			"issubscriptionexpired", "checkexpirydate",
			"validateexpiry", "getexpirydate",
			"isexpired", "hasexpired",
		},
		ClassPatterns: []string{
			"subscription", "expiry", "expire",
		},
		RequiredCalls: []string{
			"system;->currenttimemillis",
			"calendar;->getinstance",
			"date;->gettime",
			"getlong",
		},
		StringPatterns: []string{
			"expiry", "expire", "expiration",
			"subscription_expiry", "expiry_date",
		},
		ReturnType:    "Z",
		PatchType:     PatchReturnFalse,
		Weight:        1.3,
		MinMatchScore: 12,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// SUBSCRIPTION #3 — Subscription Tier Check
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "SUBSCRIPTION_TIER_CHECK",
		Category:    PatchCatSubscription,
		Description: "Subscription tier/level check",
		MethodNames: []string{
			"getsubscriptiontier", "checksubscriptionlevel",
			"getsubscriptiontype", "ismembershiplevel",
			"hastier", "getmembershiplevel",
		},
		ClassPatterns: []string{
			"subscription", "tier", "level",
			"membership", "plan",
		},
		RequiredCalls: []string{
			"getstring", "getint",
			"getsharedpreferences",
		},
		StringPatterns: []string{
			"tier", "level", "plan",
			"basic", "premium", "pro", "elite",
			"monthly", "yearly", "annual",
		},
		ReturnType:    "I",
		PatchType:     PatchReturnMaxInt,
		Weight:        1.2,
		MinMatchScore: 10,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// SUBSCRIPTION #4 — Recurring Billing Verification
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "SUBSCRIPTION_RECURRING_BILLING",
		Category:    PatchCatSubscription,
		Description: "Recurring billing verification",
		MethodNames: []string{
			"isautorenewing", "isrecurring",
			"checkrecurringbilling", "hasautorenew",
			"getautorenewstatus",
		},
		ClassPatterns: []string{
			"subscription", "billing", "recurring",
			"autorenew",
		},
		RequiredCalls: []string{
			"purchase;->isautorenewing",
			"getboolean",
		},
		StringPatterns: []string{
			"autorenew", "recurring", "auto_renew",
			"autorenewing",
		},
		ReturnType:    "Z",
		PatchType:     PatchReturnTrue,
		Weight:        1.3,
		MinMatchScore: 12,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// SUBSCRIPTION #5 — Grace Period Handling
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "SUBSCRIPTION_GRACE_PERIOD",
		Category:    PatchCatSubscription,
		Description: "Subscription grace period handling",
		MethodNames: []string{
			"isingraceperiod", "checkgraceperiod",
			"hasgraceperiod", "getgraceperiodstatus",
		},
		ClassPatterns: []string{
			"subscription", "grace", "period",
		},
		RequiredCalls: []string{
			"system;->currenttimemillis",
			"getlong", "getboolean",
		},
		StringPatterns: []string{
			"grace", "graceperiod", "grace_period",
		},
		ReturnType:    "Z",
		PatchType:     PatchReturnTrue,
		Weight:        1.2,
		MinMatchScore: 10,
	},
}

// GetAllPremiumSubscriptionPatterns returns all premium and subscription patterns
func GetAllPremiumSubscriptionPatterns() []VulnerablePattern {
	return PremiumFeaturePatterns
}
