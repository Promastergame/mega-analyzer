package ml

// ═══════════════════════════════════════════════════════════════════════════════
// GOOGLE PLAY BILLING V6 PATTERN LIBRARY
//
// Google Play Billing Library v6 patterns with enhanced security features
// Requirements: 3.2, 3.7, 3.8, 19.1
// ═══════════════════════════════════════════════════════════════════════════════

// BillingV6Patterns — Google Play Billing Library v6 specific patterns
var BillingV6Patterns = []VulnerablePattern{
	// ═══════════════════════════════════════════════════════════════════════
	// BILLING V6 #1 — Enhanced Query Purchases
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "BILLING_V6_QUERY_PURCHASES",
		Category:    PatchCatBilling,
		Description: "Billing v6 enhanced query purchases with security",
		MethodNames: []string{
			"querypurchasesasync", "querypurchases",
			"getpurchases", "fetchpurchases",
		},
		ClassPatterns: []string{
			"com/android/billingclient",
			"billingclient", "billing",
		},
		RequiredCalls: []string{
			"billingclient;->querypurchasesasync",
			"purchasesresponselistener",
			"queryproductsparams",
		},
		StringPatterns: []string{
			"com.android.billingclient",
			"inapp", "subs",
		},
		ReturnType:    "V",
		PatchType:     PatchReturnVoid,
		Weight:        1.4,
		MinMatchScore: 15,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// BILLING V6 #2 — Pending Purchase Handling
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "BILLING_V6_PENDING_PURCHASE",
		Category:    PatchCatBilling,
		Description: "Billing v6 pending purchase state handling",
		MethodNames: []string{
			"handlependingpurchase", "checkpendingpurchase",
			"ispending", "getpendingpurchases",
		},
		ClassPatterns: []string{
			"billing", "purchase", "pending",
		},
		RequiredCalls: []string{
			"purchase;->getpurchasestate",
			"purchasestate;->pending",
		},
		StringPatterns: []string{
			"pending", "purchasestate",
		},
		ReturnType:    "Z",
		PatchType:     PatchReturnFalse,
		Weight:        1.4,
		MinMatchScore: 15,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// BILLING V6 #3 — Enhanced Token Validation
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "BILLING_V6_TOKEN_VALIDATION",
		Category:    PatchCatBilling,
		Description: "Billing v6 enhanced purchase token validation",
		MethodNames: []string{
			"validatetoken", "verifytoken", "checktoken",
			"ispurchasetokenvalid", "validatepurchasetoken",
		},
		ClassPatterns: []string{
			"billing", "purchase", "token", "validation",
		},
		RequiredCalls: []string{
			"purchase;->getpurchasetoken",
			"purchase;->getaccountidentifiers",
			"textutils;->isempty",
		},
		StringPatterns: []string{
			"purchasetoken", "token", "obfuscated",
		},
		ReturnType:    "Z",
		PatchType:     PatchReturnTrue,
		Weight:        1.5,
		MinMatchScore: 15,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// BILLING V6 #4 — Enhanced Signature Verification
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "BILLING_V6_VERIFY_SIGNATURE",
		Category:    PatchCatBilling,
		Description: "Billing v6 enhanced signature verification with additional checks",
		MethodNames: []string{
			"verifysignature", "validatesignature",
			"checksignature", "verifypurchase",
			"ispurchasevalid", "validatepurchasesignature",
		},
		ClassPatterns: []string{
			"billing", "purchase", "security",
			"verification", "signature",
		},
		RequiredCalls: []string{
			"signature;->getinstance",
			"publickeyspec",
			"keyfactory",
			"purchase;->getsignature",
			"purchase;->getoriginaljson",
			"purchase;->getaccountidentifiers",
		},
		StringPatterns: []string{
			"rsa", "sha256withrsa", "sha384withrsa",
			"signature", "publickey", "base64",
		},
		ReturnType:    "Z",
		PatchType:     PatchReturnTrue,
		Weight:        1.5,
		MinMatchScore: 18,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// BILLING V6 #5 — Account Identifiers Validation
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "BILLING_V6_ACCOUNT_IDENTIFIERS",
		Category:    PatchCatBilling,
		Description: "Billing v6 account identifiers validation",
		MethodNames: []string{
			"validateaccountidentifiers", "checkaccountidentifiers",
			"verifyaccountidentifiers", "getaccountidentifiers",
		},
		ClassPatterns: []string{
			"billing", "purchase", "account",
		},
		RequiredCalls: []string{
			"purchase;->getaccountidentifiers",
			"accountidentifiers;->getobfuscatedaccountid",
			"accountidentifiers;->getobfuscatedprofileid",
		},
		StringPatterns: []string{
			"obfuscatedaccountid", "obfuscatedprofileid",
			"accountidentifiers",
		},
		ReturnType:    "Z",
		PatchType:     PatchReturnTrue,
		Weight:        1.4,
		MinMatchScore: 15,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// BILLING V6 #6 — Subscription Update/Upgrade
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "BILLING_V6_SUBSCRIPTION_UPDATE",
		Category:    PatchCatSubscription,
		Description: "Billing v6 subscription update/upgrade handling",
		MethodNames: []string{
			"updatesubscription", "upgradesubscription",
			"downgradesubscription", "changesubscription",
		},
		ClassPatterns: []string{
			"billing", "subscription", "upgrade",
		},
		RequiredCalls: []string{
			"billingflowparams;->newbuilder",
			"subscriptionupdateparams",
			"billingclient;->launchbillingflow",
		},
		StringPatterns: []string{
			"subscription", "upgrade", "downgrade",
			"prorationmode",
		},
		ReturnType:    "V",
		PatchType:     PatchReturnVoid,
		Weight:        1.3,
		MinMatchScore: 15,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// BILLING V6 #7 — Alternative Billing Methods
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "BILLING_V6_ALTERNATIVE_BILLING",
		Category:    PatchCatBilling,
		Description: "Billing v6 alternative billing methods check",
		MethodNames: []string{
			"isalternativebillingavailable",
			"checkalternativebilling",
			"getalternativebillingonly",
		},
		ClassPatterns: []string{
			"billing", "alternative",
		},
		RequiredCalls: []string{
			"billingclient;->isalternativebillingonlyavailableasync",
			"alternativebillingonlyavailabilitylistener",
		},
		StringPatterns: []string{
			"alternative", "billing",
		},
		ReturnType:    "V",
		PatchType:     PatchReturnVoid,
		Weight:        1.2,
		MinMatchScore: 12,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// BILLING V6 #8 — External Offer Token Validation
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "BILLING_V6_OFFER_TOKEN",
		Category:    PatchCatBilling,
		Description: "Billing v6 external offer token validation",
		MethodNames: []string{
			"validateoffertoken", "checkoffertoken",
			"getoffertoken", "verifyoffertoken",
		},
		ClassPatterns: []string{
			"billing", "offer", "token",
		},
		RequiredCalls: []string{
			"productdetails;->getsubscriptionofferdetails",
			"subscriptionofferdetails;->getoffertoken",
		},
		StringPatterns: []string{
			"offertoken", "baseplanoffer",
		},
		ReturnType:    "Z",
		PatchType:     PatchReturnTrue,
		Weight:        1.3,
		MinMatchScore: 12,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// BILLING V6 #9 — Purchase Verification with Server
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "BILLING_V6_SERVER_VERIFICATION",
		Category:    PatchCatBilling,
		Description: "Billing v6 server-side purchase verification",
		MethodNames: []string{
			"verifyonserver", "validatewithserver",
			"sendtoserver", "serververification",
		},
		ClassPatterns: []string{
			"billing", "verification", "server",
		},
		RequiredCalls: []string{
			"httpurlconnection",
			"purchase;->getpurchasetoken",
			"purchase;->getoriginaljson",
			"purchase;->getsignature",
		},
		StringPatterns: []string{
			"https://", "api", "verify",
			"purchasetoken", "signature",
		},
		ReturnType:    "V",
		PatchType:     PatchReturnVoid,
		Weight:        1.4,
		MinMatchScore: 15,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// BILLING V6 #10 — Billing Config Check
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "BILLING_V6_CONFIG_CHECK",
		Category:    PatchCatBilling,
		Description: "Billing v6 configuration and feature check",
		MethodNames: []string{
			"getbillingconfigasync", "checkbillingconfig",
			"isfeaturesupp orted",
		},
		ClassPatterns: []string{
			"billing", "config",
		},
		RequiredCalls: []string{
			"billingclient;->getbillingconfigasync",
			"billingconfigresponselistener",
			"billingclient;->isfeaturesupp orted",
		},
		StringPatterns: []string{
			"billingconfig", "countrycode",
		},
		ReturnType:    "V",
		PatchType:     PatchReturnVoid,
		Weight:        1.1,
		MinMatchScore: 12,
	},
}

// BillingV6SDKSignatures — detection signatures for Billing v6
var BillingV6SDKSignatures = SDKSignature{
	PackagePatterns: []string{
		"com/android/billingclient",
	},
	ClassSignatures: []string{
		"BillingClient",
		"Purchase",
		"AccountIdentifiers",
		"PurchasesResponseListener",
		"BillingConfigResponseListener",
		"AlternativeBillingOnlyAvailabilityListener",
		"ProductDetails",
		"SubscriptionOfferDetails",
		"BillingResult",
	},
	MethodSignatures: []string{
		"queryPurchasesAsync",
		"getAccountIdentifiers",
		"getBillingConfigAsync",
		"isAlternativeBillingOnlyAvailableAsync",
		"getSubscriptionOfferDetails",
	},
}

// DetectBillingV6SDK checks if Billing v6 SDK is present
func DetectBillingV6SDK(classInfo *ClassInfo) bool {
	classLower := toLowerASCII(classInfo.ClassName)
	pathLower := toLowerASCII(classInfo.FilePath)

	// Check package patterns
	for _, pkg := range BillingV6SDKSignatures.PackagePatterns {
		pkgLower := toLowerASCII(pkg)
		if containsSubstring(pathLower, pkgLower) || containsSubstring(classLower, pkgLower) {
			return true
		}
	}

	// Check class signatures - v6 specific
	v6SpecificClasses := []string{
		"AccountIdentifiers",
		"BillingConfigResponseListener",
		"AlternativeBillingOnlyAvailabilityListener",
	}

	for _, cls := range v6SpecificClasses {
		clsLower := toLowerASCII(cls)
		if containsSubstring(classLower, clsLower) {
			return true
		}
	}

	return false
}
