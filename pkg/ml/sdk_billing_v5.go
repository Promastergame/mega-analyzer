package ml

// ═══════════════════════════════════════════════════════════════════════════════
// GOOGLE PLAY BILLING V5 PATTERN LIBRARY
//
// Google Play Billing Library v5 patterns for purchase verification
// Requirements: 3.1, 3.8, 19.1
// ═══════════════════════════════════════════════════════════════════════════════

// BillingV5Patterns — Google Play Billing Library v5 specific patterns
var BillingV5Patterns = []VulnerablePattern{
	// ═══════════════════════════════════════════════════════════════════════
	// BILLING V5 #1 — Query Purchases Async
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "BILLING_V5_QUERY_PURCHASES",
		Category:    PatchCatBilling,
		Description: "Billing v5 query purchases async method",
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
		Weight:        1.3,
		MinMatchScore: 15,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// BILLING V5 #2 — Acknowledge Purchase
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "BILLING_V5_ACKNOWLEDGE",
		Category:    PatchCatBilling,
		Description: "Billing v5 acknowledge purchase method",
		MethodNames: []string{
			"acknowledgepurchase", "acknowledge",
			"confirmpurchase", "verifypurchase",
		},
		ClassPatterns: []string{
			"com/android/billingclient",
			"billingclient", "billing",
		},
		RequiredCalls: []string{
			"billingclient;->acknowledgepurchase",
			"acknowledgepurchaseparams",
			"acknowledgepurchaseresponselistener",
		},
		StringPatterns: []string{
			"purchasetoken", "acknowledge",
		},
		ReturnType:    "V",
		PatchType:     PatchReturnVoid,
		Weight:        1.3,
		MinMatchScore: 15,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// BILLING V5 #3 — Signature Verification
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "BILLING_V5_VERIFY_SIGNATURE",
		Category:    PatchCatBilling,
		Description: "Billing v5 purchase signature verification",
		MethodNames: []string{
			"verifysignature", "validatesignature",
			"checksignature", "verifypurchase",
			"ispurchasevalid",
		},
		ClassPatterns: []string{
			"billing", "purchase", "security",
			"verification",
		},
		RequiredCalls: []string{
			"signature;->getinstance",
			"publickeyspec",
			"keyfactory",
			"purchase;->getsignature",
			"purchase;->getoriginalj son",
		},
		StringPatterns: []string{
			"rsa", "sha1withrsa", "sha256withrsa",
			"signature", "publickey",
		},
		ReturnType:    "Z",
		PatchType:     PatchReturnTrue,
		Weight:        1.4,
		MinMatchScore: 18,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// BILLING V5 #4 — Consumable Purchase
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "BILLING_V5_CONSUME",
		Category:    PatchCatBilling,
		Description: "Billing v5 consume purchase method",
		MethodNames: []string{
			"consumeasync", "consume", "consumepurchase",
		},
		ClassPatterns: []string{
			"com/android/billingclient",
			"billingclient", "billing",
		},
		RequiredCalls: []string{
			"billingclient;->consumeasync",
			"consumeparams",
			"consumeresponselistener",
		},
		StringPatterns: []string{
			"purchasetoken", "consume",
		},
		ReturnType:    "V",
		PatchType:     PatchReturnVoid,
		Weight:        1.3,
		MinMatchScore: 15,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// BILLING V5 #5 — Subscription Purchase Verification
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "BILLING_V5_SUBSCRIPTION_VERIFY",
		Category:    PatchCatSubscription,
		Description: "Billing v5 subscription purchase verification",
		MethodNames: []string{
			"verifysubscription", "validatesubscription",
			"checksubscription", "issubscriptionvalid",
		},
		ClassPatterns: []string{
			"billing", "subscription", "purchase",
		},
		RequiredCalls: []string{
			"purchase;->getproducts",
			"purchase;->getpurchasestate",
			"purchase;->isautore newing",
		},
		StringPatterns: []string{
			"subs", "subscription", "autorenewing",
		},
		ReturnType:    "Z",
		PatchType:     PatchReturnTrue,
		Weight:        1.4,
		MinMatchScore: 15,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// BILLING V5 #6 — Purchase State Check
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "BILLING_V5_PURCHASE_STATE",
		Category:    PatchCatBilling,
		Description: "Billing v5 purchase state check",
		MethodNames: []string{
			"ispurchased", "haspurchase", "checkpurchasestate",
			"getpurchasestate", "ispurchasevalid",
		},
		ClassPatterns: []string{
			"billing", "purchase",
		},
		RequiredCalls: []string{
			"purchase;->getpurchasestate",
			"purchasestate",
		},
		StringPatterns: []string{
			"purchased", "pending", "unspecified",
		},
		ReturnType:    "Z",
		PatchType:     PatchReturnTrue,
		Weight:        1.3,
		MinMatchScore: 12,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// BILLING V5 #7 — BillingClient Connection
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "BILLING_V5_CONNECTION",
		Category:    PatchCatBilling,
		Description: "Billing v5 client connection state",
		MethodNames: []string{
			"startconnection", "isready", "endconnection",
			"checkconnection",
		},
		ClassPatterns: []string{
			"com/android/billingclient",
			"billingclient",
		},
		RequiredCalls: []string{
			"billingclient;->startconnection",
			"billingclient;->isready",
			"billingclientstatelistener",
		},
		StringPatterns: []string{
			"billing_unavailable", "service_disconnected",
		},
		ReturnType:    "V",
		PatchType:     PatchReturnVoid,
		Weight:        1.1,
		MinMatchScore: 12,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// BILLING V5 #8 — Purchase Token Validation
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "BILLING_V5_TOKEN_VALIDATION",
		Category:    PatchCatBilling,
		Description: "Billing v5 purchase token validation",
		MethodNames: []string{
			"validatetoken", "verifytoken", "checktoken",
			"ispurchasetokenvalid",
		},
		ClassPatterns: []string{
			"billing", "purchase", "token",
		},
		RequiredCalls: []string{
			"purchase;->getpurchasetoken",
			"textutils;->isempty",
		},
		StringPatterns: []string{
			"purchasetoken", "token",
		},
		ReturnType:    "Z",
		PatchType:     PatchReturnTrue,
		Weight:        1.3,
		MinMatchScore: 12,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// BILLING V5 #9 — Product Details Query
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "BILLING_V5_PRODUCT_DETAILS",
		Category:    PatchCatBilling,
		Description: "Billing v5 product details query",
		MethodNames: []string{
			"queryproductdetailsasync", "queryproductdetails",
			"getproductdetails", "fetchproductdetails",
		},
		ClassPatterns: []string{
			"com/android/billingclient",
			"billingclient",
		},
		RequiredCalls: []string{
			"billingclient;->queryproductdetailsasync",
			"queryproductdetailsparams",
			"productdetailsresponselistener",
		},
		StringPatterns: []string{
			"productid", "productdetails",
		},
		ReturnType:    "V",
		PatchType:     PatchReturnVoid,
		Weight:        1.0,
		MinMatchScore: 12,
	},
}

// BillingV5SDKSignatures — detection signatures for Billing v5
var BillingV5SDKSignatures = SDKSignature{
	PackagePatterns: []string{
		"com/android/billingclient",
	},
	ClassSignatures: []string{
		"BillingClient",
		"Purchase",
		"PurchasesResponseListener",
		"AcknowledgePurchaseParams",
		"ConsumeParams",
		"QueryProductDetailsParams",
		"ProductDetails",
		"BillingResult",
	},
	MethodSignatures: []string{
		"queryPurchasesAsync",
		"acknowledgePurchase",
		"consumeAsync",
		"queryProductDetailsAsync",
	},
}

// DetectBillingV5SDK checks if Billing v5 SDK is present
func DetectBillingV5SDK(classInfo *ClassInfo) bool {
	classLower := toLowerASCII(classInfo.ClassName)
	pathLower := toLowerASCII(classInfo.FilePath)

	// Check package patterns
	for _, pkg := range BillingV5SDKSignatures.PackagePatterns {
		pkgLower := toLowerASCII(pkg)
		if containsSubstring(pathLower, pkgLower) || containsSubstring(classLower, pkgLower) {
			return true
		}
	}

	// Check class signatures
	for _, cls := range BillingV5SDKSignatures.ClassSignatures {
		clsLower := toLowerASCII(cls)
		if containsSubstring(classLower, clsLower) {
			return true
		}
	}

	return false
}
