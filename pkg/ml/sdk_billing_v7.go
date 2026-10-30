package ml

// BillingV7Patterns — Google Play Billing Library v7+ (product details, external offers).
var BillingV7Patterns = []VulnerablePattern{
	{
		ID:          "BILLING_V7_QUERY_PRODUCT_DETAILS",
		Category:    PatchCatBilling,
		Description: "Billing v7 queryProductDetailsAsync purchase gate",
		MethodNames: []string{
			"queryproductdetailsasync", "getproductdetails", "fetchproductdetails",
		},
		ClassPatterns: []string{
			"com/android/billingclient", "billingclient",
		},
		RequiredCalls: []string{
			"billingclient;->queryproductdetailsasync",
			"queryproductdetailsparams",
		},
		StringPatterns: []string{"inapp", "subs", "productdetails"},
		ReturnType:     "V",
		PatchType:      PatchReturnVoid,
		Weight:         1.5,
		MinMatchScore:  14,
	},
	{
		ID:          "BILLING_V7_EXTERNAL_OFFER",
		Category:    PatchCatBilling,
		Description: "Billing v7 external offer / alternative billing availability",
		MethodNames: []string{
			"isexternalofferavailable", "isalternativebillingonlyavailable",
			"checkexternaloffer", "hasexternaloffer",
		},
		ClassPatterns: []string{"billingclient", "billing"},
		RequiredCalls: []string{
			"isexternalofferavailableasync",
			"isalternativebillingonlyavailableasync",
			"createexternalofferreportingdetailsasync",
		},
		ReturnType:    "Z",
		PatchType:     PatchReturnTrue,
		Weight:        1.4,
		MinMatchScore: 13,
	},
	{
		ID:          "BILLING_V7_PENDING_LISTENER",
		Category:    PatchCatBilling,
		Description: "Billing v7 pending purchases listener gate",
		MethodNames: []string{
			"onpurchasesupdated", "handlependingpurchases", "checkpending",
		},
		ClassPatterns: []string{"billing", "purchase", "pending"},
		RequiredCalls: []string{
			"purchasesupdatedlistener", "purchasestate",
			"enablependingpurchases",
		},
		ReturnType:    "V",
		PatchType:     PatchReturnVoid,
		Weight:        1.35,
		MinMatchScore: 12,
	},
	{
		ID:          "BILLING_V7_BILLING_CONFIG",
		Category:    PatchCatBilling,
		Description: "Billing v7 getBillingConfigAsync region/feature gate",
		MethodNames: []string{
			"getbillingconfig", "isbillingconfigready", "checkbillingconfig",
		},
		ClassPatterns: []string{"billingclient"},
		RequiredCalls: []string{
			"getbillingconfigasync", "billingconfig",
		},
		ReturnType:    "V",
		PatchType:     PatchReturnVoid,
		Weight:        1.3,
		MinMatchScore: 12,
	},
	{
		ID:          "BILLING_V7_FEATURE_SUPPORTED",
		Category:    PatchCatBilling,
		Description: "Billing v7 isFeatureSupported capability gate",
		MethodNames: []string{
			"isfeaturesupported", "checkfeaturesupported", "hassubscriptions",
		},
		ClassPatterns: []string{"billingclient"},
		RequiredCalls: []string{
			"isfeaturesupported", "billingclientfeature",
		},
		ReturnType:    "Z",
		PatchType:     PatchReturnTrue,
		Weight:        1.25,
		MinMatchScore: 11,
	},
}
