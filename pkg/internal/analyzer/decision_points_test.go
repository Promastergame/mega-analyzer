package analyzer

import (
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func TestNewDecisionPointFinder(t *testing.T) {
	f := NewDecisionPointFinder()
	if f == nil {
		t.Fatal("expected non-nil finder")
	}
	if f.config.MinConditionsForConditional != 2 {
		t.Fatalf("MinConditionsForConditional = %d, want 2", f.config.MinConditionsForConditional)
	}
	if f.config.MinConfidence != 0.6 {
		t.Fatalf("MinConfidence = %f, want 0.6", f.config.MinConfidence)
	}
}

func TestNewDecisionPointFinderWithConfig(t *testing.T) {
	cfg := DecisionPointConfig{
		MinConditionsForConditional: 5,
		MinConfidence:               0.9,
	}
	f := NewDecisionPointFinderWithConfig(cfg)
	if f.config.MinConditionsForConditional != 5 {
		t.Fatalf("got %d", f.config.MinConditionsForConditional)
	}
	if f.config.MinConfidence != 0.9 {
		t.Fatalf("got %f", f.config.MinConfidence)
	}
}

func TestFindDecisionPoints_BooleanMethod_IsLicensed(t *testing.T) {
	f := NewDecisionPointFinder()
	method := &types.SmaliMethod{
		Name:           "isLicensed",
		ReturnsBoolean: true,
		ReturnType:     "Z",
	}
	points := f.FindDecisionPoints(method, "com/app/License", "License.smali")
	if len(points) == 0 {
		t.Fatal("expected at least one decision point for isLicensed")
	}
	dp := points[0]
	if dp.Category != types.CategoryLicenseCheck {
		t.Fatalf("category = %s, want %s", dp.Category, types.CategoryLicenseCheck)
	}
	if dp.Type != types.DecisionBooleanReturn {
		t.Fatalf("type = %v, want DecisionBooleanReturn", dp.Type)
	}
	if dp.Confidence != 0.9 {
		t.Fatalf("confidence = %f, want 0.9", dp.Confidence)
	}
}

func TestFindDecisionPoints_BooleanMethod_IsPremium(t *testing.T) {
	f := NewDecisionPointFinder()
	method := &types.SmaliMethod{
		Name:           "isPremiumUser",
		ReturnsBoolean: true,
		ReturnType:     "Z",
	}
	points := f.FindDecisionPoints(method, "com/app/User", "User.smali")
	if len(points) == 0 {
		t.Fatal("expected decision point for isPremiumUser")
	}
	if points[0].Category != types.CategoryPremiumCheck {
		t.Fatalf("category = %s, want PREMIUM_CHECK", points[0].Category)
	}
}

func TestFindDecisionPoints_BooleanMethod_IsRooted(t *testing.T) {
	f := NewDecisionPointFinder()
	method := &types.SmaliMethod{
		Name:           "isRooted",
		ReturnsBoolean: true,
		ReturnType:     "Z",
	}
	points := f.FindDecisionPoints(method, "com/app/Security", "Security.smali")
	if len(points) == 0 {
		t.Fatal("expected decision point for isRooted")
	}
	if points[0].Category != types.CategoryRootDetection {
		t.Fatalf("category = %s, want root_detection", points[0].Category)
	}
}

func TestFindDecisionPoints_BooleanMethod_NoMatch(t *testing.T) {
	f := NewDecisionPointFinder()
	method := &types.SmaliMethod{
		Name:           "isEmpty",
		ReturnsBoolean: true,
		ReturnType:     "Z",
	}
	points := f.FindDecisionPoints(method, "com/app/Utils", "Utils.smali")
	if len(points) != 0 {
		t.Fatalf("expected no decision points for isEmpty, got %d", len(points))
	}
}

func TestFindDecisionPoints_NonBooleanMethod_Skipped(t *testing.T) {
	f := NewDecisionPointFinder()
	method := &types.SmaliMethod{
		Name:           "isLicensed",
		ReturnsBoolean: false, // not boolean
		ReturnType:     "V",
	}
	points := f.FindDecisionPoints(method, "com/app/License", "License.smali")
	// Should not match boolean patterns since ReturnsBoolean is false
	for _, dp := range points {
		if dp.Type == types.DecisionBooleanReturn {
			t.Fatal("should not find boolean return DP for non-boolean method")
		}
	}
}

func TestFindDecisionPoints_ConditionalMethod(t *testing.T) {
	f := NewDecisionPointFinder()
	method := &types.SmaliMethod{
		Name:       "checkLicense",
		ReturnType: "V",
		Conditions: []types.Condition{
			{}, {}, {}, // 3 conditions, above threshold of 2
		},
	}
	points := f.FindDecisionPoints(method, "com/app/LicenseManager", "LicenseManager.smali")
	found := false
	for _, dp := range points {
		if dp.Type == types.DecisionConditional {
			found = true
			if dp.Category != types.CategoryLicenseCheck {
				t.Fatalf("category = %s, want license_check", dp.Category)
			}
		}
	}
	if !found {
		t.Fatal("expected conditional decision point for checkLicense")
	}
}

func TestFindDecisionPoints_ConditionalMethod_BelowThreshold(t *testing.T) {
	f := NewDecisionPointFinder()
	method := &types.SmaliMethod{
		Name:       "checkLicense",
		ReturnType: "V",
		Conditions: []types.Condition{
			{}, // only 1 condition, below threshold of 2
		},
	}
	points := f.FindDecisionPoints(method, "com/app/LicenseManager", "LicenseManager.smali")
	for _, dp := range points {
		if dp.Type == types.DecisionConditional {
			t.Fatal("should not find conditional DP below threshold")
		}
	}
}

func TestFindDecisionPoints_ConditionalMethod_VerifyPurchase(t *testing.T) {
	f := NewDecisionPointFinder()
	method := &types.SmaliMethod{
		Name:       "verifyPurchase",
		ReturnType: "V",
		Conditions: []types.Condition{{}, {}, {}},
	}
	points := f.FindDecisionPoints(method, "com/app/Billing", "Billing.smali")
	found := false
	for _, dp := range points {
		if dp.Type == types.DecisionConditional && dp.Category == types.CategoryPurchaseVerify {
			found = true
		}
	}
	if !found {
		t.Fatal("expected conditional DP with purchase category")
	}
}

func TestFindDecisionPoints_ConditionalMethod_ValidateSignature(t *testing.T) {
	f := NewDecisionPointFinder()
	method := &types.SmaliMethod{
		Name:       "validateSignature",
		ReturnType: "V",
		Conditions: []types.Condition{{}, {}, {}},
	}
	points := f.FindDecisionPoints(method, "com/app/Integrity", "Integrity.smali")
	found := false
	for _, dp := range points {
		if dp.Type == types.DecisionConditional && dp.Category == types.CategorySignatureCheck {
			found = true
		}
	}
	if !found {
		t.Fatal("expected conditional DP with signature category")
	}
}

func TestFindDecisionPoints_CallbackMethod_DontAllow(t *testing.T) {
	f := NewDecisionPointFinder()
	method := &types.SmaliMethod{
		Name:       "dontAllow",
		ReturnType: "V",
	}
	points := f.FindDecisionPoints(method, "com/app/LVL", "LVL.smali")
	found := false
	for _, dp := range points {
		if dp.Type == types.DecisionCallback && dp.Category == types.CategoryGoogleLVL {
			found = true
			if dp.Confidence != 0.95 {
				t.Fatalf("confidence = %f, want 0.95", dp.Confidence)
			}
		}
	}
	if !found {
		t.Fatal("expected callback DP for dontAllow")
	}
}

func TestFindDecisionPoints_CallbackMethod_OnPurchasesUpdated(t *testing.T) {
	f := NewDecisionPointFinder()
	method := &types.SmaliMethod{
		Name:       "onPurchasesUpdated",
		ReturnType: "V",
	}
	points := f.FindDecisionPoints(method, "com/app/Billing", "Billing.smali")
	found := false
	for _, dp := range points {
		if dp.Type == types.DecisionCallback && dp.Category == types.CategoryBillingCallback {
			found = true
		}
	}
	if !found {
		t.Fatal("expected callback DP for onPurchasesUpdated")
	}
}

func TestFindDecisionPoints_VoidAntiPiracy(t *testing.T) {
	f := NewDecisionPointFinder()
	method := &types.SmaliMethod{
		Name:       "showPiracyWarning",
		ReturnType: "V",
	}
	points := f.FindDecisionPoints(method, "com/app/Security", "Security.smali")
	found := false
	for _, dp := range points {
		if dp.Category == types.CategoryTamperDetection {
			found = true
			if dp.Confidence != 0.85 {
				t.Fatalf("confidence = %f, want 0.85", dp.Confidence)
			}
		}
	}
	if !found {
		t.Fatal("expected anti-piracy DP for showPiracyWarning")
	}
}

func TestFindDecisionPoints_VoidAntiPiracy_NonVoid(t *testing.T) {
	f := NewDecisionPointFinder()
	method := &types.SmaliMethod{
		Name:       "showPiracyWarning",
		ReturnType: "I", // not void
	}
	points := f.FindDecisionPoints(method, "com/app/Security", "Security.smali")
	for _, dp := range points {
		if dp.Description == "Anti-piracy screen/handler method: showPiracyWarning" {
			t.Fatal("should not match void anti-piracy for non-void method")
		}
	}
}

func TestFindDecisionPoints_VoidAntiPiracy_CrackDetected(t *testing.T) {
	f := NewDecisionPointFinder()
	method := &types.SmaliMethod{
		Name:       "onCrackDetected",
		ReturnType: "V",
	}
	points := f.FindDecisionPoints(method, "com/app/Guard", "Guard.smali")
	found := false
	for _, dp := range points {
		if dp.Category == types.CategoryTamperDetection {
			found = true
		}
	}
	if !found {
		t.Fatal("expected anti-piracy DP for onCrackDetected")
	}
}

func TestFindInBody_ReturnsFalse(t *testing.T) {
	f := NewDecisionPointFinder()
	method := &types.SmaliMethod{
		SourceRange: types.SourceRange{LineStart: 10},
		Name:        "isLicensed",
	}
	body := "    const/4 v0, 0x0\n    return v0"
	points := f.FindInBody(method, body)
	if len(points) == 0 {
		t.Fatal("expected to find const/4 return false pattern")
	}
	if points[0].Category != types.CategoryLicenseCheck {
		t.Fatalf("category = %s", points[0].Category)
	}
}

func TestFindInBody_NotLicensed(t *testing.T) {
	f := NewDecisionPointFinder()
	method := &types.SmaliMethod{
		SourceRange: types.SourceRange{LineStart: 5},
		Name:        "handleResponse",
	}
	body := `const-string v0, "NOT_LICENSED"`
	points := f.FindInBody(method, body)
	if len(points) == 0 {
		t.Fatal("expected to find NOT_LICENSED pattern")
	}
	if points[0].Category != types.CategoryGoogleLVL {
		t.Fatalf("category = %s, want GOOGLE_LVL", points[0].Category)
	}
}

func TestFindInBody_PurchaseFailed(t *testing.T) {
	f := NewDecisionPointFinder()
	method := &types.SmaliMethod{
		SourceRange: types.SourceRange{LineStart: 1},
		Name:        "onResult",
	}
	body := `const-string v1, "purchase_failed"`
	points := f.FindInBody(method, body)
	if len(points) == 0 {
		t.Fatal("expected to find purchase_failed pattern")
	}
	if points[0].Category != types.CategoryPurchaseVerify {
		t.Fatalf("category = %s", points[0].Category)
	}
}

func TestFindInBody_NoMatch(t *testing.T) {
	f := NewDecisionPointFinder()
	method := &types.SmaliMethod{
		SourceRange: types.SourceRange{LineStart: 1},
		Name:        "doSomething",
	}
	body := "invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;"
	points := f.FindInBody(method, body)
	if len(points) != 0 {
		t.Fatalf("expected no matches, got %d", len(points))
	}
}

func TestFindInBodyBytes_EmptyBody(t *testing.T) {
	f := NewDecisionPointFinder()
	method := &types.SmaliMethod{
		Name: "empty",
		Body: nil,
	}
	points := f.FindInBodyBytes(method)
	if points != nil {
		t.Fatalf("expected nil for empty body, got %v", points)
	}
}

func TestFindInBodyBytes_WithBody(t *testing.T) {
	f := NewDecisionPointFinder()
	method := &types.SmaliMethod{
		SourceRange: types.SourceRange{LineStart: 1},
		Name:        "check",
		Body:        []string{`const-string v0, "NOT_LICENSED"`, "return-void"},
	}
	points := f.FindInBodyBytes(method)
	if len(points) == 0 {
		t.Fatal("expected to find NOT_LICENSED in body bytes")
	}
}

func TestDetectCategoryFromContext(t *testing.T) {
	f := NewDecisionPointFinder()

	tests := []struct {
		name       string
		nameLower  string
		classLower string
		want       types.Category
	}{
		{"license in name", "checklicense", "com/app/util", types.CategoryLicenseCheck},
		{"license in class", "check", "com/app/licensemanager", types.CategoryLicenseCheck},
		{"premium", "checkpremium", "com/app/util", types.CategoryPremiumCheck},
		{"purchase", "verifypurchase", "com/app/billing", types.CategoryPurchaseVerify},
		{"signature", "checksignature", "com/app/integrity", types.CategorySignatureCheck},
		{"piracy", "checkpiracy", "com/app/guard", types.CategoryTamperDetection},
		{"tamper", "checktamper", "com/app/security", types.CategoryTamperDetection},
		{"crack", "checkcrack", "com/app/guard", types.CategoryTamperDetection},
		{"repack", "checkrepack", "com/app/guard", types.CategoryTamperDetection},
		{"unknown", "dosomething", "com/app/util", types.CategoryUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := f.detectCategoryFromContext(tt.nameLower, tt.classLower)
			if got != tt.want {
				t.Fatalf("detectCategoryFromContext(%q, %q) = %s, want %s", tt.nameLower, tt.classLower, got, tt.want)
			}
		})
	}
}

func TestFindDecisionPoints_MultipleMatches(t *testing.T) {
	f := NewDecisionPointFinder()
	// A method that matches both boolean AND callback patterns
	method := &types.SmaliMethod{
		Name:           "onLicenseChecked",
		ReturnsBoolean: true,
		ReturnType:     "Z",
	}
	points := f.FindDecisionPoints(method, "com/app/LVL", "LVL.smali")
	// Should find both boolean (isLicensed-like) and callback matches
	if len(points) < 1 {
		t.Fatal("expected at least one decision point")
	}
}

func TestFindDecisionPoints_AllBooleanPatterns(t *testing.T) {
	f := NewDecisionPointFinder()
	patterns := []string{
		"isLicensed", "isPremium", "isPro", "isPaid", "isUnlocked",
		"isFullVersion", "isSubscribed", "hasSubscription", "isTrial",
		"isTrialExpired", "isAdFree", "hasNoAds", "adsRemoved",
		"shouldShowAds", "canShowAds", "isRooted", "isEmulator",
		"isDebuggable", "isTampered", "isModified", "isPirated",
		"isPiracy", "isModDetected", "isCracked", "isRepacked",
		"isRepackaged", "isFake", "isUnauthorized", "isBlacklisted",
		"isPurchased", "hasPurchased", "isExpired",
	}
	for _, name := range patterns {
		method := &types.SmaliMethod{
			Name:           name,
			ReturnsBoolean: true,
			ReturnType:     "Z",
		}
		points := f.FindDecisionPoints(method, "com/app/Test", "Test.smali")
		if len(points) == 0 {
			t.Errorf("expected decision point for %q", name)
		}
	}
}
