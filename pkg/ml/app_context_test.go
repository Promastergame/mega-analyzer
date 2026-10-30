package ml

import (
	"testing"
)

func TestPermissionFlags(t *testing.T) {
	perms := []string{
		"android.permission.INTERNET",
		"android.permission.READ_SMS",
		"android.permission.SEND_SMS",
		"android.permission.ACCESS_FINE_LOCATION",
	}

	pf := ParsePermissions(perms)

	if !pf.Has(PermInternet) {
		t.Error("Missing INTERNET permission")
	}
	if !pf.Has(PermReadSMS) {
		t.Error("Missing READ_SMS permission")
	}
	if pf.Has(PermCamera) {
		t.Error("Should NOT have CAMERA permission")
	}

	if pf.Count() != 4 {
		t.Errorf("Count() = %d, want 4", pf.Count())
	}

	dangerous := pf.DangerousCount()
	if dangerous == 0 {
		t.Error("DangerousCount() should be > 0")
	}

	if !pf.HasAny(PermReadSMS | PermCamera) {
		t.Error("HasAny should be true")
	}
	if pf.HasAll(PermReadSMS | PermCamera) {
		t.Error("HasAll should be false")
	}
}

func TestAppContext_Deep(t *testing.T) {
	// Banking
	ctx := NewAppContext("com.sber.banking", []string{"android.permission.INTERNET"})
	if ctx.DetectedType != AppTypeBanking {
		t.Errorf("Expected Banking for sber, got %s", ctx.DetectedType)
	}
	if !ctx.IsFinancial() {
		t.Error("Banking should be financial")
	}
	if ctx.GetRiskBias() != 5 {
		t.Errorf("Banking bias = %d, want 5", ctx.GetRiskBias())
	}

	// Gaming
	ctx2 := NewAppContext("com.rovio.gaming", []string{"android.permission.INTERNET"})
	if ctx2.DetectedType != AppTypeGaming {
		t.Errorf("Expected Gaming for rovio, got %s", ctx2.DetectedType)
	}
	if ctx2.IsFinancial() {
		t.Error("Gaming should NOT be financial")
	}
	if ctx2.GetRiskBias() != -1 {
		t.Errorf("Gaming bias = %d, want -1", ctx2.GetRiskBias())
	}

	// Accessibility
	ctx3 := NewAppContext("com.custom.a11y", []string{"android.permission.BIND_ACCESSIBILITY_SERVICE"})
	if ctx3.DetectedType != AppTypeAccessibility {
		t.Errorf("Expected Accessibility, got %s", ctx3.DetectedType)
	}
	if !ctx3.IsLegitimateAccessibilityUser() {
		t.Error("A11Y app should be legitimate user")
	}

	// Signals & Combos
	ctx.AddSignal("new_signal")
	if !ctx.HasSignal("new_signal") {
		t.Error("Signal not found after AddSignal")
	}
	ctx.AddSignal("new_signal") // Duplicate

	ctx.AddCombo(DetectedCombo{Name: "EvilCombo", Severity: "critical"})
	if !ctx.IsDangerousComboPresent() {
		t.Error("Combo should be present")
	}
}

func TestGetAppTypeInfo(t *testing.T) {
	info := GetAppTypeInfo(AppTypeBanking)
	if info.Type != AppTypeBanking {
		t.Errorf("Got type %s", info.Type)
	}

	all := AllAppTypes()
	if len(all) == 0 {
		t.Error("No app types returned")
	}
}
