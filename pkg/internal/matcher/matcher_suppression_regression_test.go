package matcher

import (
	"testing"

	"mega-analyzer/pkg/internal/types"
)

// Regression tests for the false-positive wave seen on a clean
// Minecraft-mod APK: 46 setAccessible custom-keyword findings and ~25
// matches against the vendored Google Play Billing library's own classes.

func TestSetAccessibleCustomKeywordSuppressedEverywhere(t *testing.T) {
	// setAccessible(true) is generic reflection plumbing used by androidx,
	// Play Services and app glue alike. R8-obfuscated class names hide the
	// original package, so the suppression cannot rely on SDK path prefixes.
	paths := []string{
		"smali/androidx/activity/ImmLeaksCleaner.smali",
		"smali/com/google/android/gms/internal/zzx.smali",
		"smali/a0/m.smali", // R8-obfuscated, original package unknown
		"smali/smellymoo/sand/Helper.smali",
	}
	for _, path := range paths {
		if !ShouldSuppressCustomKeyword(types.CategoryCustomKeyword,
			"invoke-virtual {v1}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V", path, "") {
			t.Errorf("setAccessible hit in %s should be suppressed", path)
		}
	}
}

func TestOtherCustomKeywordsStayVisible(t *testing.T) {
	if ShouldSuppressCustomKeyword(types.CategoryCustomKeyword,
		"invoke-virtual {v1}, Landroid/telephony/TelephonyManager;->getDeviceId()", "smali/f1/c.smali", "") {
		t.Error("telephonymanager keyword must not be suppressed by the setAccessible rule")
	}
}

func TestBillingLibraryInternalsSuppressed(t *testing.T) {
	libraryPaths := []string{
		"smali/com/android/billingclient/api/Purchase.smali",
		"smali/com/android/billingclient/api/SkuDetails.smali",
		"smali/com/google/android/gms/internal/play_billing/p.smali",
		"smali/com/android/vending/billing/IInAppBillingService.smali",
	}
	categories := []types.Category{
		types.CategoryBillingClient,
		types.CategoryPurchaseToken,
		types.CategorySubscription,
		types.CategoryPremiumCheck,
	}
	for _, cat := range categories {
		for _, path := range libraryPaths {
			if !shouldSuppress(cat, "Purchase class / SKU details", path, "") {
				t.Errorf("%s match in %s should be suppressed", cat, path)
			}
		}
	}
}

func TestAppBillingWrapperMatchesStayVisible(t *testing.T) {
	appPaths := []string{
		"smali/smellymoo/sand/Sand.smali",
		"smali/c1/d.smali", // R8-obfuscated app-side billing wrapper
		"smali/h3/c.smali",
	}
	for _, cat := range []types.Category{types.CategoryBillingClient, types.CategoryPurchaseToken} {
		for _, path := range appPaths {
			if shouldSuppress(cat, "Payment Provider: Google Play Billing", path, "") {
				t.Errorf("%s match in app wrapper %s must stay visible", cat, path)
			}
		}
	}
}
