package filter

import "testing"

func TestCanonicalSmaliPath(t *testing.T) {
	cases := []struct{ in, want string }{
		{"smali/kotlin/Unit.smali", "smali/kotlin/Unit.smali"},
		{"smali_classes2/androidx/core/R.smali", "smali/androidx/core/R.smali"},
		{"smali_classes10/com/google/android/gms/internal/zzx.smali", "smali/com/google/android/gms/internal/zzx.smali"},
		{"com/android/billingclient/api/BillingClient.smali", "smali/com/android/billingclient/api/BillingClient.smali"},
		{"lib/arm64-v8a/libfoo.so", "lib/arm64-v8a/libfoo.so"},
		{"AndroidManifest.xml", "AndroidManifest.xml"},
	}
	for _, tc := range cases {
		if got := CanonicalSmaliPath(tc.in); got != tc.want {
			t.Errorf("CanonicalSmaliPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestIsAppCode_MultidexKnownSDKs(t *testing.T) {
	f := NewFilter()
	for _, path := range []string{
		"smali_classes2/androidx/core/view/accessibility/AccessibilityNodeInfoCompat.smali",
		"smali_classes3/com/google/android/gms/internal/measurement/zzab.smali",
		"smali_classes2/kotlin/collections/CollectionsKt.smali",
	} {
		if f.IsAppCode(path) {
			t.Errorf("IsAppCode(%q) = true, want false (known SDK in multidex root)", path)
		}
	}
}

// The play_billing AIDL implementation under gms internals carries "billing"
// in its own paths. A high-value keyword match inside a vendored SDK's
// namespace must not promote the SDK to app code; otherwise the payment and
// subscription detectors scanned the library's own classes and reported
// "Payment Provider: Google Play Billing" against Play Billing itself.
func TestIsAppCode_PlayBillingInternals(t *testing.T) {
	f := NewFilter()
	for _, path := range []string{
		"smali/com/google/android/gms/internal/play_billing/p.smali",
		"smali_classes2/com/google/android/gms/internal/play_billing/s1.smali",
		"smali/com/android/billingclient/api/Purchase.smali",
	} {
		if f.IsAppCode(path) {
			t.Errorf("IsAppCode(%q) = true, want false (vendored billing SDK)", path)
		}
	}
}
