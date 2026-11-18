package main

import (
	"math"
	"testing"

	"mega-analyzer/pkg/internal/types"
	"mega-analyzer/pkg/ml/gnncache"
)

func TestGNNPredictionMargin(t *testing.T) {
	pred := &gnncache.Prediction{
		PredictedClass: 2,
		Confidence:     0.60,
		ClassProbs:     []float32{0.05, 0.10, 0.60, 0.05, 0.05, 0.05, 0.05, 0.05},
	}
	margin, ok := gnnPredictionMargin(pred)
	if !ok || math.Abs(float64(margin-0.50)) > 1e-6 {
		t.Fatalf("margin = %v, valid = %v; want 0.50, true", margin, ok)
	}
}

func TestGNNPredictionMarginRejectsMalformedDistributions(t *testing.T) {
	valid := []float32{0.60, 0.10, 0.05, 0.05, 0.05, 0.05, 0.05, 0.05}
	tests := []gnncache.Prediction{
		{PredictedClass: 0, Confidence: 0.6, ClassProbs: valid[:7]},
		{PredictedClass: 7, Confidence: 0.6, ClassProbs: valid},
		{PredictedClass: 0, Confidence: 0.7, ClassProbs: valid},
		{PredictedClass: 0, Confidence: 0.6, ClassProbs: []float32{float32(math.NaN()), 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.4}},
		{PredictedClass: 0, Confidence: 0.6, ClassProbs: []float32{0.6, 0.1, 0.05, 0.05, 0.05, 0.05, 0.05, 0.15}},
	}
	for i := range tests {
		if _, ok := gnnPredictionMargin(&tests[i]); ok {
			t.Errorf("malformed distribution %d was accepted", i)
		}
	}
}

func TestGNNNormalizedEntropy(t *testing.T) {
	uniform := []float32{0.125, 0.125, 0.125, 0.125, 0.125, 0.125, 0.125, 0.125}
	if e := gnnNormalizedEntropy(uniform); math.Abs(float64(e)-1.0) > 1e-5 {
		t.Fatalf("uniform entropy = %v, want 1.0", e)
	}
	oneHot := []float32{1, 0, 0, 0, 0, 0, 0, 0}
	if e := gnnNormalizedEntropy(oneHot); e != 0 {
		t.Fatalf("one-hot entropy = %v, want 0", e)
	}
	if e := gnnNormalizedEntropy([]float32{1}); e != 0 {
		t.Fatalf("degenerate single-class entropy = %v, want 0", e)
	}
}

func TestGNNEntropyGateRejectsFlatTails(t *testing.T) {
	// Clears confidence (0.56 >= 0.55) and margin (0.45 >= 0.10), but the
	// remaining mass is smeared across six classes - the model is unsure.
	flatTail := []float32{0.56, 0.11, 0.055, 0.055, 0.055, 0.055, 0.055, 0.055}
	e := gnnNormalizedEntropy(flatTail)
	if e <= gnnMaxNormalizedEntropy {
		t.Fatalf("flat-tail entropy = %v, want > %v", e, gnnMaxNormalizedEntropy)
	}
	if e < 0.72 || e > 0.75 {
		t.Fatalf("flat-tail entropy = %v, want ~0.733", e)
	}

	// A genuinely peaked prediction must pass the gate untouched.
	confident := []float32{0.70, 0.16, 0.04, 0.02, 0.02, 0.02, 0.02, 0.02}
	if e := gnnNormalizedEntropy(confident); e > gnnMaxNormalizedEntropy {
		t.Fatalf("confident entropy = %v, want <= %v", e, gnnMaxNormalizedEntropy)
	}
}

func TestGNNMinConfidenceForClass(t *testing.T) {
	cases := map[string]float32{
		"license-check":   0.80,
		"repack-marker":   0.60,
		"signature-spoof": 0.60,
		"dynamic-load":    0.65,
		// Untuned classes fall back to the global floor.
		"license-bypass":   gnnMinConfidence,
		"integrity-tamper": gnnMinConfidence,
		"native-bridge":    gnnMinConfidence,
		"benign":           gnnMinConfidence,
		"unknown":          gnnMinConfidence,
	}
	for class, want := range cases {
		if got := gnnMinConfidenceForClass(class); got != want {
			t.Errorf("%s threshold = %v, want %v", class, got, want)
		}
	}
}

func TestGNNLibrarySuppressed(t *testing.T) {
	// Billing libraries stay prefix-verified: license-check inside Play
	// Billing internals is never actionable, other classes stay live there.
	for _, method := range []string{
		"com.google.android.gms.internal.play_billing.zzgf-><init>",
		"com.android.billingclient.api.BillingClientImpl->queryProductDetailsAsync",
	} {
		if reason, ok := gnnLibrarySuppressed(method, "license-check", nil); !ok || reason != "billing_library" {
			t.Errorf("billing library method not suppressed: %s (reason=%q ok=%v)", method, reason, ok)
		}
		if _, ok := gnnLibrarySuppressed(method, "repack-marker", nil); ok {
			t.Errorf("suppression must apply to license-check only: %s", method)
		}
	}
	for _, method := range []string{
		"com.pairip.licensecheck3.LicenseClientV3->checkLicenseInternal",
		"Lcom/app/BillingManager;->verify()Z",
		"com.google.android.gms.internal.play_billingextra.Foo->bar",
	} {
		if _, ok := gnnLibrarySuppressed(method, "license-check", nil); ok {
			t.Errorf("app method wrongly suppressed: %s", method)
		}
	}
}

// TestGNNFrameworkSuppressionNeedsSiblingVerification covers the 2026-11-03
// corpus FP clusters: UI-library repack-marker and GMS plumbing
// repack-marker/signature-spoof/dynamite dynamic-load. A namespace match is
// suppressed only when the scan shows a genuine bundled library (sibling
// classes >= gnnFrameworkMinClasses); lone injected classes stay findings.
func TestGNNFrameworkSuppressionNeedsSiblingVerification(t *testing.T) {
	// Measured shape of the corpus runs: android.support = 617 classes
	// (Приват.apk), gms = 106 + 3 dynamite (Button VPN(1).apk).
	verified := newGNNLibraryClassIndex(map[string]*types.FileAnalysis{
		"a": {SmaliClass: &types.SmaliClass{Name: "android.support.constraint.a.e"}},
		"b": {SmaliClass: &types.SmaliClass{Name: "android.support.v7.widget.CardViewBaseImpl"}},
		"c": {SmaliClass: &types.SmaliClass{Name: "android.support.v7.widget.AppCompatTextView"}},
		"d": {SmaliClass: &types.SmaliClass{Name: "android.support.v4.content.ContextCompat"}},
		"e": {SmaliClass: &types.SmaliClass{Name: "android.support.annotation.RestrictTo"}},
		"f": {SmaliClass: &types.SmaliClass{Name: "android.support.annotation.RestrictTo$Scope"}},
		"j": {SmaliClass: &types.SmaliClass{Name: "android.support.v7.app.AppCompatActivity"}},
		"k": {SmaliClass: &types.SmaliClass{Name: "android.support.v4.app.Fragment"}},
		"g": {SmaliClass: &types.SmaliClass{Name: "androidx.core.widget.NestedScrollView"}},
		"h": {SmaliClass: &types.SmaliClass{Name: "androidx.recyclerview.widget.RecyclerView"}},
		"i": {SmaliClass: &types.SmaliClass{Name: "androidx.fragment.app.FragmentActivity"}},
		// Past the androidx floor: three map entries above plus this padding.
	})
	for i := 0; i < gnnFrameworkMinClasses; i++ {
		verified.counts["androidx."] += 1
	}
	verified.counts["com.google.android.gms."] = 10
	verified.counts["com.google.android.gms.dynamite."] = 3

	suppressedCases := []struct {
		method, class, reason string
	}{
		// The two measured UI FPs.
		{"android.support.constraint.a.e->a(Landroid/support/constraint/a/a/e;FI)V", "repack-marker", "verified_framework_bundle"},
		{"android.support.v7.widget.CardViewBaseImpl->initialize(Landroid/support/v7/widget/CardViewDelegate;FFF)V", "repack-marker", "verified_framework_bundle"},
		// The measured GMS FPs.
		{"com.google.android.gms.common.wrappers.PackageManagerWrapper->getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;", "repack-marker", "verified_framework_bundle"},
		{"com.google.android.gms.common.util.AndroidUtilsLight->getPackageCertificateHashBytes(Landroid/content/Context;Ljava/lang/String;)[B", "repack-marker", "verified_framework_bundle"},
		{"com.google.android.gms.common.internal.safeparcel.SafeParcelWriter->zzd(Landroid/os/Parcel;Landroid/os/Parcelable;I)V", "signature-spoof", "verified_framework_bundle"},
		// Stock Dynamite module loader: dynamic-load is its designed behavior,
		// gated on the whole-GMS sibling count, not the 3-class loader package.
		{"com.google.android.gms.dynamite.zzc->loadClass(Ljava/lang/String;Z)Ljava/lang/Class;", "dynamic-load", "verified_framework_bundle"},
	}
	for _, tc := range suppressedCases {
		reason, ok := gnnLibrarySuppressed(tc.method, tc.class, verified)
		if !ok || reason != tc.reason {
			t.Errorf("%s [%s] not suppressed (reason=%q ok=%v), want %q", tc.method, tc.class, reason, ok, tc.reason)
		}
	}

	unverified := newGNNLibraryClassIndex(map[string]*types.FileAnalysis{
		"a": {SmaliClass: &types.SmaliClass{Name: "android.support.constraint.a.e"}},
		"b": {SmaliClass: &types.SmaliClass{Name: "com.google.android.gms.dynamite.zzc"}},
		// Two more gms classes: still below gnnFrameworkMinClasses.
		"c": {SmaliClass: &types.SmaliClass{Name: "com.google.android.gms.common.GoogleApiAvailability"}},
		"d": {SmaliClass: &types.SmaliClass{Name: "com.google.android.gms.common.internal.safeparcel.SafeParcelWriter"}},
	})
	staysLiveCases := []struct {
		method, class, why string
	}{
		// Namespace squat below the sibling floor: not a verified bundle.
		{"android.support.constraint.a.e->a(II)V", "repack-marker", "sibling floor"},
		{"com.google.android.gms.dynamite.zzc->loadClass(Ljava/lang/String;Z)Ljava/lang/Class;", "dynamic-load", "sibling floor"},
		// Other classes stay live inside verified framework bundles: injected
		// payloads must still surface there.
		{"android.support.injected.Payload->loadDex(Ljava/lang/String;)V", "dynamic-load", "class scoping"},
		{"android.support.injected.Payload->bypass(Ljava/lang/String;)I", "license-bypass", "class scoping"},
		{"androidx.core.ContentProviderHook->a(Landroid/content/Context;)V", "dynamic-load", "class scoping"},
		{"com.google.android.gms.injected.Loader->a(Ljava/lang/String;)V", "dynamic-load", "class scoping"},
		{"com.google.android.gms.common.ChecksumHook->verify()I", "integrity-tamper", "class scoping"},
	}
	for _, tc := range staysLiveCases {
		idx := verified
		if tc.class == "repack-marker" || tc.method == "com.google.android.gms.dynamite.zzc->loadClass(Ljava/lang/String;Z)Ljava/lang/Class;" {
			idx = unverified
		}
		if reason, ok := gnnLibrarySuppressed(tc.method, tc.class, idx); ok {
			t.Errorf("%s [%s] wrongly suppressed (%s): reason=%q", tc.method, tc.class, tc.why, reason)
		}
	}

	// A nil index (no file set) must never suppress: fail open to findings.
	if _, ok := gnnLibrarySuppressed("android.support.v7.widget.CardViewBaseImpl->initialize(Landroid/support/v7/widget/CardViewDelegate;FFF)V", "repack-marker", nil); ok {
		t.Error("nil class index must not suppress framework findings")
	}
}
