package main

import (
	"math"
	"testing"

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
		"license-bypass":  gnnMinConfidence,
		"integrity-tamper": gnnMinConfidence,
		"native-bridge":   gnnMinConfidence,
		"benign":          gnnMinConfidence,
		"unknown":         gnnMinConfidence,
	}
	for class, want := range cases {
		if got := gnnMinConfidenceForClass(class); got != want {
			t.Errorf("%s threshold = %v, want %v", class, got, want)
		}
	}
}

func TestGNNLibrarySuppressed(t *testing.T) {
	for _, method := range []string{
		"com.google.android.gms.internal.play_billing.zzgf-><init>",
		"com.android.billingclient.api.BillingClientImpl->queryProductDetailsAsync",
	} {
		if !gnnLibrarySuppressed(method, "license-check") {
			t.Errorf("billing library method not suppressed: %s", method)
		}
		if gnnLibrarySuppressed(method, "repack-marker") {
			t.Errorf("suppression must apply to license-check only: %s", method)
		}
	}
	for _, method := range []string{
		"com.pairip.licensecheck3.LicenseClientV3->checkLicenseInternal",
		"Lcom/app/BillingManager;->verify()Z",
		"com.google.android.gms.internal.play_billingextra.Foo->bar",
	} {
		if gnnLibrarySuppressed(method, "license-check") {
			t.Errorf("app method wrongly suppressed: %s", method)
		}
	}
}
