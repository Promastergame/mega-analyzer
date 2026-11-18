package main

import (
	"math"
	"strings"

	"mega-analyzer/pkg/internal/types"
	"mega-analyzer/pkg/ml/gnn"
	"mega-analyzer/pkg/ml/gnncache"
)

// GNN quality-gate floors. They live here (untagged) rather than in
// runner_gnn.go (cgo-tagged) so tests and stub builds share them.
const (
	gnnMinConfidence = float32(0.55)
	gnnMinMargin     = float32(0.10)
)

// gnnPredictionMargin validates a cached or freshly inferred distribution and
// returns the gap between the top two classes. Confidence alone is unreliable
// for an eight-way classifier: a near-tie should not become a security finding.
func gnnPredictionMargin(pred *gnncache.Prediction) (float32, bool) {
	if pred == nil || pred.PredictedClass < 0 || pred.PredictedClass >= len(pred.ClassProbs) ||
		len(pred.ClassProbs) != gnn.NumVulnClasses || !isFiniteProbability(pred.Confidence) {
		return 0, false
	}
	bestIndex := -1
	best, second := float32(-1), float32(-1)
	var sum float64
	for i, probability := range pred.ClassProbs {
		if !isFiniteProbability(probability) {
			return 0, false
		}
		sum += float64(probability)
		if probability > best {
			second = best
			best = probability
			bestIndex = i
		} else if probability > second {
			second = probability
		}
	}
	if math.Abs(sum-1) > 1e-3 || bestIndex != pred.PredictedClass ||
		math.Abs(float64(best-pred.Confidence)) > 1e-5 {
		return 0, false
	}
	return best - second, true
}

// gnnMinConfidenceForClass returns the minimum accepted confidence for a
// vulnerability class. Calibrated on the golden set (clean Mindustry/FNAF as
// negatives; modmenu/PairIP/Morphe methods as positives — see train logs):
//
//   - license-check 0.80: billing-library code (Play Billing, billingclient,
//     engine IAB managers) genuinely looks like license verification, so the
//     global 0.55 admits hundreds of findings per clean game. 0.80 keeps the
//     substantive TP (connectToLicensingService, ResponseValidator at
//     0.82-0.93) while dropping one-liner lambdas that are structurally
//     indistinguishable from benign.
//   - repack-marker 0.60: 108/445 TP at 25 FP on the calibration pool;
//     0.65 already halves recall (95) for little FP gain.
//   - signature-spoof 0.60: FP vanish above 0.60 (5 at 0.60, 0 at 0.80);
//     recall is a model problem (see below), not a threshold one.
//   - dynamic-load 0.65: classloader TP hold 0.9+, FP tail cut.
//   - default 0.55: license-bypass never fires on clean data, and
//     integrity-tamper/native-bridge are silent under v10 weights — no
//     evidence for raising them yet. Revisit when the model changes.
func gnnMinConfidenceForClass(vulnName string) float32 {
	switch vulnName {
	case "license-check":
		return 0.80
	case "repack-marker":
		return 0.60
	case "signature-spoof":
		return 0.60
	case "dynamic-load":
		return 0.65
	default:
		return gnnMinConfidence
	}
}

// gnnLicenseLibraryPrefixes are known billing-library packages whose methods
// structurally ARE license verification (Play Billing internals) but are
// never actionable findings: every clean game with in-app purchases lights
// them up (~420 FP per two calibration games at 0.80). Real findings point
// at app/engine code that CALLS billing (IABillingManager, LicenseClient),
// which is unaffected. Mirrors the pipeline's stock-FP allowlisting.
var gnnLicenseLibraryPrefixes = []string{
	"com.google.android.gms.internal.play_billing.",
	"com.android.billingclient.api.",
}

// gnnFrameworkLibraryPrefixes are framework/library namespaces whose bundled
// code is recompiled wholesale by the build tooling on every APK rebuild.
// Measured FP clusters from the 2026-11-03 malware corpus run:
//
//   - android.support.* UI plumbing predicted repack-marker (ConstraintLayout
//     0.65, CardViewBaseImpl.initialize 0.75) — corner-radius switches and
//     layout math read as re-sign/attributions to the model.
//   - com.google.android.gms.* plumbing predicted repack-marker/signature-spoof
//     (PackageManagerWrapper.getPackageInfo 0.92, AndroidUtilsLight
//     .getPackageCertificateHashBytes 0.82, SafeParcelWriter 0.66) — Google's
//     own package-integrity plumbing reads as authenticity tampering.
//
// A namespace match alone is NOT trusted: malware hides in framework
// namespaces too. newGNNLibraryClassIndex verifies the bundle claim by
// counting sibling classes, so a lone injected class stays a finding.
var gnnFrameworkLibraryPrefixes = []string{
	"android.support.",
	"androidx.",
	"com.google.android.material.",
	"com.google.android.exoplayer2.",
	"com.google.android.exoplayer.",
	"com.google.android.gms.dynamite.",
	"com.google.android.gms.",
}

// gnnFrameworkMinClasses is the sibling-class floor for treating a namespace
// match as a genuine bundled library. Measured bundles: android.support.*
// = 617 classes (Приват.apk), com.google.android.gms.* = 109 (Button VPN).
// An attacker-injected namespace squat yields 1-3 classes, an order of
// magnitude below the floor; the smallest real artifact (androidx.annotation)
// still ships ~40.
const gnnFrameworkMinClasses = 8

// gnnFrameworkSuppressedClasses limits suppression to authenticity-claim
// classes: repack-marker and signature-spoof assert "the code is not what it
// claims to be", which is exactly what library plumbing spuriously resembles.
// dynamic-load, license-bypass, integrity-tamper and native-bridge stay live
// inside framework namespaces so injected payloads still surface there.
// The single exception is the stock Play-services Dynamite module loader
// (com.google.android.gms.dynamite.*): loading feature modules on demand is
// its designed behavior (measured FP 0.96), and it only suppresses when the
// whole GMS bundle passes the sibling check.
func gnnFrameworkSuppressedClass(prefix, vulnName string) bool {
	if gnnFrameworkSuppressedClasses[vulnName] {
		return true
	}
	// ExoPlayer DRM methods (setDrmLicenseRequestHeader and friends) are
	// Widevine license plumbing — the license-check class fires on them at
	// 0.81+ in every media app (measured on NewPipe, 2026-11-04), but DRM
	// license requests are never actionable licensing findings.
	if vulnName == "license-check" &&
		(prefix == "com.google.android.exoplayer2." || prefix == "com.google.android.exoplayer.") {
		return true
	}
	return vulnName == "dynamic-load" &&
		prefix == "com.google.android.gms.dynamite."
}

var gnnFrameworkSuppressedClasses = map[string]bool{
	"repack-marker":   true,
	"signature-spoof": true,
}

// gnnLibraryClassIndex counts distinct smali classes per framework prefix for
// one scan. It turns a namespace match ("looks like a library") into a
// verified one ("the whole library was bundled"), per the corpus report's
// rule that namespace strings alone must not hide results.
type gnnLibraryClassIndex struct {
	counts map[string]int
}

func newGNNLibraryClassIndex(files map[string]*types.FileAnalysis) *gnnLibraryClassIndex {
	idx := &gnnLibraryClassIndex{counts: make(map[string]int, len(gnnFrameworkLibraryPrefixes))}
	for _, file := range files {
		if file == nil || file.SmaliClass == nil {
			continue
		}
		name := file.SmaliClass.Name
		for _, prefix := range gnnFrameworkLibraryPrefixes {
			if strings.HasPrefix(name, prefix) {
				idx.counts[prefix]++
				break
			}
		}
	}
	return idx
}

// verify checks whether the matched prefix passed the sibling-class floor.
// The dynamite loader matches the narrow gms.dynamite prefix but is gated on
// the whole-GMS count: the loader package itself can hold only a handful of
// classes in a legitimate basement-only bundle.
func (idx *gnnLibraryClassIndex) verify(prefix, vulnName string) bool {
	if idx == nil {
		return false
	}
	if vulnName == "dynamic-load" && prefix == "com.google.android.gms.dynamite." {
		prefix = "com.google.android.gms."
	}
	return idx.counts[prefix] >= gnnFrameworkMinClasses
}

// gnnLibrarySuppressed reports whether a finding should be dropped as library
// noise, returning the diagnostic reason. Two mechanisms:
//
//   - billing libraries: license-check inside Play Billing internals is
//     structurally license verification but never actionable (verified by
//     prefix; namespace squatting there has no observed history).
//   - framework libraries: repack-marker/signature-spoof inside a VERIFIED
//     framework bundle (sibling classes >= gnnFrameworkMinClasses), plus the
//     stock Dynamite loader for dynamic-load. Lone injected classes fail the
//     sibling check and stay findings.
func gnnLibrarySuppressed(method, vulnName string, libIndex *gnnLibraryClassIndex) (string, bool) {
	class := method
	if idx := strings.Index(method, "->"); idx >= 0 {
		class = method[:idx]
	}
	if vulnName == "license-check" {
		for _, prefix := range gnnLicenseLibraryPrefixes {
			if strings.HasPrefix(method, prefix) {
				return "billing_library", true
			}
		}
		// The APK signing library's crypto plumbing (certificate generation,
		// lineage config, digest selection) reads as license verification to
		// the model; it is signing infrastructure, never the app's license
		// gate. Prefix-only like billing libraries: apksig is already a
		// path-verified known library in the filter, so namespace squatting
		// would require planting the whole toolchain package.
		if strings.HasPrefix(class, "com.android.apksig.") {
			return "signing_library", true
		}
		return "", false
	}
	for _, prefix := range gnnFrameworkLibraryPrefixes {
		if strings.HasPrefix(class, prefix) && gnnFrameworkSuppressedClass(prefix, vulnName) {
			if libIndex.verify(prefix, vulnName) {
				return "verified_framework_bundle", true
			}
			return "", false
		}
	}
	return "", false
}

// gnnMaxNormalizedEntropy is the third leg of the quality gate. Confidence
// checks the argmax and margin checks the top-two gap, but neither looks at
// the tail: a prediction like [0.56, 0.11, 0.055 x 6] clears both thresholds
// while the model is effectively unsure among many alternatives. Normalized
// entropy measures the whole distribution; values above this threshold are
// treated as uncertain. (With confidence >= 0.55 the maximum achievable
// normalized entropy is ~0.75, so 0.70 only rejects genuinely flat tails.)
const gnnMaxNormalizedEntropy = float32(0.70)

// gnnNormalizedEntropy returns the Shannon entropy of the distribution
// normalized to [0, 1] by log2(len(probs)): 0 = one-hot certainty,
// 1 = uniform. Callers must validate the distribution first (see
// gnnPredictionMargin); non-positive entries contribute zero, matching the
// p*log(p) -> 0 limit.
func gnnNormalizedEntropy(probs []float32) float32 {
	if len(probs) < 2 {
		return 0
	}
	var entropy float64
	for _, probability := range probs {
		if probability > 0 {
			entropy -= float64(probability) * math.Log2(float64(probability))
		}
	}
	normalized := entropy / math.Log2(float64(len(probs)))
	switch {
	case normalized < 0 || math.IsNaN(normalized):
		return 0
	case normalized > 1:
		return 1
	default:
		return float32(normalized)
	}
}

func isFiniteProbability(value float32) bool {
	return value >= 0 && value <= 1 && !math.IsNaN(float64(value)) && !math.IsInf(float64(value), 0)
}
