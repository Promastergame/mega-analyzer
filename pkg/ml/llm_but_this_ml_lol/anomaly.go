package llmkeys

// Anomaly detection targets the blind spot of a family/prefix classifier: a
// credential in a format nobody has enumerated yet. Such a value has no known
// prefix, so matchFamily misses it, but it still *looks* like a secret — long,
// high-entropy, mixed character classes, no repeating structure, and not one of
// the known structured non-secrets (UUID, hex digest, base64 text). Anomaly
// scoring surfaces exactly those "unknown-but-suspicious" strings for review.
//
// This is complementary to Classify, not a replacement: Classify already
// accepts some indicator-bearing high-entropy tokens as secrets. AnomalyScore
// instead ranks how *unusual-yet-credential-shaped* a value is, independent of
// whether Classify made a positive call.

// Anomaly describes an anomalous candidate value.
type Anomaly struct {
	// Score in [0,1]; higher means more anomalous / more worth reviewing.
	Score float64
	// Family is the classifier family if any ("" is the interesting case).
	Family string
	// IsKnownSecret is true when Classify already flags it as a secret.
	IsKnownSecret bool
	// Reason is a short human-readable explanation.
	Reason string
	// Features is the extracted feature vector.
	Features Features
}

// anomalyThreshold is the default score at/above which IsAnomalous is true.
const anomalyThreshold = 0.60

// AnomalyScore returns how anomalous-yet-credential-shaped value is, in [0,1].
//
// The score rewards signals that make a string look like an unrecognized
// secret and penalizes signals that make it look like ordinary data:
//
//   - high Shannon entropy (well-mixed characters)
//   - substantial length
//   - multiple character classes present (letters AND digits, maybe symbols)
//   - high character variety (few repeats)
//   - known credential family (not anomalous — we already recognize it)
//   - structured non-secret shape (UUID / hex digest / base64 text / sequential)
//   - placeholder markers
func AnomalyScore(value string) Anomaly {
	f, verdict := ExtractWithVerdict(value)
	return anomalyFromFeatures(value, f, verdict)
}

func anomalyFromFeatures(value string, f Features, verdict Verdict) Anomaly {
	a := Anomaly{Family: f.Family, IsKnownSecret: verdict.IsSecret, Features: f}

	if f.RuneLength < minLen {
		a.Reason = "too short to be an unknown credential"
		return a
	}

	low := NormalizedValue(value)

	// Recognized family: by definition not an anomaly — we know what it is.
	if f.HasFamily {
		a.Score = 0.0
		a.Reason = "recognized credential family '" + f.Family + "' (not anomalous)"
		return a
	}

	// Known structured non-secret shapes are the opposite of anomalous.
	if reason := matchNonSecretStructure(value, low); reason != "" {
		a.Score = 0.05
		a.Reason = "structured non-secret (" + reason + ")"
		return a
	}
	if isAllSame(value) || isSequential(low) || containsTrivialSequentialRun(low) || f.UniqueRatio < 0.25 {
		a.Score = 0.05
		a.Reason = "trivial/low-variety pattern"
		return a
	}
	if m := matchPlaceholder(low, value); m != "" {
		a.Score = 0.05
		a.Reason = "placeholder marker: " + m
		return a
	}

	// Entropy component: map 3.0..5.0 bits/rune onto 0..1.
	entComp := (f.Entropy - 3.0) / 2.0
	entComp = clamp(entComp, 0.0, 1.0)

	// Length component: 16..48 chars onto 0..1.
	lenComp := float64(f.RuneLength-16) / 32.0
	lenComp = clamp(lenComp, 0.0, 1.0)

	// Character-class diversity: how many of {lower, upper, digit, symbol} appear.
	classes := 0
	if f.Lowers > 0 {
		classes++
	}
	if f.Uppers > 0 {
		classes++
	}
	if f.Digits > 0 {
		classes++
	}
	if f.Symbols > 0 {
		classes++
	}
	diversity := float64(classes) / 4.0

	// Variety component: high unique-rune ratio.
	variety := clamp((f.UniqueRatio-0.3)/0.5, 0.0, 1.0)

	score := 0.40*entComp + 0.25*lenComp + 0.20*diversity + 0.15*variety
	a.Score = clamp(score, 0.0, 1.0)

	switch {
	case a.Score >= anomalyThreshold:
		a.Reason = "high-entropy, mixed-class token with no recognized family — possible unknown-format credential"
	case a.Score >= 0.4:
		a.Reason = "moderately credential-shaped unknown token"
	default:
		a.Reason = "low anomaly: does not strongly resemble a credential"
	}
	return a
}

// IsAnomalous reports whether value scores at/above the default anomaly
// threshold.
func IsAnomalous(value string) bool {
	return AnomalyScore(value).Score >= anomalyThreshold
}

// DetectAnomalies scores every value and returns those at/above minScore,
// sorted by descending score. Pass minScore<=0 to use the default threshold.
func DetectAnomalies(values []string, minScore float64) []Anomaly {
	if minScore <= 0 {
		minScore = anomalyThreshold
	}
	var out []Anomaly
	for _, v := range values {
		a := AnomalyScore(v)
		if a.Score >= minScore {
			out = append(out, a)
		}
	}
	sortAnomalies(out)
	return out
}

func sortAnomalies(as []Anomaly) {
	// insertion sort keeps it dependency-free and stable for the small slices
	// this produces in practice.
	for i := 1; i < len(as); i++ {
		for j := i; j > 0 && as[j].Score > as[j-1].Score; j-- {
			as[j], as[j-1] = as[j-1], as[j]
		}
	}
}
