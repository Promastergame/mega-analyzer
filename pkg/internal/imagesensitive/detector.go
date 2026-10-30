package imagesensitive

import (
	"image"
	_ "image/gif"  // register GIF decoder
	_ "image/jpeg" // register JPEG decoder
	_ "image/png"  // register PNG decoder
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// SENSITIVE-CONTENT HEURISTIC
//
// Goal: produce a neutral score in [0, 1] that hints whether an image MAY
// require human review. Implementation constraints from plan.md §6:
//
//   - 0 ML models, 0 network calls
//   - decode → 64×64 thumbnail BEFORE any analysis (RAM safety)
//   - score must be deterministic and bounded by [0, 1]
//   - the only label that ever leaves the package is the neutral string
//     "possible sensitive content"
// ═══════════════════════════════════════════════════════════════════════════════

// SensitiveLabel is the only label the package ever emits.
const SensitiveLabel = "possible sensitive content"

// thumbnailScoreThreshold is the strict cut-off above which we attach the
// neutral label. Lower thresholds explode false-positive rates.
const thumbnailScoreThreshold = 0.55

// Result is the structured output of Score. Reasons explain why the score
// was elevated, using neutral language suitable for UI display.
type Result struct {
	Score   float64
	Label   string
	Reasons []string
}

// Score returns (score, label). label is empty when score is below the
// threshold. The function never panics; named returns ensure a clean zero
// state on recovery.
func Score(img image.Image, hint string) (score float64, label string) {
	if img == nil {
		return 0, ""
	}
	defer func() {
		if recover() != nil {
			score, label = 0, ""
		}
	}()

	thumb := Resize64(img)
	skinFrac := SkinFraction(thumb)
	domHits := DominantSkinDominance(thumb)
	hintScore := HintsScore(hint)

	// If the image is nearly uniform (solid colour), suppress skin signals
	// to avoid false positives on beige/tan solid fills.
	if ColorVariance(thumb) < 0.02 {
		skinFrac *= 0.4
		domHits *= 0.3
	}

	// Combine signals — weights chosen so each signal alone never crosses 0.55.
	// skin   ∈ [0,1] · 0.55
	// dom    ∈ [0,1] · 0.20
	// hints  ∈ [0,1] · 0.35
	score = clamp01(skinFrac*0.55 + domHits*0.20 + hintScore*0.35)

	if score >= thumbnailScoreThreshold {
		label = SensitiveLabel
	}
	return score, label
}

// ScoreResult is like Score but returns the full Result struct with reasons.
func ScoreResult(img image.Image, hint string) (res Result) {
	if img == nil {
		return Result{}
	}
	defer func() {
		if recover() != nil {
			res = Result{}
		}
	}()

	thumb := Resize64(img)
	skinFrac := SkinFraction(thumb)
	domHits := DominantSkinDominance(thumb)
	hintScore := HintsScore(hint)

	if ColorVariance(thumb) < 0.02 {
		skinFrac *= 0.4
		domHits *= 0.3
	}

	res.Score = clamp01(skinFrac*0.55 + domHits*0.20 + hintScore*0.35)

	// Collect reasons.
	if skinFrac >= 0.40 {
		res.Reasons = append(res.Reasons, "large skin-tone colour fraction")
	}
	if domHits >= 0.6 {
		res.Reasons = append(res.Reasons, "dominant colour is skin-toned")
	}
	if hintScore > 0 {
		res.Reasons = append(res.Reasons, "filename suggests personal content")
	}

	if res.Score >= thumbnailScoreThreshold {
		res.Label = SensitiveLabel
	}
	return res
}

// ScoreBytes is a convenience wrapper that decodes raw bytes first.
// Returns score=0 and empty label on decode failure.
func ScoreBytes(data []byte, hint string) (score float64, label string) {
	defer func() {
		if recover() != nil {
			score, label = 0, ""
		}
	}()

	img, _, err := image.Decode(bytesReader(data))
	if err != nil {
		return 0, ""
	}
	return Score(img, hint)
}

func clamp01(v float64) float64 {
	switch {
	case v < 0:
		return 0
	case v > 1:
		return 1
	default:
		return v
	}
}

// HintsScore evaluates filename / EXIF hints. Tokenizes the hint string
// by non-alphanumeric separators to avoid matching random substrings.
func HintsScore(hint string) float64 {
	if hint == "" {
		return 0
	}
	tokens := tokenizeHint(hint)
	if len(tokens) == 0 {
		return 0
	}

	hits := 0
	for _, kw := range hintKeywords() {
		for _, tok := range tokens {
			if tok == kw {
				hits++
				break
			}
		}
	}
	// Check bigrams (e.g. "id_card" → tokens "id","card").
	for _, bg := range hintBigrams() {
		for i := 0; i+1 < len(tokens); i++ {
			if tokens[i] == bg[0] && tokens[i+1] == bg[1] {
				hits++
				break
			}
		}
	}

	if hits == 0 {
		return 0
	}
	// Each hit adds 0.4, capped at 1.0.
	score := 0.4 * float64(hits)
	if score > 1 {
		score = 1
	}
	return score
}

// tokenizeHint splits a filename/path into lowercase alphanumeric tokens.
func tokenizeHint(s string) []string {
	s = strings.ToLower(s)
	f := func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'))
	}
	return strings.FieldsFunc(s, f)
}

// hintKeywords returns single-token keywords that suggest personal content.
// Deliberately neutral — no explicit/adult terms.
func hintKeywords() []string {
	return []string{
		"selfie",
		"private",
		"personal",
		"passport",
		"nude",
	}
}

// hintBigrams returns two-token sequences that form meaningful hints.
func hintBigrams() [][2]string {
	return [][2]string{
		{"id", "card"},
	}
}
