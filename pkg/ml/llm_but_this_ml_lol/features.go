package llmkeys

import (
	"strings"
	"unicode"
)

// Features is a structured, explainable description of a single candidate value.
//
// It is the shared substrate for the higher-level capabilities in this package
// (similarity, clustering, anomaly detection and corpus insights). Everything
// here is derived purely from the value itself — no network, no models, no
// external state — so extraction is deterministic and allocation-cheap.
//
// The raw value is intentionally NOT stored on Features: a leaked credential
// must never travel further than it has to. Callers that need the value keep
// it themselves; Features carries only the derived signals.
type Features struct {
	// Length is the byte length of the trimmed value.
	Length int
	// RuneLength is the number of Unicode code points.
	RuneLength int
	// Entropy is Shannon entropy in bits per rune.
	Entropy float64

	// Character-class counts (over runes).
	Lowers  int // a-z (and lowercase Unicode letters)
	Uppers  int // A-Z (and uppercase Unicode letters)
	Digits  int // 0-9
	Symbols int // printable non-alphanumeric (-, _, ., +, /, =, :, …)
	Others  int // everything else (non-ASCII letters counted in Lowers/Uppers)

	// Character-class ratios in [0,1] (count / RuneLength).
	LowerRatio  float64
	UpperRatio  float64
	DigitRatio  float64
	SymbolRatio float64
	UniqueRatio float64 // distinct runes / RuneLength

	// Structural signals.
	Shape    string // run-length-collapsed character-class skeleton (see shapeOf)
	Segments int    // number of separator-delimited segments (-, _, ., :)
	MaxRun   int    // longest run of a single repeated rune

	// Classifier-derived signals (filled by ExtractWithVerdict / Extract).
	Family     string
	HasFamily  bool
	IsSecret   bool
	Confidence float64
}

// separators are the characters treated as segment boundaries when counting
// Segments and building the Shape skeleton.
const separators = "-_.:/+"

// Extract computes the full feature vector for value, including the classifier
// verdict (family, secret decision, confidence). It is the convenience entry
// point; use ExtractFeaturesOnly when the verdict is not needed and you want to
// skip classification work.
func Extract(value string) Features {
	v := strings.TrimSpace(value)
	f := ExtractFeaturesOnly(v)
	verdict := ClassifyCached(v)
	f.Family = verdict.Family
	f.HasFamily = verdict.Family != ""
	f.IsSecret = verdict.IsSecret
	f.Confidence = verdict.Confidence
	return f
}

// ExtractWithVerdict is like Extract but also returns the Verdict, so callers
// that need both do not classify twice.
func ExtractWithVerdict(value string) (Features, Verdict) {
	v := strings.TrimSpace(value)
	f := ExtractFeaturesOnly(v)
	verdict := ClassifyCached(v)
	f.Family = verdict.Family
	f.HasFamily = verdict.Family != ""
	f.IsSecret = verdict.IsSecret
	f.Confidence = verdict.Confidence
	return f, verdict
}

// ExtractFeaturesOnly computes the structural/statistical features of value
// without running the classifier. Family/IsSecret/Confidence are left zero.
func ExtractFeaturesOnly(value string) Features {
	v := strings.TrimSpace(value)
	runes := []rune(v)
	f := Features{
		Length:     len(v),
		RuneLength: len(runes),
		Entropy:    shannonEntropy(v),
	}
	if len(runes) == 0 {
		return f
	}

	seen := make(map[rune]bool, len(runes))
	var maxRun, curRun int
	var prev rune
	for i, r := range runes {
		seen[r] = true
		switch {
		case unicode.IsDigit(r):
			f.Digits++
		case unicode.IsLetter(r):
			if unicode.IsUpper(r) {
				f.Uppers++
			} else {
				f.Lowers++
			}
		case isSymbolRune(r):
			f.Symbols++
		default:
			f.Others++
		}
		if i > 0 && r == prev {
			curRun++
		} else {
			curRun = 1
		}
		if curRun > maxRun {
			maxRun = curRun
		}
		prev = r
	}
	n := float64(len(runes))
	f.LowerRatio = float64(f.Lowers) / n
	f.UpperRatio = float64(f.Uppers) / n
	f.DigitRatio = float64(f.Digits) / n
	f.SymbolRatio = float64(f.Symbols) / n
	f.UniqueRatio = float64(len(seen)) / n
	f.MaxRun = maxRun
	f.Shape = shapeOf(runes)
	f.Segments = segmentCount(v)
	return f
}

func isSymbolRune(r rune) bool {
	return r <= unicode.MaxASCII && r > ' ' &&
		!(r >= '0' && r <= '9') && !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z')
}

// classOf maps a rune to a single skeleton character:
//
//	a  lowercase letter        A  uppercase letter
//	0  digit                   -  separator (-, _, ., :, /, +)
//	.  other printable symbol  ?  anything else (non-ASCII, control)
func classOf(r rune) byte {
	switch {
	case r >= 'a' && r <= 'z':
		return 'a'
	case r >= 'A' && r <= 'Z':
		return 'A'
	case r >= '0' && r <= '9':
		return '0'
	case strings.ContainsRune(separators, r):
		return '-'
	case r <= unicode.MaxASCII && r > ' ':
		return '.'
	case unicode.IsLower(r):
		return 'a'
	case unicode.IsUpper(r):
		return 'A'
	case unicode.IsDigit(r):
		return '0'
	default:
		return '?'
	}
}

// shapeOf returns the run-length-collapsed character-class skeleton, e.g.
// "sk-ant-Xy12" -> "a-a-Aa0" (consecutive same-class runs collapse to one).
// This is a coarse structural signature: two tokens sharing a Shape have the
// same high-level layout even if the concrete characters differ.
func shapeOf(runes []rune) string {
	var b strings.Builder
	var prev byte
	for i, r := range runes {
		c := classOf(r)
		if i == 0 || c != prev {
			b.WriteByte(c)
		}
		prev = c
	}
	return b.String()
}

// segmentCount counts separator-delimited segments (a token with no separator
// is one segment; "sk-ant-abc" is three).
func segmentCount(v string) int {
	if v == "" {
		return 0
	}
	n := 1
	for _, r := range v {
		if strings.ContainsRune(separators, r) {
			n++
		}
	}
	return n
}
