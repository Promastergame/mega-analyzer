package deobfmetrics

// Tunable thresholds for the heuristic classifiers. They are collected here,
// each with a rationale, instead of being scattered as magic numbers through
// the code. Adjust these to fit a specific obfuscator's fingerprint.
const (
	// obfEntropyThreshold is the Shannon-entropy (bits/char) above which a
	// reasonably long identifier is considered random-looking. ~3.5 bits
	// corresponds to roughly 11+ equiprobable symbols, which real words do
	// not reach at short lengths.
	obfEntropyThreshold = 3.5

	// highEntropyStringThreshold is the entropy above which a string is
	// considered encrypted/encoded. Natural-language text sits well below
	// 4.0 bits/char; base64/ciphertext sits above it.
	highEntropyStringThreshold = 4.0

	// minHighEntropyStringLen avoids flagging short tokens (which cannot
	// accumulate enough symbols to be confidently "encrypted").
	minHighEntropyStringLen = 8

	// trivialNameMaxLen: names of this length or shorter are treated as
	// obfuscated outright (a, b, x1, ...).
	trivialNameMaxLen = 2

	// shortNoVowelMaxLen: names up to this length with no vowels look
	// machine-generated (e.g. "xkq").
	shortNoVowelMaxLen = 4

	// minMeaningfulNameLen is the minimum length for a name to even be
	// considered a real, meaningful identifier.
	minMeaningfulNameLen = 3

	// randomAlphaNumMaxLen bounds the "a1b2c3" alphanumeric-soup heuristic.
	randomAlphaNumMaxLen = 8

	// randomAlphaNumMaxLetters caps letters in the alphanumeric-soup check;
	// more letters than this suggests a real (camelCase) name.
	randomAlphaNumMaxLetters = 4
)

// Grade thresholds for OverallConfidence.
const (
	gradeS = 0.90
	gradeA = 0.80
	gradeB = 0.65
	gradeC = 0.50
	gradeD = 0.30
)

// meaningfulPrefixes is a package-level, extensible list of common
// programming-word prefixes. Exposed as a var (not a const slice) so callers
// can extend it for a specific codebase without editing classifier logic.
var meaningfulPrefixes = []string{
	"get", "set", "is", "has", "on", "init", "create",
	"update", "delete", "find", "check", "validate",
	"process", "handle", "load", "save", "parse",
}
