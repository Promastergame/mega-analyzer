package llmkeys

import "strings"

// JunkJudge adapts this package's classifier into a plain callback, ready to
// plug into the secrets scanner without any import dependency between the two
// packages (both stay plain folders of the host project):
//
//	secrets.SetValueJudge(llmkeys.JunkJudge())
//
// It reports true when the value looks like junk (placeholder, test data,
// digest, structured identifier) rather than a live credential. Verdicts are
// served through the process-wide LRU cache, so repeated values are cheap.
func JunkJudge() func(value string) bool {
	return func(value string) bool {
		return !ClassifyCached(value).IsSecret
	}
}

// homoglyphs maps common Cyrillic and Greek look-alike letters onto their
// Latin twins so an obfuscated value (say "AKIA" typed with a Cyrillic A)
// still hits prefix, family and placeholder checks. Purely offline.
var homoglyphs = strings.NewReplacer(
	"\u0410", "A", "\u0412", "B", "\u0415", "E", "\u041a", "K", "\u041c", "M",
	"\u041d", "H", "\u041e", "O", "\u0420", "P", "\u0421", "C", "\u0422", "T",
	"\u0425", "X", "\u0430", "a", "\u0435", "e", "\u043e", "o", "\u0440", "p",
	"\u0441", "c", "\u0445", "x", "\u0443", "y",
	"\u0391", "A", "\u0392", "B", "\u0395", "E", "\u0396", "Z", "\u0397", "H",
	"\u0399", "I", "\u039a", "K", "\u039c", "M", "\u039d", "N", "\u039f", "O",
	"\u03a1", "P", "\u03a4", "T", "\u03a5", "Y", "\u03a7", "X",
	"\u03bf", "o", "\u03bd", "v",
)

// NormalizeHomoglyphs rewrites visually identical non-Latin letters to Latin
// ASCII. Run it before Classify when scanning sources that may hide secrets
// behind Unicode look-alikes:
//
//	verdict := llmkeys.Classify(llmkeys.NormalizeHomoglyphs(raw))
//
// It is deliberately NOT applied inside Classify itself: genuine non-Latin
// content (including the Russian keyword indicators) must stay intact unless
// the caller opts in.
func NormalizeHomoglyphs(s string) string {
	return homoglyphs.Replace(s)
}
