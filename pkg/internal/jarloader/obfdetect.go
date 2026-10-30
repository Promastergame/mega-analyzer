package jarloader

// JVM obfuscation detection for the JAR analyzer.
//
// Commercial protectors (Allatori, Zelix, Stringer) and hand-rolled packers
// hide IOCs in encrypted strings and meaningless names. Static findings from
// such archives are a LOWER BOUND: this module does not deobfuscate, it
// measures signals per class and rolls them into one archive-level finding:
//
//	short names	class simple name <= 2 chars (A, E, a) — weak alone
//	encrypted strings	Utf8 constants with control bytes — strong
//	markers	known obfuscator fingerprints (ALLATORIxDEMO) — definite
//
// Severity: Medium when markers or encrypted strings are present (analysis
// is actively impeded), Low for name-only signals. Legit code is rarely
// affected: ProGuard-style shrinking renames without encrypting strings,
// so it lands at Low at most.

import (
	"fmt"
	"strings"

	"mega-analyzer/pkg/internal/types"
)

// classObf is the per-class obfuscation signal set.
type classObf struct {
	shortName  bool
	encStrings int
	markers    map[string]bool
}

// obfuscatorMarkers are case-insensitive fingerprints of known protectors.
var obfuscatorMarkers = []string{"allatori"}

// obfSignals measures obfuscation signals of one parsed class.
func obfSignals(cf *ClassFile) classObf {
	var out classObf
	if cf == nil {
		return out
	}
	if isShortClassName(cf.ThisClass) {
		out.shortName = true
	}
	for _, s := range cf.Strings {
		if looksEncrypted(s) {
			out.encStrings++
		}
		if m := matchObfuscatorMarker(s); m != "" {
			if out.markers == nil {
				out.markers = map[string]bool{}
			}
			out.markers[m] = true
		}
	}
	return out
}

// isShortClassName reports single/double-char simple names (A, E, a, ab)
// typical of renamed obfuscated code. Inner-class suffixes are stripped.
func isShortClassName(dotted string) bool {
	base := dotted
	if i := strings.LastIndex(base, "."); i >= 0 {
		base = base[i+1:]
	}
	if i := strings.IndexByte(base, '$'); i >= 0 {
		base = base[:i]
	}
	if len(base) > 2 || len(base) == 0 {
		return false
	}
	for i := 0; i < len(base); i++ {
		c := base[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return false
		}
	}
	return true
}

// looksEncrypted reports strings that carry control bytes: genuine text,
// identifiers and URLs never do, while encrypted blobs (Allatori/Zelix
// style) are full of them. Newlines/tabs are excluded — multiline text is
// innocent — and so is a single repeated control char: mods use \x01 as a
// text-format placeholder ("hunger: \x01, sat: \x01"). Real blobs mix
// several control values, so at least two distinct ones are required.
// Strings with NUL bytes are binary annotation blobs (Kotlin @Metadata),
// never encrypted text: MUTF-8 cannot encode a raw NUL in the pool.
func looksEncrypted(s string) bool {
	if len(s) < 24 {
		return false
	}
	bad := 0
	seen := map[byte]bool{}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == 0x00 {
			return false
		}
		if c == '\t' || c == '\n' || c == '\r' {
			continue
		}
		if c < 0x20 || c == 0x7f {
			bad++
			seen[c] = true
		}
	}
	return len(seen) >= 2 && bad*100/len(s) >= 5
}

func matchObfuscatorMarker(s string) string {
	low := strings.ToLower(s)
	for _, m := range obfuscatorMarkers {
		if strings.Contains(low, m) {
			return m
		}
	}
	return ""
}

// mergeObf folds one class result into the report accumulators. Examples
// keep the first few affected class names for the rollup finding.
func mergeObf(rep *Report, className string, o classObf) {
	if o.shortName {
		rep.obfShortNames++
	}
	rep.obfEncStrings += o.encStrings
	for m := range o.markers {
		if rep.obfMarkers == nil {
			rep.obfMarkers = map[string]bool{}
		}
		rep.obfMarkers[m] = true
	}
	if (o.shortName || o.encStrings > 0 || len(o.markers) > 0) && len(rep.obfExamples) < 5 {
		rep.obfExamples = append(rep.obfExamples, className)
	}
}

// emitObfuscationFinding drains the accumulators into one archive-level
// finding. Nil when nothing fired: clean archives stay silent.
func emitObfuscationFinding(rep *Report) *types.Match {
	if rep == nil || (rep.obfShortNames == 0 && rep.obfEncStrings == 0 && len(rep.obfMarkers) == 0) {
		return nil
	}
	category := types.CategoryObfuscatedCode
	severity := types.SeverityLow
	why := "short renamed class names only (ProGuard-style shrinking also looks like this)"
	if len(rep.obfMarkers) > 0 {
		category = types.CategoryObfuscator
		severity = types.SeverityMedium
		why = "known obfuscator fingerprint: " + strings.Join(sortedObfKeys(rep.obfMarkers), ", ")
	} else if rep.obfEncStrings > 0 {
		category = types.CategoryObfuscatedString
		severity = types.SeverityMedium
		why = "encrypted-looking string constants impede static IOC recovery"
	}
	detail := fmt.Sprintf("%d short-named classes, %d encrypted-looking strings", rep.obfShortNames, rep.obfEncStrings)
	if len(rep.obfExamples) > 0 {
		detail += "; e.g. " + strings.Join(rep.obfExamples, ", ")
	}
	return &types.Match{
		Categorized:          types.Categorized{Category: category},
		Text:                 "jar-obfuscation",
		Pattern:              "jar-obfuscation",
		Context:              "JAR obfuscation indicators: " + detail,
		Severity:             severity,
		Confidence:           "0.80",
		EvidenceType:         "heuristic",
		ReasonForSeverity:    "Code obfuscation detected (" + why + ") — treat all other findings as a lower bound",
		SourceLocation:       types.SourceLocation{File: rep.Target},
		RequiredNextEvidence: "Deobfuscate string decryption to recover hidden IOCs (URLs, class names, C2).",
		Metadata: map[string]string{
			"short_name_classes": fmt.Sprint(rep.obfShortNames),
			"encrypted_strings":  fmt.Sprint(rep.obfEncStrings),
		},
	}
}

func sortedObfKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
