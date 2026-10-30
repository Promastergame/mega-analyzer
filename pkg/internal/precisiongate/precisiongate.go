// Package precisiongate is a self-contained, drop-in false-positive filter for
// mega-analyzer. It encodes the FP root-causes proven on Shattered Pixel
// Dungeon v3.3.8 (a clean GPLv3 game that scored CRITICAL 71/100 with 56
// "critical" matches, all substring/context noise).
//
// It has ZERO dependencies on the rest of the analyzer. It is wired into
// sastrules/scanner.go (scanFile) AND pipeline/workers.go collectResult via
// pipeline/precision_gate.go. The gate
// works off the DATA THE SCANNER ACTUALLY HAS per hit: the matched literal
// (data[loc0:loc1]), a context window around it, and the file path. The
// map-based rules match by TOKEN CONTAINMENT so they are robust to how much
// text a given regex captured.
package precisiongate

import (
	"path"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// Context describes where a match was found.
type Context string

const (
	CodeCtx     Context = "code"     // smali / dex / java / kt
	AssetCtx    Context = "asset"    // assets/**, *.properties
	ResourceCtx Context = "resource" // res/**, *.xml resources
	ManifestCtx Context = "manifest"
	NativeCtx   Context = "native" // *.so
)

// Candidate is one raw pattern hit before precision filtering.
type Candidate struct {
	Category string  // rule set / category name
	Keyword  string  // the matched literal, e.g. data[loc0:loc1]
	FilePath string  // slash-normalized path inside the APK
	Context  Context // where it was found
	Line     string  // context window around the hit (superset of Keyword)
	// Media-only fields (0/"" when N/A; this scanner is text-only so they stay
	// empty, but the gate stays usable for a future media scanner):
	ByteOffset    int64
	ContainerSize int64
	ContainerFmt  string
	EmbeddedMagic string
	EntropyBits   float64
}

// Verdict is the gate's decision.
type Verdict struct {
	Keep      bool   // false => drop entirely
	Downgrade bool   // true => keep but not critical (e.g. INFO)
	Reason    string // why
}

func keep() Verdict         { return Verdict{Keep: true} }
func drop(r string) Verdict { return Verdict{Keep: false, Reason: r} }

// ---- 1. Localization / natural-language prose detection ---------------------

var langSuffix = regexp.MustCompile(`_[a-z]{2}(_[A-Z]{2})?\.(properties|xml|json|strings)$`)
var valuesLangDir = regexp.MustCompile(`(^|/)values-[a-z]{2}(-r[A-Z]{2})?/`)

// IsLocalizationBundle reports whether path holds translated UI strings, where
// natural-language words routinely collide with piracy/mod keywords
// (Swedish "magisk" = magical, English "unlocked"/"cracked" game vocabulary).
func IsLocalizationBundle(p string) bool {
	p = strings.ToLower(strings.ReplaceAll(p, "\\", "/"))
	if strings.Contains(p, "assets/messages/") || strings.Contains(p, "/messages/") {
		return true
	}
	if langSuffix.MatchString(p) || valuesLangDir.MatchString(p) {
		return true
	}
	// base bundles like items.properties/actors.properties are also i18n source
	base := path.Base(p)
	if strings.HasSuffix(base, ".properties") && !strings.Contains(p, "meta-inf/") {
		return true
	}
	return false
}

var wordRe = regexp.MustCompile(`\p{L}+`)

// looksLikeProse is a cheap heuristic: 4+ alphabetic words in the window.
func looksLikeProse(line string) bool {
	return len(wordRe.FindAllString(line, -1)) >= 4
}

// ---- 2. Token-boundary matching (kills DES in DESCEND, etc.) -----------------

// IsStandaloneToken reports whether keyword occurs in text as a whole token,
// not as a substring of a larger identifier/word. Case-insensitive.
//
// Rune-based (not byte-based): the gate filters i18n prose, so a Cyrillic or
// CJK letter adjacent to an ASCII keyword must count as a word char — byte
// indexing sees only a 0x80+ continuation byte and calls it a boundary.
// Word chars are ASCII alnum + '_' + Unicode letters/digits, which is
// identical to the old behavior on pure-ASCII input.
func IsStandaloneToken(text, keyword string) bool {
	if keyword == "" {
		return false
	}
	lt := []rune(strings.ToLower(text))
	lk := []rune(strings.ToLower(keyword))
	checkStart := isWordChar(lk[0])
	checkEnd := isWordChar(lk[len(lk)-1])

outer:
	for i := 0; i+len(lk) <= len(lt); i++ {
		for j := range lk {
			if lt[i+j] != lk[j] {
				continue outer
			}
		}
		leftOK := !checkStart || i == 0 || !isWordChar(lt[i-1])
		rightOK := !checkEnd || i+len(lk) == len(lt) || !isWordChar(lt[i+len(lk)])
		if leftOK && rightOK {
			return true
		}
	}
	return false
}

func isWordChar(r rune) bool {
	return r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r)
}

// ---- 3. Keywords that MUST have a corroborating code API nearby -------------

// codeCorroboration maps a security keyword to API tokens that must be present
// in the same window for the hit to be real.
var codeCorroboration = map[string][]string{
	"getdeviceid": {"TelephonyManager", "telephony"},               // NOT InputDevice.getDeviceId()
	"exec":        {"Ljava/lang/Runtime;->exec", "ProcessBuilder"}, // NOT freeMemory / "execute" text
	"des":         {"Cipher", "getInstance"},                       // NOT DESCEND / PEDESTAL
	"runtime":     {"->exec", "->halt(", "addShutdownHook"},        // NOT getRuntime().freeMemory()
}

// ---- 4. Media forensics gating (unused by the text-only scanner) ------------

var lossyOrCompressed = map[string]bool{
	"mp3": true, "ogg": true, "opus": true, "aac": true, "m4a": true,
	"png": true, "jpg": true, "jpeg": true, "webp": true, "gif": true,
	"zip": true, "jar": true, "gz": true, "zst": true, "xz": true,
}

// EntropyAnomalyApplies is false for already-compressed containers: entropy of
// ~7.8-7.99 bits/byte is expected there and is not evidence of hidden data.
func EntropyAnomalyApplies(fmtName string) bool {
	return !lossyOrCompressed[strings.ToLower(strings.TrimPrefix(fmtName, "."))]
}

const polyglotHeaderWindow = 64

// PolyglotIsSuspicious gates magic-signature "polyglot" hits: only a header-
// window or tail (appended payload) signature is suspicious; a deep-interior
// magic byte in a compressed stream is a collision.
func PolyglotIsSuspicious(offset, containerSize int64) bool {
	if offset <= polyglotHeaderWindow {
		return true
	}
	if containerSize > 0 && containerSize-offset <= polyglotHeaderWindow {
		return true
	}
	return false
}

// ---- 5. Signature-check reality test ----------------------------------------

var realSigTokens = []string{
	"GET_SIGNATURES", "GET_SIGNING_CERTIFICATES", "getSigningInfo",
	"signingInfo", "apkContentsSigners", "MessageDigest",
}

// SignatureCheckIsReal: getPackageInfo alone (used for versionName/versionCode)
// is benign; a real signature/anti-tamper check pulls the cert.
func SignatureCheckIsReal(methodBody string) bool {
	for _, t := range realSigTokens {
		if strings.Contains(methodBody, t) {
			return true
		}
	}
	return false
}

// ---- Top-level evaluation ----------------------------------------------------

// piracy/mod keywords that double as ordinary foreign or game words.
var ambiguousLangTokens = map[string]bool{
	"magisk":   true, // Swedish: magical
	"unlocked": true, "cracked": true, "patched": true, "autoaim": true,
	"premium": true, "unlock": true,
}

// Evaluate applies all precision rules and returns the final verdict.
// Map-based rules match by token containment (IsStandaloneToken on Keyword) so
// they work whether a regex captured just the token or a wider slice.
func Evaluate(c Candidate) Verdict {
	// (2) token boundary: never fire on a substring of a larger word. Only
	// meaningful when a context window wider than the match is supplied.
	if c.Line != "" && !IsStandaloneToken(c.Line, c.Keyword) {
		return drop("keyword is a substring of a larger token, not a standalone match")
	}

	// (1)+(foreign word) localization prose suppression for ambiguous tokens.
	// With a real window we require prose; without one (Line == Keyword) the
	// bundle itself is the evidence: ambiguous tokens inside localization
	// bundles are natural language, not mod/piracy markers.
	if c.Context == AssetCtx && IsLocalizationBundle(c.FilePath) {
		hasWindow := len(c.Line) > len(c.Keyword)
		if !hasWindow || looksLikeProse(c.Line) {
			// Sorted for a stable Reason: map order is random.
			for _, tok := range sortedKeys(ambiguousLangTokens) {
				if IsStandaloneToken(c.Keyword, tok) {
					return drop("ambiguous keyword '" + tok + "' inside localized natural-language string (i18n bundle)")
				}
			}
		}
	}

	// (3) code-corroboration required keywords.
	for _, tok := range sortedKeys(codeCorroboration) {
		apis := codeCorroboration[tok]
		if !IsStandaloneToken(c.Keyword, tok) {
			continue
		}
		if c.Context != CodeCtx {
			return drop("security keyword '" + tok + "' requires code context; found in " + string(c.Context))
		}
		if !containsAny(c.Line, apis) {
			return drop("security keyword '" + tok + "' lacks corroborating API (" + strings.Join(apis, " / ") + ")")
		}
	}

	// (5) signature-check reality test: getPackageInfo without a
	// certificate read is a version lookup, not tamper detection. The
	// trigger is narrow (the call itself); a real check carries a cert
	// token (GET_SIGNATURES and friends) in the same window and is kept.
	if c.Context == CodeCtx && IsStandaloneToken(c.Keyword, "getpackageinfo") {
		if !SignatureCheckIsReal(c.Line) {
			return drop("getPackageInfo without certificate access (version lookup, not a signature check)")
		}
	}

	// (4) media forensics (only fires if a media scanner populates these).
	if c.Category == "Media Anomaly" {
		if c.EntropyBits > 0 && !EntropyAnomalyApplies(c.ContainerFmt) {
			return drop("high entropy is normal for compressed format " + c.ContainerFmt)
		}
		if c.EmbeddedMagic != "" && !PolyglotIsSuspicious(c.ByteOffset, c.ContainerSize) {
			return drop("embedded magic signature is a deep-interior byte collision, not a header/tail polyglot")
		}
	}

	return keep()
}

func containsAny(hay string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(hay, n) {
			return true
		}
	}
	return false
}

// sortedKeys returns the keys of a set/map in stable order so Reasons are
// byte-identical across runs (Go map iteration is random).
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
