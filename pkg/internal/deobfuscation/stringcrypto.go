package deobfuscation

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"mega-analyzer/pkg/internal/networkrefs"
)

// ═══════════════════════════════════════════════════════════════════════════════
// STRING DECRYPTION — recovering plaintext from obfuscated string literals
// ═══════════════════════════════════════════════════════════════════════════════
//
// Real-world Android/JS obfuscators wrap secrets in a handful of reversible
// transforms: Base64, hex, single-byte XOR, repeating-key XOR, and ROT-N. We
// try them in increasing order of cost and only accept a candidate when it
// reads like plausible text. The scoring uses English letter-frequency so that
// we prefer real words over lucky-looking noise.

const (
	// minEncryptedLen is the shortest literal we bother classifying/attacking.
	minEncryptedLen = 8

	// highEntropyUniqueRatio: fraction of distinct bytes above which a short
	// literal is treated as suspicious (packed/encrypted rather than plain).
	highEntropyUniqueRatio = 0.7

	// minCrackLen is the shortest byte payload we attempt to XOR-crack; below
	// this, false positives dominate.
	minCrackLen = 4

	// Acceptance gates for a decoded candidate to be considered readable.
	minPrintableRatio = 0.95
	minLetterRatio    = 0.70

	// maxRepeatingKeyLen bounds the repeating-key XOR search.
	maxRepeatingKeyLen = 8
)

// englishFreq holds relative frequencies of lowercase English letters and space
// (Peter Norvig's corpus counts, normalized). It is used to score candidate
// plaintexts; higher is more English-like.
var englishFreq = [26]float64{
	0.0817, 0.0150, 0.0278, 0.0425, 0.1270, 0.0223, 0.0202, 0.0609, 0.0697,
	0.0015, 0.0077, 0.0403, 0.0241, 0.0675, 0.0751, 0.0193, 0.0010, 0.0599,
	0.0633, 0.0906, 0.0276, 0.0098, 0.0236, 0.0015, 0.0197, 0.0007,
}

// base64Variants covers every alphabet/padding combination Android's
// android.util.Base64 can emit. DEFAULT is StdEncoding; NO_PADDING needs
// RawStdEncoding; URL_SAFE needs the URL alphabet, with and without padding.
// Trying only StdEncoding silently failed on three of the four.
var base64Variants = []struct {
	name string
	enc  *base64.Encoding
}{
	{"Base64", base64.StdEncoding},
	{"Base64/nopad", base64.RawStdEncoding},
	{"Base64url", base64.URLEncoding},
	{"Base64url/nopad", base64.RawURLEncoding},
}

// ── Memoisation ──────────────────────────────────────────────────────────────
//
// An obfuscator emits one string pool and references it from hundreds of call
// sites, so the same literal reaches this function again and again — once per
// occurrence, across every class in the APK. The search it triggers is the
// most expensive thing the engine does: for each of four Base64 variants and
// hex, up to 255 single-byte keys plus seven key lengths x 256 column keys,
// every candidate scored with englishScore. Repeating that for a literal we
// have already cracked is pure waste.
//
// The answer depends only on the literal, so it is cached. The cache is
// process-wide because the workers that call it are per-file: a literal shared
// between two classes is only computed once for the whole scan.

// maxDecryptCacheEntries bounds the memo so a pathological APK full of unique
// high-entropy blobs cannot grow it without limit. Past the cap we still answer
// correctly, just without memoising further literals.
const maxDecryptCacheEntries = 1 << 16

type decryptOutcome struct {
	plain     string
	transform string
}

var (
	decryptCache     sync.Map // string -> decryptOutcome
	decryptCacheSize atomic.Int64
	decryptHits      atomic.Int64
	decryptMisses    atomic.Int64
)

// DecryptCacheStats reports how often the literal memo answered without
// re-running the search. Exported so the pipeline can log cache effectiveness
// alongside its other sub-stage counters.
func DecryptCacheStats() (hits, misses int64) {
	return decryptHits.Load(), decryptMisses.Load()
}

// ResetDecryptCache clears the memo and its counters. Tests and benchmarks use
// it to measure the cold path rather than a warm cache.
func ResetDecryptCache() {
	decryptCache = sync.Map{}
	decryptCacheSize.Store(0)
	decryptHits.Store(0)
	decryptMisses.Store(0)
}

// tryDecryptString attempts to recover plaintext from an obfuscated literal.
// It returns the recovered plaintext and a short label naming the transform
// chain that produced it. Both are empty when nothing readable was recovered.
//
// The plaintext is returned unannotated so callers can feed it straight back
// into rule matching; the label is for display only.
//
// Results are memoised; see the note above. Negative results are cached too,
// because a literal that resisted the whole chain is exactly the one that cost
// the most to reject, and it will be back on the next call site.
func tryDecryptString(encrypted string) (plain, transform string) {
	if len(encrypted) < minCrackLen {
		return "", ""
	}
	if v, ok := decryptCache.Load(encrypted); ok {
		decryptHits.Add(1)
		out := v.(decryptOutcome)
		return out.plain, out.transform
	}
	decryptMisses.Add(1)

	p, t := tryDecryptStringUncached(encrypted)

	if decryptCacheSize.Load() < maxDecryptCacheEntries {
		if _, loaded := decryptCache.LoadOrStore(encrypted, decryptOutcome{plain: p, transform: t}); !loaded {
			decryptCacheSize.Add(1)
		}
	}
	return p, t
}

// tryDecryptStringUncached is the actual transform search. Call
// tryDecryptString instead unless you specifically want to bypass the memo.
func tryDecryptStringUncached(encrypted string) (plain, transform string) {
	if len(encrypted) < minCrackLen {
		return "", ""
	}

	// 1. Base64 (all four Android variants) → plaintext, else → XOR.
	encodedBinary := false
	for _, v := range base64Variants {
		decoded, err := v.enc.DecodeString(encrypted)
		if err != nil {
			continue
		}
		encodedBinary = true
		// A successful base64 decode is not evidence of anything: most
		// identifier-shaped literals decode cleanly into printable garbage.
		// The decoded text has to clear the same bar as a cracked one.
		if isMeaningfulPlaintext(decoded) {
			return string(decoded), v.name
		}
		if recovered := decodeSaltedNibble(decoded); isMeaningfulPlaintext(recovered) || isSaltedNetworkHostname(recovered) {
			return string(recovered), v.name + "/salted-nibble"
		}
		if cracked, key := crackXOR(decoded); cracked != "" {
			return cracked, fmt.Sprintf("%s + XOR key 0x%02X", v.name, key)
		}
		if cracked, key := crackRepeatingXOR(decoded); cracked != "" {
			return cracked, fmt.Sprintf("%s + XOR key %s", v.name, formatKey(key))
		}
	}

	// 2. Hex → plaintext, else Hex → XOR.
	if hexBytes, err := hex.DecodeString(encrypted); err == nil {
		encodedBinary = true
		if isMeaningfulPlaintext(hexBytes) {
			return string(hexBytes), "Hex"
		}
		if cracked, key := crackXOR(hexBytes); cracked != "" {
			return cracked, fmt.Sprintf("Hex + XOR key 0x%02X", key)
		}
		if cracked, key := crackRepeatingXOR(hexBytes); cracked != "" {
			return cracked, fmt.Sprintf("Hex + XOR key %s", formatKey(key))
		}
	}
	// An opaque encoded payload is not a raw XOR/ROT ciphertext. Rotating
	// its printable encoding can accidentally manufacture secret-shaped text
	// and invent recoveries from large binary blobs.
	if encodedBinary {
		return "", ""
	}

	// Paths 3-5 attack the literal in place. They only make sense if the
	// literal is not already readable: a ciphertext that reads as ordinary text
	// has not hidden anything. Skipping them here removes the dominant false
	// positive, where an ordinary identifier is "decrypted" into a rearranged
	// version of itself.
	if isReadableLiteral(encrypted) {
		return "", ""
	}

	// 3. Raw single-byte XOR (literal was XORed without further encoding).
	if cracked, key := crackXOR([]byte(encrypted)); cracked != "" {
		return cracked, fmt.Sprintf("XOR key 0x%02X", key)
	}

	// 4. Raw repeating-key XOR.
	if cracked, key := crackRepeatingXOR([]byte(encrypted)); cracked != "" {
		return cracked, fmt.Sprintf("XOR key %s", formatKey(key))
	}

	// 5. ROT-N (Caesar) — cheap and common for lightweight obfuscation.
	if cracked, n := crackROT(encrypted); cracked != "" {
		return cracked, fmt.Sprintf("ROT%d", n)
	}

	return "", ""
}

// decodeSaltedNibble recognizes the self-contained six-byte salt format
// used by small Android string obfuscators. It evaluates only this bounded
// byte transform; no sample method is executed. The usual plaintext gates
// still decide whether the result is credible.
func decodeSaltedNibble(encoded []byte) []byte {
	const saltLen = 6
	if len(encoded) < saltLen+8 || len(encoded) > 256<<10 {
		return nil
	}
	salt := encoded[:saltLen]
	plain := append([]byte(nil), encoded[saltLen:]...)
	for round := 0; round < int(salt[0]&7)+1; round++ {
		for i, value := range plain {
			swapped := value<<4 | value>>4
			plain[i] = (swapped - salt[(i+1)%saltLen]) ^ salt[i%saltLen]
		}
	}
	return plain
}

func isSaltedNetworkHostname(plain []byte) bool {
	return len(plain) >= 8 && networkrefs.IsRecoveredHostname(string(plain))
}

// isReadableLiteral reports whether a literal already reads as ordinary text
// or as a plain program identifier, meaning there is nothing to decrypt.
//
// Identifiers are the important half. `IconCompat` XORed with 0x20 becomes
// `iCONcOMPAT`, which passes every printability and letter-frequency gate we
// have — englishScore folds case, so it cannot tell the two apart — and the
// result is a confident "decryption" of a string that was never encrypted.
func isReadableLiteral(s string) bool {
	if !isPrintableASCII([]byte(s)) {
		return false
	}
	letters, spaces, other := 0, 0, 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case isAlpha(c):
			letters++
		case c == ' ':
			spaces++
		case c >= '0' && c <= '9', c == '_', c == '.', c == '/', c == '-', c == '$':
			// Identifier and path punctuation: neutral.
		default:
			other++
		}
	}
	if len(s) == 0 {
		return true
	}
	// Mostly letters with only identifier punctuation: a class, method, field
	// or resource name. Real ciphertext does not look like this.
	return other == 0 && float64(letters+spaces)/float64(len(s)) >= 0.6
}

// secretMarkers are substrings that make a candidate worth keeping regardless
// of how few letters it contains. These are exactly the payloads a scan cares
// about, and they are also the ones a prose-oriented letter-ratio gate throws
// away: an endpoint URL, a connection string, a key blob or a JSON fragment is
// mostly punctuation and digits.
var secretMarkers = []string{
	"http://", "https://", "ftp://", "ws://", "wss://", "content://",
	"jdbc:", "mongodb://", "redis://", "smtp://",
	"-----begin", "bearer ", "authorization",
	"api_key", "apikey", "secret", "token", "password", "passwd",
	"aws_", "akia", "asia", "sk_live", "pk_live", "ghp_", "xoxb-", "xoxp-",
}

// acceptableRecovery decides whether a candidate decryption is worth keeping.
//
// The gate is deliberately strict, and the reason is worth stating: a
// brute-force search over 255 XOR keys and 25 rotations will always find
// *something* whose letter distribution passes a frequency test, because a
// frequency test is exactly what the search maximises. Accepting on
// "printable and letter-rich" therefore accepts almost every literal in the
// APK, and on a real target that produced hundreds of confident recoveries
// that were pure noise — which then flowed into rule matching as evidence.
//
// So a recovery must look like something a program would actually hold in an
// encrypted literal: an endpoint, a credential, a class or resource path, or a
// human-readable sentence. Anything that merely resembles English at the
// character level is rejected.
func acceptableRecovery(printableRatio, letterRatio float64, plain []byte) bool {
	if printableRatio < minPrintableRatio {
		return false
	}
	return isMeaningfulPlaintext(plain)
}

// isMeaningfulPlaintext is the single bar every recovery must clear, whatever
// transform produced it: the text has to look like something a program would
// keep in an obfuscated literal — an endpoint, a credential, a class or
// resource path, or a readable sentence.
func isMeaningfulPlaintext(plain []byte) bool {
	if len(plain) < minRecoveredLen || !isPrintableASCII(plain) {
		return false
	}
	return hasSecretShape(plain) || looksLikeSentence(plain) || looksLikeDottedPath(plain) || net.ParseIP(string(plain)) != nil
}

// commonEnglishWords is a small closed vocabulary used to tell real text from
// letter soup that happens to fit English letter frequencies.
//
// Frequency scoring cannot make this distinction — it is precisely what the
// key search optimises, so "hgoosee qatsd" scores as well as "goose quest".
// Requiring actual words is the cheapest signal that does discriminate. The
// list only needs to cover words that appear in almost any real sentence.
var commonEnglishWords = map[string]struct{}{}

func init() {
	for _, w := range strings.Fields(`
		the be to of and in that have it for not on with he as you do at this
		but his by from they we say her she or an will my one all would there
		their what so up out if about who get which go me when make can like
		time no just him know take people into year your good some could them
		see other than then now look only come its over think also back after
		use two how our work first well way even new want because any these
		give day most has had was were are is

		error failed failure invalid missing unknown success succeeded denied
		expired disabled enabled required unsupported timeout retry cancel
		warning fatal exception crash debug trace info

		license key secret token password passcode credential auth login
		signin signup account user username email phone address name id

		http https url uri host port server client request response header
		body json xml query param api endpoint session cookie proxy socket
		network connection connect download upload sync fetch send receive

		app application android google play store market version build
		release update install uninstall package activity service receiver
		provider intent permission manifest resource asset config setting
		preference database cache storage file path directory

		premium subscription purchase billing payment trial unlock unlocked
		locked verify verified validate validated check checked feature
		features free paid pro plus full readable text data value string
		message code status result response content type size count list`) {
		commonEnglishWords[w] = struct{}{}
	}
}

// packageRoots are the top-level segments real Java/Android package names
// start with. A dotted or slashed candidate that does not begin with one is
// not a class path, whatever its punctuation looks like.
var packageRoots = map[string]struct{}{
	"com": {}, "org": {}, "net": {}, "io": {}, "java": {}, "javax": {},
	"android": {}, "androidx": {}, "kotlin": {}, "kotlinx": {}, "dalvik": {},
	"me": {}, "dev": {}, "app": {}, "de": {}, "ru": {}, "uk": {}, "cn": {},
	"res": {}, "assets": {}, "lib": {},
}

// looksLikeSentence reports whether the candidate reads as human text: at
// least three alphabetic words of three or more characters covering most of
// the string, of which at least two are actual English words.
func looksLikeSentence(plain []byte) bool {
	fields := strings.Fields(string(plain))
	if len(fields) < 3 {
		return false
	}
	words, known, covered := 0, 0, 0
	for _, f := range fields {
		w := strings.Trim(f, ".,;:!?'\"()[]{}")
		if len(w) < 3 || !isAlphaRun(w) {
			continue
		}
		words++
		covered += len(w)
		if _, ok := commonEnglishWords[strings.ToLower(w)]; ok {
			known++
		}
	}
	// Most of the string must be accounted for by words, and at least two of
	// them must be real: a couple of accidental letter runs is not a sentence.
	return words >= 3 && known >= 2 &&
		float64(covered)/float64(len(plain)) >= 0.6 &&
		englishScore(plain) > 0.55
}

// looksLikeDottedPath reports whether the candidate is a Java/Android class,
// package or resource path — `com.example.Foo`, `Lcom/example/Foo;`,
// `res/layout/main.xml`. These are the second most common thing to find behind
// a string decryptor, after endpoints.
func looksLikeDottedPath(plain []byte) bool {
	s := string(plain)
	if len(s) < minCrackLen || strings.ContainsAny(s, " \t\r\n") {
		return false
	}
	sep := "."
	if strings.Count(s, "/") > strings.Count(s, ".") {
		sep = "/"
	}
	parts := strings.Split(strings.Trim(s, "L;"), sep)
	if len(parts) < 3 {
		return false
	}
	// Anchor on a real package root. Without this, any three letter runs
	// joined by dots pass — and a brute-force search produces those freely.
	if _, ok := packageRoots[strings.ToLower(parts[0])]; !ok {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for i := 0; i < len(p); i++ {
			if c := p[i]; !isAlpha(c) && !(c >= '0' && c <= '9') && c != '_' && c != '$' && c != '-' {
				return false
			}
		}
	}
	return true
}

// minRecoveredLen is the shortest candidate we will report as a recovery.
// Below this, the brute-force search has enough freedom to manufacture a
// passing string from almost any input.
const minRecoveredLen = 12

// hasSecretShape reports whether the candidate looks like machine-readable
// secret material rather than an accident of the key search.
//
// Every clause here has to be unambiguous. Earlier, looser versions accepted
// "contains a brace and a colon" and "contains = and &", which random bytes
// satisfy constantly — those two clauses alone accounted for essentially all
// the false recoveries observed on a real APK.
func hasSecretShape(plain []byte) bool {
	if len(plain) < minRecoveredLen {
		return false
	}
	s := string(plain)
	lower := strings.ToLower(s)

	for _, marker := range secretMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	// JWT: three dot-separated segments, the first starting "eyj" (base64 of
	// `{"`), every segment base64url.
	if strings.HasPrefix(lower, "eyj") {
		if parts := strings.Split(s, "."); len(parts) == 3 {
			ok := true
			for _, p := range parts {
				if len(p) < 4 || !isBase64Charset(p) {
					ok = false
					break
				}
			}
			if ok {
				return true
			}
		}
	}
	// Strict JSON: opens with a brace or bracket and carries a quoted key.
	if t := strings.TrimSpace(s); len(t) > 1 &&
		(t[0] == '{' || t[0] == '[') &&
		(strings.Contains(t, `":`) || strings.Contains(t, `": `)) {
		return true
	}
	return false
}

// isAlphaRun reports whether every byte of s is an ASCII letter.
func isAlphaRun(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isAlpha(s[i]) {
			return false
		}
	}
	return true
}

// crackXOR brute-forces a single-byte XOR key and returns the most readable
// decryption together with the key. It returns an empty string when no key
// produces text that clears the readability gates.
func crackXOR(data []byte) (string, byte) {
	if len(data) < minCrackLen {
		return "", 0
	}

	bestKey := byte(0)
	bestScore := 0.0
	var bestDecrypted []byte
	buf := make([]byte, len(data))

	for k := 1; k < 256; k++ {
		// 0x20 flips ASCII case and nothing else. It cannot hide a string, so a
		// "recovery" under it is always an artefact of scoring case-insensitively.
		if k == 0x20 {
			continue
		}
		printable, letters := 0, 0
		for i, b := range data {
			dec := b ^ byte(k)
			buf[i] = dec
			if dec >= 32 && dec <= 126 {
				printable++
				if isTextByte(dec) {
					letters++
				}
			}
		}

		ratio := float64(printable) / float64(len(data))
		letterRatio := float64(letters) / float64(len(data))
		if !acceptableRecovery(ratio, letterRatio, buf) {
			continue
		}

		// Combine coarse readability with fine English-frequency fit so that,
		// among several passable keys, the most language-like one wins.
		score := ratio + letterRatio + englishScore(buf)
		if score > bestScore {
			bestScore = score
			bestKey = byte(k)
			if bestDecrypted == nil {
				bestDecrypted = make([]byte, len(data))
			}
			copy(bestDecrypted, buf)
		}
	}

	if bestScore > 0 {
		return string(bestDecrypted), bestKey
	}
	return "", 0
}

// crackRepeatingXOR attempts to recover a repeating multi-byte XOR key by
// solving each key position independently and validating the reconstruction.
// Single-byte keys are handled by crackXOR, so the search starts at length 2.
func crackRepeatingXOR(data []byte) (string, []byte) {
	if len(data) < 2*minCrackLen {
		return "", nil
	}

	var bestKey []byte
	bestScore := 0.0
	var bestPlain []byte

	for keyLen := 2; keyLen <= maxRepeatingKeyLen && keyLen*2 <= len(data); keyLen++ {
		key := make([]byte, keyLen)
		for pos := 0; pos < keyLen; pos++ {
			key[pos] = bestColumnKey(data, pos, keyLen)
		}
		// A key made only of 0x00 and 0x20 is identity plus case-flipping — the
		// same artefact crackXOR guards against, spread over several columns.
		if isCaseFlipKey(key) {
			continue
		}

		plain := make([]byte, len(data))
		printable, letters := 0, 0
		for i, b := range data {
			dec := b ^ key[i%keyLen]
			plain[i] = dec
			if dec >= 32 && dec <= 126 {
				printable++
				if isTextByte(dec) {
					letters++
				}
			}
		}

		ratio := float64(printable) / float64(len(data))
		letterRatio := float64(letters) / float64(len(data))
		if !acceptableRecovery(ratio, letterRatio, plain) {
			continue
		}

		score := ratio + letterRatio + englishScore(plain)
		if score > bestScore {
			bestScore = score
			bestKey = append(bestKey[:0], key...)
			bestPlain = append(bestPlain[:0], plain...)
		}
	}

	if bestScore > 0 {
		return string(bestPlain), bestKey
	}
	return "", nil
}

// isCaseFlipKey reports whether every byte of the key is 0x00 or 0x20, i.e.
// the "key" only inverts ASCII case and leaves the text otherwise intact.
func isCaseFlipKey(key []byte) bool {
	for _, b := range key {
		if b != 0x00 && b != 0x20 {
			return false
		}
	}
	return true
}

// bestColumnKey finds the single byte that, XORed across one column of a
// repeating-key ciphertext, produces the most English-like column.
// The scoring is unchanged; the work per candidate key is not. The column is
// now extracted once instead of being rebuilt inside the 256-key loop, and the
// letter histogram, letter count and non-printable penalty are gathered in one
// pass instead of three. The old shape walked the ciphertext with a stride 256
// times per key position and then walked the resulting column twice more for
// every one of those keys.
func bestColumnKey(data []byte, pos, keyLen int) byte {
	raw := make([]byte, 0, len(data)/keyLen+1)
	for i := pos; i < len(data); i += keyLen {
		raw = append(raw, data[i])
	}
	if len(raw) == 0 {
		return 0
	}

	bestKey := byte(0)
	bestScore := -1.0
	for k := 0; k < 256; k++ {
		var counts [26]float64
		letters := 0
		// Penalise columns with non-printable bytes so control characters do
		// not sneak through on sparse columns.
		penalty := 0.0
		for _, b := range raw {
			dec := b ^ byte(k)
			if dec < 32 || dec > 126 {
				penalty += 1.0
			}
			c := dec | 0x20 // ASCII lowercase fold
			if c >= 'a' && c <= 'z' {
				counts[c-'a']++
				letters++
			}
		}

		// Same value englishScore(col) would return, inlined over the counts
		// gathered above: Bhattacharyya coefficient against English letter
		// frequencies, weighted by how much of the column is letters.
		score := 0.0
		if letters > 0 {
			coeff := 0.0
			for i := 0; i < 26; i++ {
				coeff += fastSqrt(counts[i] / float64(letters) * englishFreq[i])
			}
			score = coeff * (float64(letters) / float64(len(raw)))
		}
		score -= penalty

		if score > bestScore {
			bestScore = score
			bestKey = byte(k)
		}
	}
	return bestKey
}

// crackROT tries every Caesar-cipher rotation over ASCII letters and returns
// the rotation whose output looks most English-like. Rotation 0 is skipped.
func crackROT(s string) (string, int) {
	// Only meaningful for mostly-alphabetic input.
	letters := 0
	for i := 0; i < len(s); i++ {
		if isAlpha(s[i]) {
			letters++
		}
	}
	if letters == 0 || float64(letters)/float64(len(s)) < minLetterRatio {
		return "", 0
	}

	bestN := 0
	bestScore := englishScore([]byte(s))
	best := ""
	buf := make([]byte, len(s))
	for n := 1; n < 26; n++ {
		for i := 0; i < len(s); i++ {
			buf[i] = rotateByte(s[i], n)
		}
		// Same bar as every other transform. Rotating a base64 blob through 25
		// alphabets and keeping the best English score returns a "recovery" for
		// essentially any input; only a meaningful result counts.
		if !isMeaningfulPlaintext(buf) {
			continue
		}
		score := englishScore(buf)
		if score > bestScore {
			bestScore = score
			bestN = n
			best = string(buf)
		}
	}
	if bestN == 0 {
		return "", 0
	}
	return best, bestN
}

// englishScore returns a value in roughly [0,1] measuring how closely the
// letter distribution of data matches English text. Non-letters are ignored in
// the distribution but counted toward the denominator so that gibberish full
// of symbols scores low.
func englishScore(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [26]float64
	letters := 0
	for _, b := range data {
		c := b | 0x20 // ASCII lowercase fold
		if c >= 'a' && c <= 'z' {
			counts[c-'a']++
			letters++
		}
	}
	if letters == 0 {
		return 0
	}
	// Bhattacharyya coefficient between observed and English distributions:
	// sum of sqrt(p_i * q_i), which is 1.0 for identical distributions.
	coeff := 0.0
	for i := 0; i < 26; i++ {
		p := counts[i] / float64(letters)
		coeff += fastSqrt(p * englishFreq[i])
	}
	// Weight by how much of the text is actually letters.
	return coeff * (float64(letters) / float64(len(data)))
}

// isPrintableASCII reports whether data is non-empty and contains only
// printable ASCII plus the common whitespace controls.
func isPrintableASCII(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	for _, b := range data {
		if b < 32 || b > 126 {
			if b != '\n' && b != '\r' && b != '\t' {
				return false
			}
		}
	}
	return true
}

// isTextByte reports whether a printable byte is a "text" character worth
// rewarding: letters, digits, space and common identifier/path punctuation.
func isTextByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	case b == ' ' || b == '_' || b == '/' || b == '.' || b == '-' || b == ':':
		return true
	}
	return false
}

func isAlpha(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func rotateByte(b byte, n int) byte {
	switch {
	case b >= 'a' && b <= 'z':
		return 'a' + byte((int(b-'a')+n)%26)
	case b >= 'A' && b <= 'Z':
		return 'A' + byte((int(b-'A')+n)%26)
	}
	return b
}

func formatKey(key []byte) string {
	if len(key) == 0 {
		return "0x00"
	}
	var sb strings.Builder
	sb.WriteString("0x")
	for _, b := range key {
		fmt.Fprintf(&sb, "%02X", b)
	}
	return sb.String()
}

// fastSqrt is a small Newton-Raphson square root. It avoids importing math for
// this hot path and is accurate enough for a similarity score.
func fastSqrt(x float64) float64 {
	if x <= 0 {
		return 0
	}
	z := x
	for i := 0; i < 8; i++ {
		z = (z + x/z) / 2
	}
	return z
}
