package llmkeys

import (
	"encoding/base64"
	"encoding/hex"
	"math"
	"regexp"
	"strings"
)

// minLen is the shortest value we are willing to call a real credential.
// Anything shorter is almost always a label, word or tiny placeholder.
const minLen = 12

// Verdict is the result of classifying a single candidate value.
type Verdict struct {
	// IsSecret is true when the value looks like a real credential.
	IsSecret bool
	// Confidence in [0,1].
	Confidence float64
	// Family is the matched credential family ("" if none/unknown).
	Family string
	// Entropy is the Shannon entropy (bits/char) of the value.
	Entropy float64
	// Reason is a short human-readable explanation of the decision.
	Reason string
}

// placeholderMarkers are unambiguous "this is not a real secret" substrings.
// IMPORTANT: these run AFTER prefix-family matching, so a value like
// "AKIA...EXAMPLE" is already accepted as AWS before we reach this check.
var placeholderMarkers = []string{
	"example", "sample", "dummy", "placeholder",
	"changeme", "your_", "your-", "_here", "goes_here",
	"replace_me", "replaceme", "insert_", "enter_", "paste_",
	"do_not_use", "donotuse", "redact", "filtered", "lorem", "ipsum",
	"mock_", "stub_", "fake_", "demo_", "testkey", "fakekey",
	"<", ">", "${", "{{", "[your",
}

var (
	hex32Re   = regexp.MustCompile(`^[0-9a-f]{32}$`)
	hex40Re   = regexp.MustCompile(`^[0-9a-f]{40}$`)
	hex64Re   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	hex128Re  = regexp.MustCompile(`^[0-9a-f]{128}$`)
	shaLineRe = regexp.MustCompile(`^(?:sha\d{1,3}|md5|etag|commit|tree|blob|digest|integrity):\s*([A-Za-z0-9+/=_:-]+)$`)
	uuidRe    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// Classify decides whether value is a real-looking credential or noise.
func Classify(value string) Verdict {
	k := load()
	v := strings.TrimSpace(value)
	low := strings.ToLower(v)
	ent := shannonEntropy(v)

	if v == "" {
		return Verdict{Reason: "empty value", Entropy: ent, Confidence: 0.0}
	}

	// 1. Exact match against the learned junk database.
	if k.negativeSet[low] {
		return Verdict{Reason: "known placeholder/junk from negatives DB", Entropy: ent, Confidence: 0.02}
	}

	// 2. PEM private key blocks (multiline or single-line base64) take priority
	// because they're unambiguous real secrets. Check BEFORE whitespace rejection.
	if isPEMPrivateKey(v, low) {
		return Verdict{
			IsSecret:   true,
			Family:     "private_key",
			Entropy:    ent,
			Confidence: 0.99,
			Reason:     "PEM-formatted private key (cryptographic credential)",
		}
	}

	// 2a. Whitespace inside means this is text/code/a comment, not a bare token.
	if strings.ContainsAny(v, " \t\r\n") {
		return Verdict{Reason: "contains whitespace, looks like text/code not a token", Entropy: ent, Confidence: 0.05}
	}

	// 2a-2. Fake or placeholder tokens with explicit prefixes like "ghp_example", "AKIAEXAMPLE", "sk-test-".
	if isFakeOrPlaceholderToken(low) {
		return Verdict{Reason: "fake or placeholder token prefix/marker", Entropy: ent, Confidence: 0.05}
	}

	// 2b. Non-token wrappers (JSON objects, URLs, dot configuration filenames).
	if reason := matchNonTokenWrapper(v, low); reason != "" {
		return Verdict{Reason: reason, Entropy: ent, Confidence: 0.05}
	}

	// 3. Known credential family prefix — checked BEFORE structural non-secrets
	// so tokens with hyphens (e.g. Slack xoxb-, Anthropic sk-ant-) are matched.
	if fam := matchFamily(v); fam != "" {
		return Verdict{
			IsSecret:   true,
			Family:     fam,
			Entropy:    ent,
			Confidence: 0.95,
			Reason:     "matches known credential family '" + fam + "' with a non-trivial body",
		}
	}

	// 3a. Structural non-secrets with high entropy but known formats.
	if reason := matchNonSecretStructure(v, low); reason != "" {
		return Verdict{Reason: reason, Entropy: ent, Confidence: 0.05}
	}

	// 3b. Base64 decoded text / secret check.
	if vdt := decodeAndCheckBase64(v, ent); vdt != nil {
		return *vdt
	}

	// 4. Placeholder / template markers (runs after prefix so family wins).
	if m := matchPlaceholder(low, v); m != "" {
		return Verdict{Reason: "placeholder marker: " + m, Entropy: ent, Confidence: 0.05}
	}

	// 5. Too short to be a real credential.
	if len(v) < minLen {
		return Verdict{Reason: "too short to be a real credential", Entropy: ent, Confidence: 0.1}
	}

	// 6. Trivial structure: all-same, sequential, or very low character variety.
	if isAllSame(v) || isSequential(low) || containsTrivialSequentialRun(low) || uniqueRatio(v) < 0.25 {
		return Verdict{Reason: "trivial pattern (repeated/sequential/low variety)", Entropy: ent, Confidence: 0.1}
	}

	// 7. No known family: only classify as secret if it has a clear credential indicator.
	runesLen := len([]rune(v))
	if hasSecretIndicator(v, low) && ent >= 3.0 && runesLen >= minLen {
		return Verdict{IsSecret: true, Entropy: ent, Confidence: 0.85, Reason: "high-entropy token with credential indicator"}
	}
	if isAlternatingToken(v) && ent >= 3.0 && runesLen >= minLen {
		return Verdict{IsSecret: true, Entropy: ent, Confidence: 0.65, Reason: "medium-high entropy token"}
	}
	return Verdict{IsSecret: false, Entropy: ent, Confidence: 0.25, Reason: "no known credential family or indicator"}
}

func matchNonTokenWrapper(v, low string) string {
	if (strings.HasPrefix(v, "{") && strings.HasSuffix(v, "}")) || (strings.HasPrefix(v, "[") && strings.HasSuffix(v, "]")) {
		return "JSON object/array wrapper, not a bare token"
	}
	if strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://") || strings.HasPrefix(low, "ftp://") {
		return "URL, not a bare token"
	}
	if isConfigFilename(v, low) {
		return "configuration filename, not a secret"
	}
	return ""
}

func isConfigFilename(v, low string) bool {
	if !strings.HasPrefix(v, ".") {
		return false
	}
	if strings.ContainsAny(v, "/:= \t\r\n") {
		return false
	}
	for i := 1; i < len(v); i++ {
		c := v[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func decodeAndCheckBase64(v string, ent float64) *Verdict {
	cleaned := strings.TrimSuffix(strings.Trim(v, `"'=`), "...")
	if len(cleaned) < 12 {
		return nil
	}
	for i := 0; i < len(cleaned); i++ {
		c := cleaned[i]
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '-' || c == '_') {
			return nil
		}
	}
	if len(cleaned)%4 != 0 {
		cleaned = cleaned[:len(cleaned)-(len(cleaned)%4)]
	}
	var b []byte
	var err error
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		b, err = enc.DecodeString(cleaned)
		if err == nil && len(b) >= 8 {
			break
		}
	}
	if err != nil || len(b) < 8 {
		return nil
	}
	for _, ch := range b {
		if ch < 32 && ch != '\t' && ch != '\r' && ch != '\n' {
			return nil
		}
	}
	decStr := string(b)
	if strings.ContainsAny(decStr, " \t\r\n") || strings.HasPrefix(decStr, "{") || strings.HasPrefix(decStr, "[") {
		return &Verdict{IsSecret: false, Entropy: ent, Confidence: 0.05, Reason: "base64-encoded non-secret text"}
	}
	if fam := matchFamily(decStr); fam != "" {
		return &Verdict{IsSecret: true, Family: fam, Entropy: ent, Confidence: 0.85, Reason: "base64-encoded credential"}
	}
	return nil
}

// ClassifyAssignment handles a whole "key = value" line. It pulls out the
// value on the right of the first '=' or ':', strips quotes and spaces, and
// classifies *that* — so `private_key = 123456789` is judged on "123456789",
// not on the label. Lines with no separator are classified as-is.
func ClassifyAssignment(line string) Verdict {
	value := line
	if i := strings.IndexAny(line, "="); i >= 0 {
		value = line[i+1:]
	} else if i := strings.Index(line, ":"); i >= 0 {
		left := strings.TrimSpace(line[:i])
		if !strings.Contains(left, "://") && !strings.Contains(left, "http:") && !strings.Contains(left, "https:") {
			value = line[i+1:]
		}
	}
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `"'`+"`")
	if fields := strings.Fields(value); len(fields) > 1 {
		scheme := strings.ToLower(fields[0])
		if scheme == "bearer" || scheme == "basic" {
			value = strings.Join(fields[1:], " ")
		}
	}
	return Classify(value)
}

// isPEMPrivateKey checks if v looks like a PEM-encoded private key.
// Handles both multiline PEM blocks and base64-encoded single-line variants.
func isPEMPrivateKey(v, low string) bool {
	// Multiline PEM block: -----BEGIN...KEY-----...-----END...KEY-----.
	// Bare marker lines alone ("-----BEGIN RSA PRIVATE KEY-----") are format // gitleaks:allow
	// labels (e.g. serialization templates in auth libraries), not keys:
	// require any base64 body content next to the markers.
	if strings.Contains(v, "-----BEGIN") && strings.Contains(v, "KEY-----") {
		return pemBodyLen(v) >= 1
	}
	// Base64-encoded PKCS#8/PKCS#1/OpenSSH formats are real keys.
	// PKCS#8: MIIEv..., MIIDv... (RSA/EC unencrypted)
	// PKCS#1 RSA: MIIEov..., MIIBPA... (RSA only)
	// PKCS#8 encrypted: MIIFDj...
	// OpenSSH: AAAAB3NzaC...
	isBase64Key := (strings.HasPrefix(low, "mii") && len(v) >= 100) || // PKCS family
		(strings.HasPrefix(low, "aaaab3nzac") && len(v) >= 80) // OpenSSH
	return isBase64Key
}

// pemBodyLen counts base64 characters outside -----MARKER----- runs: a real
// embedded key always carries body content next to the markers (even a
// truncated fixture), a bare header/footer line carries none.
func pemBodyLen(v string) int {
	n := 0
	for _, line := range strings.Split(v, "\n") {
		t := strings.TrimSpace(line)
		for {
			i := strings.Index(t, "-----")
			if i < 0 {
				break
			}
			j := strings.Index(t[i+5:], "-----")
			if j < 0 {
				t = t[:i]
				break
			}
			t = t[:i] + " " + t[i+5+j+5:]
		}
		for i := 0; i < len(t); i++ {
			c := t[i]
			if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '=' {
				n++
			}
		}
	}
	return n
}

func matchNonSecretStructure(v, low string) string {
	// bcrypt / scrypt / argon2 hashes are REAL secrets — never classify as non-secret.
	// They look like: $2b$12$<60 chars>, $argon2id$..., $scrypt$...
	if strings.HasPrefix(v, "$2a$") || strings.HasPrefix(v, "$2b$") || strings.HasPrefix(v, "$2y$") ||
		strings.HasPrefix(v, "$argon2") || strings.HasPrefix(v, "$scrypt$") {
		return "" // let the entropy path handle it
	}

	// PEM private keys are always real credentials (checked in isPEMPrivateKey
	// which runs before we reach here, so this is defensive only).
	if isPEMPrivateKey(v, low) {
		return ""
	}

	if uuidRe.MatchString(low) {
		return "uuid-like identifier"
	}
	if strings.Count(v, "-") >= 3 && len(v) >= 20 && !strings.Contains(v, " ") {
		if isSegmentedID(v) {
			return "structured identifier, not a secret"
		}
	}
	trimmedLow := strings.TrimSuffix(low, "...")
	if hex32Re.MatchString(trimmedLow) || hex40Re.MatchString(trimmedLow) || hex64Re.MatchString(trimmedLow) || hex128Re.MatchString(trimmedLow) || (isAllHex(trimmedLow) && len(trimmedLow) >= 30) {
		return "hex digest/checksum, not a secret"
	}
	if strings.HasPrefix(low, "sha") || strings.HasPrefix(low, "md5") || strings.HasPrefix(low, "etag:") ||
		strings.HasPrefix(low, "commit:") || strings.HasPrefix(low, "tree:") || strings.HasPrefix(low, "blob:") ||
		strings.HasPrefix(low, "integrity:") {
		if parts := shaLineRe.FindStringSubmatch(low); len(parts) == 2 {
			if isLikelyDigest(parts[1]) {
				return "digest/fingerprint line, not a secret"
			}
		}
	}
	if strings.HasPrefix(low, "eyj") && len(v) > 40 && strings.Count(v, ".") == 2 {
		return ""
	}
	if strings.HasPrefix(low, "md5-") || strings.HasPrefix(low, "sha256:") || strings.HasPrefix(low, "sha1:") {
		return "checksum-like string, not a secret"
	}
	// Credential-adjacent code identifiers ("newRefreshToken") and dotted
	// config keys ("meteor.github.authorization") carry credential words but
	// have identifier structure: real secret values are opaque. Family
	// patterns (ghp_, AKIA, xoxb-) already matched above and are unaffected.
	if isIdentifierName(v) {
		return "identifier-shaped name, not a secret value"
	}
	if isDottedConfigKey(low) {
		return "dotted configuration key, not a secret value"
	}
	if isConcatRecipe(v) {
		return "string-concat recipe, not a secret value"
	}
	return ""
}

// isIdentifierName reports camelCase/PascalCase code identifiers: letters
// only, both cases present, no digits or separators. A field name like
// newRefreshToken is not a credential no matter which words it contains.
func isIdentifierName(v string) bool {
	if len(v) < 8 || len(v) > 48 {
		return false
	}
	hasLower, hasUpper := false, false
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= 'a' && c <= 'z':
			hasLower = true
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		default:
			return false
		}
	}
	return hasLower && hasUpper
}

// isDottedConfigKey reports lowercase dotted paths like
// meteor.github.authorization: structured key names, never secret values.
// (JWTs carry uppercase/base64 segments and never match.)
func isDottedConfigKey(low string) bool {
	if len(low) < 8 || len(low) > 128 {
		return false
	}
	parts := strings.Split(low, ".")
	if len(parts) < 2 || len(parts) > 6 {
		return false
	}
	for _, p := range parts {
		if len(p) < 2 || len(p) > 32 || p[0] < 'a' || p[0] > 'z' {
			return false
		}
		for i := 0; i < len(p); i++ {
			c := p[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
				return false
			}
		}
	}
	return true
}

// isConcatRecipe reports invokedynamic string-concat templates like
// "owner;name;branch;accessToken": compiler-generated recipes made of
// identifier segments, never credential values.
func isConcatRecipe(v string) bool {
	if len(v) < 8 || len(v) > 128 || !strings.Contains(v, ";") {
		return false
	}
	for _, p := range strings.Split(v, ";") {
		if len(p) < 2 || len(p) > 32 {
			return false
		}
		for i := 0; i < len(p); i++ {
			c := p[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
				return false
			}
		}
		if !(p[0] >= 'a' && p[0] <= 'z' || p[0] >= 'A' && p[0] <= 'Z' || p[0] == '_') {
			return false
		}
	}
	return true
}

func isAllHex(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func isSegmentedID(v string) bool {
	parts := strings.Split(v, "-")
	if len(parts) < 3 {
		return false
	}
	alphaNum := 0
	for _, p := range parts {
		if len(p) < 2 {
			return false
		}
		for i := 0; i < len(p); i++ {
			c := p[i]
			if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
				alphaNum++
			}
		}
	}
	return alphaNum >= len(v)*3/4
}

func isLikelyDigest(s string) bool {
	cleaned := strings.Trim(s, `"'`)
	if len(cleaned) == 0 {
		return false
	}
	if len(cleaned)%2 == 0 {
		if _, err := hex.DecodeString(cleaned); err == nil {
			return true
		}
	}
	if strings.Contains(cleaned, "=") || strings.Contains(cleaned, "+") || strings.Contains(cleaned, "/") {
		if _, err := base64.StdEncoding.DecodeString(cleaned); err == nil {
			return true
		}
	}
	return hex32Re.MatchString(cleaned) || hex40Re.MatchString(cleaned) || hex64Re.MatchString(cleaned) || hex128Re.MatchString(cleaned)
}

func matchPlaceholder(low, original string) string {
	for _, m := range placeholderMarkers {
		if !strings.Contains(low, m) {
			continue
		}
		// "example" and "sample" are common suffixes in synthetic training data.
		// Only treat them as noise when they dominate the value (>30% of length).
		if (m == "example" || m == "sample") && len(m)*10 < len(original)*3 {
			continue
		}
		return m
	}
	return ""
}

func isFakeOrPlaceholderToken(low string) bool {
	fakePrefixes := []string{
		"ghp_example", "ghp_sample", "ghp_test", "ghp_fake",
		"akiaexample", "akiasample", "akiatest", "akiafake",
		"sk-test-", "sk_test_", "sk-example", "sk-sample", "sk-test",
		"xoxb-example", "xoxb-sample", "xoxb-test",
	}
	for _, fp := range fakePrefixes {
		if strings.HasPrefix(low, fp) {
			return true
		}
	}
	return false
}

func hasSecretIndicator(v, low string) bool {
	leads := []string{
		"мой_секретный_ключ", "секретный_ключ", "secret_key", "api_key",
		"apikey_", "access_key", "auth_token", "private_key",
		"token",
	}
	for _, ld := range leads {
		if strings.Contains(low, ld) {
			return true
		}
	}
	if strings.HasPrefix(v, "eyJ") && strings.Count(v, ".") >= 2 {
		return true
	}
	if strings.Contains(v, "BEGIN") && strings.Contains(v, "KEY") {
		return true
	}
	return false
}

// isAlternatingToken reports whether a bare value looks like a random
// mixed-class credential body: long enough, strictly alphanumeric, at least
// two character classes and high per-character variety. It replaces an old
// hard-coded stub that only matched one specific string.
func isAlternatingToken(v string) bool {
	runes := []rune(v)
	if len(runes) < 12 {
		return false
	}
	var lowers, uppers, digits int
	for _, r := range runes {
		switch {
		case r >= 'a' && r <= 'z':
			lowers++
		case r >= 'A' && r <= 'Z':
			uppers++
		case r >= '0' && r <= '9':
			digits++
		default:
			// Symbols and non-ASCII bodies are judged by other branches.
			return false
		}
	}
	classes := 0
	if lowers > 0 {
		classes++
	}
	if uppers > 0 {
		classes++
	}
	if digits > 0 {
		classes++
	}
	if classes < 2 {
		return false
	}
	return uniqueRatio(v) >= 0.7
}

// matchFamily returns the family name when the value starts with a known
// credential prefix AND the body after the prefix is not a placeholder stub.
func matchFamily(v string) string {
	low := strings.ToLower(v)
	if isDiscordBotToken(v) {
		return "discord"
	}
	if isTelegramBotToken(v) {
		return "telegram"
	}
	for _, f := range knownFamilies {
		for _, p := range f.Prefixes {
			lowP := strings.ToLower(p)
			if !strings.HasPrefix(low, lowP) {
				continue
			}
			body := low[len(p):]
			minLen := f.MinBodyLen
			if minLen == 0 {
				minLen = minFamilyBodyLen
			}
			if isTrivialBody(body, low, minLen) {
				continue
			}
			// Twilio SIDs are AC/SK + 30-32 hex chars; the 2-char prefixes alone
			// match ordinary words ("ACCESS_CONTROL_*"), so require hex body.
			if f.Name == "twilio" && !isAllHex(body) {
				continue
			}
			return f.Name
		}
	}
	return ""
}

func isDiscordBotToken(v string) bool {
	clean := strings.TrimSuffix(v, "...")
	if strings.Count(clean, ".") != 2 {
		return false
	}
	parts := strings.Split(clean, ".")
	if len(parts) != 3 {
		return false
	}
	if len(parts[0]) < 15 || len(parts[1]) != 6 || len(parts[2]) < 2 {
		return false
	}
	return true
}

func isTelegramBotToken(v string) bool {
	parts := strings.SplitN(v, ":", 2)
	if len(parts) != 2 {
		return false
	}
	left, right := parts[0], parts[1]
	if len(left) < 8 || len(left) > 12 || len(right) < 20 {
		return false
	}
	for i := 0; i < len(left); i++ {
		if left[i] < '0' || left[i] > '9' {
			return false
		}
	}
	return true
}

// isTrivialBody reports whether the body of a prefixed token is a placeholder
// or simply too short to be a real credential (as opposed to an ordinary word
// that happens to start with a short, ambiguous prefix like "SK" or "co-").
func isTrivialBody(body, full string, minLen int) bool {
	if len(body) < minLen {
		return true
	}
	if isAllSame(body) && (len(body) == 0 || body[0] != 'x') {
		return true
	}
	if isSequential(body) {
		return true
	}
	if strings.HasPrefix(body, "example") || strings.HasPrefix(body, "sample") {
		return true
	}
	for _, m := range placeholderMarkers {
		if !strings.Contains(body, m) {
			continue
		}
		if m == "example" || m == "sample" {
			if !strings.HasPrefix(body, m) {
				rem := strings.ReplaceAll(body, m, "")
				if len(rem) >= 10 && !isAllSame(rem) && !isSequential(rem) {
					continue
				}
			}
		}
		return true
	}
	return false
}

func isAllSame(s string) bool {
	for i := 1; i < len(s); i++ {
		if s[i] != s[0] {
			return false
		}
	}
	return len(s) > 0
}

const (
	seqDigits = "0123456789"
	seqAlpha  = "abcdefghijklmnopqrstuvwxyz"
)

// isSequential reports whether s is a straight run of digits or letters
// (forwards or backwards), e.g. "123456789", "abcdefghij" or a long
// wrap-around run like "1234567890123456".
func isSequential(low string) bool {
	if len(low) < 4 {
		return false
	}
	rev := reverse(low)
	for _, seq := range []string{seqDigits, seqAlpha} {
		if strings.Contains(seq, low) || strings.Contains(seq, rev) {
			return true
		}
	}
	allDig := true
	allAlpha := true
	for i := 0; i < len(low); i++ {
		if low[i] < '0' || low[i] > '9' {
			allDig = false
		}
		if low[i] < 'a' || low[i] > 'z' {
			allAlpha = false
		}
	}
	if !allDig && !allAlpha {
		return false
	}
	inc, dec := 0, 0
	for i := 1; i < len(low); i++ {
		switch int(low[i]) - int(low[i-1]) {
		case 1:
			inc++
		case -1:
			dec++
		}
	}
	pairs := len(low) - 1
	return pairs > 0 && (inc*4 >= pairs*3 || dec*4 >= pairs*3)
}

func containsTrivialSequentialRun(low string) bool {
	runes := []rune(low)
	if len(runes) < 10 {
		return false
	}
	seqs := []string{
		"012345678901234567890123456789",
		"987654321098765432109876543210",
		"abcdefghijklmnopqrstuvwxyz",
		"zyxwvutsrqponmlkjihgfedcba",
	}
	seqRunes := 0
	i := 0
	for i <= len(runes)-8 {
		matched := 0
		for l := len(runes) - i; l >= 8; l-- {
			sub := string(runes[i : i+l])
			for _, s := range seqs {
				if strings.Contains(s, sub) {
					matched = l
					break
				}
			}
			if matched > 0 {
				break
			}
		}
		if matched > 0 {
			seqRunes += matched
			i += matched
		} else {
			i++
		}
	}
	return seqRunes*2 >= len(runes)
}

// uniqueRatio is the fraction of distinct runes in s (1.0 == all different).
func uniqueRatio(s string) float64 {
	runes := []rune(s)
	if len(runes) == 0 {
		return 0
	}
	seen := make(map[rune]bool, len(runes))
	for _, r := range runes {
		seen[r] = true
	}
	return float64(len(seen)) / float64(len(runes))
}

func reverse(s string) string {
	b := []byte(s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}

// ClassifyBatch classifies multiple values efficiently. It shares the single
// database initialization cost across all calls and deduplicates repeated
// values within the batch, classifying each distinct value at most once — a
// common case when scanning binaries whose string tables repeat constants.
func ClassifyBatch(values []string) []Verdict {
	_ = load()
	results := make([]Verdict, len(values))
	memo := make(map[string]Verdict, len(values))
	for i, v := range values {
		if cached, ok := memo[v]; ok {
			results[i] = cached
			continue
		}
		verdict := Classify(v)
		memo[v] = verdict
		results[i] = verdict
	}
	return results
}

// credentialKeyWords are key-name substrings that strongly suggest the associated
// value is a credential. Used by ClassifyWithKeyHint and ClassifyContext.
var credentialKeyWords = []string{
	"key", "token", "secret", "password", "passwd", "pass", "pwd",
	"auth", "credential", "apikey", "api_key", "accesskey", "access_key",
	"private_key", "signing_key", "signing_secret", "webhook_secret",
	"client_secret", "client_id", "bearer", "pat", "service_account",
	"connection_string", "database_url", "db_url", "dsn",
}

// antiCredentialKeyWords are key-name substrings that strongly suggest the
// associated value is NOT a secret (e.g. a version string, a filename, a label).
var antiCredentialKeyWords = []string{
	"version", "name", "label", "title", "description", "comment",
	"path", "file", "filename", "dir", "directory", "url", "uri",
	"host", "port", "timeout", "retry", "count", "size", "limit",
	"debug", "verbose", "log", "format", "encoding", "charset",
}

// ClassifyWithKeyHint is like Classify but bumps confidence when keyName
// contains a credential-suggestive word (api_key, token, secret, password…).
// Only affects values already classified as secrets — non-secrets stay non-secrets.
func ClassifyWithKeyHint(value, keyName string) Verdict {
	v := Classify(value)
	lk := strings.ToLower(keyName)

	// Anti-credential key name: lower confidence of borderline secrets.
	if v.IsSecret && v.Confidence < 0.80 {
		for _, aw := range antiCredentialKeyWords {
			if strings.Contains(lk, aw) {
				v.Confidence -= 0.15
				if v.Confidence < 0.20 {
					v.Confidence = 0.20
					v.IsSecret = false
				}
				v.Reason += "; key name suggests non-credential"
				break
			}
		}
	}

	if !v.IsSecret {
		return v
	}

	for _, w := range credentialKeyWords {
		if strings.Contains(lk, w) {
			if v.Confidence < 0.92 {
				v.Confidence += 0.10
				if v.Confidence > 0.95 {
					v.Confidence = 0.95
				}
				v.Reason += "; key name suggests credential"
			}
			break
		}
	}
	return v
}

// ContextScore is the result of ClassifyContext, combining both value signals
// and structural context (key name, surrounding text, nesting depth).
type ContextScore struct {
	Verdict
	// KeyName is the variable/field name found to the left of the value.
	KeyName string
	// NearbyKeywords are credential-suggestive words found near the value.
	NearbyKeywords []string
	// StructuralBoost is the extra confidence added from structural signals.
	StructuralBoost float64
}

// ClassifyContext is the highest-level API. It accepts the raw value, an
// optional key name (may be ""), and an optional surrounding text snippet
// (the line or paragraph around the value). It returns a ContextScore that
// combines value signals, key-name signals, and textual context signals.
//
// Use this when you have the full source line or surrounding lines available —
// it dramatically reduces false positives on configuration files.
func ClassifyContext(value, keyName, surroundingText string) ContextScore {
	base := ClassifyWithKeyHint(value, keyName)
	cs := ContextScore{Verdict: base, KeyName: keyName}

	low := strings.ToLower(surroundingText)

	// Look for credential-suggestive words in the surrounding text.
	var found []string
	for _, w := range credentialKeyWords {
		if strings.Contains(low, w) {
			found = append(found, w)
		}
	}
	cs.NearbyKeywords = found

	if base.IsSecret {
		// Boost: surrounding text strongly suggests a secret context.
		if len(found) >= 2 {
			cs.StructuralBoost += 0.05
		}
		// Boost: value appears inside quotes (common in .env / config files).
		trimmed := strings.TrimSpace(surroundingText)
		if strings.Contains(trimmed, `"`+value+`"`) || strings.Contains(trimmed, `'`+value+`'`) {
			cs.StructuralBoost += 0.03
		}
		// Penalty: surrounding text looks like documentation or a comment.
		if strings.Contains(low, "// ") || strings.Contains(low, "# ") ||
			strings.Contains(low, "/*") || strings.Contains(low, " example") {
			cs.StructuralBoost -= 0.10
		}
		// Penalty: value is inside a test file name context.
		if strings.Contains(low, "_test") || strings.Contains(low, "test_") ||
			strings.Contains(low, "spec.") || strings.Contains(low, ".test.") {
			cs.StructuralBoost -= 0.08
		}
		cs.Confidence = clamp(cs.Confidence+cs.StructuralBoost, 0.01, 0.99)
		cs.IsSecret = cs.Confidence >= 0.50
	}
	return cs
}

// clamp returns v clamped to [lo, hi].
func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// shannonEntropy returns the Shannon entropy in bits per rune of s.
func shannonEntropy(s string) float64 {
	runes := []rune(s)
	if len(runes) == 0 {
		return 0
	}
	freq := make(map[rune]int, len(runes))
	for _, r := range runes {
		freq[r]++
	}
	n := float64(len(runes))
	var h float64
	for _, c := range freq {
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}
