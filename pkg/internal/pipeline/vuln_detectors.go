// pkg/internal/pipeline/vuln_detectors.go
//
// New vulnerability detector classes (plan §3).
//
// All detectors follow the combination-of-signals rule: a single keyword is
// never enough; each class requires 2+ independent evidence points before
// issuing a critical finding. This keeps the false-positive rate near zero
// while surfacing vulnerability classes that no other detector covers.
//
// Detectors in this file:
//   - VulnCryptoDetector      — ECB mode, static IV, MD5/SHA1 for passwords
//   - VulnSecretDetector      — hardcoded API keys and private-key PEM blocks
//   - VulnNetworkDetector     — cleartext HTTP, insecure TrustManager/HostnameVerifier
//   - VulnManifestDetector    — see manifest_bridge.go: unified on the
//     binary-AXML manifestaudit module (byte-scanner retired, roadmap task #3)
//   - VulnPendingIntentDetector — mutable PendingIntent (FLAG_IMMUTABLE missing)
//   - VulnWebViewDetector     — addJavascriptInterface + JS enabled + remote URL combo
//   - VulnZipSlipDetector     — ZipEntry.getName() written to disk without traversal filter
//   - VulnDlopenObfuscationDetector — native library name built via StringBuilder before loadLibrary
package pipeline

import (
	"bytes"
	"fmt"
	"mega-analyzer/pkg/internal/networkrefs"
	"net"
	"regexp"
	"strings"

	"mega-analyzer/pkg/internal/types"
)

// ═══════════════════════════════════════════════════════════════════════════════
// 1. WEAK CRYPTO DETECTOR
// ═══════════════════════════════════════════════════════════════════════════════
//
// Flags: ECB mode, static (all-zero) IV, MD5/SHA1 used for password hashing.
// Each finding requires a SECOND signal so resource-string false positives are
// suppressed (e.g. "aes" appearing in a config key with no cipher context).

type VulnCryptoDetector struct {
	ac *detectorAC
}

func NewVulnCryptoDetector() *VulnCryptoDetector {
	entries := []detectorACEntry{
		// ECB mode — unambiguous: the mode string itself is the second signal
		// because it appears inside a Cipher.getInstance call context.
		{[]byte(`"aes/ecb/`), "ecb", "Cipher AES/ECB — no semantic security", types.CategoryWeakCrypto, true},
		{[]byte(`"des/ecb/`), "ecb", "Cipher DES/ECB — no semantic security", types.CategoryWeakCrypto, true},
		{[]byte(`"aes/ecb"`), "ecb", "Cipher AES/ECB — no semantic security", types.CategoryWeakCrypto, true},
		// Default AES on Android = ECB when no mode specified
		{[]byte(`cipher.getinstance("aes")`), "ecb_default", `Cipher.getInstance("AES") defaults to ECB on Android`, types.CategoryWeakCrypto, true},
		// Static IV: IvParameterSpec with literal zero-filled byte array
		{[]byte("ivparameterspec(new byte["), "static_iv", "Static/zero IV passed to IvParameterSpec", types.CategoryWeakCrypto, true},
		{[]byte("ivparameterspec({0,0,0,0"), "static_iv", "Hardcoded zero IV in IvParameterSpec", types.CategoryWeakCrypto, true},
		// MD5 for password hashing
		{[]byte(`messagedigest.getinstance("md5")`), "md5_digest", `MD5 MessageDigest — collision-vulnerable; not for passwords`, types.CategoryWeakCrypto, false},
		{[]byte(`messagedigest.getinstance("sha-1")`), "sha1_digest", `SHA-1 MessageDigest — deprecated for security`, types.CategoryWeakCrypto, false},
		// DES / 3DES — weak key sizes
		{[]byte("desedekeyspec"), "3des", "Triple-DES key — prefer AES-256", types.CategoryWeakCrypto, false},
		{[]byte(`secretkeyfactory.getinstance("des"`), "des_key", "DES key factory — 56-bit key, breakable", types.CategoryWeakCrypto, true},
		// RSA without padding
		{[]byte(`"rsa/ecb/nopadding"`), "rsa_nopad", "RSA/ECB/NoPadding — textbook RSA, vulnerable to many attacks", types.CategoryWeakCrypto, true},
		{[]byte(`"rsa/none/nopadding"`), "rsa_nopad", "RSA/None/NoPadding — no semantic security", types.CategoryWeakCrypto, true},
		// Random seed
		{[]byte("securerandom().setseed("), "seeded_rng", "SecureRandom seeded with constant — deterministic output", types.CategoryWeakCrypto, true},
	}
	return &VulnCryptoDetector{ac: newDetectorAC(entries)}
}

func (d *VulnCryptoDetector) Name() string { return "vuln_crypto" }

func (d *VulnCryptoDetector) Detect(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	if ctx.FileType != types.FileTypeSmali && ctx.FileType != types.FileTypeText &&
		ctx.FileType != types.FileTypeJSON && ctx.FileType != types.FileTypeProperties {
		return
	}
	if !ctx.IsTextContent() {
		return
	}
	// Structured path: real smali with a parsed AST. The byte patterns below
	// encode decompiled-Java syntax (`cipher.getinstance("aes")`) that never
	// occurs in smali, so they are useless there — run the register-aware
	// detector instead (audit B5/P0-2).
	if ctx.FileType == types.FileTypeSmali && ctx.Class != nil {
		detectCryptoFromAST(ctx, analysis)
		detectWeakCryptoFieldInits(ctx, analysis)
		return
	}
	d.ac.findMatches(ctx.ContentLower, ctx, analysis)

	// Combination: MD5/SHA-1 digest used near password/credential context
	// is an escalation (password hashing with a broken algorithm).
	hasMD5 := bytes.Contains(ctx.ContentLower, []byte(`messagedigest.getinstance("md5")`)) ||
		bytes.Contains(ctx.ContentLower, []byte(`messagedigest.getinstance("sha-1")`))
	if hasMD5 {
		hasPassCtx := bytes.Contains(ctx.ContentLower, []byte("password")) ||
			bytes.Contains(ctx.ContentLower, []byte("passwd")) ||
			bytes.Contains(ctx.ContentLower, []byte("credentials")) ||
			bytes.Contains(ctx.ContentLower, []byte("auth"))
		if hasPassCtx {
			idx := bytes.Index(ctx.ContentLower, []byte("messagedigest"))
			analysis.Matches = append(analysis.Matches, newMatch(
				types.CategoryWeakCrypto, analysis.Path,
				lineAt(ctx.LineOffsets, idx),
				"MD5/SHA-1 used for password or credential hashing — use bcrypt/PBKDF2",
				"MessageDigest + password context",
				true,
			))
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// 2. HARDCODED SECRET DETECTOR
// ═══════════════════════════════════════════════════════════════════════════════
//
// Looks for well-known API-key prefixes and PEM private-key headers. Each
// prefix is already a strong second signal (format-specific), so a single
// pattern match is sufficient for critical. The detector is skipped for SDK
// paths and test/example files.

type VulnSecretDetector struct {
	ac *detectorAC
}

func NewVulnSecretDetector() *VulnSecretDetector {
	entries := []detectorACEntry{
		// Google / Firebase
		{[]byte(`"aiza`), "gcp_api", "Google API key (AIza…)", types.CategoryHardcodedSecret, true},
		{[]byte(`"aaaa`), "fcm_key", "FCM Server Key (AAAA…)", types.CategoryHardcodedSecret, true},
		// Stripe
		{[]byte("sk_live_"), "stripe_secret", "Stripe secret key (sk_live_)", types.CategoryHardcodedSecret, true},
		{[]byte("rk_live_"), "stripe_restricted", "Stripe restricted key (rk_live_)", types.CategoryHardcodedSecret, true},
		// GitHub
		{[]byte("ghp_"), "github_pat", "GitHub Personal Access Token (ghp_)", types.CategoryHardcodedSecret, true},
		{[]byte("github_pat_"), "github_pat2", "GitHub Fine-grained PAT (github_pat_)", types.CategoryHardcodedSecret, true},
		{[]byte("gho_"), "github_oauth", "GitHub OAuth token (gho_)", types.CategoryHardcodedSecret, true},
		// Slack
		{[]byte("xoxb-"), "slack_bot", "Slack bot token (xoxb-)", types.CategoryHardcodedSecret, true},
		{[]byte("xoxp-"), "slack_user", "Slack user token (xoxp-)", types.CategoryHardcodedSecret, true},
		{[]byte("xoxa-"), "slack_app", "Slack app token (xoxa-)", types.CategoryHardcodedSecret, true},
		// AWS
		{[]byte("akia"), "aws_key", "AWS Access Key ID (AKIA…)", types.CategoryHardcodedSecret, true},
		// Private key PEM blocks
		{[]byte("begin rsa private key"), "pem_rsa", "RSA private key PEM block embedded in APK", types.CategoryHardcodedSecret, true},
		{[]byte("begin ec private key"), "pem_ec", "EC private key PEM block embedded in APK", types.CategoryHardcodedSecret, true},
		{[]byte("begin private key"), "pem_pkcs8", "PKCS#8 private key PEM block embedded in APK", types.CategoryHardcodedSecret, true},
		{[]byte("begin openssh private key"), "pem_ssh", "OpenSSH private key embedded in APK", types.CategoryHardcodedSecret, true},
		// SendGrid / Twilio / Mailgun
		{[]byte("sg."), "sendgrid", "Potential SendGrid API key (SG.…)", types.CategoryHardcodedSecret, false},
		{[]byte("sk_test_"), "stripe_test", "Stripe test secret key (sk_test_ — still a credential)", types.CategoryHardcodedSecret, false},
		// Mapbox / HereMaps
		{[]byte("pk.eyjhbgcioijsuzi"), "mapbox", "Mapbox public token (pk.eyJ…)", types.CategoryHardcodedSecret, false},
	}
	return &VulnSecretDetector{ac: newDetectorAC(entries)}
}

func (d *VulnSecretDetector) Name() string { return "vuln_secrets" }

func (d *VulnSecretDetector) Detect(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	// Secrets only in app code, not SDK libraries.
	if !ctx.IsAppCode {
		return
	}
	// Skip native binary files — entropy scanners handle those.
	if ctx.FileType == types.FileTypeNative || ctx.FileType == types.FileTypeMedia {
		return
	}
	if d.ac == nil || d.ac.ac == nil {
		return
	}

	hits := d.ac.ac.SearchBytes(ctx.ContentLower)
	seenGroups := make(map[string]bool, 4)
	for _, h := range hits {
		if h < 0 || h >= len(d.ac.entries) {
			continue
		}
		e := &d.ac.entries[h]
		if e.group != "" {
			if seenGroups[e.group] {
				continue
			}
			seenGroups[e.group] = true
		}
		idx := bytes.Index(ctx.ContentLower, e.patternLower)
		if e.group == "fcm_key" {
			idx = findFCMServerKey(ctx.Content, ctx.ContentLower, e.patternLower)
		}
		if idx < 0 {
			continue
		}
		if e.group == "aws_key" && !looksLikeAWSAccessKeyAt(ctx.Content, idx) {
			continue
		}
		if e.group == "sendgrid" && !looksLikeSendGridKeyAt(ctx.Content, idx) {
			continue
		}
		analysis.Matches = append(analysis.Matches, newMatch(
			e.category, analysis.Path,
			lineAt(ctx.LineOffsets, idx),
			e.desc,
			string(e.patternLower),
			e.critical,
		))
	}
}

func looksLikeAWSAccessKeyAt(content []byte, idx int) bool {
	const keyLen = 20
	if idx < 0 || idx+keyLen > len(content) {
		return false
	}
	key := content[idx : idx+keyLen]
	prefix := bytes.ToUpper(key[:4])
	if !bytes.Equal(prefix, []byte("AKIA")) {
		return false
	}
	for _, c := range key[4:] {
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		if !((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	if idx > 0 && isSecretTokenChar(content[idx-1]) {
		return false
	}
	if idx+keyLen < len(content) && isSecretTokenChar(content[idx+keyLen]) {
		return false
	}
	return true
}

func findFCMServerKey(content, contentLower, patternLower []byte) int {
	for start := 0; start < len(contentLower); {
		rel := bytes.Index(contentLower[start:], patternLower)
		if rel < 0 {
			return -1
		}
		idx := start + rel
		if looksLikeFCMServerKeyAt(content, idx) {
			return idx
		}
		start = idx + len(patternLower)
	}
	return -1
}

func looksLikeFCMServerKeyAt(content []byte, idx int) bool {
	const (
		projectSegmentLen = 11 // "AAAA" plus seven base64url characters.
		minKeyLen         = 100
	)
	if idx < 0 || idx >= len(content) {
		return false
	}

	keyStart := idx
	if content[keyStart] == '"' {
		keyStart++
	}
	if keyStart+minKeyLen > len(content) || keyStart+projectSegmentLen >= len(content) {
		return false
	}
	if keyStart > 0 && isSecretTokenChar(content[keyStart-1]) {
		return false
	}
	if !bytes.Equal(content[keyStart:keyStart+4], []byte("AAAA")) {
		return false
	}
	for _, c := range content[keyStart+4 : keyStart+projectSegmentLen] {
		if !isSecretTokenChar(c) {
			return false
		}
	}
	if content[keyStart+projectSegmentLen] != ':' {
		return false
	}

	end := keyStart + projectSegmentLen + 1
	for end < len(content) && isSecretTokenChar(content[end]) {
		end++
	}
	return end-keyStart >= minKeyLen
}

var sendGridKeyRegexp = regexp.MustCompile(`^(?i)sg\.[a-z0-9_-]{16,}\.[a-z0-9_-]{16,}`)

func looksLikeSendGridKeyAt(content []byte, idx int) bool {
	if idx < 0 || idx+3 >= len(content) {
		return false
	}
	end := idx + 100
	if end > len(content) {
		end = len(content)
	}
	return sendGridKeyRegexp.Match(content[idx:end])
}

func isSecretTokenChar(c byte) bool {
	return (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') ||
		c == '_' || c == '-'
}

// ═══════════════════════════════════════════════════════════════════════════════
// 3. INSECURE NETWORK DETECTOR
// ═══════════════════════════════════════════════════════════════════════════════
//
// Flags: cleartext HTTP URLs (non-localhost), empty TrustManager, always-true
// HostnameVerifier. Combination required for TrustManager: the class must
// both implement checkServerTrusted AND not throw or call super.

type VulnNetworkDetector struct {
	acHTTP *detectorAC
}

func NewVulnNetworkDetector() *VulnNetworkDetector {
	httpEntries := []detectorACEntry{
		{[]byte(`"http://`), "http_url", "Cleartext HTTP URL hardcoded in app code", types.CategoryCleartextTraffic, false},
		{[]byte(`http://`), "http_url2", "Cleartext HTTP URL reference", types.CategoryCleartextTraffic, false},
	}
	return &VulnNetworkDetector{
		acHTTP: newDetectorAC(httpEntries),
	}
}

func (d *VulnNetworkDetector) Name() string { return "vuln_network" }

func (d *VulnNetworkDetector) Detect(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	// A runtime-looking path alone must never suppress findings.
	if !ctx.IsTextContent() {
		return
	}

	d.detectCleartextURLs(ctx, analysis)

	for _, issue := range detectTLSSemantics(ctx.Content, ctx.ContentLower, ctx.FileType) {
		match := newMatch(
			types.CategoryInsecureTLS, analysis.Path,
			lineAt(ctx.LineOffsets, issue.offset),
			issue.description, issue.evidence, issue.critical,
		)
		match.Scored.Confidence = issue.confidence
		match.Severity = types.SeverityHigh
		match.EvidenceType = "semantic_method_analysis"
		match.Metadata = map[string]string{
			"rule_id":  issue.ruleID,
			"detector": d.Name(),
		}
		analysis.Matches = append(analysis.Matches, match)
	}
}

func (d *VulnNetworkDetector) detectCleartextURLs(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	if !ctx.IsAppCode {
		return
	}
	seen := make(map[string]bool)
	for offset := 0; offset < len(ctx.ContentLower); {
		rel := bytes.Index(ctx.ContentLower[offset:], []byte("http://"))
		if rel < 0 {
			break
		}
		idx := offset + rel
		offset = idx + len("http://")
		if isXMLNamespaceURL(ctx.Content, idx) || isKnownNonEndpointHTTPReference(ctx.ContentLower[idx:]) {
			continue
		}
		raw, _ := extractURLBytes(ctx.Content, idx)
		if raw == "" || seen[raw] {
			continue
		}
		host, _, _, _ := parseEndpoint(raw)
		ip := net.ParseIP(host)
		if host == "" || host == "localhost" || host == "10.0.2.2" || (ip != nil && ip.IsLoopback()) {
			continue
		}
		seen[raw] = true
		match := newMatch(types.CategoryCleartextTraffic, analysis.Path,
			lineAt(ctx.LineOffsets, idx),
			"Cleartext HTTP URL reference; verify runtime reachability (CWE-319)", raw, false)
		match.Severity = types.SeverityMedium
		analysis.Matches = append(analysis.Matches, match)
	}
}

// Namespace URIs identify XML vocabulary. Check the attribute, not the
// hostname, so an image href on the same host is still retained.
func isXMLNamespaceURL(content []byte, offset int) bool {
	return networkrefs.IsXMLMetadataURL(content, offset)
}

func isKnownNonEndpointHTTPReference(window []byte) bool {
	window = bytes.TrimLeft(window, `"'`)
	for _, prefix := range [][]byte{
		[]byte("http://schemas.android.com/"),
		[]byte("http://www.w3.org/"),
		[]byte("http://xmlpull.org/"),
		[]byte("http://xml.org/sax/"),
		[]byte("http://json-schema.org/"),
		// XML DTD / namespace identifiers — never fetched at runtime.
		[]byte("http://www.gwtproject.org/"),
		[]byte("http://gwtproject.org/"),
		[]byte("http://java.sun.com/"),
		[]byte("http://www.apache.org/"),
		[]byte("http://apache.org/"),
		[]byte("http://ns.adobe.com/"),
		[]byte("http://purl.org/"),
		[]byte("http://schemas.xmlsoap.org/"),
		// Store deep links. These strings are handed to an ACTION_VIEW intent
		// (or sit next to the real `market://details?id=` constant) — the app
		// never sends data over them, and the browser upgrades to HTTPS. A dead
		// `http://play.google.com/store/...` literal is not a CWE-319 channel.
		[]byte("http://play.google.com/"),
		[]byte("http://market.android.com/"),
	} {
		if bytes.HasPrefix(window, prefix) {
			return true
		}
	}
	return false
}

// ═══════════════════════════════════════════════════════════════════════════════
// 4. MANIFEST VULNERABILITY DETECTOR
// ═══════════════════════════════════════════════════════════════════════════════
//
// Moved to manifest_bridge.go (roadmap task #3): VulnManifestDetector is now
// a bridge over the binary-AXML manifestaudit module. The former byte-scanner
// (indexManifestTag / manifestAttrValue / detectExportedComponents /
// detectHostlessDeepLinks / parseTargetSdkVersion) has been retired — one
// structured manifest code path remains.

// ═══════════════════════════════════════════════════════════════════════════════
// 5. PENDING INTENT VULNERABILITY DETECTOR
// ═══════════════════════════════════════════════════════════════════════════════
//
// Mutable PendingIntents (missing FLAG_IMMUTABLE) can be exploited by
// malicious apps to redirect the wrapped Intent. Required on API >= 31;
// strongly recommended from API 23+.
// Combination: PendingIntent.get* call WITHOUT "flag_immutable" or
// "flag_one_shot" in nearby context.

type VulnPendingIntentDetector struct {
	ac *detectorAC
}

func NewVulnPendingIntentDetector() *VulnPendingIntentDetector {
	entries := []detectorACEntry{
		{[]byte("pendingintent.getactivity("), "pi_activity", "PendingIntent.getActivity", types.CategoryPendingIntentVuln, false},
		{[]byte("pendingintent.getservice("), "pi_service", "PendingIntent.getService", types.CategoryPendingIntentVuln, false},
		{[]byte("pendingintent.getbroadcast("), "pi_broadcast", "PendingIntent.getBroadcast", types.CategoryPendingIntentVuln, false},
		{[]byte("pendingintent.getactivities("), "pi_activities", "PendingIntent.getActivities", types.CategoryPendingIntentVuln, false},
	}
	return &VulnPendingIntentDetector{ac: newDetectorAC(entries)}
}

func (d *VulnPendingIntentDetector) Name() string { return "vuln_pending_intent" }

func (d *VulnPendingIntentDetector) SupportsFile(fileType types.FileType, _ string) bool {
	return fileType == types.FileTypeSmali
}

func (d *VulnPendingIntentDetector) Detect(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	if ctx.FileType != types.FileTypeSmali {
		return
	}
	// Compat-library call sites (androidx SearchView's mutable voice-search
	// PendingIntent is the canonical example) follow the platform
	// recommendation; mutability findings are only meaningful in app code.
	if analysis != nil && analysis.IsLibrary {
		return
	}
	// Only check files where PendingIntent is referenced.
	if !bytes.Contains(ctx.ContentLower, []byte("pendingintent")) {
		return
	}

	// Structured path: resolve the flags register of each factory call site
	// inside its own method. The legacy logic below checked FLAG_IMMUTABLE
	// file-wide (one safe call suppressed every unsafe call) and matched
	// decompiled-Java syntax that never occurs in smali (audit B1/P0-3).
	if ctx.Class != nil {
		detectPendingIntentFromAST(ctx, analysis)
		return
	}

	hasFlagImmutable := bytes.Contains(ctx.ContentLower, []byte("flag_immutable")) ||
		bytes.Contains(ctx.ContentLower, []byte("0x04000000")) // FLAG_IMMUTABLE constant
	if hasFlagImmutable {
		return // correctly uses FLAG_IMMUTABLE → no finding
	}

	// At least one PendingIntent.get* call without FLAG_IMMUTABLE.
	piMethods := [][]byte{
		[]byte("pendingintent.getactivity("),
		[]byte("pendingintent.getservice("),
		[]byte("pendingintent.getbroadcast("),
		[]byte("pendingintent.getactivities("),
	}
	for _, pm := range piMethods {
		if idx := bytes.Index(ctx.ContentLower, pm); idx >= 0 {
			analysis.Matches = append(analysis.Matches, newMatch(
				types.CategoryPendingIntentReview, analysis.Path,
				lineAt(ctx.LineOffsets, idx),
				"PendingIntent factory reference without AST flag resolution; mutability and a vulnerability are not established",
				string(pm),
				false,
			))
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// 6. WEBVIEW REMOTE JS DETECTOR (enhanced)
// ═══════════════════════════════════════════════════════════════════════════════
//
// Requires all three signals: addJavascriptInterface, setJavaScriptEnabled,
// and a remote URL (http/https or a variable suggesting external content).
// A WebView that only loads local assets with JS is NOT flagged.

type VulnWebViewDetector struct{}

func NewVulnWebViewDetector() *VulnWebViewDetector { return &VulnWebViewDetector{} }

func (d *VulnWebViewDetector) Name() string { return "vuln_webview" }

func (d *VulnWebViewDetector) SupportsFile(fileType types.FileType, _ string) bool {
	return fileType == types.FileTypeSmali
}

func (d *VulnWebViewDetector) Detect(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	if ctx.FileType != types.FileTypeSmali {
		return
	}
	if !bytes.Contains(ctx.ContentLower, []byte("webview")) {
		return
	}

	// Prefer per-call-site AST analysis: resolves the boolean arguments of
	// the WebSettings setters and proves remote loading from actual URL
	// operands (audit B4). Byte fallback below runs only without an AST.
	if ctx.Class != nil {
		detectWebViewFromAST(ctx, analysis)
		return
	}

	c := ctx.ContentLower

	// ── File access from file:// URLs (local file exfiltration, CWE-200/668) ─
	if idx := bytes.Index(c, []byte("setallowuniversalaccessfromfileurls")); idx >= 0 {
		m := newMatch(
			types.CategoryWebViewFileAccess, analysis.Path,
			lineAt(ctx.LineOffsets, idx),
			"WebView setAllowUniversalAccessFromFileURLs — a file:// page can read arbitrary local files and any origin (CWE-200)",
			"setAllowUniversalAccessFromFileURLs(true)",
			false,
		)
		m.Severity = types.SeverityHigh
		analysis.Matches = append(analysis.Matches, m)
	}
	if idx := bytes.Index(c, []byte("setallowfileaccessfromfileurls")); idx >= 0 {
		m := newMatch(
			types.CategoryWebViewFileAccess, analysis.Path,
			lineAt(ctx.LineOffsets, idx),
			"WebView setAllowFileAccessFromFileURLs — a file:// page can read other local files (CWE-200)",
			"setAllowFileAccessFromFileURLs(true)",
			false,
		)
		m.Severity = types.SeverityMedium
		analysis.Matches = append(analysis.Matches, m)
	}

	// ── Native JS bridge present (RCE surface on API < 17: CVE-2012-6636) ─
	if bytes.Contains(c, []byte("addjavascriptinterface")) && bytes.Contains(c, []byte("setjavascriptenabled")) {
		idx := bytes.Index(c, []byte("addjavascriptinterface"))
		m := newMatch(
			types.CategoryWebViewJSBridge, analysis.Path,
			lineAt(ctx.LineOffsets, idx),
			"WebView bridge and JavaScript-setting references; arguments, exposed methods and content origins require review",
			"addJavascriptInterface + setJavaScriptEnabled",
			false,
		)
		m.Severity = types.SeverityInfo
		analysis.Matches = append(analysis.Matches, m)
	}

	hasJSIface := bytes.Contains(ctx.ContentLower, []byte("addjavascriptinterface"))
	hasJSEnabled := bytes.Contains(ctx.ContentLower, []byte("setjavascriptenabled")) &&
		bytes.Contains(ctx.ContentLower, []byte("(z)v")) // the boolean setter

	if !hasJSIface || !hasJSEnabled {
		return
	}

	// Third signal: loads remote content (not just file:// or assets://).
	// Parenthesized explicitly: Go binds && tighter than ||, so the old
	// `A || B && C` form made a bare `"http` string alone sufficient (audit B4).
	hasRemote := (bytes.Contains(ctx.ContentLower, []byte(`"http`)) ||
		bytes.Contains(ctx.ContentLower, []byte("loadurl"))) &&
		!bytes.Contains(ctx.ContentLower, []byte("file://android_asset"))

	if hasRemote {
		idx := bytes.Index(ctx.ContentLower, []byte("addjavascriptinterface"))
		analysis.Matches = append(analysis.Matches, newMatch(
			types.CategoryWebViewRemoteJS, analysis.Path,
			lineAt(ctx.LineOffsets, idx),
			"WebView bridge and content-loader references without AST resolution; remote loading and code execution are not established",
			"addJavascriptInterface + JS enabled + remote loadUrl",
			false,
		))
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// 7. ZIP-SLIP / PATH TRAVERSAL DETECTOR
// ═══════════════════════════════════════════════════════════════════════════════
//
// The analyzer's own archive extractor is already hardened against Zip-Slip
// (pkg/internal/apkloader/extractor.go). Nothing, however, checks whether the
// *analyzed app itself* bundles a vulnerable unzip routine — apps that ship
// their own asset-pack/mod-loader/plugin unzip code are a common source of
// this bug (CVE-class: writing a ZipEntry to disk using its raw name lets a
// crafted "../../.." entry escape the destination directory).
//
// Combination required: ZIP extraction API (ZipInputStream/ZipFile) AND a
// ZipEntry.getName() read AND a file-write sink, with NO canonical-path/".."
// sanitization signal anywhere in the file. Any one of these alone is
// completely ordinary code and must not be flagged.

type VulnZipSlipDetector struct{}

func NewVulnZipSlipDetector() *VulnZipSlipDetector { return &VulnZipSlipDetector{} }

func (d *VulnZipSlipDetector) Name() string { return "vuln_zip_slip" }

func (d *VulnZipSlipDetector) SupportsFile(fileType types.FileType, _ string) bool {
	return fileType == types.FileTypeSmali
}

func (d *VulnZipSlipDetector) Detect(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	if ctx == nil || ctx.FileType != types.FileTypeSmali || !ctx.IsAppCode {
		return
	}

	c := ctx.ContentLower
	hasZipAPI := bytes.Contains(c, []byte("ljava/util/zip/zipinputstream;")) ||
		bytes.Contains(c, []byte("ljava/util/zip/zipfile;")) ||
		bytes.Contains(c, []byte("zipentry;->getname()"))
	if !hasZipAPI {
		return
	}

	contentStr := string(ctx.Content)
	lines := strings.Split(strings.ReplaceAll(contentStr, "\r\n", "\n"), "\n")

	if ctx.Class != nil {
		for i := range ctx.Class.Methods {
			method := &ctx.Class.Methods[i]
			methodLines := extractMethodLines(method, lines)
			checkZipSlipInMethod(method, methodLines, ctx.Class.Name, analysis)
		}
	} else {
		scanZipSlipInSmaliText(lines, analysis)
	}
}

func checkZipSlipInMethod(method *types.SmaliMethod, methodLines []string, className string, analysis *types.FileAnalysis) {
	hasZipEntry := false
	hasFileSink := false
	hasGuard := false
	zipEntryLine := 0
	fileSinkLine := 0

	checkLine := func(line string, lineNo int) {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "zipentry;->getname()") || strings.Contains(lower, "zipinputstream;->getnextentry()") {
			hasZipEntry = true
			if lineNo > 0 && (zipEntryLine == 0 || strings.Contains(lower, "zipentry;->getname()")) {
				zipEntryLine = lineNo
			}
		}
		// Only real write sinks count. `new File(...)` is a path object, not a
		// write: archive readers (ReLinker, APK self-extractors) construct File
		// handles for ZipFile/openStream all the time, which produced a false
		// Zip-Slip on a clean APK.
		if strings.Contains(lower, "fileoutputstream;-><init>") ||
			strings.Contains(lower, "filewriter;-><init>") ||
			strings.Contains(lower, "randomaccessfile;-><init>") ||
			strings.Contains(lower, "files;->copy") ||
			strings.Contains(lower, "files;->write") ||
			strings.Contains(lower, "files;->newoutputstream") {
			hasFileSink = true
			if fileSinkLine == 0 && lineNo > 0 {
				fileSinkLine = lineNo
			}
		}
		if strings.Contains(lower, "getcanonicalpath") ||
			strings.Contains(lower, "getcanonicalfile") ||
			strings.Contains(lower, "startswith") ||
			strings.Contains(lower, "getpathsegments") ||
			strings.Contains(lower, "getlastpathsegment") ||
			strings.Contains(lower, "normalize") ||
			(strings.Contains(lower, "contains") && strings.Contains(lower, "..")) {
			hasGuard = true
		}
	}

	for idx, line := range methodLines {
		checkLine(line, method.LineStart+idx)
	}

	hasGuard = hasGuard && zipHasConditional(methodLines)
	if hasZipEntry && hasFileSink && !hasGuard {
		lineNo := zipEntryLine
		if lineNo == 0 {
			lineNo = fileSinkLine
		}
		if lineNo == 0 {
			lineNo = method.LineStart
		}
		if lineNo <= 0 {
			lineNo = 1
		}
		match := newMatch(
			types.CategoryZipSlip, analysis.Path,
			lineNo,
			"Zip-Slip: ZipEntry.getName() written to a file path without canonical-path/\"..\" sanitization in method "+method.Name+" — archive extraction may write outside target directory",
			"ZipEntry.getName() + file write, no traversal check",
			true,
		)
		match.ClassName = className
		match.MethodName = method.Name
		match.EvidenceType = "smali_zip_slip_ast"
		analysis.Matches = append(analysis.Matches, match)
	}
}

// A normalizer whose result is never checked cannot establish containment.
// This is a heuristic prerequisite; a conditional alone is not a proof.
func zipHasConditional(lines []string) bool {
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "if-") {
			return true
		}
	}
	return false
}

func scanZipSlipInSmaliText(lines []string, analysis *types.FileAnalysis) {
	inMethod := false
	var currentMethodLines []string
	methodName := ""
	methodLineStart := 1

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, ".method ") {
			inMethod = true
			currentMethodLines = []string{line}
			methodName = parseMethodNameFromSig(line)
			methodLineStart = i + 1
			continue
		}
		if inMethod {
			currentMethodLines = append(currentMethodLines, line)
			if trimmed == ".end method" {
				inMethod = false
				dummyMethod := &types.SmaliMethod{
					Name: methodName,
					SourceRange: types.SourceRange{
						LineStart: methodLineStart,
						LineEnd:   i + 1,
					},
				}
				checkZipSlipInMethod(dummyMethod, currentMethodLines, "", analysis)
				currentMethodLines = nil
			}
		}
	}
}

func parseMethodNameFromSig(sig string) string {
	parts := strings.Fields(sig)
	if len(parts) < 2 {
		return ""
	}
	last := parts[len(parts)-1]
	if idx := strings.IndexByte(last, '('); idx >= 0 {
		return last[:idx]
	}
	return last
}

// ═══════════════════════════════════════════════════════════════════════════════
// 8. OBFUSCATED DLOPEN / LOADLIBRARY DETECTOR
// ═══════════════════════════════════════════════════════════════════════════════
//
// Malware frequently avoids a literal "libfoo.so"/library-name string (which
// every static scanner greps for) by assembling it at runtime through
// repeated StringBuilder.append() calls and handing the result straight to
// System.loadLibrary()/Runtime.load() — which then dlopen()s it natively.
// StringBuilder and loadLibrary are both completely ordinary APIs on their
// own; the combination — 2+ append calls feeding directly into a load call,
// with no literal library name ever appearing in the file — is the tell.

type VulnDlopenObfuscationDetector struct{}

func NewVulnDlopenObfuscationDetector() *VulnDlopenObfuscationDetector {
	return &VulnDlopenObfuscationDetector{}
}

func (d *VulnDlopenObfuscationDetector) Name() string { return "vuln_dlopen_obfuscation" }

func (d *VulnDlopenObfuscationDetector) SupportsFile(fileType types.FileType, _ string) bool {
	return fileType == types.FileTypeSmali
}

// dlopenLoadCallPatterns — smali call sites that ultimately trigger dlopen()
// on a runtime-built library name.
var dlopenLoadCallPatterns = [][]byte{
	[]byte("ljava/lang/system;->loadlibrary("),
	[]byte("ljava/lang/runtime;->loadlibrary("),
	[]byte("ljava/lang/runtime;->load("),
}

// dlopenScanWindow — how far back (in bytes) to look from a load call for the
// StringBuilder append sequence that built its argument.
const dlopenScanWindow = 1200

func (d *VulnDlopenObfuscationDetector) Detect(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	if ctx.FileType != types.FileTypeSmali {
		return
	}
	c := ctx.ContentLower
	if !bytes.Contains(c, []byte("stringbuilder;->append(")) {
		return
	}

	for _, pat := range dlopenLoadCallPatterns {
		start := 0
		for {
			pos := bytes.Index(c[start:], pat)
			if pos < 0 {
				break
			}
			idx := start + pos
			windowStart := idx - dlopenScanWindow
			if windowStart < 0 {
				windowStart = 0
			}
			window := c[windowStart:idx]
			appendCount := bytes.Count(window, []byte("stringbuilder;->append("))
			constStringCount := bytes.Count(window, []byte("const-string"))

			// Combination: 2+ piecewise appends fed by 2+ const-string
			// literals — a single append (e.g. a fixed prefix + one
			// user-controlled suffix) is ordinary code, not obfuscation.
			if appendCount >= 2 && constStringCount >= 2 {
				analysis.Matches = append(analysis.Matches, newMatch(
					types.CategoryDlopenObfuscation, analysis.Path,
					lineAt(ctx.LineOffsets, idx),
					fmt.Sprintf("Native library name assembled via %d StringBuilder.append() calls before being passed to loadLibrary/load() — avoids literal library-name string scanning", appendCount),
					safeSnippet(ctx.Content, idx, 60),
					true,
				))
			}

			start = idx + len(pat)
			if start >= len(c) {
				break
			}
		}
	}
}

// ---------------------------------------------------------------------------
// 9. RESOURCE INTEGRITY / MODIFIABLE TRUST MATERIAL DETECTOR
// ---------------------------------------------------------------------------
//
// "Resources can be changed": assets/res inside an APK are trivially editable
// and repackageable, and they are NOT covered by any runtime integrity check.
// That only becomes a vulnerability when a *security decision* depends on a
// modifiable resource. The highest-impact case is TLS trust:
//   (a) a CA / trust bundle shipped as a plain asset (cacert.pem, *.bks, *.p12); and
//   (b) app code that builds a custom TrustManager / KeyStore from getAssets().
// An attacker who repackages the APK swaps the bundled CA and MITMs every
// connection that trusts this store (CWE-295 / CWE-494). Each signal is a
// concrete artifact, not a generic keyword, and is reported independently.

type VulnResourceIntegrityDetector struct{}

func NewVulnResourceIntegrityDetector() *VulnResourceIntegrityDetector {
	return &VulnResourceIntegrityDetector{}
}

func (d *VulnResourceIntegrityDetector) Name() string { return "vuln_resource_integrity" }

func (d *VulnResourceIntegrityDetector) Detect(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	c := ctx.ContentLower

	// (a) Trust material shipped as a modifiable asset.
	if ctx.FileType == types.FileTypeText || ctx.FileType == types.FileTypeResource {
		p := strings.ToLower(analysis.Path)
		looksLikeCertFile := strings.HasSuffix(p, ".pem") || strings.HasSuffix(p, ".crt") ||
			strings.HasSuffix(p, ".cer") || strings.HasSuffix(p, ".bks") ||
			strings.HasSuffix(p, ".p12") || strings.HasSuffix(p, ".keystore") ||
			strings.Contains(p, "cacert") || strings.Contains(p, "truststore")
		isCABundle := bytes.Contains(c, []byte("ca root certificates")) ||
			bytes.Contains(c, []byte("trusted certificate")) ||
			bytes.Count(c, []byte("begin certificate")) >= 2
		if looksLikeCertFile && isCABundle {
			idx := bytes.Index(c, []byte("begin certificate"))
			if idx < 0 {
				idx = 0
			}
			m := newMatch(
				types.CategoryResourceIntegrity, analysis.Path,
				lineAt(ctx.LineOffsets, idx),
				"Trust anchors (a CA bundle) are shipped as a modifiable app resource. Assets carry no integrity protection, so an attacker who repackages the APK can add or replace a CA and MITM every TLS connection that trusts this store (CWE-295/CWE-494)",
				"bundled CA trust store in assets",
				false,
			)
			m.Severity = types.SeverityMedium
			analysis.Matches = append(analysis.Matches, m)
		}
	}

	// (b) Custom trust store / TrustManager built from getAssets() in app/library code.
	if ctx.FileType == types.FileTypeSmali {
		hasGetAssets := bytes.Contains(c, []byte("getassets"))
		hasTrustBuild := bytes.Contains(c, []byte("ljavax/net/ssl/trustmanagerfactory")) ||
			bytes.Contains(c, []byte("ljava/security/keystore;->load"))
		if hasGetAssets && hasTrustBuild {
			idx := bytes.Index(c, []byte("getassets"))
			if idx < 0 {
				idx = 0
			}
			m := newMatch(
				types.CategoryResourceIntegrity, analysis.Path,
				lineAt(ctx.LineOffsets, idx),
				"Custom trust store / TrustManager is initialized from a bundled asset (getAssets -> KeyStore/TrustManagerFactory). The trust anchor lives in a modifiable resource, so repackaging the APK lets an attacker swap the CA and intercept TLS (MITM, CWE-295)",
				"getAssets + KeyStore/TrustManagerFactory",
				false,
			)
			m.Severity = types.SeverityHigh
			analysis.Matches = append(analysis.Matches, m)
		}
	}
}

// ── Staging / pre-production endpoint exposure ─────────────────────
// A release build that ships hostnames belonging to staging, pre-prod or
// UAT environments leaks internal infrastructure and widens the attack
// surface (CWE-200). Such hosts inside App Links also weaken deep-link
// verification because the extra domains must be autoVerified separately.

type VulnStagingEndpointDetector struct{}

func NewVulnStagingEndpointDetector() *VulnStagingEndpointDetector {
	return &VulnStagingEndpointDetector{}
}

func (d *VulnStagingEndpointDetector) Name() string { return "vuln_staging_endpoint" }

func stagingIsHostByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '-' || b == '.'
}

func stagingIsAlphaLabel(s string) bool {
	if len(s) < 2 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 'a' || s[i] > 'z' {
			return false
		}
	}
	return true
}

func (d *VulnStagingEndpointDetector) Detect(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	switch ctx.FileType {
	case types.FileTypeXML, types.FileTypeText, types.FileTypeJSON, types.FileTypeProperties:
		// scan these text-like files
	case types.FileTypeSmali:
		if !ctx.IsAppCode {
			return
		}
	default:
		return
	}

	c := ctx.ContentLower
	seen := map[string]bool{}
	for _, tok := range []string{"staging", "preprod", "pre-prod", "uat"} {
		bt := []byte(tok)
		start := 0
		for {
			rel := bytes.Index(c[start:], bt)
			if rel < 0 {
				break
			}
			idx := start + rel
			start = idx + len(bt)
			if idx > 0 {
				pb := c[idx-1]
				if (pb >= 'a' && pb <= 'z') || (pb >= '0' && pb <= '9') || pb == '-' {
					continue
				}
			}
			if idx+len(bt) >= len(c) || c[idx+len(bt)] != '.' {
				continue
			}
			l := idx
			for l > 0 && stagingIsHostByte(c[l-1]) {
				l--
			}
			r := idx + len(bt)
			for r < len(c) && stagingIsHostByte(c[r]) {
				r++
			}
			host := strings.Trim(string(c[l:r]), ".")
			labels := strings.Split(host, ".")
			if len(labels) < 3 {
				continue
			}
			if !stagingIsAlphaLabel(labels[len(labels)-1]) {
				continue
			}
			isLabel := false
			for _, lb := range labels {
				if lb == tok {
					isLabel = true
					break
				}
			}
			if !isLabel || seen[host] {
				continue
			}
			seen[host] = true
			m := newMatch(
				types.CategoryStagingEndpoint, analysis.Path,
				lineAt(ctx.LineOffsets, idx),
				fmt.Sprintf("Non-production endpoint %q shipped in a release build (%q environment) — leaks internal infrastructure and widens the attack surface (CWE-200)", host, tok),
				host,
				false,
			)
			m.Severity = types.SeverityLow
			analysis.Matches = append(analysis.Matches, m)
			if len(seen) >= 5 {
				return
			}
		}
	}
}
