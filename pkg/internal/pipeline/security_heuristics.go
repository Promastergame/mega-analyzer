package pipeline

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"net/url"
	"regexp"
	"strings"
	"unicode"

	"mega-analyzer/pkg/internal/types"
)

// ═══════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════

const (
	maxScanSize        = 4 * 1024 * 1024
	maxFindingsPerRule = 20
	minBase64Len       = 16
	minHexLen          = 16

	// maxDecodeDepth limits recursive ScanContent calls on decoded blobs.
	// Depth 0 = direct call, depth 1 = first decoded pass, depth 2 = final.
	maxDecodeDepth = 2

	// proximityWindow is the byte radius used when deciding whether two
	// findings are "close enough" to be correlated.
	proximityWindow = int64(512)
)

// ═══════════════════════════════════════════════════════════════════════════════
// RULE TYPES
// ═══════════════════════════════════════════════════════════════════════════════

type heuristicRule struct {
	pattern    []byte
	category   types.Category
	severity   types.Severity
	confidence Confidence
	label      string
}

type fragmentRule struct {
	fragments  [][]byte
	category   types.Category
	severity   types.Severity
	confidence Confidence
	label      string
}

// ═══════════════════════════════════════════════════════════════════════════════
// RULE CATALOGUE
// ═══════════════════════════════════════════════════════════════════════════════

var codeExecutionRules = []heuristicRule{
	{[]byte("su -c"), types.CategoryMalware, types.SeverityCritical, ConfidenceHigh, "root command execution"},
	{[]byte("chmod 777"), types.CategoryMalware, types.SeverityHigh, ConfidenceMedium, "world-writable permission"},
	{[]byte("pm install"), types.CategoryMalware, types.SeverityCritical, ConfidenceHigh, "silent APK installation"},
	{[]byte("ProcessBuilder"), types.CategoryMalware, types.SeverityHigh, ConfidenceMedium, "process spawning via ProcessBuilder"},
	{[]byte("PathClassLoader"), types.CategoryMalware, types.SeverityHigh, ConfidenceMedium, "dynamic class loading"},
	{[]byte("DexClassLoader"), types.CategoryMalware, types.SeverityCritical, ConfidenceHigh, "dynamic DEX loading"},
	{[]byte("/system/bin/sh"), types.CategoryMalware, types.SeverityCritical, ConfidenceHigh, "direct shell path"},
	{[]byte("InMemoryDexClassLoader"), types.CategoryMalware, types.SeverityCritical, ConfidenceDefinitive, "in-memory DEX loading"},
	{[]byte("Runtime.getRuntime().exec"), types.CategoryMalware, types.SeverityCritical, ConfidenceHigh, "shell via Runtime.exec"},
}

var codeExecutionFragments = []fragmentRule{
	{
		[][]byte{[]byte("Runtime"), []byte("exec")},
		types.CategoryMalware, types.SeverityCritical, ConfidenceMedium,
		"obfuscated Runtime.exec (fragment)",
	},
	{
		[][]byte{[]byte("DexClass"), []byte("Loader")},
		types.CategoryMalware, types.SeverityHigh, ConfidenceLow,
		"obfuscated DexClassLoader (fragment)",
	},
	{
		[][]byte{[]byte("/system"), []byte("/bin"), []byte("sh")},
		types.CategoryMalware, types.SeverityCritical, ConfidenceMedium,
		"obfuscated shell path (fragment)",
	},
}

var webviewRules = []heuristicRule{
	{[]byte("setJavaScriptEnabled"), types.CategoryVulnerability, types.SeverityMedium, ConfidenceMedium, "JS enabled in WebView"},
	{[]byte("addJavascriptInterface"), types.CategoryVulnerability, types.SeverityHigh, ConfidenceHigh, "WebView JS bridge (RCE risk API<17)"},
	{[]byte("android:usesCleartextTraffic=\"true\""), types.CategoryVulnerability, types.SeverityHigh, ConfidenceDefinitive, "cleartext HTTP permitted"},
}

var cryptoRules = []heuristicRule{
	{[]byte("RC4"), types.CategoryVulnerability, types.SeverityHigh, ConfidenceHigh, "RC4 (broken)"},
	{[]byte("ECB"), types.CategoryVulnerability, types.SeverityHigh, ConfidenceMedium, "ECB block mode (insecure)"},
	{[]byte("DES/"), types.CategoryVulnerability, types.SeverityHigh, ConfidenceHigh, "DES cipher (broken)"},
	{[]byte("MD5"), types.CategoryVulnerability, types.SeverityMedium, ConfidenceMedium, "MD5 (collision-vulnerable)"},
	{[]byte("SHA1"), types.CategoryVulnerability, types.SeverityMedium, ConfidenceMedium, "SHA-1 (deprecated)"},
	{[]byte("TrustAllCerts"), types.CategoryVulnerability, types.SeverityCritical, ConfidenceHigh, "trust-all SSL certs"},
	{[]byte("checkClientTrusted"), types.CategoryVulnerability, types.SeverityMedium, ConfidenceLow, "custom trust manager"},
	{[]byte("SSLCertificateSocketFactory"), types.CategoryVulnerability, types.SeverityHigh, ConfidenceMedium, "custom SSL socket factory"},
	{[]byte("ALLOW_ALL_HOSTNAME_VERIFIER"), types.CategoryVulnerability, types.SeverityCritical, ConfidenceDefinitive, "TLS hostname verification disabled"},
}

var credentialRules = []heuristicRule{
	{[]byte("AKIA"), types.CategoryCredential, types.SeverityCritical, ConfidenceHigh, "AWS access key prefix"},
	{[]byte("secret="), types.CategoryCredential, types.SeverityHigh, ConfidenceMedium, "hardcoded secret field"},
	{[]byte("api_key"), types.CategoryCredential, types.SeverityHigh, ConfidenceLow, "API key reference"},
	{[]byte("password="), types.CategoryCredential, types.SeverityHigh, ConfidenceMedium, "hardcoded password"},
	{[]byte("api_secret"), types.CategoryCredential, types.SeverityHigh, ConfidenceMedium, "API secret reference"},
	{[]byte("Authorization: Bearer"), types.CategoryCredential, types.SeverityCritical, ConfidenceHigh, "hardcoded Bearer token"},
	{[]byte("-----BEGIN PRIVATE KEY-----"), types.CategoryCredential, types.SeverityCritical, ConfidenceDefinitive, "PEM private key"},
	{[]byte("-----BEGIN RSA PRIVATE KEY-----"), types.CategoryCredential, types.SeverityCritical, ConfidenceDefinitive, "RSA private key"},
}

var permissionRules = []heuristicRule{
	{[]byte("android.permission.CAMERA"), types.CategoryPrivacy, types.SeverityMedium, ConfidenceDefinitive, "camera permission"},
	{[]byte("android.permission.READ_SMS"), types.CategoryPrivacy, types.SeverityHigh, ConfidenceDefinitive, "SMS read permission"},
	{[]byte("android.permission.SEND_SMS"), types.CategoryPrivacy, types.SeverityHigh, ConfidenceDefinitive, "SMS send permission"},
	{[]byte("android.permission.RECORD_AUDIO"), types.CategoryPrivacy, types.SeverityHigh, ConfidenceDefinitive, "microphone permission"},
	{[]byte("android.permission.RECEIVE_SMS"), types.CategoryPrivacy, types.SeverityHigh, ConfidenceDefinitive, "SMS receive permission"},
	{[]byte("android.permission.READ_CONTACTS"), types.CategoryPrivacy, types.SeverityMedium, ConfidenceDefinitive, "contacts read permission"},
	{[]byte("android.permission.INSTALL_PACKAGES"), types.CategoryMalware, types.SeverityCritical, ConfidenceDefinitive, "package install permission"},
	{[]byte("android.permission.ACCESS_FINE_LOCATION"), types.CategoryPrivacy, types.SeverityHigh, ConfidenceDefinitive, "precise location permission"},
	{[]byte("android.permission.REQUEST_INSTALL_PACKAGES"), types.CategoryMalware, types.SeverityHigh, ConfidenceDefinitive, "install-request permission"},
}

var rootBypassRules = []heuristicRule{
	{[]byte("isRooted"), types.CategoryRootBypass, types.SeverityMedium, ConfidenceLow, "root detection check"},
	{[]byte("RootBeer"), types.CategoryRootBypass, types.SeverityHigh, ConfidenceMedium, "RootBeer root detection"},
	{[]byte("Superuser.apk"), types.CategoryRootBypass, types.SeverityCritical, ConfidenceHigh, "Superuser APK reference"},
	{[]byte("/data/local/tmp"), types.CategoryRootBypass, types.SeverityHigh, ConfidenceMedium, "writable tmp (rooted path)"},
	{[]byte("com.topjohnwu.magisk"), types.CategoryRootBypass, types.SeverityCritical, ConfidenceHigh, "Magisk root framework"},
}

var networkRules = []heuristicRule{
	{[]byte("/dev/tcp/"), types.CategoryMalware, types.SeverityCritical, ConfidenceHigh, "bash /dev/tcp redirect"},
	{[]byte("reverse_tcp"), types.CategoryMalware, types.SeverityCritical, ConfidenceHigh, "reverse TCP indicator"},
	{[]byte("meterpreter"), types.CategoryMalware, types.SeverityCritical, ConfidenceDefinitive, "Meterpreter reference"},
	{[]byte("metasploit"), types.CategoryMalware, types.SeverityCritical, ConfidenceDefinitive, "Metasploit reference"},
}

var elfSpecificRules = []heuristicRule{
	{[]byte("JNI_OnLoad"), types.CategoryMalware, types.SeverityHigh, ConfidenceMedium, "JNI entry point"},
	{[]byte("dlopen"), types.CategoryMalware, types.SeverityHigh, ConfidenceMedium, "dynamic library loading"},
	{[]byte("execve"), types.CategoryMalware, types.SeverityCritical, ConfidenceHigh, "execve syscall"},
	{[]byte("system("), types.CategoryMalware, types.SeverityCritical, ConfidenceHigh, "system() call"},
	{[]byte("ptrace"), types.CategoryMalware, types.SeverityHigh, ConfidenceMedium, "ptrace (anti-debug or injection)"},
}

var allRuleGroups = [][]heuristicRule{
	credentialRules,
	permissionRules,
	networkRules,
	rootBypassRules,
	codeExecutionRules,
	webviewRules,
	cryptoRules,
}

// ═══════════════════════════════════════════════════════════════════════════════
// FRAGMENT SEARCH — adaptive gap
// ═══════════════════════════════════════════════════════════════════════════════

func adaptiveGap(fragments [][]byte, dataLen int) int {
	total := 0
	for _, f := range fragments {
		total += len(f)
	}
	gap := total * 2
	if gap < 32 {
		gap = 32
	}
	fileFraction := dataLen / 100
	if fileFraction > gap {
		gap = fileFraction
	}
	if gap > 128 {
		gap = 128
	}
	return gap
}

func containsFragments(data []byte, parts [][]byte, maxGap int) (bool, int) {
	pos := 0
	firstAbs := -1
	for _, part := range parts {
		window := data[pos:]
		limit := maxGap + len(part)
		if limit < len(window) {
			window = window[:limit]
		}
		idx := bytes.Index(window, part)
		if idx == -1 {
			return false, -1
		}
		abs := pos + idx
		if firstAbs == -1 {
			firstAbs = abs
		}
		pos = abs + len(part)
	}
	return true, firstAbs
}

// ═══════════════════════════════════════════════════════════════════════════════
// URL VALIDATION — with IP severity boost
// ═══════════════════════════════════════════════════════════════════════════════

var httpPattern = regexp.MustCompile(`https?://[^\s"'<>]{4,}`)

type urlFinding struct {
	raw        string
	isPublicIP bool
}

func extractValidURLs(data []byte) []urlFinding {
	matches := httpPattern.FindAll(data, 256)
	seen := make(map[string]struct{}, len(matches))
	var result []urlFinding

	for _, m := range matches {
		raw := string(m)
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		host := strings.ToLower(u.Hostname())

		if isFilteredHost(host) {
			continue
		}

		if _, dup := seen[raw]; dup {
			continue
		}
		seen[raw] = struct{}{}

		result = append(result, urlFinding{
			raw:        raw,
			isPublicIP: isPublicIPHost(host),
		})
	}
	return result
}

func isFilteredHost(host string) bool {
	switch {
	case host == "localhost",
		host == "127.0.0.1",
		strings.HasSuffix(host, ".example.com"),
		strings.HasSuffix(host, ".example.org"),
		strings.HasSuffix(host, ".test"),
		strings.HasSuffix(host, "schemas.android.com"),
		strings.HasSuffix(host, "schemas.xmlsoap.org"),
		strings.HasSuffix(host, "www.w3.org"),
		strings.HasSuffix(host, "xmlns.jcp.org"):
		return true
	}
	return false
}

func isPublicIPHost(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
	}
	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return false
		}
	}
	return true
}

// ═══════════════════════════════════════════════════════════════════════════════
// BASE64 / HEX DECODER — with depth guard
// ═══════════════════════════════════════════════════════════════════════════════

var base64Candidate = regexp.MustCompile(`[A-Za-z0-9+/]{32,}={0,2}`)
var hexCandidate = regexp.MustCompile(`[0-9a-fA-F]{32,}`)

// blobRunMin mirrors the {32,} quantifier of the two candidate regexps above.
const blobRunMin = 32

// b64ClassTable / hexClassTable are byte-class lookup tables for the candidate
// character classes. Profiling put regexp.FindAll inside extractDecodedBlobs at
// 87.72% cumulative of ScanContent, all of it in the NFA (machine.add 26.85%,
// machine.step 24.55%) — even though both patterns only describe a maximal run
// of one byte class. A single linear pass is exact and allocation-free.
var (
	b64ClassTable [256]bool
	hexClassTable [256]bool
)

func init() {
	for c := 0; c < 256; c++ {
		b := byte(c)
		isDigit := b >= '0' && b <= '9'
		b64ClassTable[c] = (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') ||
			isDigit || b == '+' || b == '/'
		hexClassTable[c] = isDigit || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
	}
}

// scanClassRuns returns up to limit maximal runs of class bytes with length
// >= minRun, in order. With padding, up to two trailing '=' bytes join the run
// and scanning resumes after them — exactly what `{32,}={0,2}` plus FindAll did.
// Runs shorter than minRun are skipped wholesale: no match can start inside
// them, since any such match would be even shorter.
func scanClassRuns(data []byte, class *[256]bool, minRun int, padding bool, limit int) [][]byte {
	var out [][]byte
	for i, n := 0, len(data); i < n && len(out) < limit; {
		if !class[data[i]] {
			i++
			continue
		}
		j := i + 1
		for j < n && class[data[j]] {
			j++
		}
		if j-i >= minRun {
			end := j
			if padding {
				for k := 0; k < 2 && end < n && data[end] == '='; k++ {
					end++
				}
			}
			out = append(out, data[i:end])
			i = end
			continue
		}
		i = j
	}
	return out
}

// hasClassRun reports whether data contains a run of >= minRun class bytes.
// Replaces hexCandidate.Match on an already-extracted candidate.
func hasClassRun(data []byte, class *[256]bool, minRun int) bool {
	run := 0
	for _, b := range data {
		if class[b] {
			run++
			if run >= minRun {
				return true
			}
			continue
		}
		run = 0
	}
	return false
}

func extractDecodedBlobs(data []byte) [][]byte {
	var blobs [][]byte

	for _, match := range scanClassRuns(data, &b64ClassTable, blobRunMin, true, 128) {
		if hasClassRun(match, &hexClassTable, blobRunMin) {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(string(match))
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(string(match))
		}
		if err == nil && len(decoded) >= minBase64Len && isPrintableOrBinary(decoded) {
			blobs = append(blobs, decoded)
		}
	}

	for _, match := range scanClassRuns(data, &hexClassTable, blobRunMin, false, 128) {
		decoded, err := hex.DecodeString(string(match))
		if err == nil && len(decoded) >= minHexLen {
			blobs = append(blobs, decoded)
		}
	}

	return blobs
}

func isPrintableOrBinary(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	if bytes.HasPrefix(data, []byte("dex\n")) ||
		bytes.HasPrefix(data, []byte{0x7f, 'E', 'L', 'F'}) ||
		bytes.HasPrefix(data, []byte("PK\x03\x04")) {
		return true
	}
	printable := 0
	for _, b := range data {
		if b >= 0x20 && b <= 0x7e {
			printable++
		}
	}
	return float64(printable)/float64(len(data)) > 0.7
}

// ═══════════════════════════════════════════════════════════════════════════════
// ENTROPY — refined conditions
// ═══════════════════════════════════════════════════════════════════════════════

func isLikelyEncoded(data []byte) bool {
	if len(data) < 64 {
		return false
	}
	spaces := 0
	for _, b := range data {
		if b == ' ' || b == '\n' || b == '\r' || b == '\t' {
			spaces++
		}
	}
	if float64(spaces)/float64(len(data)) > 0.02 {
		return false
	}
	for _, b := range data {
		isB64 := (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') ||
			(b >= '0' && b <= '9') || b == '+' || b == '/' || b == '=' || b == '-' || b == '_'
		if !isB64 {
			return false
		}
	}
	return true
}

// ═══════════════════════════════════════════════════════════════════════════════
// PRE-FILTER
// ═══════════════════════════════════════════════════════════════════════════════

func prefilterPasses(data []byte, ft types.FileType) bool {
	if ft == types.FileTypeResource {
		return hasSignificantASCII(data)
	}
	return true
}

func hasSignificantASCII(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	limit := len(data)
	if limit > 4096 {
		limit = 4096
	}
	count := 0
	for _, b := range data[:limit] {
		if b >= 0x20 && b <= 0x7e {
			count++
		}
	}
	return float64(count)/float64(limit) > 0.20
}

// ═══════════════════════════════════════════════════════════════════════════════
// SCAN RESULT & DEDUPLICATION
// ═══════════════════════════════════════════════════════════════════════════════

type ScanResult struct {
	File     string
	Findings []Finding
	// Truncated reports that the input exceeded maxScanSize and the tail was
	// never inspected. Without it a caller cannot tell "clean" from "not scanned".
	Truncated    bool
	TotalBytes   int
	ScannedBytes int
}

func deduplicationKey(file string, offset int64, pattern string) string {
	return fmt.Sprintf("%s\x00%d\x00%s", file, offset, pattern)
}

// ═══════════════════════════════════════════════════════════════════════════════
// FILE-LEVEL RISK AGGREGATION
// ═══════════════════════════════════════════════════════════════════════════════

type FileRiskFlags struct {
	HasExec        bool
	HasNetwork     bool
	HasCredentials bool
	HasRootBypass  bool
	HasPrivacy     bool
	HasCrypto      bool
}

type FileRisk struct {
	File         string
	TotalScore   float64
	WorstSev     types.Severity
	FindingCount int
	Flags        FileRiskFlags
}

func AggregateFileRisk(result ScanResult) FileRisk {
	r := FileRisk{File: result.File}

	for _, f := range result.Findings {
		r.TotalScore += f.Score
		r.FindingCount++

		if f.Severity > r.WorstSev {
			r.WorstSev = f.Severity
		}

		switch f.Category {
		case types.CategoryMalware:
			if strings.Contains(f.Pattern, "exec") ||
				strings.Contains(f.Pattern, "shell") ||
				strings.Contains(f.Pattern, "Runtime") ||
				strings.Contains(f.Pattern, "DexClass") ||
				strings.Contains(f.Pattern, "ProcessBuilder") {
				r.Flags.HasExec = true
			}
			if strings.Contains(f.Pattern, "network") ||
				strings.Contains(f.Pattern, "tcp") ||
				strings.Contains(f.Pattern, "meterpreter") ||
				strings.Contains(f.Pattern, "reverse") {
				r.Flags.HasNetwork = true
			}
		case types.CategoryCredential:
			r.Flags.HasCredentials = true
		case types.CategoryRootBypass:
			r.Flags.HasRootBypass = true
		case types.CategoryPrivacy:
			r.Flags.HasPrivacy = true
		case types.CategoryVulnerability:
			if strings.Contains(f.Pattern, "SSL") ||
				strings.Contains(f.Pattern, "TLS") ||
				strings.Contains(f.Pattern, "crypto") ||
				strings.Contains(f.Pattern, "cipher") {
				r.Flags.HasCrypto = true
			}
		}
	}

	if r.TotalScore > 100 {
		r.TotalScore = 100
	}
	return r
}

// ═══════════════════════════════════════════════════════════════════════════════
// PROXIMITY-AWARE CORRELATION
// ═══════════════════════════════════════════════════════════════════════════════

type correlationSignal struct {
	requires []types.Category
	label    string
	bonus    float64
}

var correlationSignals = []correlationSignal{
	{
		[]types.Category{types.CategoryMalware, types.CategoryCredential},
		"malware + embedded credential — likely C2 config", 1.5,
	},
	{
		[]types.Category{types.CategoryMalware, types.CategoryPrivacy, types.CategoryVulnerability},
		"multi-category cluster — spyware profile", 2.0,
	},
	{
		[]types.Category{types.CategoryRootBypass, types.CategoryMalware},
		"root bypass + code execution — privilege escalation", 1.8,
	},
}

func applyCorrelation(findings []Finding) []Finding {
	if len(findings) == 0 {
		return findings
	}

	for _, sig := range correlationSignals {
		reqSet := make(map[types.Category]struct{}, len(sig.requires))
		for _, c := range sig.requires {
			reqSet[c] = struct{}{}
		}

		var candidates []int
		catSeen := make(map[types.Category]struct{}, len(sig.requires))
		for i, f := range findings {
			if _, ok := reqSet[f.Category]; ok {
				candidates = append(candidates, i)
				catSeen[f.Category] = struct{}{}
			}
		}

		if len(catSeen) < len(sig.requires) {
			continue
		}

		hasProximatePair := false
		for i := 0; i < len(candidates) && !hasProximatePair; i++ {
			for j := i + 1; j < len(candidates); j++ {
				a := findings[candidates[i]].Offset
				b := findings[candidates[j]].Offset
				if a < 0 || b < 0 {
					hasProximatePair = true
					break
				}
				diff := a - b
				if diff < 0 {
					diff = -diff
				}
				if diff <= proximityWindow {
					hasProximatePair = true
					break
				}
			}
		}

		if !hasProximatePair {
			continue
		}

		for _, idx := range candidates {
			findings[idx].Score += sig.bonus
			if findings[idx].Score > 10.0 {
				findings[idx].Score = 10.0
			}
			if findings[idx].Score >= 8.0 {
				findings[idx].IsCritical = true
			}
		}
	}

	return findings
}

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN SCANNER
// ═══════════════════════════════════════════════════════════════════════════════

func ScanContent(
	data []byte,
	file string,
	ft types.FileType,
	sourceKind SourceKind,
	depth int,
) ScanResult {
	result := ScanResult{File: file}

	if depth > maxDecodeDepth {
		return result
	}

	if !prefilterPasses(data, ft) {
		return result
	}

	result.TotalBytes = len(data)
	if len(data) > maxScanSize {
		data = data[:maxScanSize]
		result.Truncated = true
	}
	result.ScannedBytes = len(data)

	isBinary := ft == types.FileTypeNative ||
		ft == types.FileTypeCache ||
		ft == types.FileTypeDex

	seen := make(map[string]struct{}, 64)

	addFinding := func(f Finding) {
		key := deduplicationKey(f.File, f.Offset, f.Pattern)
		if _, dup := seen[key]; dup {
			return
		}
		seen[key] = struct{}{}
		result.Findings = append(result.Findings, f)
	}

	// ── Pass 1: direct pattern scan — all occurrences ────────────────────────
	for _, group := range allRuleGroups {
		for _, rule := range group {
			offset := 0
			hitCount := 0
			for hitCount < maxFindingsPerRule {
				idx := bytes.Index(data[offset:], rule.pattern)
				if idx == -1 {
					break
				}
				abs := int64(offset + idx)
				conf := adjustConfidence(rule.confidence, isBinary)
				f := newBinaryFinding(
					rule.category, file, abs,
					sourceKind, rule.label, extractSnippet(data, int(abs), 80),
					rule.severity, conf,
				)
				f.Score += float64(hitCount) * 0.2
				addFinding(f)
				hitCount++
				offset = int(abs) + 1
			}
		}
	}

	// ── Pass 2: fragment / obfuscation scan ──────────────────────────────────
	for _, rule := range codeExecutionFragments {
		ruleGap := adaptiveGap(rule.fragments, len(data))
		if found, abs := containsFragments(data, rule.fragments, ruleGap); found {
			conf := adjustConfidence(rule.confidence, isBinary)
			addFinding(newBinaryFinding(
				rule.category, file, int64(abs),
				sourceKind, rule.label, extractSnippet(data, abs, 80),
				rule.severity, conf,
			))
		}
	}

	// ── Pass 3: decoded blob re-scan (depth-limited) ─────────────────────────
	if depth < maxDecodeDepth {
		for _, blob := range extractDecodedBlobs(data) {
			sub := ScanContent(blob, file+"[decoded]", types.FileTypeText, sourceKind, depth+1)
			for _, f := range sub.Findings {
				f.Confidence -= 0.1
				if f.Confidence < ConfidenceWeak {
					f.Confidence = ConfidenceWeak
				}
				f.Pattern = "[decoded] " + f.Pattern
				addFinding(f)
			}
		}
	}

	// ── Pass 4: URL extraction with IP severity boost ────────────────────────
	for _, uf := range extractValidURLs(data) {
		idx := bytes.Index(data, []byte(uf.raw))
		abs := int64(0)
		if idx >= 0 {
			abs = int64(idx)
		}

		sev := types.SeverityMedium
		conf := ConfidenceLow
		label := "cleartext HTTP endpoint: " + uf.raw

		if uf.isPublicIP {
			sev = types.SeverityHigh
			conf = ConfidenceHigh
			label = "hard-coded public IP endpoint: " + uf.raw
		}
		if isBinary {
			conf = adjustConfidence(conf, true)
		}

		addFinding(newBinaryFinding(
			types.CategoryVulnerability, file, abs,
			sourceKind, label, extractSnippet(data, int(abs), 80),
			sev, conf,
		))
	}

	// ── Pass 5: entropy analysis ─────────────────────────────────────────────
	if !isBinary {
		e := shannonEntropy(data)
		if e > 5.5 && hasAnyUpper(data) && hasAnyDigit(data) && isLikelyEncoded(data) {
			addFinding(newFinding(
				types.CategoryCredential, file, 0, -1,
				sourceKind, types.SeverityMedium, ConfidenceLow,
				"high-entropy encoded content",
				fmt.Sprintf("entropy=%.2f — possible encoded credential or encrypted data", e),
				false,
			))
		}
	}

	// ── Pass 6: ELF-specific rules ───────────────────────────────────────────
	if sourceKind == SourceKindNative {
		for _, rule := range elfSpecificRules {
			offset := 0
			hitCount := 0
			for hitCount < maxFindingsPerRule {
				idx := bytes.Index(data[offset:], rule.pattern)
				if idx == -1 {
					break
				}
				abs := int64(offset + idx)
				conf := adjustConfidence(rule.confidence, true)
				f := newBinaryFinding(
					rule.category, file, abs,
					sourceKind, rule.label, extractSnippet(data, int(abs), 80),
					rule.severity, conf,
				)
				f.Score += float64(hitCount) * 0.1
				addFinding(f)
				hitCount++
				offset = int(abs) + 1
			}
		}
	}

	// ── Pass 7: proximity-aware correlation ──────────────────────────────────
	result.Findings = applyCorrelation(result.Findings)

	return result
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

func adjustConfidence(conf Confidence, isBinary bool) Confidence {
	if !isBinary {
		return conf
	}
	conf -= 0.2
	if conf < ConfidenceWeak {
		return ConfidenceWeak
	}
	return conf
}

func extractSnippet(data []byte, offset, width int) string {
	start := offset - width/2
	if start < 0 {
		start = 0
	}
	end := offset + width/2
	if end > len(data) {
		end = len(data)
	}
	return safeSnippetStr(string(data[start:end]), width)
}

func shannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var freq [256]int
	for _, b := range data {
		freq[b]++
	}
	n := float64(len(data))
	var e float64
	for _, f := range freq {
		if f > 0 {
			p := float64(f) / n
			e -= p * math.Log2(p)
		}
	}
	return e
}

// isPrintableRune reports whether r is a displayable Unicode character.
func isPrintableRune(r rune) bool {
	return unicode.IsPrint(r) && !unicode.IsControl(r)
}
