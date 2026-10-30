package binzap

import (
	"fmt"
	"math"
	"regexp"
	"strings"
	"unicode"

	"mega-analyzer/pkg/binzap/lex"
	"mega-analyzer/pkg/internal/secrets"
)

// knownBenignPrefixes are patterns that are almost certainly not secrets despite
// high Shannon entropy (e.g. data URIs, version strings, UUIDs, package names).
var knownBenignPrefixes = []string{
	"iVBORw0KGgo", // PNG base64 header
	"R0lGOD",      // GIF base64 header
	"UEsDB",       // ZIP base64 header
	"data:image/", // Data URI
	"data:audio/",
	"com.", // Java package names
	"android.",
	"androidx.",
	"java.",
	"javax.",
	"org.",
	"http://",
	"https://",
}

// entropyBenignPattern matches common low-risk high-entropy patterns:
// UUIDs, semantic versions, hex color codes, locale strings, etc.
var entropyBenignPattern = regexp.MustCompile(
	`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$` + // UUID
		`|^[0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?$` + // semver / version
		`|^#[0-9a-fA-F]{3,8}$` + // hex color
		`|^[a-z]{2,8}[-_][A-Z]{2,4}$` + // locale (en_US)
		`|^[0-9a-f]{40}$` + // SHA-1 hex (git commits, certificate fingerprints)
		`|^[0-9a-f]{64}$`, // SHA-256 hex
)

// looksLikeRepeatedPattern returns true when a string is dominated by
// a repeating byte sequence (e.g. "AAAA…" or "ababab…"), which produces
// artificially low entropy but can still pass the >4.8 threshold with noise.
func looksLikeRepeatedPattern(s string) bool {
	if len(s) < 8 {
		return false
	}
	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}
	// If the top character accounts for >50% of the string it is repetitive noise.
	for _, cnt := range freq {
		if float64(cnt)/float64(len(s)) > 0.50 {
			return true
		}
	}
	return false
}

// isPrintableASCIIOnly returns true when all runes in s are printable ASCII.
// High-entropy binary garbage should be skipped as it is not a credential.
func isPrintableASCIIOnly(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII || !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// entropyIsFalsePositive applies a layered allowlist/heuristic check and
// returns true (skip) when the string is almost certainly not a secret.
func entropyIsFalsePositive(val string) bool {
	// Must be pure printable ASCII — binary blobs are not credentials
	if !isPrintableASCIIOnly(val) {
		return true
	}
	// Known-benign prefixes
	for _, pfx := range knownBenignPrefixes {
		if strings.HasPrefix(val, pfx) {
			return true
		}
	}
	// UUID / version / color / locale / hex digest
	if entropyBenignPattern.MatchString(val) {
		return true
	}
	// Repetition noise
	if looksLikeRepeatedPattern(val) {
		return true
	}
	// Must have at least 6 distinct characters to be a plausible secret
	distinct := make(map[rune]struct{})
	for _, c := range val {
		distinct[c] = struct{}{}
	}
	if len(distinct) < 6 {
		return true
	}
	return false
}

// RuleWeakCrypto detects usage of weak hashing algorithms like MD5 or SHA1.
type RuleWeakCrypto struct{}

func (r *RuleWeakCrypto) ID() string         { return "BZ-PASS-001" }
func (r *RuleWeakCrypto) Name() string       { return "Weak Cryptographic Hash Detected" }
func (r *RuleWeakCrypto) Severity() Severity { return SeverityHigh }

func (r *RuleWeakCrypto) Match(ctx ScanContext, tokens []lex.Token) []Finding {
	var findings []Finding

	pattern := lex.Pattern{
		lex.Opcode("const-string"),
		lex.AnyRegister(),
		func(t lex.Token) bool {
			return t.Type == lex.TokenLiteralString &&
				(strings.ToUpper(t.Value) == "MD5" || strings.ToUpper(t.Value) == "SHA-1" || strings.ToUpper(t.Value) == "SHA1")
		},
		lex.Opcode("invoke-static"),
	}

	matchIndices := lex.Match(tokens, pattern)

	for _, idx := range matchIndices {
		hashName := tokens[idx+2].Value
		evidence := fmt.Sprintf("%s %s, \"%s\"", tokens[idx].Value, tokens[idx+1].Value, hashName)

		findings = append(findings, Finding{
			RuleID:     r.ID(),
			Severity:   r.Severity(),
			Message:    fmt.Sprintf("Insecure cryptographic hash algorithm detected: %s", hashName),
			File:       ctx.File,
			Line:       tokens[idx].Line,
			Evidence:   evidence,
			Confidence: ConfidenceHigh,
		})
	}

	return findings
}

// RuleAntiAnalysis detects common anti-analysis or root-detection strings.
type RuleAntiAnalysis struct{}

func (r *RuleAntiAnalysis) ID() string         { return "BZ-PASS-002" }
func (r *RuleAntiAnalysis) Name() string       { return "Anti-Analysis / Root Detection String" }
func (r *RuleAntiAnalysis) Severity() Severity { return SeverityMedium }

func (r *RuleAntiAnalysis) Match(ctx ScanContext, tokens []lex.Token) []Finding {
	var findings []Finding
	suspiciousStrings := []string{"su", "magisk", "frida", "xposed", "edxposed", "lsposed"}

	pattern := lex.Pattern{
		lex.Opcode("const-string"),
		lex.AnyRegister(),
		func(t lex.Token) bool {
			if t.Type != lex.TokenLiteralString {
				return false
			}
			val := strings.ToLower(t.Value)
			for _, sus := range suspiciousStrings {
				if val == sus || strings.Contains(val, sus) {
					return true
				}
			}
			return false
		},
	}

	matchIndices := lex.Match(tokens, pattern)

	for _, idx := range matchIndices {
		susString := tokens[idx+2].Value
		evidence := fmt.Sprintf("%s %s, \"%s\"", tokens[idx].Value, tokens[idx+1].Value, susString)
		findings = append(findings, Finding{
			RuleID:     r.ID(),
			Severity:   r.Severity(),
			Message:    fmt.Sprintf("Suspicious anti-analysis string found: %s", susString),
			File:       ctx.File,
			Line:       tokens[idx].Line,
			Evidence:   evidence,
			Confidence: ConfidenceMedium,
		})
	}

	return findings
}

// RuleSuspiciousExecution detects command execution or dynamic code loading.
type RuleSuspiciousExecution struct{}

func (r *RuleSuspiciousExecution) ID() string         { return "BZ-PASS-003" }
func (r *RuleSuspiciousExecution) Name() string       { return "Suspicious Code Execution / Dynamic Loading" }
func (r *RuleSuspiciousExecution) Severity() Severity { return SeverityCritical }

func (r *RuleSuspiciousExecution) Match(ctx ScanContext, tokens []lex.Token) []Finding {
	var findings []Finding

	// Look for Runtime.exec() or System.loadLibrary() or DexClassLoader
	pattern := lex.Pattern{
		func(t lex.Token) bool {
			return t.Type == lex.TokenMethodRef && (strings.Contains(t.Value, "Ljava/lang/Runtime;->exec") ||
				strings.Contains(t.Value, "Ljava/lang/System;->loadLibrary") ||
				strings.Contains(t.Value, "Ldalvik/system/DexClassLoader;-><init>"))
		},
	}

	matchIndices := lex.Match(tokens, pattern)

	for _, idx := range matchIndices {
		methodRef := tokens[idx].Value
		findings = append(findings, Finding{
			RuleID:     r.ID(),
			Severity:   r.Severity(),
			Message:    "Dynamic code execution or library loading detected",
			File:       ctx.File,
			Line:       tokens[idx].Line,
			Evidence:   methodRef,
			Confidence: ConfidenceHigh,
		})
	}

	return findings
}

// RuleHighEntropy detects potential hardcoded secrets (API keys, tokens) using Shannon Entropy.
type RuleHighEntropy struct{}

func (r *RuleHighEntropy) ID() string         { return "BZ-PASS-004" }
func (r *RuleHighEntropy) Name() string       { return "High Entropy String (Potential Secret)" }
func (r *RuleHighEntropy) Severity() Severity { return SeverityHigh }

func (r *RuleHighEntropy) Match(ctx ScanContext, tokens []lex.Token) []Finding {
	var findings []Finding

	for _, t := range tokens {
		if t.Type == lex.TokenLiteralString {
			for _, sf := range secrets.DetectProviders(t.Value, ctx.File) {
				findings = append(findings, Finding{
					RuleID:     sf.RuleID,
					Severity:   severityFromProvider(sf.Severity),
					Message:    fmt.Sprintf("Provider credential detected: %s", sf.Name),
					File:       ctx.File,
					Line:       t.Line,
					Evidence:   fmt.Sprintf("%s", sf.MaskedValue),
					Confidence: ConfidenceHigh,
				})
			}

			// Entropy-only detection: skip very short strings and apply FP filter
			if len(t.Value) < 20 {
				continue
			}

			// Skip strings that are known-benign despite high entropy
			if entropyIsFalsePositive(t.Value) {
				continue
			}

			entropy := calculateEntropy(t.Value)
			// Raised threshold from 4.8 → 5.0 to reduce noise on base64 URLs etc.
			// Additionally require at least 32 chars for the entropy-only rule
			// (provider rules above already handle shorter provider-specific tokens).
			if entropy > 5.0 && len(t.Value) >= 32 {
				findings = append(findings, Finding{
					RuleID:     r.ID(),
					Severity:   r.Severity(),
					Message:    fmt.Sprintf("High entropy string (%.2f bits/char, len=%d) — probable hardcoded secret or key material", entropy, len(t.Value)),
					File:       ctx.File,
					Line:       t.Line,
					Evidence:   fmt.Sprintf("\"%s\"", t.Value),
					Confidence: ConfidenceLow,
				})
			}
		}
	}

	return findings
}

func severityFromProvider(sev string) Severity {
	switch strings.ToLower(sev) {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium":
		return SeverityMedium
	default:
		return SeverityLow
	}
}

// calculateEntropy calculates the Shannon entropy of a string.
func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	frequencies := make(map[rune]float64)
	for _, char := range s {
		frequencies[char]++
	}

	entropy := 0.0
	length := float64(len(s))
	for _, count := range frequencies {
		p := count / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// RuleUnsafeReflection detects dangerous use of Java/Dalvik Reflection to bypass access controls.
type RuleUnsafeReflection struct{}

func (r *RuleUnsafeReflection) ID() string         { return "BZ-PASS-005" }
func (r *RuleUnsafeReflection) Name() string       { return "Unsafe Reflection Usage" }
func (r *RuleUnsafeReflection) Severity() Severity { return SeverityHigh }

func (r *RuleUnsafeReflection) Match(ctx ScanContext, tokens []lex.Token) []Finding {
	var findings []Finding
	// Detect forName + getDeclaredMethod/Field + setAccessible(true) patterns
	// which are used to bypass access modifiers and call hidden APIs.
	dangerousReflectionMethods := []string{
		"Ljava/lang/Class;->forName",
		"Ljava/lang/Class;->getDeclaredMethod",
		"Ljava/lang/Class;->getDeclaredField",
		"Ljava/lang/reflect/Method;->setAccessible",
		"Ljava/lang/reflect/Field;->setAccessible",
		"Ljava/lang/reflect/Constructor;->setAccessible",
	}
	for _, t := range tokens {
		if t.Type != lex.TokenMethodRef {
			continue
		}
		for _, dangerous := range dangerousReflectionMethods {
			if strings.Contains(t.Value, dangerous) {
				findings = append(findings, Finding{
					RuleID:     r.ID(),
					Severity:   r.Severity(),
					Message:    fmt.Sprintf("Unsafe reflection detected: %s — can bypass access controls and invoke hidden APIs", dangerous),
					File:       ctx.File,
					Line:       t.Line,
					Evidence:   t.Value,
					Confidence: ConfidenceHigh,
				})
				break
			}
		}
	}
	return findings
}

// RuleInsecureDeserialization detects use of ObjectInputStream or Parcel.readValue
// which are common vectors for deserialization attacks in Android.
type RuleInsecureDeserialization struct{}

func (r *RuleInsecureDeserialization) ID() string         { return "BZ-PASS-006" }
func (r *RuleInsecureDeserialization) Name() string       { return "Insecure Deserialization" }
func (r *RuleInsecureDeserialization) Severity() Severity { return SeverityCritical }

func (r *RuleInsecureDeserialization) Match(ctx ScanContext, tokens []lex.Token) []Finding {
	var findings []Finding
	sinks := []string{
		"Ljava/io/ObjectInputStream;->readObject",
		"Ljava/io/ObjectInputStream;->readUnshared",
		"Landroid/os/Parcel;->readValue",
		"Landroid/os/Parcel;->readSerializable",
		"Lcom/google/gson/Gson;->fromJson",
	}
	for _, t := range tokens {
		if t.Type != lex.TokenMethodRef {
			continue
		}
		for _, sink := range sinks {
			if strings.Contains(t.Value, sink) {
				findings = append(findings, Finding{
					RuleID:     r.ID(),
					Severity:   r.Severity(),
					Message:    fmt.Sprintf("Insecure deserialization sink: %s — attacker-controlled data may lead to RCE", sink),
					File:       ctx.File,
					Line:       t.Line,
					Evidence:   t.Value,
					Confidence: ConfidenceMedium,
				})
				break
			}
		}
	}
	return findings
}

// RulePathTraversal detects path construction from user-controlled strings that may allow
// directory traversal attacks (e.g. getFilesDir + user input).
type RulePathTraversal struct{}

func (r *RulePathTraversal) ID() string         { return "BZ-PASS-007" }
func (r *RulePathTraversal) Name() string       { return "Potential Path Traversal" }
func (r *RulePathTraversal) Severity() Severity { return SeverityHigh }

func (r *RulePathTraversal) Match(ctx ScanContext, tokens []lex.Token) []Finding {
	var findings []Finding
	// Look for known path literals containing ".." traversal sequences
	pattern := lex.Pattern{
		lex.Opcode("const-string"),
		lex.AnyRegister(),
		func(t lex.Token) bool {
			if t.Type != lex.TokenLiteralString {
				return false
			}
			return strings.Contains(t.Value, "../") || strings.Contains(t.Value, "..\\") ||
				strings.HasPrefix(t.Value, "/proc/") || strings.HasPrefix(t.Value, "/sys/")
		},
	}
	matchIndices := lex.Match(tokens, pattern)
	for _, idx := range matchIndices {
		val := tokens[idx+2].Value
		findings = append(findings, Finding{
			RuleID:     r.ID(),
			Severity:   r.Severity(),
			Message:    fmt.Sprintf("Hardcoded traversal or sensitive path: \"%s\"", val),
			File:       ctx.File,
			Line:       tokens[idx].Line,
			Evidence:   fmt.Sprintf("%s %s, \"%s\"", tokens[idx].Value, tokens[idx+1].Value, val),
			Confidence: ConfidenceMedium,
		})
	}
	return findings
}

// RuleClipboardDataTheft detects reads from the Android Clipboard which may capture
// sensitive user data (passwords, OTPs, crypto keys) without consent.
type RuleClipboardDataTheft struct{}

func (r *RuleClipboardDataTheft) ID() string         { return "BZ-PASS-008" }
func (r *RuleClipboardDataTheft) Name() string       { return "Clipboard Data Access (Privacy Risk)" }
func (r *RuleClipboardDataTheft) Severity() Severity { return SeverityMedium }

func (r *RuleClipboardDataTheft) Match(ctx ScanContext, tokens []lex.Token) []Finding {
	var findings []Finding
	clipboardSinks := []string{
		"Landroid/content/ClipboardManager;->getPrimaryClip",
		"Landroid/content/ClipboardManager;->getText",
		"Landroid/content/ClipData;->getItemAt",
	}
	for _, t := range tokens {
		if t.Type != lex.TokenMethodRef {
			continue
		}
		for _, sink := range clipboardSinks {
			if strings.Contains(t.Value, sink) {
				findings = append(findings, Finding{
					RuleID:     r.ID(),
					Severity:   r.Severity(),
					Message:    "Clipboard read detected — may capture passwords or OTPs without user consent",
					File:       ctx.File,
					Line:       t.Line,
					Evidence:   t.Value,
					Confidence: ConfidenceMedium,
				})
				break
			}
		}
	}
	return findings
}

// RuleDebugBackdoor detects remnant debug APIs, hidden backdoor endpoints,
// and BuildConfig.DEBUG checks that alter security-critical behavior.
type RuleDebugBackdoor struct{}

func (r *RuleDebugBackdoor) ID() string         { return "BZ-PASS-009" }
func (r *RuleDebugBackdoor) Name() string       { return "Debug Backdoor / Development Artifact" }
func (r *RuleDebugBackdoor) Severity() Severity { return SeverityHigh }

func (r *RuleDebugBackdoor) Match(ctx ScanContext, tokens []lex.Token) []Finding {
	var findings []Finding
	debugStrings := []string{
		"debug_mode", "debug_key", "backdoor", "master_key", "skeleton_key",
		"admin_override", "bypass_auth", "disable_ssl", "no_ssl", "dev_mode",
		"testing_mode", "test_key", "allow_all_hosts", "ALLOW_ALL",
	}
	pattern := lex.Pattern{
		lex.Opcode("const-string"),
		lex.AnyRegister(),
		func(t lex.Token) bool {
			if t.Type != lex.TokenLiteralString {
				return false
			}
			val := strings.ToLower(t.Value)
			for _, ds := range debugStrings {
				if strings.Contains(val, ds) {
					return true
				}
			}
			return false
		},
	}
	matchIndices := lex.Match(tokens, pattern)
	for _, idx := range matchIndices {
		val := tokens[idx+2].Value
		findings = append(findings, Finding{
			RuleID:     r.ID(),
			Severity:   r.Severity(),
			Message:    fmt.Sprintf("Debug/backdoor artifact found: \"%s\" — must not be present in release builds", val),
			File:       ctx.File,
			Line:       tokens[idx].Line,
			Evidence:   fmt.Sprintf("%s %s, \"%s\"", tokens[idx].Value, tokens[idx+1].Value, val),
			Confidence: ConfidenceHigh,
		})
	}

	// Also detect android.util.Log calls which may leak sensitive data in release
	logPattern := lex.Pattern{
		func(t lex.Token) bool {
			return t.Type == lex.TokenMethodRef &&
				(strings.Contains(t.Value, "Landroid/util/Log;->d") ||
					strings.Contains(t.Value, "Landroid/util/Log;->v") ||
					strings.Contains(t.Value, "Landroid/util/Log;->i"))
		},
	}
	logMatches := lex.Match(tokens, logPattern)
	for _, idx := range logMatches {
		findings = append(findings, Finding{
			RuleID:     r.ID(),
			Severity:   SeverityLow,
			Message:    "Verbose/Debug logging in release build may expose sensitive data to logcat",
			File:       ctx.File,
			Line:       tokens[idx].Line,
			Evidence:   tokens[idx].Value,
			Confidence: ConfidenceLow,
		})
	}
	return findings
}

// RuleHardcodedURL detects hardcoded internal/staging/production URLs and IP addresses
// that may expose infrastructure topology or allow SSRF-like pivoting.
type RuleHardcodedURL struct{}

func (r *RuleHardcodedURL) ID() string         { return "BZ-PASS-010" }
func (r *RuleHardcodedURL) Name() string       { return "Hardcoded Internal URL / IP Address" }
func (r *RuleHardcodedURL) Severity() Severity { return SeverityMedium }

func (r *RuleHardcodedURL) Match(ctx ScanContext, tokens []lex.Token) []Finding {
	var findings []Finding
	for _, t := range tokens {
		if t.Type != lex.TokenLiteralString {
			continue
		}
		v := t.Value
		isInternalIP := (strings.HasPrefix(v, "10.") ||
			strings.HasPrefix(v, "192.168.") ||
			strings.HasPrefix(v, "172.16.") ||
			strings.HasPrefix(v, "172.17.") ||
			strings.HasPrefix(v, "172.18.") ||
			strings.HasPrefix(v, "172.30.") ||
			strings.HasPrefix(v, "172.31.") ||
			strings.HasPrefix(v, "127.0.")) && len(v) > 6
		isStagingURL := strings.Contains(v, "://") && len(v) > 10 &&
			(strings.Contains(v, "staging") ||
				strings.Contains(v, "internal") ||
				strings.Contains(v, "dev.") ||
				strings.Contains(v, "localhost") ||
				strings.Contains(v, "0.0.0.0"))
		if isInternalIP || isStagingURL {
			findings = append(findings, Finding{
				RuleID:     r.ID(),
				Severity:   r.Severity(),
				Message:    fmt.Sprintf("Hardcoded internal/staging URL or IP: \"%s\" — leaks infrastructure topology", v),
				File:       ctx.File,
				Line:       t.Line,
				Evidence:   fmt.Sprintf("\"%s\"", v),
				Confidence: ConfidenceMedium,
			})
		}
	}
	return findings
}

// Registry of all active rules
var PassiveRules = []Rule{
	&RuleWeakCrypto{},
	&RuleAntiAnalysis{},
	&RuleSuspiciousExecution{},
	&RuleHighEntropy{},
	&RuleUnsafeReflection{},
	&RuleInsecureDeserialization{},
	&RulePathTraversal{},
	&RuleClipboardDataTheft{},
	&RuleDebugBackdoor{},
	&RuleHardcodedURL{},
}

// RunPassiveScanner executes all rules on the token stream
func RunPassiveScanner(ctx ScanContext, tokens []lex.Token) []Finding {
	var allFindings []Finding
	// Run hardcoded passive rules
	for _, rule := range PassiveRules {
		findings := rule.Match(ctx, tokens)
		allFindings = append(allFindings, findings...)
	}
	// Run dynamically registered rules
	for _, rule := range GetDynamicBinzapRules() {
		findings := rule.Match(ctx, tokens)
		allFindings = append(allFindings, findings...)
	}
	return allFindings
}
