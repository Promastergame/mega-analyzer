package apkloader

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	"mega-analyzer/pkg/internal/deobfuscation"
	"mega-analyzer/pkg/internal/secrets"
	"mega-analyzer/pkg/internal/types"
)

// Magic bytes for Hermes Bytecode: uint64 MAGIC = 0x1F1903C103BC1FC6
// ("Hermes" in ancient Greek, UTF-16BE, truncated to 8 bytes).
// LE form is what v98+ bundles (e.g. index.android.bundle) start with:
// c6 1f bc 03 c1 03 19 1f.
var HermesMagicLE = []byte{0xC6, 0x1F, 0xBC, 0x03, 0xC1, 0x03, 0x19, 0x1F}
var HermesMagicBE = []byte{0x1F, 0x19, 0x03, 0xC1, 0x03, 0xBC, 0x1F, 0xC6}

// IsHermesBytecode recognizes either byte order before parsing or editing a
// bundle. Even a malformed HBC header must never enter a text-patching path.
func IsHermesBytecode(data []byte) bool {
	return len(data) >= 8 && (bytes.Equal(data[:8], HermesMagicLE) || bytes.Equal(data[:8], HermesMagicBE) || isHermesDelta(data))
}

// Delta-prepared HBC must also stay out of the text-rewriting path.
func isHermesDelta(data []byte) bool {
	if len(data) < 8 {
		return false
	}
	le, be := true, true
	for i := 0; i < 8; i++ {
		le = le && data[i] == ^HermesMagicLE[i]
		be = be && data[i] == ^HermesMagicBE[i]
	}
	return le || be
}

// hotUpdaterMagic marks HotUpdater OTA chunks shipped as extensionless
// assets/* files (e.g. assets/0pG73O0oLIbWPR0M): 00 49 41 50 02 ("\x00IAP\x02").
var hotUpdaterMagic = []byte{0x00, 0x49, 0x41, 0x50, 0x02}

// unitySignatures are the container magics used by Unity AssetBundles. Unity
// games (e.g. Subway Surfers) ship hundreds of *.bundle asset containers that
// are game DATA, not React Native code. They must not be mislabeled as JS.
var unitySignatures = [][]byte{
	[]byte("UnityFS"),
	[]byte("UnityRaw"),
	[]byte("UnityWeb"),
	[]byte("UnityArchive"),
}

// bundleKind classifies a *.bundle file by its actual content, not extension.
type bundleKind int

const (
	bundleUnknown bundleKind = iota
	bundleHermes
	bundleUnity
	bundleJS
)

// ScanHermes is the compatibility wrapper for the detailed, cancellable scan.
func ScanHermes(appDir string) ([]types.ArtifactFinding, error) {
	result, err := ScanHermesContext(context.Background(), appDir)
	return result.Findings, err
}

// classifyBundle inspects the raw bytes of a *.bundle file and decides what it
// actually is. This drives both correct labeling and how much work we do.
func classifyBundle(data []byte) bundleKind {
	if IsHermesBytecode(data) {
		return bundleHermes
	}
	for _, sig := range unitySignatures {
		if bytes.HasPrefix(data, sig) {
			return bundleUnity
		}
	}
	if looksLikeJS(data[:mapClamp(len(data), 4096)]) {
		return bundleJS
	}
	return bundleUnknown
}

// looksLikeJS reports whether a probe of the file head is predominantly text
// and contains recognizable JavaScript / React Native tokens.
func looksLikeJS(probe []byte) bool {
	if len(probe) == 0 {
		return false
	}
	printable := 0
	for _, b := range probe {
		if b == '\n' || b == '\t' || b == '\r' || (b >= 0x20 && b < 0x7f) {
			printable++
		}
	}
	if printable*100/len(probe) < 85 {
		return false
	}
	s := string(probe)
	for _, tok := range []string{
		"__d(", "__BUNDLE_START_TIME__", "require(", "module.exports",
		"function", "React", "var ", "const ", "let ", "=>",
	} {
		if strings.Contains(s, tok) {
			return true
		}
	}
	return false
}

func scanBundleFile(path, baseDir string) ([]types.ArtifactFinding, error) {
	coverage := BundleFileAnalysis{Path: path, Status: "complete"}
	findings, err := scanBundleFileContext(context.Background(), path, baseDir, &coverage)
	if coverage.Status != "complete" {
		findings = append(findings, bundleCoverageFinding(coverage))
	}
	return findings, err
}

func scanBundleFileContext(ctx context.Context, path, baseDir string, coverage *BundleFileAnalysis) ([]types.ArtifactFinding, error) {
	var findings []types.ArtifactFinding
	data, err := ReadBundleFile(ctx, path)
	if err != nil {
		coverage.Status = "failed"
		coverage.Diagnostics = append(coverage.Diagnostics, err.Error())
		return nil, err
	}
	coverage.TotalBytes, coverage.ScannedBytes = int64(len(data)), int64(len(data))

	relPath, _ := filepath.Rel(baseDir, path)
	if relPath == "" {
		relPath = path
	}
	coverage.Path = relPath

	// Classify by CONTENT, not by the .bundle extension. We deliberately emit
	// NO per-file "detected" banner anymore: only the real findings below
	// (endpoints, secrets, bridges) are reported. Classification is used only
	// to label those real findings and to skip pointless work (JS
	// deobfuscation on binary game assets / bytecode).
	var findingType string
	var extracted []string
	structured := false
	switch classifyBundle(data) {
	case bundleHermes:
		findingType = "Hermes Bytecode Bundle"
		coverage.Kind, coverage.Mode, coverage.Version = "hermes_bytecode", "string_table", HermesBytecodeVersion(data)
		hbc, parseErr := ParseHermesBytecode(data)
		if parseErr == nil {
			structured = true
			coverage.Status = hbc.AnalysisStatus
			coverage.Diagnostics = append(coverage.Diagnostics, hbc.Diagnostics...)
			coverage.TotalStrings, coverage.ScannedStrings = int(hbc.Header.StringCount), len(hbc.Strings)
			extracted = hbc.StringValues()
			for _, module := range hbc.Modules {
				if module.Name != "" {
					extracted = append(extracted, module.Name)
				}
			}
		} else {
			coverage.Status, coverage.Mode = "failed", "printable_strings"
			if errors.Is(parseErr, ErrUnsupportedHermes) {
				coverage.Status = "unsupported"
			}
			coverage.Diagnostics = append(coverage.Diagnostics, parseErr.Error(), "Only printable-string fallback was available; structured HBC coverage is incomplete")
		}
	case bundleUnity:
		findingType = "Unity AssetBundle"
		coverage.Kind, coverage.Mode = "unity_assetbundle", "printable_strings"
	case bundleJS:
		findingType = "React Native JS Bundle"
		coverage.Kind, coverage.Mode = "javascript", "decoded_literals"
		engine := deobfuscation.NewJSDeobfuscator(deobfuscation.ScanJSOptions())
		data = []byte(engine.Deobfuscate(string(data)))
	default:
		findingType = "Binary Bundle"
		coverage.Kind, coverage.Mode, coverage.Status = "unknown_binary", "printable_strings", "unsupported"
		coverage.Diagnostics = append(coverage.Diagnostics, "Unknown bundle format; only printable strings were scanned")
	}
	if !structured {
		extracted = extractPrintableStrings(data, 4)
	}
	if coverage.Mode == "printable_strings" && coverage.Kind == "hermes_bytecode" && coverage.Status == "failed" && len(extracted) > 0 {
		coverage.Status = "partial"
	}

	// Keep track of what we find to avoid duplicates
	seenFindings := make(map[string]bool)
	addUniqueFinding := func(finding types.ArtifactFinding) {
		key := string(finding.Severity) + "|" + finding.Reason + "|" + finding.Payload
		if !seenFindings[key] {
			seenFindings[key] = true
			findings = append(findings, finding)
		}
	}

	// Run scans on extracted strings
	endpointRegex := regexp.MustCompile(`(?i)\b(?:https?|wss?)://[a-z0-9._~-]+(?::[0-9]{1,5})?(?:/[a-z0-9._~!$&'()*+,;=:@%/?#-]*)?`)
	graphqlRegex := regexp.MustCompile(`(?i)(?:\bgraphql\b|/(?:api/)?graphql(?:/|\b))`)
	// Google's client API keys are designed to be embedded, so we keep a direct
	// shape match for them (high recall). All OTHER credential providers go
	// through the entropy-gated provider detector below, which replaces the old
	// noisy `aws[_-]?key` / `api[_-]?key` keyword regexes that fired on any
	// variable name.
	googleKeyRegex := regexp.MustCompile(`AIzaSy[a-zA-Z0-9-_]{33}`)

	for i, rawStr := range extracted {
		if i%1024 == 0 {
			if err := ctx.Err(); err != nil {
				coverage.Status = "partial"
				coverage.Diagnostics = append(coverage.Diagnostics, err.Error())
				return findings, err
			}
		}
		s := strings.Trim(rawStr, "\"'`()[]{},; ")

		// 1. Scan for HTTP/WebSocket endpoints anywhere inside the structured
		// string. HBC strings often contain a JSON fragment around the URL.
		for _, endpoint := range endpointRegex.FindAllString(s, -1) {
			reason := fmt.Sprintf("[%s] URL reference (runtime use unverified): %s", findingType, endpoint)
			stages := []string{"hermes", "endpoint", "inventory"}
			if bundleDocumentationURL(endpoint) {
				stages = append(stages, "documentation")
			}
			if strings.HasPrefix(strings.ToLower(endpoint), "ws") {
				reason = fmt.Sprintf("[%s] WebSocket URL reference (runtime use unverified): %s", findingType, endpoint)
				stages = append(stages, "websocket")
			}
			addUniqueFinding(types.ArtifactFinding{
				Path:     relPath,
				Severity: types.SeverityInfo,
				Reason:   reason,
				Payload:  endpoint,
				Stages:   stages,
			})
			if graphqlRegex.MatchString(endpoint) {
				addUniqueFinding(types.ArtifactFinding{
					Path:     relPath,
					Severity: types.SeverityInfo,
					Reason:   fmt.Sprintf("[%s] GraphQL URL reference (runtime use unverified): %s", findingType, endpoint),
					Payload:  endpoint,
					Stages:   []string{"hermes", "endpoint", "graphql", "inventory"},
				})
			}
		}
		if graphqlRegex.MatchString(s) && !endpointRegex.MatchString(s) {
			addUniqueFinding(types.ArtifactFinding{
				Path:     relPath,
				Severity: types.SeverityInfo,
				Reason:   fmt.Sprintf("[%s] GraphQL operation or relative endpoint found", findingType),
				Payload:  s,
				Stages:   []string{"hermes", "graphql", "inventory"},
			})
		}

		// 2. Google API key (shape match, embedded-by-design).
		if googleKeyRegex.MatchString(s) {
			addUniqueFinding(types.ArtifactFinding{
				Path:     relPath,
				Severity: types.SeverityHigh,
				Reason:   fmt.Sprintf("[%s] Hardcoded Secret found (Google API Key): %s", findingType, s),
				Payload:  s,
				Stages:   []string{"hermes", "secret"},
			})
		}

		// 3. Scan for React Native modules & Java bridges
		if containsAny(s, "NativeModules", "com.facebook.react", "__fbBatchedBridge", "registerCallableModule", "TurboModuleRegistry", "getEnforcing") {
			addUniqueFinding(types.ArtifactFinding{
				Path:     relPath,
				Severity: types.SeverityInfo,
				Reason:   fmt.Sprintf("[%s] React Native bridge reference (runtime use unverified)", findingType),
				Payload:  s,
				Stages:   []string{"hermes", "bridge", "inventory"},
			})
		}
	}

	// 4. High-precision provider-aware secret scan over the whole extracted
	// corpus (GitHub/Slack/Stripe/Telegram/AWS-AKIA/JWT/private keys, ...). This
	// uses Shannon-entropy + charset gating and masks the value in the report,
	// so it does not re-introduce the keyword false positives we removed above.
	corpus := strings.Join(extracted, "\n")
	for _, sf := range secrets.DetectProviders(corpus, relPath) {
		if sf.Provider == "google" {
			continue // already covered by the direct shape match above
		}
		addUniqueFinding(types.ArtifactFinding{
			Path:     relPath,
			Severity: hermesSeverity(sf.Severity),
			Reason:   fmt.Sprintf("[%s] Hardcoded Secret found (%s): %s", findingType, sf.Name, sf.MaskedValue),
			Payload:  sf.MaskedValue,
			Stages:   []string{"hermes", "secret"},
		})
	}

	// 5. Structured semantic detectors over the clean HBC string table:
	// deep-link scheme usage, age-verification flow, OTA update channel,
	// and realtime voice (LiveKit). These replace manual grepping of the
	// bundle for the same indicators.
	for _, f := range scanHermesSemantics(extracted, relPath, findingType) {
		addUniqueFinding(f)
	}

	return findings, nil
}

// hermesSemanticRule is one substring-set detector over HBC strings.
type hermesSemanticRule struct {
	contains []string
	reason   string
	severity types.Severity
	stages   []string
}

// scanHermesSemantics runs cheap substring detectors over extracted bundle
// strings. Each rule fires once per distinct matching string value.
func scanHermesSemantics(extracted []string, relPath, findingType string) []types.ArtifactFinding {
	rules := []hermesSemanticRule{
		{
			contains: []string{"character://"},
			reason:   fmt.Sprintf("[%s] Custom deep-link scheme usage: character://", findingType),
			severity: types.SeverityInfo,
			stages:   []string{"hermes", "deeplink"},
		},
		{
			contains: []string{"amp-"},
			reason:   fmt.Sprintf("[%s] Amplitude engagement deep-link scheme usage (amp-*)", findingType),
			severity: types.SeverityInfo,
			stages:   []string{"hermes", "deeplink"},
		},
		{
			contains: []string{"share.character.ai", "links.chat.character.ai", "links.email.character.ai", "links.account.character.ai", "characterai.onelink.me", "fetchOneLinkDetails", "processAppsflyerDeeplink", "isAppsflyerLink"},
			reason:   fmt.Sprintf("[%s] Share/OneLink deep-link handling (share.character.ai / AppsFlyer OneLink)", findingType),
			severity: types.SeverityInfo,
			stages:   []string{"hermes", "deeplink"},
		},
		{
			contains: []string{"/chat/user/get-user-birthday-status/", "/chat/user/update-user-birthday/", "updateUserBirthday", "fetchBirthdayStatus", "date_of_birth"},
			reason:   fmt.Sprintf("[%s] Age-gate: self-reported birthday API (get/update-user-birthday)", findingType),
			severity: types.SeverityInfo,
			stages:   []string{"hermes", "age-verification"},
		},
		{
			contains: []string{"withpersona.com/verify", "getAgeVerificationLink", "getAgeVerificationStatus", "startAgeVerification", "AgeVerificationFlow"},
			reason:   fmt.Sprintf("[%s] Age-verification: Persona IDV flow (getAgeVerificationLink/Status)", findingType),
			severity: types.SeverityInfo,
			stages:   []string{"hermes", "age-verification"},
		},
		{
			contains: []string{"SkipAgeVerificationSheet", "acknowledgeAgeVerification", "ageVerificationGracePeriodExpiry", "gracePeriodExpiresDate", "/external/user/age-update/acknowledge", "U18Countdown", "useIsUserAnAdult", "isAgeCategoryAnAdult"},
			reason:   fmt.Sprintf("[%s] Age-verification: grace/skip/acknowledge + client-side adult gating", findingType),
			severity: types.SeverityInfo,
			stages:   []string{"hermes", "age-verification"},
		},
		{
			contains: []string{"/moderation/v1/parental/", "/moderation/v1/kid/"},
			reason:   fmt.Sprintf("[%s] Parental-controls API (moderation/v1/parental|kid)", findingType),
			severity: types.SeverityInfo,
			stages:   []string{"hermes", "age-verification"},
		},
		{
			contains: []string{"updater.character.ai/api/check-update", "hot-updater-disabled.invalid", "HotUpdaterGetBaseURL", "hot-update config from statsig", "ota_updates", "mobile_codepush_internal"},
			reason:   fmt.Sprintf("[%s] OTA update channel (HotUpdater + updater.character.ai, Statsig-gated)", findingType),
			severity: types.SeverityInfo,
			stages:   []string{"hermes", "ota"},
		},
		{
			contains: []string{".livekit.cloud", "livekit", "LIVEKIT_URL"},
			reason:   fmt.Sprintf("[%s] Realtime voice: LiveKit (wss *.livekit.cloud)", findingType),
			severity: types.SeverityInfo,
			stages:   []string{"hermes", "webrtc"},
		},
		{
			contains: []string{"neo-prod.characterai.dev", "neo-stage.characterai.dev", "neo.character.ai", "auth.character.ai"},
			reason:   fmt.Sprintf("[%s] Backend API surface (neo.*/auth.character.ai)", findingType),
			severity: types.SeverityInfo,
			stages:   []string{"hermes", "endpoint"},
		},
	}
	var out []types.ArtifactFinding
	for _, rule := range rules {
		seen := make(map[string]bool)
		for _, s := range extracted {
			matched := ""
			for _, sub := range rule.contains {
				if strings.Contains(s, sub) {
					matched = sub
					break
				}
			}
			if matched == "" || seen[s] {
				continue
			}
			seen[s] = true
			// Cap per-rule volume: representative samples, not 2000x repeats.
			if len(seen) > 25 {
				break
			}
			out = append(out, types.ArtifactFinding{
				Path:     relPath,
				Severity: rule.severity,
				Reason:   rule.reason,
				Payload:  s,
				Stages:   append(append([]string(nil), rule.stages...), "inventory"),
			})
		}
	}
	return out
}

// isHotUpdaterChunkPath reports extensionless assets/<id> OTA chunk paths.
func isHotUpdaterChunkPath(path, name string) bool {
	if strings.Contains(path, "assets"+string(os.PathSeparator)) || strings.Contains(path, "assets/") {
		if !strings.Contains(name, ".") && len(name) >= 8 {
			return true
		}
	}
	return false
}

// scanHotUpdaterChunk flags HotUpdater OTA chunks by magic bytes.
func scanHotUpdaterChunk(path, baseDir string) (types.ArtifactFinding, bool) {
	f, err := os.Open(path)
	if err != nil {
		return types.ArtifactFinding{}, false
	}
	defer f.Close()
	head := make([]byte, len(hotUpdaterMagic))
	if n, _ := f.Read(head); n != len(hotUpdaterMagic) || !bytes.Equal(head, hotUpdaterMagic) {
		return types.ArtifactFinding{}, false
	}
	relPath, _ := filepath.Rel(baseDir, path)
	if relPath == "" {
		relPath = path
	}
	return types.ArtifactFinding{
		Path:     relPath,
		Severity: types.SeverityMedium,
		Reason:   "[HotUpdater OTA chunk] Extensionless assets/* payload with HotUpdater magic (\\x00IAP\\x02) - out-of-band JS update, review update integrity",
		Payload:  relPath,
		Stages:   []string{"hermes", "ota"},
	}, true
}

func containsAny(s string, values ...string) bool {
	for _, value := range values {
		if strings.Contains(s, value) {
			return true
		}
	}
	return false
}

// hermesSeverity maps a provider-finding severity string to the artifact
// severity scale.
func hermesSeverity(sev string) types.Severity {
	switch strings.ToLower(sev) {
	case "critical":
		return types.SeverityCritical
	case "high":
		return types.SeverityHigh
	case "medium":
		return types.SeverityMedium
	case "low":
		return types.SeverityLow
	default:
		return types.SeverityInfo
	}
}

func extractPrintableStrings(data []byte, minLen int) []string {
	var results []string
	var current []rune

	for _, b := range data {
		r := rune(b)
		if unicode.IsPrint(r) && !unicode.IsSpace(r) {
			current = append(current, r)
		} else {
			if len(current) >= minLen {
				results = append(results, string(current))
			}
			current = nil
		}
	}
	if len(current) >= minLen {
		results = append(results, string(current))
	}
	return results
}

func mapClamp(val, max int) int {
	if val > max {
		return max
	}
	return val
}

// A documentation URL is retained as inventory, never hidden or allow-listed
// from independent secret/risk detectors.
func bundleDocumentationURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	return strings.HasPrefix(host, "docs.") || host == "github.com" || host == "stackoverflow.com" || host == "dev.to" || host == "reactnative.dev" || host == "reactnavigation.org"
}
