// Package chromium provides specialized analysis patterns for Chromium-based
// browsers (Chrome, Edge, Brave, Opera, Vivaldi) and WebView-based apps.
// Detects data harvesting, extension abuse, unsafe WebView configs,
// credential theft vectors, and browser fingerprinting techniques.
package chromium

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// PATTERN TYPES
// ═══════════════════════════════════════════════════════════════════════════════

// Severity for Chromium-specific findings.
type Severity uint8

const (
	SevInfo Severity = iota
	SevLow
	SevMedium
	SevHigh
	SevCrit
)

func (s Severity) String() string {
	names := [...]string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
	if int(s) < len(names) {
		return names[s]
	}
	return "UNKNOWN"
}

// Category classifies the type of Chromium finding.
type Category string

const (
	CatWebViewMisconfig Category = "webview-misconfiguration"
	CatDataExfiltration Category = "data-exfiltration"
	CatExtensionAbuse   Category = "extension-abuse"
	CatCredentialTheft  Category = "credential-theft"
	CatFingerprinting   Category = "browser-fingerprinting"
	CatJSBridge         Category = "javascript-bridge"
	CatCookieTheft      Category = "cookie-theft"
	CatDebuggable       Category = "debuggable-webview"
	CatCleartext        Category = "cleartext-traffic"
)

// Pattern is a single Chromium-specific detection rule.
type Pattern struct {
	ID          string
	Name        string
	Description string
	Category    Category
	Severity    Severity
	Indicators  []string // code/API patterns to look for
	FileFilter  string   // file extension filter (e.g. "*.smali")
}

// Finding is a matched pattern in the target.
type Finding struct {
	Pattern *Pattern
	File    string
	Line    int
	Snippet string
	Context string // surrounding context
}

// ═══════════════════════════════════════════════════════════════════════════════
// ANALYZER
// ═══════════════════════════════════════════════════════════════════════════════

// Analyzer scans code for Chromium-specific vulnerabilities.
type Analyzer struct {
	Patterns []*Pattern
	Findings []Finding
}

// NewAnalyzer creates an analyzer with built-in Chromium patterns.
func NewAnalyzer() *Analyzer {
	a := &Analyzer{}
	a.loadPatterns()
	return a
}

// AnalyzeFile checks a single source file against all patterns.
func (a *Analyzer) AnalyzeFile(path string, content []byte) []Finding {
	base := strings.ToLower(filepath.Base(path))
	text := string(content)
	lines := strings.Split(text, "\n")
	var findings []Finding

	for _, pat := range a.Patterns {
		if pat.FileFilter != "" {
			// Match against the real file name, not just the extension:
			// the old `"*"+ext` form could never fire an exact-name
			// filter and obscured what was being filtered.
			matched, _ := filepath.Match(strings.ToLower(pat.FileFilter), base)
			if !matched {
				continue
			}
		}
		// Fast path: only scan lines for indicators present in the file.
		// On a large codebase almost no indicator is present, so this
		// turns the per-pattern line walk into a single substring scan.
		var live []string
		for _, indicator := range pat.Indicators {
			if strings.Contains(text, indicator) {
				live = append(live, indicator)
			}
		}
		if len(live) == 0 {
			continue
		}
		for lineNum, line := range lines {
			if isCommentLine(line) {
				continue
			}
			for _, indicator := range live {
				if strings.Contains(line, indicator) {
					ctx := ""
					if lineNum > 0 {
						ctx = lines[lineNum-1]
					}
					findings = append(findings, Finding{
						Pattern: pat,
						File:    path,
						Line:    lineNum + 1,
						Snippet: strings.TrimSpace(line),
						Context: strings.TrimSpace(ctx),
					})
					break // one match per pattern per line
				}
			}
		}
	}

	a.Findings = append(a.Findings, findings...)
	return findings
}

// isCommentLine reports whether a line is entirely a comment in the
// languages this analyzer scans (Java/Kotlin/Smali/XML/JSON/JS).
// Indicator text inside comments (commented-out code, docs, sample configs)
// is the cheapest source of false positives, so whole-comment lines are
// skipped. Lines with code followed by a trailing comment are still scanned.
func isCommentLine(line string) bool {
	t := strings.TrimSpace(line)
	for _, p := range []string{"//", "*", "#", "<!--"} {
		if strings.HasPrefix(t, p) {
			return true
		}
	}
	return false
}

// RenderReport generates a Markdown report of all findings.
func (a *Analyzer) RenderReport() string {
	if len(a.Findings) == 0 {
		return "No Chromium-specific vulnerabilities detected.\n"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Chromium-Aware Analysis Report\n\n")
	fmt.Fprintf(&b, "**%d findings detected**\n\n", len(a.Findings))

	// Group by category; sort so two runs over the same findings produce
	// byte-identical reports (Go map order is random).
	groups := make(map[Category][]Finding)
	for _, f := range a.Findings {
		groups[f.Pattern.Category] = append(groups[f.Pattern.Category], f)
	}
	cats := make([]Category, 0, len(groups))
	for cat := range groups {
		cats = append(cats, cat)
	}
	sort.Slice(cats, func(i, j int) bool { return cats[i] < cats[j] })

	for _, cat := range cats {
		findings := groups[cat]
		fmt.Fprintf(&b, "## %s\n\n", cat)
		fmt.Fprintf(&b, "| Severity | Rule | File | Line |\n|---|---|---|---|\n")
		for _, f := range findings {
			fmt.Fprintf(&b, "| %s | %s | `%s` | %d |\n",
				f.Pattern.Severity, f.Pattern.Name, f.File, f.Line)
		}
		b.WriteString("\n")
	}
	return b.String()
}

// ═══════════════════════════════════════════════════════════════════════════════
// BUILT-IN PATTERNS
// ═══════════════════════════════════════════════════════════════════════════════

func (a *Analyzer) loadPatterns() {
	a.Patterns = []*Pattern{
		// --- WebView Misconfigurations ---
		{
			ID: "CHROMIUM-WV-001", Name: "JavaScript Enabled in WebView",
			Description: "WebView with JavaScript enabled can execute arbitrary scripts",
			Category:    CatWebViewMisconfig, Severity: SevMedium,
			Indicators: []string{"setJavaScriptEnabled(true)", "setJavaScriptEnabled(1)",
				"settings.javaScriptEnabled = true"},
		},
		{
			ID: "CHROMIUM-WV-002", Name: "File Access in WebView",
			Description: "WebView with file:// access can read local files",
			Category:    CatWebViewMisconfig, Severity: SevHigh,
			Indicators: []string{"setAllowFileAccess(true)", "setAllowFileAccessFromFileURLs(true)",
				"setAllowUniversalAccessFromFileURLs(true)", "setAllowContentAccess(true)"},
		},
		{
			ID: "CHROMIUM-WV-003", Name: "Mixed Content Allowed",
			Description: "WebView allows HTTP content in HTTPS pages",
			Category:    CatWebViewMisconfig, Severity: SevMedium,
			Indicators: []string{"MIXED_CONTENT_ALWAYS_ALLOW", "setMixedContentMode(0)"},
		},
		{
			ID: "CHROMIUM-WV-005", Name: "Custom SSL Error Handling",
			Description: "onReceivedSslError override — verify the handler does not call proceed(), which disables certificate validation and enables MITM",
			Category:    CatWebViewMisconfig, Severity: SevHigh,
			Indicators: []string{"onReceivedSslError", "handler.proceed()", "SslErrorHandler"},
		},
		{
			ID: "CHROMIUM-WV-006", Name: "Safe Browsing Disabled",
			Description: "WebView Safe Browsing explicitly disabled — phishing/malware URLs load without warning",
			Category:    CatWebViewMisconfig, Severity: SevLow,
			Indicators: []string{"setSafeBrowsingEnabled(false)"},
		},
		{
			ID: "CHROMIUM-WV-007", Name: "WebView Permission Auto-Grant",
			Description: "onPermissionRequest override — verify it does not auto-grant camera/mic/geolocation without user consent",
			Category:    CatWebViewMisconfig, Severity: SevMedium,
			Indicators: []string{"onPermissionRequest", "onGeolocationPermissionsShowPrompt"},
		},
		{
			ID: "CHROMIUM-NET-001", Name: "Cleartext Traffic Allowed",
			Description: "HTTP traffic permitted — credentials and session data cross the network unencrypted",
			Category:    CatCleartext, Severity: SevHigh,
			Indicators: []string{"android:usesCleartextTraffic=\"true\"", "usesCleartextTraffic",
				"cleartextTrafficPermitted", "NSAllowsArbitraryLoads"},
		},
		{
			ID: "CHROMIUM-WV-004", Name: "Debuggable WebView",
			Description: "WebView debugging enabled — allows Chrome DevTools attachment",
			Category:    CatDebuggable, Severity: SevHigh,
			Indicators: []string{"setWebContentsDebuggingEnabled(true)",
				"WebView.setWebContentsDebuggingEnabled"},
		},

		// --- JavaScript Bridge Attacks ---
		{
			ID: "CHROMIUM-JS-001", Name: "addJavascriptInterface Exposure",
			Description: "Exposes Java objects to JavaScript — RCE vector on API < 17",
			Category:    CatJSBridge, Severity: SevCrit,
			Indicators: []string{"addJavascriptInterface(", "@JavascriptInterface"},
		},
		{
			ID: "CHROMIUM-JS-002", Name: "evaluateJavascript Injection",
			Description: "Dynamic JS evaluation — potential injection vector",
			Category:    CatJSBridge, Severity: SevMedium,
			Indicators: []string{"evaluateJavascript(", "loadUrl(\"javascript:"},
		},

		// --- Data Exfiltration ---
		{
			ID: "CHROMIUM-DATA-001", Name: "Cookie Extraction",
			Description: "Reading cookies from CookieManager — credential theft risk",
			Category:    CatCookieTheft, Severity: SevHigh,
			// NB: bare "getCookie(" fired on every unrelated cookie API;
			// only the WebView CookieManager singleton counts here.
			Indicators: []string{"CookieManager.getInstance().getCookie(",
				"CookieManager.getInstance().setCookie(", "CookieSyncManager"},
		},
		{
			ID: "CHROMIUM-DATA-002", Name: "Form Data Harvesting",
			Description: "Saving form data from WebView forms",
			Category:    CatDataExfiltration, Severity: SevMedium,
			Indicators: []string{"setSaveFormData(true)", "setSavePassword(true)",
				"getHttpAuthUsernamePassword"},
		},

		// --- Browser Fingerprinting ---
		{
			ID: "CHROMIUM-FP-001", Name: "Canvas Fingerprinting",
			Description: "Canvas API used for browser fingerprinting",
			Category:    CatFingerprinting, Severity: SevLow,
			Indicators: []string{"toDataURL(", "getImageData(", "canvas.getContext(\"2d\")"},
		},
		{
			ID: "CHROMIUM-FP-002", Name: "WebGL Fingerprinting",
			Description: "WebGL renderer info used for device fingerprinting",
			Category:    CatFingerprinting, Severity: SevLow,
			Indicators: []string{"UNMASKED_VENDOR_WEBGL", "UNMASKED_RENDERER_WEBGL",
				"getExtension(\"WEBGL_debug_renderer_info\")"},
		},
		{
			ID: "CHROMIUM-FP-003", Name: "AudioContext Fingerprinting",
			Description: "AudioContext used for audio-based fingerprinting",
			Category:    CatFingerprinting, Severity: SevLow,
			Indicators: []string{"OfflineAudioContext", "AudioContext()",
				"createOscillator", "createDynamicsCompressor"},
		},

		// --- Extension Abuse ---
		{
			ID: "CHROMIUM-EXT-001", Name: "Chrome Extension Content Script Injection",
			Description: "Extension injects scripts into all pages",
			Category:    CatExtensionAbuse, Severity: SevHigh,
			Indicators: []string{"\"content_scripts\"", "\"matches\": [\"<all_urls>\"]",
				"\"run_at\": \"document_start\""},
			FileFilter: "*.json",
		},
		{
			ID: "CHROMIUM-EXT-002", Name: "Extension Background Persistence",
			Description: "Extension runs persistent background scripts",
			Category:    CatExtensionAbuse, Severity: SevMedium,
			// NB: bare "background" matched theme JSONs; MV3 persistence
			// is a service worker, MV2 an explicitly persistent page.
			Indicators: []string{"\"persistent\": true", "\"service_worker\"",
				"chrome.runtime.onInstalled"},
			FileFilter: "*.json",
		},

		// --- Credential Theft ---
		{
			ID: "CHROMIUM-CRED-001", Name: "Password Manager Access",
			Description: "Accessing stored browser passwords",
			Category:    CatCredentialTheft, Severity: SevCrit,
			// NB: bare "logins" fired on any variable with that name;
			// these are the actual Login Data store columns.
			Indicators: []string{"Login Data", "password_value",
				"origin_url", "username_value"},
		},
		{
			ID: "CHROMIUM-CRED-002", Name: "Autofill Data Access",
			Description: "Accessing Chrome autofill database",
			Category:    CatCredentialTheft, Severity: SevHigh,
			// NB: bare "autofill" fired on legit Android Autofill API use;
			// these are the actual Web Data store tables.
			Indicators: []string{"Web Data", "autofill_profiles", "credit_cards",
				"card_number_encrypted"},
		},
	}
}
