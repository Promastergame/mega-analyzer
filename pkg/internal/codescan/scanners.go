package codescan

import (
	"regexp"
	"strings"

	"mega-analyzer/pkg/internal/secrets"
)

// ──────────────────── JS / TS / RN bundle ────────────────────

var (
	reJSEval = regexp.MustCompile(`\beval\s*\(`)
	// new Function("…") family; intentionally permissive, we want false-
	// positives over false-negatives in an APK forensic context.
	reJSNewFunc       = regexp.MustCompile(`new\s+Function\s*\(`)
	reJSSetTimeoutStr = regexp.MustCompile(`set(?:Timeout|Interval)\s*\(\s*['"]`)
	reJSDocWrite      = regexp.MustCompile(`document\.write(?:ln)?\s*\(`)
	reJSInnerHTML     = regexp.MustCompile(`\.innerHTML\s*=`)
	reJSOuterHTML     = regexp.MustCompile(`\.outerHTML\s*=`)
	reJSInsertAdj     = regexp.MustCompile(`\.insertAdjacentHTML\s*\(`)
	reJSLoc           = regexp.MustCompile(`location\s*=\s*['"]?https?://`)
	reJSPostMessage   = regexp.MustCompile(`postMessage\s*\(`)
	reJSAddJsIface    = regexp.MustCompile(`addJavascriptInterface\s*\(`)
	reJSWebViewLoad   = regexp.MustCompile(`loadDataWithBaseURL|loadUrl\s*\(\s*['"]javascript:`)
	reJSProtoPoll     = regexp.MustCompile(`__proto__\s*\[|Object\.prototype\.[A-Za-z_]+\s*=`)
	reJSAtobLong      = regexp.MustCompile(`atob\s*\(\s*['"][A-Za-z0-9+/=]{60,}['"]`)
	reJSObfHex        = regexp.MustCompile(`\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}`)
	reJSObfUni        = regexp.MustCompile(`\\u[0-9a-fA-F]{4}\\u[0-9a-fA-F]{4}\\u[0-9a-fA-F]{4}`)
	reJSReverseStr    = regexp.MustCompile(`['"][^'"\n]{40,}['"]\.split\(\s*['"]['"]\s*\)\.reverse\(\)`)
	reJSFetchExt      = regexp.MustCompile(`fetch\s*\(\s*['"]https?://`)
	reJSXHROpen       = regexp.MustCompile(`\.open\s*\(\s*['"](?:GET|POST|PUT|DELETE)['"]\s*,\s*['"]https?://`)
	reJSWebSocket     = regexp.MustCompile(`new\s+WebSocket\s*\(\s*['"]wss?://`)
	reJSCrypto        = regexp.MustCompile(`createCipher\s*\(\s*['"]des|createCipher\s*\(\s*['"]rc4|MD5|SHA-?1\b`)
	reJSDangerSet     = regexp.MustCompile(`dangerouslySetInnerHTML`)
	reJSChild         = regexp.MustCompile(`child_process|spawn\s*\(|exec\s*\(`)
	// WebView / hybrid-app sinks. setAllowUniversalAccessFromFileURLs and
	// setAllowFileAccessFromFileURLs let remote pages read local files (a
	// classic Android WebView exfil chain). injectedJavaScript / evaluateJavascript
	// push code into a WebView.
	reJSWebViewUniversal = regexp.MustCompile(`setAllowUniversalAccessFromFileURLs\s*\(\s*true|setAllowFileAccessFromFileURLs\s*\(\s*true`)
	reJSWebViewFileAcc   = regexp.MustCompile(`setAllowFileAccess\s*\(\s*true|setAllowContentAccess\s*\(\s*true`)
	reJSWebViewInject    = regexp.MustCompile(`injectedJavaScript(?:BeforeContentLoaded)?\s*[:=]|evaluateJavascript\s*\(`)
	reJSCordovaExec      = regexp.MustCompile(`cordova\.exec\s*\(|window\.cordova\.exec\s*\(`)
	// Disabled TLS validation — the single most common cause of MITM-able
	// React Native / Node apps.
	reJSTLSReject = regexp.MustCompile(`rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*['"]?0|allowsAnyHTTPSCertificate|trustAllCerts`)
)

var reJSChildImport = regexp.MustCompile(`require\s*\(\s*['"]child_process['"]\s*\)|import\s+[^'"]+\s+from\s+['"]child_process['"]|import\s+['"]child_process['"]`)

// isRNAppBundle reports whether the path is a React Native application bundle —
// the primary container for the app's OWN JavaScript, not a vendored framework.
// Findings here are real application code and must NOT be suppressed as
// "framework noise" the way vendor/webpack chunks are.
func isRNAppBundle(lowerPath string) bool {
	return strings.Contains(lowerPath, "index.android.bundle") ||
		strings.Contains(lowerPath, "index.ios.bundle") ||
		strings.Contains(lowerPath, "main.jsbundle") ||
		strings.HasSuffix(lowerPath, ".hbc")
}

func scanJSLike(filePath string, text string) []Finding {
	var out []Finding
	rules := []reFinder{
		{reJSEval, "js/eval", "eval() call", SevHigh, "eval", "Direct eval is a code-injection sink."},
		{reJSNewFunc, "js/new-function", "new Function(...) constructor", SevHigh, "eval", "Equivalent to eval, builds code from string."},
		{reJSSetTimeoutStr, "js/timeout-string", "setTimeout/Interval with string", SevMedium, "eval", "String first arg is implicitly evaluated."},
		{reJSDocWrite, "js/document-write", "document.write()", SevMedium, "xss", "Injects unsanitized HTML into the DOM."},
		{reJSInnerHTML, "js/inner-html", "innerHTML assignment", SevMedium, "xss", "Direct HTML sink — XSS risk if unsanitized."},
		{reJSOuterHTML, "js/outer-html", "outerHTML assignment", SevMedium, "xss", "Direct HTML sink — XSS risk if unsanitized."},
		{reJSInsertAdj, "js/insert-adj", "insertAdjacentHTML", SevMedium, "xss", "HTML sink without sanitization."},
		{reJSLoc, "js/location-redirect", "location = http://…", SevLow, "network", "Hardcoded redirect."},
		{reJSPostMessage, "js/post-message", "postMessage usage", SevLow, "ipc", "Cross-origin messaging — verify origin checks."},
		{reJSAddJsIface, "js/jsinterface", "addJavascriptInterface", SevHigh, "bridge", "Exposes Java to JS — RCE if WebView untrusted."},
		{reJSWebViewLoad, "js/javascript-url", "loadUrl(\"javascript:\")", SevHigh, "bridge", "JS injection into WebView."},
		{reJSProtoPoll, "js/proto-pollution", "Prototype pollution gadget", SevHigh, "proto-pollution", "Mutates Object.prototype directly."},
		{reJSAtobLong, "js/atob-blob", "atob() with long base64", SevMedium, "obfuscation", "Likely decoded payload at runtime."},
		{reJSObfHex, "js/hex-string", "Hex-escaped string sequence", SevMedium, "obfuscation", "Identifier or string hex-encoded."},
		{reJSObfUni, "js/unicode-string", "Unicode-escaped string sequence", SevMedium, "obfuscation", "Identifier or string \\uXXXX-encoded."},
		{reJSReverseStr, "js/reverse-string", "split('').reverse() trick", SevMedium, "obfuscation", "Classic packer string-reverse."},
		{reJSFetchExt, "js/fetch-external", "fetch(http(s)://…)", SevLow, "network", "Outbound network call."},
		{reJSXHROpen, "js/xhr-external", "XMLHttpRequest(http(s)://…)", SevLow, "network", "Outbound network call."},
		{reJSWebSocket, "js/websocket", "WebSocket(ws(s)://…)", SevLow, "network", "Outbound websocket connection."},
		{reJSCrypto, "js/weak-crypto", "Weak crypto primitive", SevMedium, "crypto", "DES/RC4/MD5/SHA-1 are unsafe today."},
		{reJSDangerSet, "js/react-danger", "dangerouslySetInnerHTML", SevMedium, "xss", "React's HTML sink — bypasses default escaping."},
		{reJSChild, "js/exec", "child_process / exec / spawn", SevHigh, "exec", "Process exec from JS."},
		{reJSWebViewUniversal, "js/webview-universal-access", "WebView universal/file access from file URLs", SevHigh, "webview", "Lets remote pages read local files — local-file exfiltration sink."},
		{reJSWebViewFileAcc, "js/webview-file-access", "WebView file/content access enabled", SevMedium, "webview", "Broadens WebView file access — review against untrusted content."},
		{reJSWebViewInject, "js/webview-inject", "injectedJavaScript / evaluateJavascript", SevMedium, "webview", "Injects JS into a WebView — RCE if the page or input is untrusted."},
		{reJSCordovaExec, "js/cordova-exec", "cordova.exec native bridge call", SevMedium, "bridge", "Calls into native Cordova plugins from JS."},
		{reJSTLSReject, "js/tls-disabled", "TLS certificate validation disabled", SevHigh, "tls", "rejectUnauthorized:false / trust-all certs — traffic is MITM-able."},
	}

	lowerPath := strings.ToLower(filePath)
	// A React Native *application* bundle is the app's own code — never treat it
	// as framework noise. Only genuine vendor/framework chunks are suppressed.
	isFramework := !isRNAppBundle(lowerPath) &&
		(strings.Contains(lowerPath, "react") ||
			strings.Contains(lowerPath, "core-js") ||
			strings.Contains(lowerPath, "polyfill") ||
			strings.Contains(lowerPath, "webpack") ||
			strings.Contains(lowerPath, "vendor") ||
			strings.Contains(lowerPath, "bundle"))

	hasChildProcessImport := reJSChildImport.MatchString(text)

	for _, r := range rules {
		findings := r.find(text)
		for _, f := range findings {
			// Skip/suppress rules inside frameworks
			if isFramework {
				if f.ID == "js/react-danger" {
					f.Severity = SevInfo
				} else if f.ID == "js/inner-html" || f.ID == "js/outer-html" || f.ID == "js/insert-adj" {
					f.Severity = SevInfo // no user-controlled dataflow proof
				} else if f.ID == "js/post-message" && (strings.Contains(strings.ToLower(f.Snippet), "messagechannel") || strings.Contains(f.Snippet, `"*"`)) {
					f.Severity = SevInfo
				} else if f.ID == "js/eval" || f.ID == "js/new-function" || f.ID == "js/timeout-string" || f.ID == "js/document-write" || f.ID == "js/weak-crypto" {
					f.Severity = SevLow
				}
			}

			// Process execution checks
			if f.ID == "js/exec" {
				// check if 'exec' is used as a function parameter name
				// e.g. function(exec), (exec) =>, exec:, or function exec(
				snipLower := strings.ToLower(f.Snippet)
				isParamName := strings.Contains(snipLower, "function exec") ||
					strings.Contains(snipLower, "function(exec)") ||
					strings.Contains(snipLower, "function (exec)") ||
					strings.Contains(snipLower, "(exec) =>") ||
					strings.Contains(snipLower, "(exec)=") ||
					strings.Contains(snipLower, "exec:") ||
					strings.Contains(snipLower, ", exec,") ||
					strings.Contains(snipLower, ",exec,") ||
					strings.Contains(snipLower, "(exec,") ||
					strings.Contains(snipLower, "(exec ")

				if isParamName {
					continue // skip parameter name false positives
				}

				if !hasChildProcessImport {
					f.Severity = SevLow // child_process/exec/spawn is HIGH only if there is a direct require/import
				}
			}

			out = append(out, f)
		}
	}
	return out
}

// ──────────────────── HTML ────────────────────

var (
	reHTMLOnEvt      = regexp.MustCompile(`(?i)\son[a-z]+\s*=\s*["']`)
	reHTMLJSURL      = regexp.MustCompile(`(?i)href\s*=\s*["']javascript:`)
	reHTMLDataURI    = regexp.MustCompile(`(?i)src\s*=\s*["']data:[a-z]+/[a-z]+;base64,[A-Za-z0-9+/=]{200,}`)
	reHTMLIframe     = regexp.MustCompile(`(?i)<iframe[^>]*\ssrc\s*=\s*["']https?:`)
	reHTMLForm       = regexp.MustCompile(`(?i)<form[^>]*\saction\s*=\s*["']https?:`)
	reHTMLInline     = regexp.MustCompile(`(?i)<script(?:\s[^>]*)?>[^<]{50,}</script>`)
	reHTMLMeta       = regexp.MustCompile(`(?i)<meta[^>]+http-equiv\s*=\s*["']refresh["'][^>]+url\s*=\s*[^>]+>`)
	reHTMLObject     = regexp.MustCompile(`(?i)<(?:object|embed)[^>]*\sdata\s*=\s*["']`)
	reHTMLScriptBody = regexp.MustCompile(`(?is)<script(?:\s[^>]*)?>(.*?)</script>`)
)

func scanHTML(filePath string, text string) []Finding {
	var out []Finding
	rules := []reFinder{
		{reHTMLOnEvt, "html/inline-event", "Inline DOM event handler", SevMedium, "xss", "Inline onXxx= attributes are a JS sink."},
		{reHTMLJSURL, "html/javascript-url", "javascript: URL in href", SevHigh, "xss", "Executes JS on click."},
		{reHTMLDataURI, "html/data-uri-payload", "Large base64 data: URI", SevMedium, "obfuscation", "Embedded asset/script in data URI."},
		{reHTMLIframe, "html/iframe-external", "External <iframe src=…>", SevMedium, "network", "Loads remote content into the page."},
		{reHTMLForm, "html/form-external", "External form action", SevLow, "network", "Submits data to remote endpoint."},
		{reHTMLInline, "html/inline-script", "Large inline <script>", SevLow, "structural", "Inline JS over 50 chars — review."},
		{reHTMLMeta, "html/meta-refresh", "<meta refresh> redirect", SevLow, "network", "Auto-redirect via meta refresh."},
		{reHTMLObject, "html/object-embed", "<object|embed data=…>", SevMedium, "structural", "Could load Flash/SVG/HTML payload."},
	}
	for _, r := range rules {
		out = append(out, r.find(text)...)
	}
	// JS scan over inline <script> blocks — quick & dirty extraction.
	for _, idx := range reHTMLScriptBody.FindAllStringSubmatchIndex(text, 50) {
		if len(idx) >= 4 {
			body := text[idx[2]:idx[3]]
			out = append(out, scanJSLike(filePath, body)...)
		}
	}
	return out
}

// ──────────────────── CSS ────────────────────

var (
	reCSSExpr   = regexp.MustCompile(`expression\s*\(`)
	reCSSURL    = regexp.MustCompile(`(?i)url\s*\(\s*['"]?https?:`)
	reCSSImport = regexp.MustCompile(`(?i)@import\s+(?:url\(\s*)?['"]https?:`)
)

func scanCSS(text string) []Finding {
	var out []Finding
	rules := []reFinder{
		{reCSSExpr, "css/expression", "CSS expression()", SevHigh, "xss", "IE-era JS sink in CSS."},
		{reCSSURL, "css/external-url", "External url(http(s)://…)", SevLow, "network", "References remote resource."},
		{reCSSImport, "css/external-import", "@import http(s)://…", SevLow, "network", "Loads remote stylesheet."},
	}
	for _, r := range rules {
		out = append(out, r.find(text)...)
	}
	return out
}

// ──────────────────── JSON ────────────────────

var (
	reJSONJWT  = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`)
	reJSONLong = regexp.MustCompile(`"[A-Za-z0-9+/]{200,}={0,2}"`)
)

func scanJSON(text string) []Finding {
	var out []Finding
	rules := []reFinder{
		{reJSONJWT, "json/jwt", "Hardcoded JWT", SevHigh, "secret", "JSON Web Token shipped in resources."},
		{reJSONLong, "json/blob", "Long base64-like blob", SevLow, "obfuscation", "Large opaque string — possibly a key or payload."},
	}
	for _, r := range rules {
		out = append(out, r.find(text)...)
	}
	return out
}

// ──────────────────── Lua / Python / Shell / SQL ────────────────────

var (
	reLuaLoad    = regexp.MustCompile(`\bload(?:string)?\s*\(`)
	reLuaOsExec  = regexp.MustCompile(`os\.execute\s*\(|io\.popen\s*\(`)
	rePyExec     = regexp.MustCompile(`\b(?:exec|eval|compile)\s*\(`)
	rePySubproc  = regexp.MustCompile(`subprocess\.(?:Popen|call|run|check_output)\s*\(`)
	rePyOSCmd    = regexp.MustCompile(`os\.(?:system|popen|spawn[a-z]*)\s*\(`)
	rePyPickle   = regexp.MustCompile(`\bpickle\.(?:load|loads)\s*\(`)
	reShellEval  = regexp.MustCompile(`\beval\s+|\bsource\s+|\.\s+/[^ ]+`)
	reShellCurl  = regexp.MustCompile(`\bcurl\s+[^|;\n]*\|\s*sh\b|\bwget\s+[^|;\n]*\|\s*sh\b`)
	reShellChmod = regexp.MustCompile(`\bchmod\s+\+x\b`)
	reSQLConcat  = regexp.MustCompile(`(?i)(SELECT|INSERT|UPDATE|DELETE)[^;]{0,80}\+\s*['"]?\$`)
	reSQLDropAll = regexp.MustCompile(`(?i)DROP\s+(?:TABLE|DATABASE)`)
)

func scanLua(text string) []Finding {
	rules := []reFinder{
		{reLuaLoad, "lua/load", "Lua load/loadstring", SevHigh, "eval", "Compiles arbitrary code from string."},
		{reLuaOsExec, "lua/os-exec", "os.execute / io.popen", SevHigh, "exec", "Shell command execution."},
	}
	var out []Finding
	for _, r := range rules {
		out = append(out, r.find(text)...)
	}
	return out
}

func scanPython(text string) []Finding {
	rules := []reFinder{
		{rePyExec, "py/exec", "exec / eval / compile", SevHigh, "eval", "Dynamic code execution."},
		{rePySubproc, "py/subprocess", "subprocess call", SevMedium, "exec", "Spawns external process."},
		{rePyOSCmd, "py/os-cmd", "os.system / os.popen", SevHigh, "exec", "Shell command execution."},
		{rePyPickle, "py/pickle", "pickle.load", SevHigh, "deser", "Pickle deserialisation can run code."},
	}
	var out []Finding
	for _, r := range rules {
		out = append(out, r.find(text)...)
	}
	return out
}

func scanShell(text string) []Finding {
	rules := []reFinder{
		{reShellEval, "sh/eval", "eval / source / dot-include", SevHigh, "eval", "Runs arbitrary code from a string or file."},
		{reShellCurl, "sh/curl-pipe-sh", "curl|wget piped to sh", SevCritical, "exec", "Remote-pulled code piped to shell."},
		{reShellChmod, "sh/chmod-x", "chmod +x", SevLow, "structural", "Marks file executable."},
	}
	var out []Finding
	for _, r := range rules {
		out = append(out, r.find(text)...)
	}
	return out
}

func scanSQL(text string) []Finding {
	rules := []reFinder{
		{reSQLConcat, "sql/string-concat", "Probable SQL string concatenation", SevHigh, "sqli", "Likely SQL-injection: query built from string interpolation."},
		{reSQLDropAll, "sql/drop", "DROP TABLE/DATABASE", SevMedium, "structural", "Destructive DDL statement."},
	}
	var out []Finding
	for _, r := range rules {
		out = append(out, r.find(text)...)
	}
	return out
}

// ──────────────────── Secrets / URLs (any text) ────────────────────

var (
	reSecretAWS     = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	reSecretGoogle  = regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)
	reSecretGitHub  = regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36}`)
	reSecretSlack   = regexp.MustCompile(`xox[bpoa]-[0-9A-Za-z\-]{10,}`)
	reSecretStripe  = regexp.MustCompile(`sk_(?:live|test)_[0-9A-Za-z]{20,}`)
	reSecretFB      = regexp.MustCompile(`EAACEdEose0cBA[0-9A-Za-z]+`)
	reSecretBearer  = regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._\-]{20,}`)
	reSecretPriv    = regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`)
	reSecretGeneric = regexp.MustCompile(`(?i)(?:api[_-]?key|secret[_-]?key|password|passwd|access[_-]?token)\s*[:=]\s*['"][A-Za-z0-9._\-]{16,}['"]`)
	reURL           = regexp.MustCompile(`https?://[^\s"'<>()\\]{4,}`)
)

func scanSecrets(filePath string, text string) []Finding {
	var out []Finding
	lowerPath := strings.ToLower(filePath)
	isManifestOrConfig := strings.Contains(lowerPath, "androidmanifest.xml") ||
		strings.Contains(lowerPath, "google-services") ||
		strings.Contains(lowerPath, "config")

	for _, sf := range secrets.DetectProviders(text, filePath) {
		sev := sf.Severity
		detail := sf.Name + " detected by provider-aware scanner. " + sf.Remediation
		if sf.RuleID == "secret/google-api" {
			// Google / Firebase keys triage.
			surroundingLower := strings.ToLower(sf.Context)
			hasPaidAbuseRisk := strings.Contains(surroundingLower, "maps") ||
				strings.Contains(surroundingLower, "vision") ||
				strings.Contains(surroundingLower, "places") ||
				strings.Contains(surroundingLower, "translate") ||
				strings.Contains(surroundingLower, "directions") ||
				strings.Contains(surroundingLower, "compute") ||
				strings.Contains(surroundingLower, "cloud") ||
				strings.Contains(surroundingLower, "billing")
			isFirebase := strings.Contains(surroundingLower, "firebase") ||
				strings.Contains(surroundingLower, "google_api_key") ||
				strings.Contains(surroundingLower, "google_app_id") ||
				strings.Contains(lowerPath, "google-services.json")
			if isFirebase && !hasPaidAbuseRisk {
				sev = SevInfo
				detail = "Standard Firebase API key (designed to be client-side public). verify API restrictions: package name, SHA fingerprint, allowed APIs, quota."
			} else if hasPaidAbuseRisk {
				sev = SevHigh
				detail = "Google Paid API key detected with active paid API keywords in surrounding context. verify API restrictions: package name, SHA fingerprint, allowed APIs, quota."
			} else if isManifestOrConfig {
				sev = SevMedium
				detail = "Google API key of unclear scope declared in manifest/config resources. verify API restrictions: package name, SHA fingerprint, allowed APIs, quota."
			} else {
				sev = SevHigh
			}
		}
		// Surface the offline structural check (verifier.go) so a report reader
		// can tell a live-looking token apart from a provably-dead one without
		// any network call.
		if sf.Validation != "" {
			if sf.Verified {
				detail += " [offline verification: " + sf.Validation + "]"
			} else {
				detail += " [offline check: " + sf.Validation + " — appears inactive/expired]"
			}
		}
		out = append(out, Finding{
			ID:       sf.RuleID,
			Title:    sf.Name,
			Severity: sev,
			Category: "secret",
			Line:     sf.Line,
			Column:   sf.Column,
			Snippet:  sf.MaskedValue,
			Rule:     "provider-secret",
			Detail:   detail,
		})
	}

	// Legacy broad patterns are kept only for providers not covered by the
	// high-confidence detector and for generic key/value credentials.
	rules := []reFinder{
		{reSecretAWS, "secret/aws-key", "AWS Access Key ID", SevCritical, "secret", "Hardcoded AWS access key."},
		{reSecretGoogle, "secret/google-api-key", "Google API Key", SevHigh, "secret", "Hardcoded Google API key."},
		{reSecretGitHub, "secret/github-token", "GitHub Personal Access Token", SevCritical, "secret", "Hardcoded GitHub token."},
		{reSecretSlack, "secret/slack-token", "Slack API Token", SevHigh, "secret", "Hardcoded Slack token."},
		{reSecretStripe, "secret/stripe-key", "Stripe Secret Key", SevCritical, "secret", "Hardcoded Stripe API key."},
		{reSecretPriv, "secret/private-key", "Private Key Material", SevCritical, "secret", "Hardcoded private key."},
		{reSecretFB, "secret/facebook-token", "Facebook OAuth token", SevHigh, "secret", "Hardcoded Facebook token."},
		{reSecretBearer, "secret/bearer", "Bearer token literal", SevMedium, "secret", "Hardcoded Bearer token."},
		{reSecretGeneric, "secret/keyword", "Generic credential keyword", SevMedium, "secret", "key/password/secret pattern."},
	}
	for _, r := range rules {
		out = append(out, r.find(text)...)
	}
	return out
}
func scanURLs(filePath string, text string) []Finding {
	matches := reURL.FindAllStringIndex(text, 50)
	var out []Finding
	seen := map[string]struct{}{}
	lowerPath := strings.ToLower(filePath)

	isLicenseOrDoc := strings.Contains(lowerPath, "license") ||
		strings.Contains(lowerPath, "notice") ||
		strings.Contains(lowerPath, "readme") ||
		strings.Contains(lowerPath, "copying") ||
		strings.HasSuffix(lowerPath, ".md") ||
		strings.Contains(lowerPath, "protobuf") ||
		strings.Contains(lowerPath, "docs") ||
		strings.HasSuffix(lowerPath, ".proto")

	for _, m := range matches {
		urlStr := text[m[0]:m[1]]
		host := strings.SplitN(urlStr, "/", 4)
		key := ""
		if len(host) >= 3 {
			key = host[2]
		}
		if key == "" {
			continue
		}
		lk := strings.ToLower(key)
		if lk == "schemas.android.com" ||
			lk == "w3.org" || lk == "www.w3.org" ||
			lk == "schema.org" || lk == "www.schema.org" ||
			lk == "schemas.google.com" ||
			strings.HasSuffix(lk, ".w3.org") ||
			strings.HasSuffix(lk, ".schema.org") ||
			strings.HasSuffix(lk, ".schemas.microsoft.com") ||
			lk == "schemas.microsoft.com" {
			continue
		}
		// Dedup per host.
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		line, col := lineCol(text, m[0])

		urlClass := classifyURL(urlStr)
		category := "network: " + urlClass
		title := "External URL [" + urlClass + "]: " + key
		detail := "Hardcoded URL — verify trust boundary."
		sev := SevLow

		snippet := snippetAt(text, m[0], m[1])
		hasDoubleSlashComment := false
		if idx := strings.Index(snippet, "//"); idx != -1 {
			if idx > 0 {
				prefix := snippet[:idx]
				if !strings.HasSuffix(prefix, "http:") && !strings.HasSuffix(prefix, "https:") {
					hasDoubleSlashComment = true
				}
			} else {
				hasDoubleSlashComment = true
			}
		}
		isComment := hasDoubleSlashComment ||
			strings.Contains(snippet, "/*") ||
			strings.HasPrefix(strings.TrimSpace(snippet), "*") ||
			strings.Contains(snippet, "#")

		// 1. Path/context downgrades
		// github.com / reactjs.org / developers.google.com in licenses/comments are INFO
		isGoogleReactGithub := strings.Contains(lk, "github.com") ||
			strings.Contains(lk, "reactjs.org") ||
			strings.Contains(lk, "developers.google.com") ||
			strings.Contains(lk, "developer.android.com")

		if isGoogleReactGithub && (isLicenseOrDoc || isComment) {
			sev = SevInfo
			detail = "Benign developer doc/license link in comment or license file."
		} else if isLicenseOrDoc || isComment {
			// Do not elevate severity for comments / licenses / notices
			sev = SevLow
			detail = "Benign URL reference in comments or documentation resources."
		} else {
			// Regular context
			switch urlClass {
			case "Auth/OAuth":
				sev = SevMedium
				detail = "login/oauth/passport endpoint — compliance/trust-boundary review required."
			case "telemetry":
				sev = SevInfo // appmetrica/clck/analytics endpoints are LOW/INFO
				detail = "Benign analytics/telemetry endpoint."
			case "CDN":
				sev = SevLow
				detail = "Static content distribution network (CDN) host."
			case "developer/docs/license links":
				sev = SevInfo
				detail = "Reference to documentation or license terms."
			case "backend API":
				// Check for /dev endpoint
				if strings.Contains(strings.ToLower(urlStr), "/dev") {
					sev = SevMedium
					detail = "/dev endpoint detected in release context — verify production build config."
				} else {
					sev = SevLow
					detail = "Potential hardcoded backend API endpoint."
				}
			default:
				sev = SevLow
			}
		}

		out = append(out, Finding{
			ID:       "net/external-url",
			Title:    title,
			Severity: sev,
			Category: category,
			Line:     line,
			Column:   col,
			Snippet:  snippet,
			Detail:   detail,
		})
	}
	return out
}

func classifyURL(urlStr string) string {
	urlStrLower := strings.ToLower(urlStr)
	switch {
	case strings.Contains(urlStrLower, "login") || strings.Contains(urlStrLower, "oauth") || strings.Contains(urlStrLower, "passport") || strings.Contains(urlStrLower, "auth") || strings.Contains(urlStrLower, "token") || strings.Contains(urlStrLower, "signin") || strings.Contains(urlStrLower, "session"):
		return "Auth/OAuth"
	case strings.Contains(urlStrLower, "telemetry") || strings.Contains(urlStrLower, "analytics") || strings.Contains(urlStrLower, "metrics") || strings.Contains(urlStrLower, "track") || strings.Contains(urlStrLower, "appmetrica") || strings.Contains(urlStrLower, "clck") || strings.Contains(urlStrLower, "bugsnag") || strings.Contains(urlStrLower, "crashlytics") || strings.Contains(urlStrLower, "amplitude") || strings.Contains(urlStrLower, "mixpanel") || strings.Contains(urlStrLower, "stat"):
		return "telemetry"
	case strings.Contains(urlStrLower, "cdn") || strings.Contains(urlStrLower, "cdnjs") || strings.Contains(urlStrLower, "jsdelivr") || strings.Contains(urlStrLower, "unpkg") || strings.Contains(urlStrLower, "bootstrapcdn") || strings.Contains(urlStrLower, "googleapis.com/ajax"):
		return "CDN"
	case strings.Contains(urlStrLower, "github.com") || strings.Contains(urlStrLower, "reactjs.org") || strings.Contains(urlStrLower, "developers.google.com") || strings.Contains(urlStrLower, "developer.android.com") || strings.Contains(urlStrLower, "w3.org") || strings.Contains(urlStrLower, "schema.org") || strings.Contains(urlStrLower, "apache.org") || strings.Contains(urlStrLower, "license") || strings.Contains(urlStrLower, "docs") || strings.Contains(urlStrLower, "readme") || strings.Contains(urlStrLower, "notice"):
		return "developer/docs/license links"
	case strings.Contains(urlStrLower, "api.") || strings.Contains(urlStrLower, "api/") || strings.Contains(urlStrLower, "backend") || strings.Contains(urlStrLower, "endpoint") || strings.Contains(urlStrLower, "/v1/") || strings.Contains(urlStrLower, "/v2/") || strings.Contains(urlStrLower, "graphql"):
		return "backend API"
	default:
		return "unknown"
	}
}

func isSensitiveHost(host string) bool {
	host = strings.ToLower(host)
	for _, k := range []string{"login", "auth", "oauth", "token", "admin", "internal", "staging"} {
		if strings.Contains(host, k) {
			return true
		}
	}
	return false
}

// ──────────────────── proto ────────────────────

var (
	rePackage  = regexp.MustCompile(`(?m)^\s*package\s+([A-Za-z0-9_.]+)\s*;`)
	reImport   = regexp.MustCompile(`(?m)^\s*import\s+(?:public\s+|weak\s+)?"([^"]+)"\s*;`)
	reMessage  = regexp.MustCompile(`(?m)^\s*message\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{`)
	reEnum     = regexp.MustCompile(`(?m)^\s*enum\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{`)
	reService  = regexp.MustCompile(`(?ms)^\s*service\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{(.*?)\n\s*\}`)
	reRPC      = regexp.MustCompile(`\brpc\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(`)
	reAnyMap   = regexp.MustCompile(`\bgoogle\.protobuf\.Any\b`)
	reFieldNum = regexp.MustCompile(`=\s*(\d{6,})\s*[;\]]`) // suspiciously high tag numbers
	reReserved = regexp.MustCompile(`\breserved\s+\d+\s*to\s+max\b`)
)

func scanProto(filePath string, text string) (*Schema, []Finding) {
	s := &Schema{Options: map[string]string{}}

	if m := rePackage.FindStringSubmatch(text); len(m) == 2 {
		s.Package = m[1]
	}
	for _, m := range reImport.FindAllStringSubmatch(text, -1) {
		s.Imports = append(s.Imports, m[1])
	}
	for _, m := range reMessage.FindAllStringSubmatch(text, -1) {
		s.Messages = append(s.Messages, m[1])
	}
	for _, m := range reEnum.FindAllStringSubmatch(text, -1) {
		s.Enums = append(s.Enums, m[1])
	}
	for _, m := range reService.FindAllStringSubmatch(text, -1) {
		svc := Service{Name: m[1]}
		for _, r := range reRPC.FindAllStringSubmatch(m[2], -1) {
			svc.RPCs = append(svc.RPCs, r[1])
		}
		s.Services = append(s.Services, svc)
	}

	var out []Finding
	rules := []reFinder{
		{reAnyMap, "proto/any", "google.protobuf.Any usage", SevInfo, "proto", "Allows arbitrary embedded payload — verify type-URL handling."},
		{reFieldNum, "proto/large-tag", "Suspiciously large field number", SevInfo, "proto-bomb", "Field tags ≥ 1e6 may be used to confuse decoders."},
		{reReserved, "proto/reserved-max", "reserved … to max", SevInfo, "proto", "Reserves tag space for forward-compat."},
	}
	for _, r := range rules {
		out = append(out, r.find(text)...)
	}
	if len(s.Services) == 0 && len(s.Messages) == 0 && len(s.Enums) == 0 {
		out = append(out, Finding{
			ID:       "proto/empty",
			Title:    "No messages/services declared",
			Severity: SevInfo,
			Category: "structural",
			Detail:   "File parses as proto but is empty or non-standard.",
		})
	}
	return s, out
}

// ──────────────────── License Compliance ────────────────────

var (
	reLicenseGPL    = regexp.MustCompile(`(?i)\b(?:General Public License|GPL)\b`)
	reLicenseLGPL   = regexp.MustCompile(`(?i)\b(?:Lesser General Public License|LGPL)\b`)
	reLicenseApache = regexp.MustCompile(`(?i)\bApache\s+License\b|\bApache\s+Software\s+License\b`)
	reLicenseMIT    = regexp.MustCompile(`(?i)\bMIT\s+License\b|Permission is hereby granted.*obtaining a copy`)
	reLicenseBSD    = regexp.MustCompile(`(?i)\bBSD\s+[234]-Clause\b|\bBSD\s+License\b|Redistribution and use in source and binary forms`)
)

func scanLicenses(filePath string, text string) []Finding {
	lowerPath := strings.ToLower(filePath)
	isLicenseFile := strings.Contains(lowerPath, "license") ||
		strings.Contains(lowerPath, "notice") ||
		strings.Contains(lowerPath, "copying") ||
		strings.HasSuffix(lowerPath, ".txt") ||
		strings.HasSuffix(lowerPath, ".md")

	if !isLicenseFile {
		return nil
	}

	var out []Finding
	component := extractComponentName(filePath)
	snippet := ""
	if len(text) > 200 {
		snippet = text[:200] + "…"
	} else {
		snippet = text
	}

	// 1. GPL Check
	if m := reLicenseGPL.FindStringIndex(text); m != nil {
		sev := SevInfo
		detail := "GPL license text block detected (compliance inventory)."
		isNativeFolder := strings.Contains(lowerPath, "/lib/") || strings.Contains(lowerPath, "/assets/")
		if isNativeFolder {
			sev = SevHigh
			detail = "GPL licensed packaged native binary or component detected. Verify copyleft compliance terms."
		}
		line, col := lineCol(text, m[0])
		out = append(out, Finding{
			ID:       "license/gpl",
			Title:    "GPL License Inventory: " + component,
			Severity: sev,
			Category: "license",
			Line:     line,
			Column:   col,
			Snippet:  snippet,
			Detail:   detail,
		})
	}

	// 2. LGPL Check
	if m := reLicenseLGPL.FindStringIndex(text); m != nil {
		line, col := lineCol(text, m[0])
		out = append(out, Finding{
			ID:       "license/lgpl",
			Title:    "LGPL License Check: " + component,
			Severity: SevMedium,
			Category: "license",
			Line:     line,
			Column:   col,
			Snippet:  snippet,
			Detail:   "LGPL license text block detected. Verify compliance/linking terms.",
		})
	}

	// 3. Apache Check
	if m := reLicenseApache.FindStringIndex(text); m != nil {
		line, col := lineCol(text, m[0])
		out = append(out, Finding{
			ID:       "license/apache",
			Title:    "Apache License Inventory: " + component,
			Severity: SevInfo,
			Category: "license",
			Line:     line,
			Column:   col,
			Snippet:  snippet,
			Detail:   "Apache license text block detected (compliance inventory).",
		})
	}

	// 4. MIT Check
	if m := reLicenseMIT.FindStringIndex(text); m != nil {
		line, col := lineCol(text, m[0])
		out = append(out, Finding{
			ID:       "license/mit",
			Title:    "MIT License Inventory: " + component,
			Severity: SevInfo,
			Category: "license",
			Line:     line,
			Column:   col,
			Snippet:  snippet,
			Detail:   "MIT license text block detected (compliance inventory).",
		})
	}

	// 5. BSD Check
	if m := reLicenseBSD.FindStringIndex(text); m != nil {
		line, col := lineCol(text, m[0])
		out = append(out, Finding{
			ID:       "license/bsd",
			Title:    "BSD-style License Inventory: " + component,
			Severity: SevInfo,
			Category: "license",
			Line:     line,
			Column:   col,
			Snippet:  snippet,
			Detail:   "BSD-style license text block detected (compliance inventory).",
		})
	}

	return out
}

func extractComponentName(filePath string) string {
	parts := strings.Split(strings.ReplaceAll(filePath, "\\", "/"), "/")
	for i := len(parts) - 1; i >= 0; i-- {
		p := parts[i]
		pl := strings.ToLower(p)
		if !strings.Contains(pl, "license") &&
			!strings.Contains(pl, "notice") &&
			!strings.Contains(pl, "copying") &&
			p != "" {
			return p
		}
	}
	return "unknown-component"
}

// ──────────────────── WASM ────────────────────

func scanWASM(data []byte) []Finding {
	var out []Finding
	if len(data) < 8 {
		out = append(out, Finding{
			ID: "wasm/truncated", Title: "Truncated WASM module",
			Severity: SevHigh, Category: "structural",
			Detail: "Header is shorter than 8 bytes.",
		})
		return out
	}
	if !(data[0] == 0x00 && data[1] == 'a' && data[2] == 's' && data[3] == 'm') {
		out = append(out, Finding{
			ID: "wasm/bad-magic", Title: "Bad WASM magic",
			Severity: SevMedium, Category: "structural",
			Detail: "First 4 bytes are not \\x00asm.",
		})
		return out
	}
	// Imports section is id=2; if present, advertise it.
	if findWASMSection(data, 2) {
		out = append(out, Finding{
			ID: "wasm/imports", Title: "WASM module declares host imports",
			Severity: SevLow, Category: "structural",
			Detail: "Module imports host functions — review the host bindings.",
		})
	}
	if findWASMSection(data, 7) {
		out = append(out, Finding{
			ID: "wasm/exports", Title: "WASM module exports symbols",
			Severity: SevLow, Category: "structural",
			Detail: "Module exposes functions to the host.",
		})
	}
	return out
}

// findWASMSection scans the (very simple) section list for a given id.
// Returns true if the section is present. Does not validate sizes.
func findWASMSection(data []byte, id byte) bool {
	if len(data) < 8 {
		return false
	}
	pos := 8
	for pos < len(data) {
		secID := data[pos]
		pos++
		size, n := readVarUint(data[pos:])
		if n == 0 {
			return false
		}
		pos += n
		if secID == id {
			return true
		}
		pos += int(size)
	}
	return false
}

func readVarUint(b []byte) (uint64, int) {
	var x uint64
	var s uint
	for i := 0; i < len(b) && i < 10; i++ {
		x |= uint64(b[i]&0x7f) << s
		if b[i]&0x80 == 0 {
			return x, i + 1
		}
		s += 7
	}
	return 0, 0
}

// ──────────────────── Smali ────────────────────

var (
	reSmaliDebuggable    = regexp.MustCompile(`FLAG_DEBUGGABLE`)
	reSmaliReflectInvoke = regexp.MustCompile(`Ljava/lang/reflect/Method;->invoke`)
	reSmaliClassForName  = regexp.MustCompile(`Ljava/lang/Class;->forName`)
	reSmaliNativeLoad    = regexp.MustCompile(`Ljava/lang/System;->loadLibrary`)
	reSmaliIntentAction  = regexp.MustCompile(`"android\.intent\.action\.BOOT_COMPLETED"`)
)

func scanSmali(text string) []Finding {
	rules := []reFinder{
		{reSmaliDebuggable, "smali/flag-debuggable", "FLAG_DEBUGGABLE check", SevHigh, "anti-debug", "Checks ApplicationInfo.FLAG_DEBUGGABLE to detect debugging."},
		{reSmaliReflectInvoke, "smali/reflection-invoke", "Reflection Method.invoke()", SevHigh, "reflection", "Invokes methods dynamically via reflection."},
		{reSmaliClassForName, "smali/class-forname", "Reflection Class.forName()", SevMedium, "reflection", "Resolves class names dynamically (possible obfuscation wrapper)."},
		{reSmaliNativeLoad, "smali/native-library-load", "Native library load", SevMedium, "native", "Loads dynamic/native shared libraries at runtime."},
		{reSmaliIntentAction, "smali/intent-filter-action", "BOOT_COMPLETED intent action", SevLow, "persistence", "Monitors device boot to start background service (autostart)."},
	}
	var out []Finding
	for _, r := range rules {
		out = append(out, r.find(text)...)
	}
	return out
}
