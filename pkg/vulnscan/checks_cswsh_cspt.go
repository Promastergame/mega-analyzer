package vulnscan

// Passive, response-body heuristics (no extra requests):
//   WS-CSPT-001   Client-Side Path Traversal sink in served JavaScript (CWE-22)
//   WS-CSWSH-001  Cross-Site WebSocket Hijacking exposure (CWE-1385 / CWE-352)
// These run on already-fetched response bodies alongside secret detection, so
// they add coverage without extra traffic. They are heuristic and therefore
// emit lower-severity findings meant for manual confirmation.

import (
	"fmt"
	"regexp"
	"strings"
)

// CSPT: user-influenced value concatenated directly into a request path passed
// to fetch/XHR/axios. We look for path building from location/query values.
var csptSinkPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)fetch\(\s*["'` + "`" + `][^"'` + "`" + `]*["'` + "`" + `]\s*\+\s*(location|window\.location|document\.location|params|query|searchparams)`),
	regexp.MustCompile(`(?i)(axios|xhr|\$\.(get|post|ajax))[^;\n]{0,80}\+\s*(location|window\.location|params|searchparams)`),
	regexp.MustCompile(`(?i)\.open\(\s*["'][A-Z]+["']\s*,\s*["'` + "`" + `][^"'` + "`" + `]*["'` + "`" + `]\s*\+\s*(location|params|searchparams)`),
}

// CSWSH: a WebSocket is opened to a same-site endpoint that (per the served
// code) relies on ambient cookies, with no explicit origin/token check nearby.
var wsOpenPattern = regexp.MustCompile(`(?i)new\s+WebSocket\(\s*["'` + "`" + `](wss?://[^"'` + "`" + `]+|/[^"'` + "`" + `]*)`)

// checkPassiveWebExtras runs the passive body heuristics for one response.
func (s *Scanner) checkPassiveWebExtras(body, pageURL string) []Vulnerability {
	var list []Vulnerability
	if body == "" {
		return list
	}

	// --- CSPT ---
	for _, re := range csptSinkPatterns {
		if m := re.FindString(body); m != "" {
			list = append(list, Vulnerability{
				ID:          "WS-CSPT-001",
				Name:        "Client-Side Path Traversal Sink",
				Description: "Served JavaScript builds a request path by concatenating a user-influenced value (location/query) into a fetch/XHR URL. An attacker may traverse the path to reach unintended same-origin endpoints (CSPT), which can chain into CSRF or data exfiltration.",
				Severity:    SeverityLow,
				URL:         pageURL,
				Evidence:    fmt.Sprintf("Sink pattern: %s", truncate(strings.TrimSpace(m), 160)),
				Mitigation:  "Do not concatenate untrusted values into request paths; validate/encode path segments and use fixed endpoint templates with allowlisted identifiers.",
			})
			break
		}
	}

	// --- CSWSH ---
	if m := wsOpenPattern.FindString(body); m != "" {
		// Heuristic corroboration: the page/app appears to authenticate via
		// cookies (session cookie usage) and we saw no explicit origin guard
		// token in the served code.
		cookieAuth := strings.Contains(strings.ToLower(body), "document.cookie") ||
			strings.Contains(strings.ToLower(body), "withcredentials") ||
			strings.Contains(strings.ToLower(body), "session")
		originGuard := strings.Contains(strings.ToLower(body), "origin") && strings.Contains(strings.ToLower(body), "websocket")
		if cookieAuth && !originGuard {
			list = append(list, Vulnerability{
				ID:          "WS-CSWSH-001",
				Name:        "Potential Cross-Site WebSocket Hijacking",
				Description: "The page opens a WebSocket and appears to rely on ambient cookies for authentication with no visible Origin validation. If the WebSocket handshake is authenticated solely by cookies, a malicious site can open a cross-site connection and act as the victim.",
				Severity:    SeverityMedium,
				URL:         pageURL,
				Evidence:    fmt.Sprintf("WebSocket open: %s", truncate(strings.TrimSpace(m), 160)),
				Mitigation:  "Validate the Origin header on the WebSocket handshake and require a per-session CSRF/handshake token rather than relying on cookies alone.",
			})
		}
	}

	return list
}
