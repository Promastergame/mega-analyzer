package vulnscan

import (
	"fmt"
	"net/http"
	"strings"
)

// checkCookieFlags inspects Set-Cookie headers in an HTTP response for missing security flags.
func (s *Scanner) checkCookieFlags(resp *http.Response) []Vulnerability {
	var list []Vulnerability

	cookies := resp.Cookies()
	if len(cookies) == 0 {
		return list
	}

	isHTTPS := s.BaseURL.Scheme == "https"

	for _, cookie := range cookies {
		cookieName := cookie.Name
		isSession := isSessionCookie(cookieName)

		// ── HttpOnly ────────────────────────────────────────────────────────
		if !cookie.HttpOnly {
			sev := SeverityLow
			desc := fmt.Sprintf("The cookie '%s' is missing the HttpOnly flag, allowing JavaScript code to access it.", cookieName)
			if isSession {
				sev = SeverityHigh
				desc = fmt.Sprintf("The session cookie '%s' is missing the HttpOnly flag. JavaScript running in the page context (e.g. via XSS) can steal the session token.", cookieName)
			}
			list = append(list, Vulnerability{
				ID:          "WS-COOK-001",
				Name:        fmt.Sprintf("Cookie Missing HttpOnly Flag: %s", cookieName),
				Description: desc,
				Severity:    sev,
				URL:         s.Target,
				Evidence:    fmt.Sprintf("Set-Cookie: %s=...; (no HttpOnly)", cookieName),
				Mitigation:  "Set the HttpOnly attribute on all cookies that do not require JavaScript access, especially session tokens.",
			})
		}

		// ── Secure ──────────────────────────────────────────────────────────
		if isHTTPS && !cookie.Secure {
			sev := SeverityMedium
			desc := fmt.Sprintf("The cookie '%s' is served over HTTPS but lacks the Secure flag, which means it can also be sent over HTTP.", cookieName)
			if isSession {
				sev = SeverityHigh
				desc = fmt.Sprintf("The session cookie '%s' is missing the Secure flag, allowing it to be transmitted over unencrypted HTTP connections and intercepted by a network attacker.", cookieName)
			}
			list = append(list, Vulnerability{
				ID:          "WS-COOK-002",
				Name:        fmt.Sprintf("Cookie Missing Secure Flag: %s", cookieName),
				Description: desc,
				Severity:    sev,
				URL:         s.Target,
				Evidence:    fmt.Sprintf("Set-Cookie: %s=...; (no Secure)", cookieName),
				Mitigation:  "Set the Secure attribute on all cookies to prevent transmission over unencrypted connections.",
			})
		}

		// ── SameSite ────────────────────────────────────────────────────────
		sameSiteVal := cookie.SameSite
		if sameSiteVal == http.SameSiteDefaultMode || sameSiteVal == http.SameSiteNoneMode {
			sev := SeverityLow
			label := "SameSite=None"
			if sameSiteVal == http.SameSiteDefaultMode {
				label = "SameSite not set"
			}

			desc := fmt.Sprintf("The cookie '%s' has %s, which may allow cross-site request forgery (CSRF) attacks.", cookieName, label)
			if isSession && sameSiteVal == http.SameSiteNoneMode {
				sev = SeverityMedium
				desc = fmt.Sprintf("The session cookie '%s' uses SameSite=None without Secure, enabling CSRF via cross-origin requests.", cookieName)
			}

			list = append(list, Vulnerability{
				ID:          "WS-COOK-003",
				Name:        fmt.Sprintf("Cookie Weak SameSite Policy: %s (%s)", cookieName, label),
				Description: desc,
				Severity:    sev,
				URL:         s.Target,
				Evidence:    fmt.Sprintf("Set-Cookie: %s=...; %s", cookieName, label),
				Mitigation:  "Set SameSite=Lax or SameSite=Strict on session and sensitive cookies to prevent CSRF.",
			})
		}

		// ── No expiry on session cookie (optional info) ──────────────────────
		// (Not flagged as vuln — informational note only, skip for brevity)
	}

	return list
}

// isSessionCookie returns true if the cookie name looks like a session identifier.
func isSessionCookie(name string) bool {
	sessionPatterns := []string{
		"sess", "session", "sid", "token", "auth", "jwt",
		"PHPSESSID", "JSESSIONID", "ASP.NET_SessionId",
		"connect.sid", "laravel_session", "csrf",
	}
	lower := strings.ToLower(name)
	for _, p := range sessionPatterns {
		if strings.Contains(lower, strings.ToLower(p)) {
			return true
		}
	}
	return false
}
