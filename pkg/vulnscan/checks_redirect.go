package vulnscan

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// openRedirectParams is the list of common redirect parameter names to probe
var openRedirectParams = []string{
	"redirect", "redirect_uri", "redirect_url",
	"url", "uri",
	"next", "next_url",
	"return", "return_to", "return_url",
	"redir", "redir_url",
	"goto", "go",
	"continue", "continue_url",
	"callback", "callback_url",
	"dest", "destination",
	"target",
	"forward",
	"successUrl", "failureUrl",
	"ref", "referrer",
	"out",
}

// openRedirectPayloads are tested as values for the redirect parameters
var openRedirectPayloads = []string{
	"//evil-attacker.com",
	"https://evil-attacker.com",
	"//evil-attacker.com/%2F..",
	"///evil-attacker.com",
	"/\\evil-attacker.com",
	"https:evil-attacker.com",
	"//\t@evil-attacker.com",
}

// checkOpenRedirect probes known redirect parameters on the target for Open Redirect.
func (s *Scanner) checkOpenRedirect() []Vulnerability {
	var list []Vulnerability
	seen := make(map[string]bool) // deduplicate by param name

	for _, param := range openRedirectParams {
		if seen[param] {
			continue
		}

		for _, payload := range openRedirectPayloads {
			u, err := url.Parse(s.Target)
			if err != nil {
				continue
			}
			q := u.Query()
			q.Set(param, payload)
			u.RawQuery = q.Encode()
			testURL := u.String()

			req, err := http.NewRequest("GET", testURL, nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", s.Config.UserAgent)

			resp, err := s.Client.Do(req)

			if err != nil {
				continue
			}
			io.Copy(io.Discard, resp.Body) //nolint:errcheck
			resp.Body.Close()

			// Check for redirect to attacker-controlled domain
			if resp.StatusCode >= 300 && resp.StatusCode < 400 {
				location := resp.Header.Get("Location")
				if isExternalRedirect(location, s.BaseURL.Host) {
					seen[param] = true
					list = append(list, Vulnerability{
						ID:          "WS-REDIR-001",
						Name:        "Open Redirect",
						Description: "The application redirects users to an arbitrary external URL controlled by an attacker via an unvalidated redirect parameter.",
						Severity:    SeverityMedium,
						URL:         testURL,
						Parameter:   param,
						Payload:     payload,
						Evidence:    fmt.Sprintf("HTTP %d → Location: %s", resp.StatusCode, location),
						Mitigation:  "Validate redirect destinations against a strict allowlist of trusted domains. Never redirect to user-supplied URLs directly.",
					})
					break // one finding per param is enough
				}
			}

			// Also check for meta refresh or JS redirect in body (soft redirect)
			// (not done here to keep it lightweight — handled by passive rules)
		}
	}

	// Also probe forms discovered during crawl for redirect params
	// This is handled by RunDynamicFuzzRules with a dedicated rule if configured.

	return list
}

// isExternalRedirect returns true if location redirects outside the target host.
func isExternalRedirect(location, targetHost string) bool {
	if location == "" {
		return false
	}
	if strings.HasPrefix(location, "//") || strings.HasPrefix(location, "http") {
		parsed, err := url.Parse(location)
		if err != nil {
			return false
		}
		// If the host differs from the target, it's an external redirect
		lHost := strings.TrimPrefix(parsed.Host, "www.")
		tHost := strings.TrimPrefix(targetHost, "www.")
		return lHost != "" && lHost != tHost
	}
	return false
}
