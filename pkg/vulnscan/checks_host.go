package vulnscan

import (
	"fmt"
	"net/http"
	"strings"
)

// checkHostHeaderInjection tests for Host Header Injection vulnerabilities.
func (s *Scanner) checkHostHeaderInjection() []Vulnerability {
	var list []Vulnerability

	poisonHost := "evil-host-header-test.com"

	// Test both the 'Host' header and 'X-Forwarded-Host'
	headersToTest := map[string]string{
		"Host":             poisonHost,
		"X-Forwarded-Host": poisonHost,
	}

	for headerName, payload := range headersToTest {
		req, err := http.NewRequest("GET", s.Target, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", s.Config.UserAgent)

		if headerName == "Host" {
			req.Host = payload
		} else {
			req.Header.Set(headerName, payload)
		}

		// We use a custom client that doesn't follow redirects automatically
		// because we want to inspect the Location header
		client := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		if s.Config.IOwnThisTarget { // Only apply custom transport if needed
			client.Transport = s.Client.Transport
		}

		resp, err := client.Do(req)

		if err != nil {
			continue
		}

		bodyBytes := s.readBody(resp)
		body := string(bodyBytes)
		resp.Body.Close()

		triggered := false
		evidence := ""

		// 1. Check if reflected in Location header (Open Redirect via Host Header)
		location := resp.Header.Get("Location")
		if location != "" && strings.Contains(location, poisonHost) {
			triggered = true
			evidence = fmt.Sprintf("Reflected in Location header: %s", location)
		}

		// 2. Check if reflected in response body (e.g., generating absolute URLs)
		if !triggered && strings.Contains(body, poisonHost) {
			triggered = true
			evidence = "Reflected in response body (likely in generated links or scripts)."
		}

		if triggered {
			list = append(list, Vulnerability{
				ID:          "WS-HOST-001",
				Name:        "Host Header Injection",
				Description: fmt.Sprintf("The server trusts the user-supplied '%s' header and reflects it in the response. This can lead to Web Cache Poisoning, Open Redirects, or Password Reset Poisoning.", headerName),
				Severity:    SeverityMedium,
				URL:         s.Target,
				Payload:     fmt.Sprintf("%s: %s", headerName, payload),
				Evidence:    evidence,
				Mitigation:  "Do not rely on the Host header for generating links or redirects. Use a statically configured server name/URL. If you must use it, validate it against an allowlist.",
			})
		}
	}

	return list
}
