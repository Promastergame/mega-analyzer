package vulnscan

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

// checkCORS tests for CORS misconfiguration by spoofing the Origin header.
// Detects:
//   - Wildcard ACAO with credentials (critical)
//   - Attacker origin reflected in ACAO (high)
//   - Null origin allowed (medium)
func (s *Scanner) checkCORS() []Vulnerability {
	var list []Vulnerability

	type originTest struct {
		origin   string
		id       string
		label    string
		severity Severity
	}

	tests := []originTest{
		{
			origin:   "https://evil-attacker.com",
			id:       "WS-CORS-001",
			label:    "CORS — Arbitrary Origin Reflected",
			severity: SeverityHigh,
		},
		{
			origin:   "null",
			id:       "WS-CORS-002",
			label:    "CORS — Null Origin Allowed",
			severity: SeverityMedium,
		},
		{
			origin:   fmt.Sprintf("https://evil-%s", s.BaseURL.Host),
			id:       "WS-CORS-003",
			label:    "CORS — Subdomain/Prefix Origin Bypass",
			severity: SeverityHigh,
		},
	}

	for _, test := range tests {
		req, err := http.NewRequest("GET", s.Target, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", s.Config.UserAgent)
		req.Header.Set("Origin", test.origin)

		resp, err := s.Client.Do(req)

		if err != nil {
			continue
		}
		io.Copy(io.Discard, resp.Body) //nolint:errcheck
		resp.Body.Close()

		acao := resp.Header.Get("Access-Control-Allow-Origin")
		acac := strings.ToLower(resp.Header.Get("Access-Control-Allow-Credentials"))

		if acao == "" {
			continue
		}

		// Case 1: wildcard with credentials — critical
		if acao == "*" && acac == "true" {
			list = append(list, Vulnerability{
				ID:          "WS-CORS-000",
				Name:        "CORS — Wildcard Origin with Credentials",
				Description: "The server returns Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true, which browsers reject but indicates a misconfiguration that may be exploited via other vectors.",
				Severity:    SeverityCritical,
				URL:         s.Target,
				Evidence:    fmt.Sprintf("ACAO: %s | ACAC: %s", acao, acac),
				Mitigation:  "Never combine wildcard origin with credentials. Explicitly allow only trusted origins.",
			})
			continue
		}

		// Case 2: attacker origin reflected
		if acao == test.origin || acao == "*" {
			severity := test.severity
			desc := fmt.Sprintf("The server reflects the attacker-controlled Origin '%s' in the Access-Control-Allow-Origin header.", test.origin)
			mitigation := "Maintain a strict server-side allowlist of trusted origins. Do not reflect the request Origin header without validation."

			// Escalate to Critical if credentials are also enabled
			if acac == "true" {
				severity = SeverityCritical
				desc += " Combined with Access-Control-Allow-Credentials: true, this allows cross-origin authenticated requests from any website."
				mitigation = "Remove Access-Control-Allow-Credentials or restrict ACAO to a validated allowlist. Never reflect arbitrary origins with credentials."
			}

			list = append(list, Vulnerability{
				ID:          test.id,
				Name:        test.label,
				Description: desc,
				Severity:    severity,
				URL:         s.Target,
				Evidence:    fmt.Sprintf("Sent Origin: %s → ACAO: %s | ACAC: %s", test.origin, acao, acac),
				Mitigation:  mitigation,
			})
		}
	}

	return list
}
