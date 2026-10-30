package vulnscan

// Mass assignment / auto-binding (CWE-915). Sends privileged fields the client
// should never control to a JSON endpoint and looks for the server echoing them
// back as accepted. Only runs against JSON-speaking endpoints to keep noise low.

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

var massAssignFields = []string{"role", "is_admin", "isAdmin", "admin", "verified", "account_balance", "privilege"}

// checkMassAssignment probes the target for auto-binding of privileged fields.
func (s *Scanner) checkMassAssignment() []Vulnerability {
	var list []Vulnerability
	if s.Client == nil {
		return list
	}
	// Unlike the other Step 4 checks this sends real POST/PUT/PATCH bodies to
	// the target — it can create or modify live state, not just observe it.
	// Require the same explicit LabMode opt-in as the raw-TCP desync test.
	if !s.Config.LabMode {
		return list
	}

	// Only meaningful where the endpoint accepts/returns JSON.
	baseCT, _, ok := s.baselineContentType()
	if !ok || !strings.Contains(strings.ToLower(baseCT), "json") {
		return list
	}

	sentinel := "maSSpwn_9137"
	payload := fmt.Sprintf(`{"role":"%s","is_admin":true,"isAdmin":true,"verified":true,"privilege":"%s"}`, sentinel, sentinel)

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch} {
		req, err := http.NewRequest(method, s.Target, strings.NewReader(payload))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		s.applyAuthHeaders(req)

		resp, err := s.Client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, int64(maxOrDefault(s.Config.MaxBodyBytes, 1<<20))))
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 && strings.Contains(string(body), sentinel) {
			// The server accepted and reflected a privileged field we injected.
			var reflected []string
			lowerBody := strings.ToLower(string(body))
			for _, f := range massAssignFields {
				if strings.Contains(lowerBody, strings.ToLower(f)) {
					reflected = append(reflected, f)
				}
			}
			list = append(list, Vulnerability{
				ID:          "WS-MASSA-001",
				Name:        "Mass Assignment / Auto-Binding",
				Description: "The endpoint accepted and echoed privileged fields supplied by the client, indicating the model binds request attributes without an allowlist. An attacker may escalate privileges by setting fields such as role or is_admin.",
				Severity:    SeverityHigh,
				URL:         s.Target,
				Payload:     payload,
				Evidence:    fmt.Sprintf("%s %d accepted; sentinel reflected. Privileged fields present in response: %s", method, resp.StatusCode, strings.Join(reflected, ", ")),
				Mitigation:  "Bind only an explicit allowlist of client-writable fields (DTOs/strong parameters). Never mass-assign request bodies onto persistence models.",
			})
			break
		}
	}

	return list
}

// baselineContentType issues a GET and returns the Content-Type and body.
func (s *Scanner) baselineContentType() (string, string, bool) {
	req, err := http.NewRequest(http.MethodGet, s.Target, nil)
	if err != nil {
		return "", "", false
	}
	s.applyAuthHeaders(req)
	resp, err := s.Client.Do(req)
	if err != nil {
		return "", "", false
	}
	defer resp.Body.Close()
	body, _ := ReadBodyBounded(resp, int64(s.Config.MaxBodyBytes))
	return resp.Header.Get("Content-Type"), string(body), true
}

func maxOrDefault(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}
