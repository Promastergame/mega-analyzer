package vulnscan

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// testPrototypePollution checks for client-side/server-side prototype pollution vectors.
// It injects `__proto__[poc]=polluted` into URL parameters.
func (s *Scanner) testPrototypePollution(form Form) []Vulnerability {
	var list []Vulnerability

	if form.Method != "GET" {
		return list // Simplified for now, mostly testing query params
	}

	for _, inputName := range form.Inputs {
		payloads := []string{
			"__proto__[poc]=polluted",
			"constructor[prototype][poc]=polluted",
		}

		for _, payload := range payloads {
			vals := url.Values{}
			for _, inp := range form.Inputs {
				vals.Set(inp, "test")
			}

			// We need to append the payload directly to the raw query to avoid URL encoding of brackets
			// if we want to test raw parsing, but net/url encodes them. We'll do a simple string append.
			u, _ := url.Parse(form.Action)
			u.RawQuery = vals.Encode()

			queryWithPayload := u.RawQuery
			if queryWithPayload != "" {
				queryWithPayload += "&"
			}
			queryWithPayload += payload

			testURL := fmt.Sprintf("%s://%s%s?%s", u.Scheme, u.Host, u.Path, queryWithPayload)

			req, _ := http.NewRequest("GET", testURL, nil)
			req.Header.Set("User-Agent", s.Config.UserAgent)

			resp, err := s.Client.Do(req)

			if err != nil {
				continue
			}

			bodyBytes := s.readBody(resp)
			body := string(bodyBytes)
			resp.Body.Close()

			// Check if the payload was evaluated or reflected in a suspicious way.
			// True server-side PP detection usually requires out-of-band or specific error messages (e.g. Object.prototype changes).
			// Here we use a heuristic: if the server responds with JSON and includes the polluted property at the root level.

			if strings.Contains(body, `"poc":"polluted"`) || strings.Contains(body, `"poc": "polluted"`) {
				list = append(list, Vulnerability{
					ID:          "WS-PROTO-001",
					Name:        "Potential Prototype Pollution",
					Description: fmt.Sprintf("Injected a prototype pollution payload (%s) and it was reflected back in the response, suggesting the backend (likely Node.js) or frontend might have merged it into an object prototype.", payload),
					Severity:    SeverityLow, // Requires manual verification
					URL:         form.Action,
					Parameter:   inputName,
					Payload:     payload,
					Evidence:    "The property 'poc':'polluted' was found in the response body.",
					Mitigation:  "Avoid recursive merge functions without prototype safeguards. Use Object.create(null) or validate keys (reject __proto__ and constructor).",
				})
			}
		}
	}

	return list
}
