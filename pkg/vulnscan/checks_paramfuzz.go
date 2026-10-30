package vulnscan

// Shared helpers for endpoint-level parameter fuzzing used by the newer
// detectors (NoSQL / LDAP / XPath / timing / ReDoS). They operate on the query
// parameters already present on the scan target, which keeps false positives
// low: we only perturb inputs the application actually consumes.

import (
	"net/http"
	"strings"
	"time"
)

// paramProbe is the result of a single parameter perturbation.
type paramProbe struct {
	Status  int
	Body    string
	Elapsed time.Duration
	OK      bool
}

// targetParams returns the names of the query parameters present on the scan
// target. Endpoint-level active checks fuzz exactly these.
func (s *Scanner) targetParams() []string {
	if s.BaseURL == nil {
		return nil
	}
	var out []string
	for k := range s.BaseURL.Query() {
		out = append(out, k)
	}
	return out
}

// applyAuthHeaders copies the configured authentication material onto a probe
// request so authenticated surfaces can be tested.
func (s *Scanner) applyAuthHeaders(req *http.Request) {
	if s.Config.UserAgent != "" {
		req.Header.Set("User-Agent", s.Config.UserAgent)
	}
	if s.Config.AuthCookie != "" {
		req.Header.Set("Cookie", s.Config.AuthCookie)
	}
	if s.Config.AuthBearer != "" {
		req.Header.Set("Authorization", "Bearer "+s.Config.AuthBearer)
	}
}

// probeQueryParam issues a GET against the target with a single query parameter
// overridden to value, returning a compact probe result.
func (s *Scanner) probeQueryParam(param, value string) paramProbe {
	if s.BaseURL == nil || s.Client == nil {
		return paramProbe{}
	}
	u := *s.BaseURL
	q := u.Query()
	q.Set(param, value)
	u.RawQuery = q.Encode()

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return paramProbe{}
	}
	s.applyAuthHeaders(req)

	start := time.Now()
	resp, err := s.Client.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		return paramProbe{}
	}
	defer resp.Body.Close()

	body, err := ReadBodyBounded(resp, int64(s.Config.MaxBodyBytes))
	if err != nil {
		return paramProbe{Status: resp.StatusCode, Elapsed: elapsed, OK: true}
	}
	return paramProbe{Status: resp.StatusCode, Body: string(body), Elapsed: elapsed, OK: true}
}

// containsAnyFold reports whether haystack contains any of the needles,
// case-insensitively. Needles must be supplied lowercase.
func containsAnyFold(haystack string, needles []string) (string, bool) {
	lower := strings.ToLower(haystack)
	for _, n := range needles {
		if strings.Contains(lower, n) {
			return n, true
		}
	}
	return "", false
}
