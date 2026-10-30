package vulnscan

// OAuth2 / OIDC authorization-endpoint weaknesses:
//   WS-OAUTH-001  PKCE downgrade (code_challenge_method=plain accepted, or PKCE
//                 not enforced for a public client)  (CWE-757)
//   WS-OAUTH-002  redirect_uri validation bypass (open redirect on the
//                 authorization endpoint)             (CWE-601)
// The detector only activates when the target already looks like an OAuth
// authorization endpoint (carries response_type + client_id), so it never fires
// on unrelated pages.

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// isAuthorizeEndpoint reports whether the target looks like an OAuth authorize
// endpoint and returns its parsed query.
func (s *Scanner) authorizeQuery() (url.Values, bool) {
	if s.BaseURL == nil {
		return nil, false
	}
	q := s.BaseURL.Query()
	if q.Get("response_type") == "" || q.Get("client_id") == "" {
		return nil, false
	}
	pathLooksAuth := strings.Contains(strings.ToLower(s.BaseURL.Path), "auth")
	if !pathLooksAuth && q.Get("redirect_uri") == "" {
		return nil, false
	}
	return q, true
}

// redirectlessClient issues a GET without following redirects.
func (s *Scanner) noRedirectGet(rawURL string) (*http.Response, bool) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, false
	}
	s.applyAuthHeaders(req)
	client := *s.Client
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, false
	}
	return resp, true
}

// checkOAuthPKCE checks whether the authorization endpoint enforces PKCE and
// rejects the downgradable "plain" challenge method.
func (s *Scanner) checkOAuthPKCE() []Vulnerability {
	var list []Vulnerability
	q, ok := s.authorizeQuery()
	if !ok {
		return list
	}

	u := *s.BaseURL
	vals := cloneValues(q)
	vals.Set("code_challenge", "plainchallenge")
	vals.Set("code_challenge_method", "plain")
	u.RawQuery = vals.Encode()

	resp, ok := s.noRedirectGet(u.String())
	if !ok {
		return list
	}
	loc := resp.Header.Get("Location")
	resp.Body.Close()

	// If the server redirects back with a code (i.e. accepts plain PKCE without
	// error), the downgrade is honored.
	if (resp.StatusCode == 302 || resp.StatusCode == 303) && strings.Contains(loc, "code=") &&
		!strings.Contains(strings.ToLower(loc), "error=") {
		list = append(list, Vulnerability{
			ID:          "WS-OAUTH-001",
			Name:        "PKCE Downgrade (plain challenge accepted)",
			Description: "The authorization endpoint issued an authorization code for code_challenge_method=plain, allowing an attacker who intercepts the code to bypass PKCE protection intended for the S256 method.",
			Severity:    SeverityMedium,
			URL:         s.Target,
			Parameter:   "code_challenge_method",
			Payload:     "code_challenge_method=plain",
			Evidence:    fmt.Sprintf("Authorization redirect returned a code for the plain method: %s", truncate(loc, 200)),
			Mitigation:  "Require code_challenge_method=S256 for public clients and reject the plain method.",
		})
	}
	return list
}

// checkOAuthRedirectURI tests redirect_uri validation on the authorization
// endpoint using conservative bypass mutations.
func (s *Scanner) checkOAuthRedirectURI() []Vulnerability {
	var list []Vulnerability
	q, ok := s.authorizeQuery()
	if !ok {
		return list
	}
	original := q.Get("redirect_uri")
	if original == "" {
		return list
	}
	origHost := hostOf(original)
	if origHost == "" {
		return list
	}

	attacker := "https://attacker-oauth-poc.example"
	mutations := []string{
		attacker,                                 // wholesale replacement
		original + ".attacker-oauth-poc.example", // suffix append
		original + "@attacker-oauth-poc.example", // userinfo confusion
		attacker + "?" + original,                // prefix trick
		original + "/../../attacker",             // path traversal
	}

	for _, m := range mutations {
		u := *s.BaseURL
		vals := cloneValues(q)
		vals.Set("redirect_uri", m)
		u.RawQuery = vals.Encode()

		resp, gok := s.noRedirectGet(u.String())
		if !gok {
			continue
		}
		loc := resp.Header.Get("Location")
		resp.Body.Close()
		if loc == "" {
			continue
		}
		locHost := hostOf(loc)
		// A bypass is confirmed when the server redirects to a host we control
		// (and not the legitimately registered host).
		if locHost == "attacker-oauth-poc.example" && locHost != origHost {
			list = append(list, Vulnerability{
				ID:          "WS-OAUTH-002",
				Name:        "OAuth redirect_uri Validation Bypass",
				Description: "The authorization endpoint accepted a manipulated redirect_uri and redirected to an attacker-controlled host, enabling authorization-code/token theft.",
				Severity:    SeverityHigh,
				URL:         s.Target,
				Parameter:   "redirect_uri",
				Payload:     m,
				Evidence:    fmt.Sprintf("Location redirected to attacker host: %s", truncate(loc, 200)),
				Mitigation:  "Match redirect_uri against an exact, pre-registered allowlist (full string comparison including scheme, host, port, path). Reject partial/suffix/substring matches.",
			})
			break
		}
	}
	return list
}

func cloneValues(v url.Values) url.Values {
	out := url.Values{}
	for k, vs := range v {
		for _, x := range vs {
			out.Add(k, x)
		}
	}
	return out
}

func hostOf(raw string) string {
	p, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return p.Hostname()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
