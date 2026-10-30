package vulnscan

// Package check: OS command injection and time-based blind SQL injection.
//
// Detection methodology: differential + statistical timing analysis rather than
// naive string matching.
//   - Command injection uses two independent signals: (a) a transformed
//     canary emitted by a shell printf command which cannot be a direct payload
//     reflection, and (b) a statistically significant response delay from a
//     `sleep`/`ping` payload versus a multi-sample timing baseline.
//   - Blind SQLi uses a SLEEP()-style payload and the same timing-anomaly test.
// Known limitations: heavily rate-limited or high-jitter targets can mask the
// timing signal; the statistical floor (minDeltaMs) mitigates false positives.
// References: CWE-78, CWE-89, OWASP A03:2021, PortSwigger blind-injection labs.

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func init() {
	RegisterCheck(CheckDescriptor{
		ID:           "WS-CMDI-001",
		Name:         "OS Command Injection",
		CWE:          []int{78},
		OWASP:        []string{"A03:2021"},
		Phase:        PhaseActive,
		Invasiveness: InvDestructive,
		Run:          runCommandInjection,
	})
	RegisterCheck(CheckDescriptor{
		ID:           "WS-SQLI-BLIND-001",
		Name:         "Time-based Blind SQL Injection",
		CWE:          []int{89},
		OWASP:        []string{"A03:2021"},
		Phase:        PhaseActive,
		Invasiveness: InvDestructive,
		Run:          runBlindSQLi,
	})
}

// buildSurfaceRequest constructs a probe request that carries `value` in the
// targeted injection point and a benign value in every other point.
func buildSurfaceRequest(s *Scanner, surface *AttackSurface, point InjectionPoint, value string) (*http.Request, error) {
	method := "GET"
	rawURL := ""
	if surface.BaseRequest != nil {
		if surface.BaseRequest.Method != "" {
			method = strings.ToUpper(surface.BaseRequest.Method)
		}
		rawURL = surface.BaseRequest.URL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if !u.IsAbs() && s.BaseURL != nil {
		u = s.BaseURL.ResolveReference(u)
	}

	vals := url.Values{}
	for _, p := range surface.InjectionPoints {
		v := "1"
		if p.Name == point.Name {
			v = value
		}
		vals.Set(p.Name, v)
	}
	if len(surface.InjectionPoints) == 0 {
		vals.Set(point.Name, value)
	}

	var req *http.Request
	switch method {
	case "POST", "PUT", "PATCH", "DELETE":
		req, err = http.NewRequest(method, u.String(), strings.NewReader(vals.Encode()))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	default:
		q := u.Query()
		for k, vv := range vals {
			for _, x := range vv {
				q.Set(k, x)
			}
		}
		u.RawQuery = q.Encode()
		req, err = http.NewRequest(method, u.String(), nil)
		if err != nil {
			return nil, err
		}
	}

	if s.Config.UserAgent != "" {
		req.Header.Set("User-Agent", s.Config.UserAgent)
	}
	if s.Config.AuthCookie != "" {
		req.Header.Set("Cookie", s.Config.AuthCookie)
	}
	if s.Config.AuthBearer != "" {
		req.Header.Set("Authorization", "Bearer "+s.Config.AuthBearer)
	}
	return req, nil
}

// sendAndSign sends a request and returns its response signature (bounded body).
func sendAndSign(s *Scanner, req *http.Request) (*ResponseSignature, error) {
	if s.Client == nil {
		return nil, fmt.Errorf("scanner has no HTTP client")
	}
	start := time.Now()
	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := ReadBodyBounded(resp, int64(s.Config.MaxBodyBytes))
	elapsed := time.Since(start).Milliseconds()
	return ComputeResponseSignature(resp.StatusCode, resp.Header, body, elapsed), nil
}

// sendCapture sends a request and returns the (bounded) response body.
func sendCapture(s *Scanner, req *http.Request) ([]byte, int, error) {
	if s.Client == nil {
		return nil, 0, fmt.Errorf("scanner has no HTTP client")
	}
	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, _ := ReadBodyBounded(resp, int64(s.Config.MaxBodyBytes))
	return body, resp.StatusCode, nil
}

// collectTimingBaseline sends the benign value `n` times and returns the
// observed latencies (milliseconds) for use as a statistical baseline.
func collectTimingBaseline(s *Scanner, surface *AttackSurface, point InjectionPoint, n int) []int64 {
	var samples []int64
	for i := 0; i < n; i++ {
		req, err := buildSurfaceRequest(s, surface, point, "1")
		if err != nil {
			break
		}
		if !s.InScope(req.URL.String()) {
			break
		}
		sig, err := sendAndSign(s, req)
		if err != nil || sig == nil {
			continue
		}
		samples = append(samples, sig.TimingMs)
	}
	return samples
}

func runCommandInjection(s *Scanner, surface *AttackSurface) []Finding {
	if surface == nil || s == nil || s.Client == nil {
		return nil
	}
	var findings []Finding

	for _, point := range surface.InjectionPoints {
		if point.DataType == TypeUUID || point.DataType == TypeToken {
			continue // opaque identifiers are not command sinks
		}

		// The payload encodes the canary, so direct payload reflection cannot
		// satisfy the check. Only shell evaluation produces the plain marker.
		canary := NewCanary("cmd" + point.Name)
		encodedCanary := shellOctalEncode(canary)
		echoPayloads := []string{
			";printf '" + encodedCanary + "'",
			"&&printf '" + encodedCanary + "'",
			"|printf '" + encodedCanary + "'",
		}
		detected := false
		for _, pl := range echoPayloads {
			req, err := buildSurfaceRequest(s, surface, point, pl)
			if err != nil {
				continue
			}
			if !s.InScope(req.URL.String()) {
				continue
			}
			body, _, herr := sendCapture(s, req)
			if herr != nil {
				continue
			}
			if strings.Contains(string(body), canary) {
				f := Finding{Vulnerability: Vulnerability{
					ID:          "WS-CMDI-001",
					Name:        "OS command injection (command output reflected)",
					Description: fmt.Sprintf("Parameter %q on %s reflected the plain output of an injected shell command (canary %q), confirming OS command injection.", point.Name, req.URL.String(), canary),
					Severity:    SeverityCritical,
					URL:         req.URL.String(),
					Parameter:   point.Name,
					Payload:     pl,
					Evidence:    canary,
					Mitigation:  "Never pass user input to a shell. Use exec APIs with argument arrays and strict allowlists; validate and escape all inputs.",
				}}
				EnrichWithTaxonomy(&f)
				ApplyConfidence(&f, SigReflectedVerbatim, SigDifferentialOnly, SigMultiPayloadTrigger)
				findings = append(findings, f)
				detected = true
				break
			}
		}
		if detected {
			continue
		}

		// (b) Time-based detection against a statistical baseline.
		baseline := collectTimingBaseline(s, surface, point, 3)
		if len(baseline) == 0 {
			continue
		}
		timePayloads := []string{";sleep 5", "| sleep 5", "$(sleep 5)", "`sleep 5`", "& ping -c 5 127.0.0.1"}
		for _, pl := range timePayloads {
			req, err := buildSurfaceRequest(s, surface, point, pl)
			if err != nil {
				continue
			}
			if !s.InScope(req.URL.String()) {
				continue
			}
			sig, err := sendAndSign(s, req)
			if err != nil || sig == nil {
				continue
			}
			if TimingIsAnomalous(baseline, sig.TimingMs, 3.0, 4000) {
				f := Finding{Vulnerability: Vulnerability{
					ID:          "WS-CMDI-001",
					Name:        "OS command injection (time-based blind)",
					Description: fmt.Sprintf("Parameter %q on %s introduced a response delay consistent with an injected sleep command versus a statistical baseline, indicating blind OS command injection.", point.Name, req.URL.String()),
					Severity:    SeverityCritical,
					URL:         req.URL.String(),
					Parameter:   point.Name,
					Payload:     pl,
					Mitigation:  "Never pass user input to a shell. Use exec APIs with argument arrays and strict allowlists; validate and escape all inputs.",
				}}
				EnrichWithTaxonomy(&f)
				ApplyConfidence(&f, SigTimingAnomaly, SigDifferentialOnly)
				findings = append(findings, f)
				break
			}
		}
	}
	return findings
}

func shellOctalEncode(value string) string {
	var encoded strings.Builder
	for _, b := range []byte(value) {
		fmt.Fprintf(&encoded, `\%03o`, b)
	}
	return encoded.String()
}

func runBlindSQLi(s *Scanner, surface *AttackSurface) []Finding {
	if surface == nil || s == nil || s.Client == nil {
		return nil
	}
	var findings []Finding

	for _, point := range surface.InjectionPoints {
		if SelectSQLiPayloads(point) == nil {
			continue // UUID/token fields: skip
		}
		baseline := collectTimingBaseline(s, surface, point, 3)
		if len(baseline) == 0 {
			continue
		}
		sleepPayloads := []string{
			"1' AND SLEEP(5)-- -",
			"1 AND SLEEP(5)",
			"1); SELECT SLEEP(5)-- -",
			"' OR SLEEP(5)-- -",
			"1 || pg_sleep(5)",
		}
		for _, pl := range sleepPayloads {
			req, err := buildSurfaceRequest(s, surface, point, pl)
			if err != nil {
				continue
			}
			if !s.InScope(req.URL.String()) {
				continue
			}
			sig, err := sendAndSign(s, req)
			if err != nil || sig == nil {
				continue
			}
			if TimingIsAnomalous(baseline, sig.TimingMs, 3.0, 4000) {
				f := Finding{Vulnerability: Vulnerability{
					ID:          "WS-SQLI-BLIND-001",
					Name:        "Time-based blind SQL injection",
					Description: fmt.Sprintf("Parameter %q on %s exhibited a response delay consistent with a SQL SLEEP()/pg_sleep() payload versus a statistical timing baseline, indicating time-based blind SQL injection.", point.Name, req.URL.String()),
					Severity:    SeverityCritical,
					URL:         req.URL.String(),
					Parameter:   point.Name,
					Payload:     pl,
					Mitigation:  "Use parameterized queries / prepared statements; never concatenate user input into SQL. Apply least-privilege DB accounts.",
				}}
				EnrichWithTaxonomy(&f)
				ApplyConfidence(&f, SigTimingAnomaly, SigDifferentialOnly)
				findings = append(findings, f)
				break
			}
		}
	}
	return findings
}
