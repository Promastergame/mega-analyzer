package vulnscan

// CRLF injection, registry-native.
//
// Detection methodology: two independent, differential variants.
//   - Header injection: the parameter carries a CR/LF sequence followed by a
//     unique response header. The finding requires that exact header to
//     appear on the response, which is impossible without the server
//     interpreting the injected line break.
//   - Newline reflection: a control value (single canary) and an injected
//     value (canary + CR/LF + second canary) are compared. Only when the
//     response for the injected value contains a real CR/LF immediately
//     before the second canary — absent from the control — is decoded
//     newline reflection reported (log forging / response splitting surface).
// References: CWE-113, CWE-93, OWASP A03:2021.

import (
	"fmt"
	"net/http"
	"strings"
)

func init() {
	RegisterCheck(CheckDescriptor{
		ID:           "WS-CRLF-001",
		Name:         "CRLF Injection",
		CWE:          []int{113, 93},
		OWASP:        []string{"A03:2021"},
		Phase:        PhaseActive,
		Invasiveness: InvSafe,
		Run:          runCRLF,
	})
}

// sendCaptureHeaders behaves like sendCapture but also returns the response
// headers, which the header-injection variant needs as evidence.
func sendCaptureHeaders(s *Scanner, req *http.Request) ([]byte, http.Header, int, error) {
	if s.Client == nil {
		return nil, nil, 0, fmt.Errorf("scanner has no HTTP client")
	}
	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, nil, 0, err
	}
	defer resp.Body.Close()
	body, _ := ReadBodyBounded(resp, int64(s.Config.MaxBodyBytes))
	return body, resp.Header, resp.StatusCode, nil
}

func runCRLF(s *Scanner, surface *AttackSurface) []Finding {
	if surface == nil || s == nil || s.Client == nil {
		return nil
	}
	var findings []Finding

	for _, point := range surface.InjectionPoints {
		canary := NewCanary("crlf" + point.Name)
		headerName := "X-Crlf-" + canary

		// Variant 1: injected response header.
		payload := "1\r\n" + headerName + ": hit"
		req, err := buildSurfaceRequest(s, surface, point, payload)
		if err != nil || !s.InScope(req.URL.String()) {
			continue
		}
		_, hdrs, _, herr := sendCaptureHeaders(s, req)
		if herr == nil && hdrs.Get(headerName) == "hit" {
			f := Finding{Vulnerability: Vulnerability{
				ID:          "WS-CRLF-001",
				Name:        "CRLF injection (response header injection)",
				Description: fmt.Sprintf("Parameter %q on %s allowed injecting a CR/LF sequence that produced a new response header (%s). Attackers can poison caches, set cookies or split the response.", point.Name, req.URL.String(), headerName),
				Severity:    SeverityMedium,
				URL:         req.URL.String(),
				Parameter:   point.Name,
				Payload:     payload,
				Evidence:    fmt.Sprintf("response carried injected header %s: hit", headerName),
				Mitigation:  "Reject or encode CR and LF characters in user input before reflecting it into response headers or redirects.",
			}}
			EnrichWithTaxonomy(&f)
			ApplyConfidence(&f, SigReflectedVerbatim, SigDifferentialOnly)
			findings = append(findings, f)
			continue // one finding per point is enough
		}

		// Variant 2: decoded newline reflection in the body (differential).
		controlCanary := NewCanary("crlfctl" + point.Name)
		creq, err := buildSurfaceRequest(s, surface, point, controlCanary)
		if err != nil || !s.InScope(creq.URL.String()) {
			continue
		}
		cbody, _, cerr := sendCapture(s, creq)
		if cerr != nil || strings.Contains(string(cbody), canary) {
			continue
		}

		bodyPayload := controlCanary + "\r\n" + canary
		breq, err := buildSurfaceRequest(s, surface, point, bodyPayload)
		if err != nil || !s.InScope(breq.URL.String()) {
			continue
		}
		bbody, _, berr := sendCapture(s, breq)
		if berr != nil {
			continue
		}
		if strings.Contains(string(bbody), "\r\n"+canary) || strings.Contains(string(bbody), "\n"+canary) {
			f := Finding{Vulnerability: Vulnerability{
				ID:          "WS-CRLF-001",
				Name:        "CRLF injection (newline reflection)",
				Description: fmt.Sprintf("Parameter %q on %s reflects decoded CR/LF sequences into the response body, enabling log forging and HTTP response splitting where the sink is a header or log line.", point.Name, breq.URL.String()),
				Severity:    SeverityLow,
				URL:         breq.URL.String(),
				Parameter:   point.Name,
				Payload:     bodyPayload,
				Evidence:    fmt.Sprintf("response body contains a raw newline immediately before canary %s; control value lacked it", canary),
				Mitigation:  "Reject or encode CR and LF characters in user input before reflecting it into responses or logs.",
			}}
			EnrichWithTaxonomy(&f)
			ApplyConfidence(&f, SigDifferentialOnly, SigSingleVariantOnly)
			findings = append(findings, f)
		}
	}
	return findings
}
