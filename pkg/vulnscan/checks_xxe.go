package vulnscan

// XML External Entity (XXE) injection, registry-native.
//
// Detection methodology: a high-entropy canary is split across two internal
// entities so the contiguous marker can only surface in the response when the
// parser actually expands entities. A control document (identical except for
// the DTD) must NOT surface the canary, ruling out raw body echo. No
// out-of-band channel or local file disclosure is attempted: the proof is
// entity expansion, not data exfiltration.
// References: CWE-611, OWASP A05:2021.

import (
	"fmt"
	"net/http"
	"strings"
)

func init() {
	RegisterCheck(CheckDescriptor{
		ID:           "WS-XXE-001",
		Name:         "XML External Entity Injection (entity expansion)",
		CWE:          []int{611},
		OWASP:        []string{"A05:2021"},
		Phase:        PhaseActive,
		Invasiveness: InvDestructive,
		Run:          runXXE,
	})
}

// xmlSafeElementName maps a parameter name onto a valid XML element name.
func xmlSafeElementName(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	if b.Len() == 0 {
		return "p"
	}
	return b.String()
}

// xxeRequest builds an application/xml POST against the surface endpoint.
func xxeRequest(s *Scanner, surface *AttackSurface, xmlBody string) (*http.Request, error) {
	target := ""
	if surface.BaseRequest != nil {
		target = surface.BaseRequest.URL
	}
	if target == "" {
		target = surface.URL
	}
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(xmlBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/xml")
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

func runXXE(s *Scanner, surface *AttackSurface) []Finding {
	if surface == nil || s == nil || s.Client == nil {
		return nil
	}
	var findings []Finding

	for _, point := range surface.InjectionPoints {
		if point.DataType == TypeUUID || point.DataType == TypeToken {
			continue // opaque identifiers are not XML sinks
		}
		elem := xmlSafeElementName(point.Name)
		canary := NewCanary("xxe" + point.Name)

		// Control document: same shape, no DTD. Its response must not contain
		// the canary, which proves later hits come from entity expansion
		// rather than raw request-body echo.
		control := fmt.Sprintf(`<?xml version="1.0"?><root><%s>1</%s></root>`, elem, elem)
		creq, err := xxeRequest(s, surface, control)
		if err != nil || !s.InScope(creq.URL.String()) {
			continue
		}
		cbody, _, cerr := sendCapture(s, creq)
		if cerr != nil {
			continue
		}
		if strings.Contains(string(cbody), canary) {
			continue // canary already surfaces without a DTD: unusable signal
		}

		// Split the canary across two entities: the contiguous marker cannot
		// appear in the raw payload, so its presence in the response proves
		// the parser expanded the entities.
		half := len(canary) / 2
		payload := fmt.Sprintf(
			`<?xml version="1.0"?><!DOCTYPE r [<!ENTITY mqa "%s"><!ENTITY mqb "%s">]><root><%s>&mqa;&mqb;</%s></root>`,
			canary[:half], canary[half:], elem, elem)
		req, err := xxeRequest(s, surface, payload)
		if err != nil || !s.InScope(req.URL.String()) {
			continue
		}
		body, status, herr := sendCapture(s, req)
		if herr != nil || status >= 500 {
			continue
		}
		if !strings.Contains(string(body), canary) {
			continue
		}

		f := Finding{Vulnerability: Vulnerability{
			ID:          "WS-XXE-001",
			Name:        "XML entity expansion confirmed (XXE)",
			Description: fmt.Sprintf("Parameter %q on %s accepted an XML document whose internal entities were expanded and echoed back (canary %q). The XML parser processes DTDs, so external-entity and SSRF payloads are likely viable.", point.Name, req.URL.String(), canary),
			Severity:    SeverityHigh,
			URL:         req.URL.String(),
			Parameter:   point.Name,
			Payload:     payload,
			Evidence:    fmt.Sprintf("canary %s absent from control response, present after entity expansion", canary),
			Mitigation:  "Disable DTD processing and external entity resolution in the XML parser (e.g. disallow-doctype-decl / feature secure processing); validate and reject documents with DOCTYPE declarations.",
		}}
		EnrichWithTaxonomy(&f)
		ApplyConfidence(&f, SigDifferentialOnly, SigReflectedVerbatim)
		findings = append(findings, f)
	}
	return findings
}
