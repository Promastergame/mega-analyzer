package vulnscan

// HTTP verb tampering, registry-native.
//
// Detection methodology: differential only. A baseline request using the
// surface's native method must be denied (401/403). Alternate verbs —
// including a nonsense verb many ACLs fail to enumerate — are then tried
// against the same resource with benign values. A bypass is reported only
// when a different verb returns a success/redirect status the baseline was
// denied, proving the access control is verb-specific rather than absent.
// References: CWE-285, OWASP A01:2021.

import (
	"fmt"
	"net/http"
)

func init() {
	RegisterCheck(CheckDescriptor{
		ID:           "WS-VERB-001",
		Name:         "HTTP Verb Tampering (auth bypass via method)",
		CWE:          []int{285},
		OWASP:        []string{"A01:2021"},
		Phase:        PhaseActive,
		Invasiveness: InvSafe,
		Run:          runVerbTampering,
	})
}

// verbTamperMethods lists alternate verbs to try. The nonsense verb catches
// ACLs that enumerate standard methods and default to allow.
var verbTamperMethods = []string{
	http.MethodHead, http.MethodOptions, http.MethodPost, http.MethodPut,
	http.MethodPatch, http.MethodDelete, "JEEPERS",
}

func runVerbTampering(s *Scanner, surface *AttackSurface) []Finding {
	if surface == nil || s == nil || s.Client == nil || len(surface.InjectionPoints) == 0 {
		return nil
	}
	point := surface.InjectionPoints[0]

	// Baseline: the surface's native method must be actively denied.
	breq, err := buildSurfaceRequest(s, surface, point, "1")
	if err != nil || !s.InScope(breq.URL.String()) {
		return nil
	}
	_, baseStatus, berr := sendCapture(s, breq)
	if berr != nil || (baseStatus != http.StatusUnauthorized && baseStatus != http.StatusForbidden) {
		return nil // nothing protected: no differential possible
	}

	for _, m := range verbTamperMethods {
		if m == breq.Method {
			continue
		}
		req, err := buildSurfaceRequest(s, surface, point, "1")
		if err != nil || !s.InScope(req.URL.String()) {
			continue
		}
		req.Method = m // override after construction; params stay in place
		_, status, rerr := sendCapture(s, req)
		if rerr != nil || status >= 400 {
			continue
		}

		f := Finding{Vulnerability: Vulnerability{
			ID:          "WS-VERB-001",
			Name:        "Authentication bypass via HTTP verb tampering",
			Description: fmt.Sprintf("%s on %s is denied for %s (HTTP %d) but reachable with verb %s (HTTP %d). The access control rule is verb-specific and can be bypassed.", req.URL.String(), req.URL.Host, breq.Method, baseStatus, m, status),
			Severity:    SeverityMedium,
			URL:         req.URL.String(),
			Parameter:   point.Name,
			Payload:     m,
			Evidence:    fmt.Sprintf("baseline %s -> %d; verb %s -> %d on identical resource", breq.Method, baseStatus, m, status),
			Mitigation:  "Enforce authorization on the resource regardless of HTTP method; deny unknown verbs instead of defaulting to allow.",
		}}
		EnrichWithTaxonomy(&f)
		ApplyConfidence(&f, SigDifferentialOnly)
		return []Finding{f} // one finding per surface: the bypass is proven
	}
	return nil
}
