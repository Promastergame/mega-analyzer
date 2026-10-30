package vulnscan

import (
	"fmt"
	"math/rand"
	"net/http"
	"strings"
)

// sstiMarker returns a randomized arithmetic pair whose product is a
// high-entropy integer unlikely to occur naturally in a page body. A fixed
// marker (like the classic 7777) produces false positives on pages that
// merely contain that number (prices, ids, phone numbers).
func sstiMarker() (a, b, product int) {
	for i := 0; i < 64; i++ {
		a = 1234 + rand.Intn(7654) // 1234..8887
		b = 1234 + rand.Intn(7654)
		product = a * b
		ps := fmt.Sprintf("%d", product)
		if len(ps) >= 7 && !strings.Contains(ps, "0") {
			return a, b, product
		}
	}
	return 5437, 7193, 5437 * 7193
}

// checkSSTI probes form parameters for Server-Side Template Injection (SSTI).
//
// SSTI is often overlooked by generic scanners because payloads are engine-specific.
// We use polyglot probes that produce a distinctive numeric output across multiple
// template engines (Jinja2, Twig, FreeMarker, Velocity, Pebble, Thymeleaf, Smarty,
// Mako, ERB, Handlebars, Mustache, Nunjucks, Tornado, Go html/template).
//
// Detection logic:
//  1. Inject a math expression that evaluates to a randomized high-entropy integer.
//  2. Compare against a benign baseline for the same input: the marker must be
//     ABSENT from the baseline and PRESENT after injection (differential proof).
//  3. A second probe checks for error messages that indicate template evaluation.
func (s *Scanner) checkSSTI(form Form) []Vulnerability {
	var list []Vulnerability

	// Error-based indicators (engine leaks in error messages)
	errorIndicators := []string{
		"templatesyntaxerror",
		"undefinederror",
		"jinja2",
		"freemarker",
		"velocity",
		"smarty",
		"template engine",
		"templateexception",
		"parseexception",
		"renderingexception",
	}

	for _, inputName := range form.Inputs {
		// Baseline behavior with a benign value: markers or error fingerprints
		// already present here are application behavior, not injection evidence.
		baseBodies, _, _ := s.sendFuzzRequest(form, inputName, "test")
		baseLower := strings.ToLower(baseBodies)

		a, b, product := sstiMarker()
		expected := fmt.Sprintf("%d", product)
		expr := fmt.Sprintf("%d*%d", a, b)

		// Polyglot probes: each evaluates expr in a different engine family.
		probes := []struct {
			payload string
			engine  string
		}{
			// Jinja2 / Twig / Nunjucks / Tornado
			{"{{" + expr + "}}", "Jinja2/Twig/Nunjucks"},
			// FreeMarker / Pebble / Mako / Cheetah
			{"${" + expr + "}", "FreeMarker/Pebble/Mako"},
			// Velocity
			{fmt.Sprintf("#set($x=%s)${x}", expr), "Velocity"},
			// Smarty
			{fmt.Sprintf("{math equation='%s'}", expr), "Smarty"},
			// ERB (Ruby)
			{"<%= " + expr + " %>", "ERB"},
		}

		confirmed := false
		errFingerprinted := false
		for _, probe := range probes {
			bodies, _, _ := s.sendFuzzRequest(form, inputName, probe.payload)

			// Primary: expression evaluated → confirmed SSTI (differential:
			// marker absent from the benign baseline, present after injection).
			if strings.Contains(bodies, expected) && !strings.Contains(baseBodies, expected) {
				cf, cinp, cpl, cexp := form, inputName, probe.payload, expected
				list = append(list, Vulnerability{
					ID:          "WS-SSTI-001",
					Name:        "Server-Side Template Injection (SSTI) — Confirmed",
					Description: fmt.Sprintf("The parameter '%s' is interpreted by a server-side template engine (%s). The expression '%s' evaluated to '%s' in the response. SSTI can lead to Remote Code Execution.", inputName, probe.engine, probe.payload, expected),
					Severity:    SeverityCritical,
					URL:         form.Action,
					Parameter:   inputName,
					Payload:     probe.payload,
					Evidence:    fmt.Sprintf("Injected: %s | Evaluated marker %s in body (absent from benign baseline)", probe.payload, expected),
					Mitigation:  "Never render user-supplied data directly as a template. Use template sandboxing, strict input validation, and avoid dynamic template compilation.",
					Probe: &ReplayProbe{Retry: func(sc *Scanner) (bool, error) {
						reBodies, _, _ := sc.sendFuzzRequest(cf, cinp, cpl)
						return strings.Contains(reBodies, cexp), nil
					}},
				})
				confirmed = true
				break // One confirmed hit per parameter is sufficient
			}

			// Secondary: error message reveals template engine (differential).
			// Report at most one fingerprint per parameter.
			if errFingerprinted {
				continue
			}
			bodyLower := strings.ToLower(bodies)
			for _, errInd := range errorIndicators {
				if strings.Contains(bodyLower, errInd) && !strings.Contains(baseLower, errInd) {
					cf, cinp, cpl, cind := form, inputName, probe.payload, errInd
					list = append(list, Vulnerability{
						ID:          "WS-SSTI-002",
						Name:        "Server-Side Template Injection (SSTI) — Error-Based Fingerprint",
						Description: fmt.Sprintf("The parameter '%s' triggered a template engine error containing '%s'. The server likely interprets input as template syntax, indicating a probable SSTI surface.", inputName, errInd),
						Severity:    SeverityHigh,
						URL:         form.Action,
						Parameter:   inputName,
						Payload:     probe.payload,
						Evidence:    fmt.Sprintf("Error indicator '%s' found when injecting: %s (absent from benign baseline)", errInd, probe.payload),
						Mitigation:  "Sanitize and encode all user input before passing it to template rendering functions. Use context-aware templating libraries.",
						Probe: &ReplayProbe{Retry: func(sc *Scanner) (bool, error) {
							reBodies, _, _ := sc.sendFuzzRequest(cf, cinp, cpl)
							return strings.Contains(strings.ToLower(reBodies), cind), nil
						}},
					})
					errFingerprinted = true
					break
				}
			}
		}

		// De-duplicate per parameter: when SSTI is confirmed, drop the weaker
		// error-based findings for this parameter to avoid noise.
		if confirmed {
			var deduped []Vulnerability
			for _, v := range list {
				if v.Parameter == inputName && v.ID == "WS-SSTI-002" {
					continue
				}
				deduped = append(deduped, v)
			}
			list = deduped
		}
	}

	return list
}

// checkSSTIInHeaders tests common headers that are reflected into server-rendered templates.
// Headers like User-Agent and Referer are sometimes rendered unsafely in error pages or logs.
func (s *Scanner) checkSSTIInHeaders() []Vulnerability {
	var list []Vulnerability

	a, b, product := sstiMarker()
	expected := fmt.Sprintf("%d", product)
	expr := fmt.Sprintf("%d*%d", a, b)

	headerProbes := []struct {
		header  string
		payload string
	}{
		{"User-Agent", "{{" + expr + "}}"},
		{"Referer", "${" + expr + "}"},
		{"X-Forwarded-For", "{{" + expr + "}}"},
	}

	// Baseline: a clean request to the same URL. Any marker or fingerprint
	// already present is not injection evidence.
	baseResp, err := s.Client.Get(s.Target)
	baseBody := ""
	if err == nil {
		baseBytes, rerr := ReadBodyLimited(baseResp, NeedFull)
		baseResp.Body.Close()
		if rerr == nil {
			baseBody = string(baseBytes)
		}
	}

	for _, probe := range headerProbes {
		req, err := http.NewRequest("GET", s.Target, nil)
		if err != nil {
			continue
		}
		req.Header.Set(probe.header, probe.payload)

		resp, err := s.Client.Do(req)
		if err != nil {
			continue
		}
		bodyBytes, readErr := ReadBodyLimited(resp, NeedFull)
		resp.Body.Close()
		if readErr != nil {
			continue
		}
		body := string(bodyBytes)

		if strings.Contains(body, expected) && !strings.Contains(baseBody, expected) {
			list = append(list, Vulnerability{
				ID:          "WS-SSTI-003",
				Name:        "SSTI via HTTP Header — Confirmed",
				Description: fmt.Sprintf("The '%s' header value is rendered as a server-side template. The expression '%s' evaluated to '%s'. An attacker can achieve Remote Code Execution by sending crafted HTTP headers.", probe.header, probe.payload, expected),
				Severity:    SeverityCritical,
				URL:         s.Target,
				Parameter:   probe.header,
				Payload:     probe.payload,
				Evidence:    fmt.Sprintf("Header: %s: %s → evaluated marker %s in body (absent from baseline)", probe.header, probe.payload, expected),
				Mitigation:  "Do not render raw HTTP header values inside template engines. Treat all external input as untrusted data, not template code.",
			})
		}
	}
	return list
}
