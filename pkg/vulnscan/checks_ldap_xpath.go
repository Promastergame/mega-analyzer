package vulnscan

// LDAP injection (CWE-90) and blind XPath injection (CWE-643). Both perturb the
// target's existing query parameters. LDAP relies on backend error signatures;
// XPath uses a boolean true/false differential plus optional error signatures
// to keep false positives low.

import "fmt"

var ldapErrorSignatures = []string{
	"javax.naming",
	"com.sun.jndi.ldap",
	"ldapexception",
	"invalid dn syntax",
	"ldap_search",
	"protocol error",
	"bad search filter",
	"unbalanced parenthesis",
}

var xpathErrorSignatures = []string{
	"xpathexception",
	"xmlxpatheval",
	"simplexmlelement::xpath",
	"xpath_eval",
	"unclosed token",
	"invalid predicate",
	"unfinished literal",
}

// checkLDAPInjection tests target query parameters for LDAP filter injection.
func (s *Scanner) checkLDAPInjection() []Vulnerability {
	var list []Vulnerability
	params := s.targetParams()
	if len(params) == 0 {
		return list
	}

	for _, p := range params {
		baseline := s.probeQueryParam(p, "1")
		if !baseline.OK {
			continue
		}
		if _, baseHit := containsAnyFold(baseline.Body, ldapErrorSignatures); baseHit {
			continue // noisy baseline; skip to avoid false positives
		}
		probe := s.probeQueryParam(p, "*)(&(objectClass=*)")
		if !probe.OK {
			continue
		}
		if sig, hit := containsAnyFold(probe.Body, ldapErrorSignatures); hit {
			list = append(list, Vulnerability{
				ID:          "WS-LDAP-001",
				Name:        "LDAP Injection",
				Description: "An LDAP filter metacharacter payload provoked an LDAP backend error signature, indicating unsanitized input is placed into an LDAP search filter.",
				Severity:    SeverityHigh,
				URL:         s.Target,
				Parameter:   p,
				Payload:     "*)(&(objectClass=*)",
				Evidence:    fmt.Sprintf("LDAP error signature %q surfaced under the filter payload.", sig),
				Mitigation:  "Escape LDAP filter metacharacters (RFC 4515) or use a parameterized LDAP API; validate input against an allowlist.",
			})
		}
	}

	return list
}

// checkBlindXPath tests target query parameters for blind XPath injection using
// a boolean-differential oracle.
func (s *Scanner) checkBlindXPath() []Vulnerability {
	var list []Vulnerability
	params := s.targetParams()
	if len(params) == 0 {
		return list
	}

	for _, p := range params {
		baseline := s.probeQueryParam(p, "1")
		if !baseline.OK {
			continue
		}

		// Error-based signal first (cheap, high confidence).
		errProbe := s.probeQueryParam(p, "'\"]|")
		if errProbe.OK {
			if sig, hit := containsAnyFold(errProbe.Body, xpathErrorSignatures); hit {
				if _, baseHit := containsAnyFold(baseline.Body, xpathErrorSignatures); !baseHit {
					list = append(list, Vulnerability{
						ID:          "WS-XPATH-001",
						Name:        "XPath Injection (Error-based)",
						Description: "A broken XPath expression provoked an XPath engine error not present in the baseline, indicating input is concatenated into an XPath query.",
						Severity:    SeverityHigh,
						URL:         s.Target,
						Parameter:   p,
						Payload:     `'"]|`,
						Evidence:    fmt.Sprintf("XPath error signature %q surfaced only under the broken-expression payload.", sig),
						Mitigation:  "Use parameterized XPath (precompiled expressions with variable binding); never concatenate user input into XPath strings.",
					})
					continue
				}
			}
		}

		// Boolean differential: TRUE condition should resemble a legitimate
		// result while FALSE should diverge.
		trueProbe := s.probeQueryParam(p, "1' and '1'='1")
		falseProbe := s.probeQueryParam(p, "1' and '1'='2")
		if trueProbe.OK && falseProbe.OK && trueProbe.Status == 200 {
			if trueProbe.Status != falseProbe.Status || absDiff(len(trueProbe.Body), len(falseProbe.Body)) > 64 {
				if absDiff(len(trueProbe.Body), len(baseline.Body)) < 64 {
					list = append(list, Vulnerability{
						ID:          "WS-XPATH-001",
						Name:        "XPath Injection (Boolean Blind)",
						Description: "A TRUE XPath predicate reproduced the baseline response while a FALSE predicate diverged, a boolean oracle indicating blind XPath injection.",
						Severity:    SeverityMedium,
						URL:         s.Target,
						Parameter:   p,
						Payload:     "1' and '1'='1  /  1' and '1'='2",
						Evidence:    fmt.Sprintf("TRUE len=%d, FALSE len=%d, baseline len=%d", len(trueProbe.Body), len(falseProbe.Body), len(baseline.Body)),
						Mitigation:  "Use parameterized XPath with variable binding and validate input against an allowlist.",
					})
				}
			}
		}
	}

	return list
}
