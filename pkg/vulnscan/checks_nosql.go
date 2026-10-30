package vulnscan

// NoSQL injection (CWE-943). Endpoint-level detector that perturbs the target's
// existing query parameters with MongoDB/JSON operator payloads and confirms
// via two independent signals:
//   - a backend NoSQL error signature surfaces, or
//   - an operator payload that should always evaluate true returns a materially
//     different (larger) response than a benign baseline while an always-false
//     payload matches the baseline.
// Conservative by design: a single differential without the false-payload
// control is reported only as a Suspect-tier signal.

import (
	"fmt"
)

var noSQLErrorSignatures = []string{
	"mongoerror",
	"mongo: ",
	"casterror",
	"$where",
	"unexpected token",
	"bson.",
	"e11000",
	"couchdb",
	"unclosed brace",
	"mongoclient",
}

// checkNoSQLInjection tests every target query parameter for NoSQL injection.
func (s *Scanner) checkNoSQLInjection() []Vulnerability {
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

		// Signal 1: operator payload that provokes a backend parse/type error.
		errProbe := s.probeQueryParam(p, "'\"{\"$gt\":\"\"}")
		if errProbe.OK {
			if sig, hit := containsAnyFold(errProbe.Body, noSQLErrorSignatures); hit {
				if _, baseHit := containsAnyFold(baseline.Body, noSQLErrorSignatures); !baseHit {
					list = append(list, Vulnerability{
						ID:          "WS-NOSQL-001",
						Name:        "NoSQL Injection (Error-based)",
						Description: "A NoSQL operator payload provoked a database error signature not present in the baseline response, indicating unsanitized input reaches a NoSQL query.",
						Severity:    SeverityHigh,
						URL:         s.Target,
						Parameter:   p,
						Payload:     `{"$gt":""}`,
						Evidence:    fmt.Sprintf("Error signature %q surfaced only under the operator payload.", sig),
						Mitigation:  "Reject query operators from user input; cast parameters to expected scalar types and use strict schema validation before building NoSQL queries.",
					})
					continue
				}
			}
		}

		// Signal 2: always-true vs always-false operator differential.
		trueProbe := s.probeQueryParam(p, "[$ne]=this_value_never_matches_xyz")
		falseProbe := s.probeQueryParam(p, "[$eq]=this_value_never_matches_xyz")
		if trueProbe.OK && falseProbe.OK {
			trueLen := len(trueProbe.Body)
			falseLen := len(falseProbe.Body)
			baseLen := len(baseline.Body)
			// Vulnerable pattern: $ne returns a full/larger listing (bypasses the
			// filter) while $eq collapses to the empty/baseline result.
			if trueProbe.Status == 200 && trueLen > baseLen+64 && absDiff(falseLen, baseLen) < 64 {
				list = append(list, Vulnerability{
					ID:          "WS-NOSQL-001",
					Name:        "NoSQL Injection (Operator Differential)",
					Description: "An always-true NoSQL operator ($ne) returned substantially more data than an always-false operator ($eq), indicating the parameter is interpolated into a NoSQL query where operators are honored.",
					Severity:    SeverityHigh,
					URL:         s.Target,
					Parameter:   p,
					Payload:     p + "[$ne]=...",
					Evidence:    fmt.Sprintf("$ne len=%d vs $eq len=%d vs baseline len=%d", trueLen, falseLen, baseLen),
					Mitigation:  "Reject operator objects from user input; enforce scalar types and schema validation before constructing NoSQL queries.",
				})
			}
		}
	}

	return list
}

func absDiff(a, b int) int {
	if a < b {
		return b - a
	}
	return a - b
}
