package vulnscan

// Timing side-channel (CWE-208) and Regular-Expression DoS (CWE-1333).
// Both are gated behind the Scan() ownership requirement (IOwnThisTarget) and
// use the shared TimingIsAnomalous model with a multi-sample baseline so that
// ordinary network jitter does not trigger a finding.

import (
	"fmt"
	"strings"
)

const (
	timingSamples  = 6
	timingK        = 4.0 // std-devs above baseline mean before flagging
	timingMinDelta = 250 // ms; ignore anomalies smaller than this
)

// gatherBaseline issues n probes with a benign value and returns per-sample
// latencies in milliseconds.
func (s *Scanner) gatherBaseline(param, value string, n int) []int64 {
	var samples []int64
	for i := 0; i < n; i++ {
		pr := s.probeQueryParam(param, value)
		if !pr.OK {
			continue
		}
		samples = append(samples, pr.Elapsed.Milliseconds())
	}
	return samples
}

// checkReDoS looks for catastrophic-backtracking amplification on target query
// parameters by comparing a benign input against a pathological one.
func (s *Scanner) checkReDoS() []Vulnerability {
	var list []Vulnerability
	if !s.Config.IOwnThisTarget {
		return list
	}
	params := s.targetParams()
	if len(params) == 0 {
		return list
	}

	// Classic catastrophic-backtracking trigger: long run of 'a' plus a
	// non-matching suffix.
	evil := strings.Repeat("a", 40000) + "!"

	for _, p := range params {
		baseline := s.gatherBaseline(p, "aaaaaaaa", timingSamples)
		if len(baseline) < timingSamples/2 {
			continue
		}
		probe := s.probeQueryParam(p, evil)
		if !probe.OK {
			continue
		}
		observed := probe.Elapsed.Milliseconds()
		if TimingIsAnomalous(baseline, observed, timingK, timingMinDelta) {
			// Confirm with a second pathological sample to reduce jitter FPs.
			probe2 := s.probeQueryParam(p, evil)
			if probe2.OK && TimingIsAnomalous(baseline, probe2.Elapsed.Milliseconds(), timingK, timingMinDelta) {
				list = append(list, Vulnerability{
					ID:          "WS-REDOS-001",
					Name:        "Regular-Expression Denial of Service (ReDoS)",
					Description: "A pathological input caused a large, repeatable increase in response time versus a benign baseline, indicating catastrophic regex backtracking on server-side input validation.",
					Severity:    SeverityMedium,
					URL:         s.Target,
					Parameter:   p,
					Payload:     "a{40000}!",
					Evidence:    fmt.Sprintf("baseline ~%dms, pathological %dms/%dms (both anomalous)", medianI64(baseline), observed, probe2.Elapsed.Milliseconds()),
					Mitigation:  "Replace vulnerable regexes with linear-time engines (RE2) or bounded quantifiers; enforce input length limits before matching.",
				})
			}
		}
	}
	return list
}

// checkTimingOracle looks for auth/validation timing side-channels on
// credential-like parameters (token/password/otp/email) where a
// valid-vs-invalid distinction leaks through response latency.
func (s *Scanner) checkTimingOracle() []Vulnerability {
	var list []Vulnerability
	if !s.Config.IOwnThisTarget {
		return list
	}
	params := s.targetParams()
	if len(params) == 0 {
		return list
	}

	sensitive := []string{"token", "password", "passwd", "otp", "code", "secret", "api_key", "apikey", "email", "user", "username"}
	for _, p := range params {
		if !nameMatchesAny(p, sensitive) {
			continue
		}
		// Two candidate values with very different prefixes; a byte-by-byte
		// comparison leaks via latency differences.
		baseA := s.gatherBaseline(p, "AAAAAAAAAAAAAAAA", timingSamples)
		baseB := s.gatherBaseline(p, "zzzzzzzzzzzzzzzz", timingSamples)
		if len(baseA) < timingSamples/2 || len(baseB) < timingSamples/2 {
			continue
		}
		medB := medianI64(baseB)
		if TimingIsAnomalous(baseA, medB, timingK, timingMinDelta) {
			list = append(list, Vulnerability{
				ID:          "WS-TIMING-001",
				Name:        "Authentication Timing Side-Channel",
				Description: "Response latency differs consistently between two credential candidates for a sensitive parameter, suggesting a non-constant-time comparison that can be exploited as an oracle.",
				Severity:    SeverityLow,
				URL:         s.Target,
				Parameter:   p,
				Evidence:    fmt.Sprintf("median latency A=%dms vs B=%dms exceeds the anomaly threshold", medianI64(baseA), medB),
				Mitigation:  "Use constant-time comparison for secrets/tokens and add uniform response delays for authentication failures.",
			})
		}
	}
	return list
}

func nameMatchesAny(name string, subs []string) bool {
	l := strings.ToLower(name)
	for _, s := range subs {
		if strings.Contains(l, s) {
			return true
		}
	}
	return false
}

func medianI64(v []int64) int64 {
	if len(v) == 0 {
		return 0
	}
	cp := make([]int64, len(v))
	copy(cp, v)
	for i := 1; i < len(cp); i++ {
		for j := i; j > 0 && cp[j-1] > cp[j]; j-- {
			cp[j-1], cp[j] = cp[j], cp[j-1]
		}
	}
	return cp[len(cp)/2]
}
