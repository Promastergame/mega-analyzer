package vulnscan

import "strings"

// ReplayProbe captures how to retransmit the trigger request of a finding so
// the confirmation pass can verify that the evidence reproduces before the
// finding is reported. High/Critical active findings are the most expensive
// false positives for a consumer to triage, so they get one retransmission.
type ReplayProbe struct {
	// Retry retransmits the trigger probe and reports whether the evidence
	// reproduced. A non-nil error means the retransmission itself failed
	// (transport-level), which the confirmation pass treats as inconclusive
	// and keeps the finding rather than dropping a true positive on a
	// transient network blip.
	Retry func(s *Scanner) (evidenceReproduced bool, err error)
}

// runConfirmationPass retransmits the trigger probe of every High/Critical
// finding that registered a ReplayProbe. Findings whose evidence does not
// reproduce are dropped; transport errors are inconclusive and keep the
// finding. Findings without a probe (passive detections, checks that already
// performed their own differential verification inline) pass through.
func (s *Scanner) runConfirmationPass(vulns []Vulnerability) []Vulnerability {
	kept := make([]Vulnerability, 0, len(vulns))
	for _, v := range vulns {
		if (v.Severity != SeverityHigh && v.Severity != SeverityCritical) ||
			v.Probe == nil || v.Probe.Retry == nil {
			kept = append(kept, v)
			continue
		}
		reproduced, err := v.Probe.Retry(s)
		if err != nil {
			s.log("[?] Confirmation inconclusive for %s at %s (retransmit failed: %v); keeping finding\n", v.ID, v.URL, err)
			kept = append(kept, v)
			continue
		}
		if !reproduced {
			s.log("[!] Dropped %s at %s: evidence did not reproduce on retransmit\n", v.ID, v.URL)
			continue
		}
		v.Evidence = strings.TrimSpace(v.Evidence) + " (reconfirmed on retransmit)"
		kept = append(kept, v)
	}
	return kept
}
