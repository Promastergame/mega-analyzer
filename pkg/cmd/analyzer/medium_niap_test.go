package main

import (
	"testing"

	"mega-analyzer/pkg/internal/niap"
	"mega-analyzer/pkg/internal/types"
)

// Review round: the NIAP finding mapping. The old `!m.Matched` condition
// reported clean negative rules ("AES-ECB used" with no match) and stayed
// silent on real hits — this pins the Status-based mapping.

func TestNiapFindingMapping(t *testing.T) {
	cases := []struct {
		match   niap.Match
		wantOK  bool
		wantSev types.Severity
	}{
		// Found anti-pattern → real finding.
		{niap.Match{RuleID: "ANTI", Status: niap.StatusFailed, Matched: true}, true, types.SeverityMedium},
		// Absent positive pattern → compliance gap, not a proved vulnerability.
		{niap.Match{RuleID: "POS", Status: niap.StatusFailed, Matched: false}, true, types.SeverityInfo},
		// Clean negative rule (anti-pattern NOT found) → silence.
		{niap.Match{RuleID: "ANTI", Status: niap.StatusPassed, Matched: false}, false, 0},
		// Satisfied positive rule → silence.
		{niap.Match{RuleID: "POS", Status: niap.StatusPassed, Matched: true}, false, 0},
		// Manual-review rule → informational only, never Medium.
		{niap.Match{RuleID: "MAN", Status: niap.StatusManual, Matched: false}, true, types.SeverityInfo},
	}
	for _, tc := range cases {
		sev, reason, ok := niapFinding(tc.match)
		if ok != tc.wantOK {
			t.Errorf("%s/%s: ok = %v, want %v",
				tc.match.RuleID, tc.match.Status, ok, tc.wantOK)
			continue
		}
		if !ok {
			continue
		}
		if sev != tc.wantSev {
			t.Errorf("%s/%s: severity = %v, want %v",
				tc.match.RuleID, tc.match.Status, sev, tc.wantSev)
		}
		if reason == "" {
			t.Errorf("%s/%s: empty reason", tc.match.RuleID, tc.match.Status)
		}
	}
}
