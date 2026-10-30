package report

import (
	"strings"
	"testing"
)

// TestBuildMachineCodeSection_RevealCheckbox covers --scan-native-reveal-secrets
// HTML surface: the "Show sensitive data" checkbox and the full-value div
// must only appear when a finding actually carries PayloadFull (i.e. the
// scan ran with reveal enabled) — never leaking a secret into the DOM
// otherwise.
func TestBuildMachineCodeSection_RevealCheckbox(t *testing.T) {
	view := HTMLReportView{
		Report: ReportView{
			MachineCodeReports: []MachineCodeReportView{
				{
					Target: "libfoo.so",
					Findings: []MachineCodeFindingView{
						{Title: "Embedded credential", Category: "EMBEDDED_SECRET", Severity: "low", Evidence: "****", PayloadFull: "1234"},
					},
				},
			},
		},
	}
	r := &HTMLReporter{}
	var sb strings.Builder
	r.buildMachineCodeSection(&sb, view)
	out := sb.String()
	if !strings.Contains(out, "Show sensitive data") {
		t.Error("expected the reveal checkbox to be rendered when a finding has PayloadFull")
	}
	if !strings.Contains(out, `class="mc-finding-payload-full" hidden`) {
		t.Error("expected the full-value div to be present but hidden by default")
	}
	if !strings.Contains(out, "1234") {
		t.Error("expected the full value to actually be in the DOM (server-side gated, client just toggles visibility)")
	}

	// Without any PayloadFull, no checkbox and no sensitive value should render at all.
	view2 := HTMLReportView{
		Report: ReportView{
			MachineCodeReports: []MachineCodeReportView{
				{
					Target: "libbar.so",
					Findings: []MachineCodeFindingView{
						{Title: "Embedded credential", Category: "EMBEDDED_SECRET", Severity: "low", Evidence: "****"},
					},
				},
			},
		},
	}
	var sb2 strings.Builder
	r.buildMachineCodeSection(&sb2, view2)
	out2 := sb2.String()
	if strings.Contains(out2, "Show sensitive data") {
		t.Error("checkbox must not render when reveal was off at scan time (no PayloadFull anywhere)")
	}
	if strings.Contains(out2, "mc-finding-payload-full") {
		t.Error("no payload-full div should be emitted when reveal was off")
	}
}
