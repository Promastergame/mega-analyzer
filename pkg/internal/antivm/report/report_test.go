package report

import (
	"encoding/json"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/antivm/planner"
	"mega-analyzer/pkg/internal/antivm/verifier"
)

func sampleReport() planner.RunReport {
	return planner.RunReport{
		Status: verifier.StatusPartial,
		Modules: []planner.ModuleResult{
			{
				Module: "identity",
				Verify: verifier.Report{
					Status: verifier.StatusPassed,
					Counts: verifier.Counts{Passed: 4},
					Checks: []verifier.Check{
						{Group: verifier.GroupIdentity, Field: "model", Expected: "Pixel 7", Actual: "Pixel 7", Status: verifier.StatusPassed},
					},
				},
			},
			{
				Module: "battery",
				Verify: verifier.Report{
					Status: verifier.StatusFailed,
					Counts: verifier.Counts{Failed: 1},
					Mismatches: []verifier.Check{
						{Group: verifier.GroupBattery, Field: "level", Expected: "71", Actual: "5", Status: verifier.StatusFailed, Severity: verifier.SeverityLow},
					},
					Checks: []verifier.Check{
						{Group: verifier.GroupBattery, Field: "level", Expected: "71", Actual: "5", Status: verifier.StatusFailed, Severity: verifier.SeverityLow},
					},
				},
			},
		},
		Warnings: []string{"battery: 1 verification mismatch(es)"},
	}
}

func TestRender_JSON(t *testing.T) {
	out, err := Render(sampleReport(), FormatJSON)
	if err != nil {
		t.Fatal(err)
	}
	var back planner.RunReport
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatalf("JSON not round-trippable: %v", err)
	}
	if back.Status != verifier.StatusPartial {
		t.Errorf("status lost in JSON: %q", back.Status)
	}
}

func TestRender_Text(t *testing.T) {
	out, err := Render(sampleReport(), FormatText)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{"Status:  partial", "identity", "battery", "level", "expected \"71\", got \"5\""} {
		if !strings.Contains(s, want) {
			t.Errorf("text report missing %q\n%s", want, s)
		}
	}
}

func TestRender_HTML(t *testing.T) {
	out, err := Render(sampleReport(), FormatHTML)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.HasPrefix(s, "<!DOCTYPE html>") {
		t.Error("HTML report missing doctype")
	}
	if !strings.Contains(s, "Pixel 7") || !strings.Contains(s, "class=\"failed\"") {
		t.Errorf("HTML report missing expected content")
	}
}

func TestRender_UnknownFormat(t *testing.T) {
	if _, err := Render(sampleReport(), Format("pdf")); err == nil {
		t.Error("expected error for unknown format")
	}
}

func TestRender_HTMLEscapes(t *testing.T) {
	r := sampleReport()
	r.Modules[0].Err = "<script>alert(1)</script>"
	out, _ := Render(r, FormatHTML)
	if strings.Contains(string(out), "<script>alert(1)</script>") {
		t.Error("HTML report did not escape module error")
	}
}
