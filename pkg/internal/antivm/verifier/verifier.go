// Package verifier proves what actually happened on a device. It diffs a
// DeviceProfile (expected) against a DeviceState (actual) grouped into semantic
// categories, and reports a status per check and overall. It deliberately does
// not use a coarse "Applied: true" boolean — a run is described by its status,
// its per-field checks, and the concrete mismatches found.
package verifier

import (
	"sort"

	"mega-analyzer/pkg/internal/antivm/adapter"
	"mega-analyzer/pkg/internal/antivm/profile"
)

// Status is the outcome of a check or of the whole verification.
type Status string

const (
	StatusPassed  Status = "passed"  // everything compared matched
	StatusPartial Status = "partial" // some settings unavailable / not applied
	StatusFailed  Status = "failed"  // a critical check did not match
	StatusSkipped Status = "skipped" // could not be checked at all
)

// Severity ranks a mismatch.
type Severity string

const (
	SeverityLow    Severity = "low"
	SeverityMedium Severity = "medium"
	SeverityHigh   Severity = "high"
)

// Group is a semantic category of checks.
type Group string

const (
	GroupIdentity    Group = "identity"
	GroupBuild       Group = "build"
	GroupDisplay     Group = "display"
	GroupNetwork     Group = "network"
	GroupBattery     Group = "battery"
	GroupSensors     Group = "sensors"
	GroupEnvironment Group = "environment"
)

// Check is a single expected-vs-actual comparison.
type Check struct {
	Group    Group    `json:"group"`
	Field    string   `json:"field"`
	Expected string   `json:"expected"`
	Actual   string   `json:"actual"`
	Status   Status   `json:"status"`
	Severity Severity `json:"severity,omitempty"`
}

// Report is the full verification result.
type Report struct {
	Status     Status           `json:"status"`
	Counts     Counts           `json:"checks"`
	Checks     []Check          `json:"detail"`
	Mismatches []Check          `json:"mismatches,omitempty"`
	ByGroup    map[Group]Status `json:"by_group"`
}

// Counts summarises check outcomes.
type Counts struct {
	Passed  int `json:"passed"`
	Failed  int `json:"failed"`
	Skipped int `json:"skipped"`
	Partial int `json:"partial"`
}

// spec describes one field to verify: where the expected value comes from and
// where to read the actual value in DeviceState.
type spec struct {
	group    Group
	field    string
	expected string
	// actual is looked up from the relevant state map by key; empty actual with
	// present=false means "not readable" → skipped.
	actualKey string
	source    func(adapter.DeviceState, string) (string, bool)
	severity  Severity
}

func propSource(st adapter.DeviceState, key string) (string, bool) {
	v, ok := st.Props[key]
	return v, ok
}
func batterySource(st adapter.DeviceState, key string) (string, bool) {
	v, ok := st.Battery[key]
	return v, ok
}
func displaySource(st adapter.DeviceState, key string) (string, bool) {
	v, ok := st.Display[key]
	return v, ok
}
func networkSource(st adapter.DeviceState, key string) (string, bool) {
	v, ok := st.Network[key]
	return v, ok
}

// Verify compares expected profile against actual state and produces a Report.
// criticalGroups lists groups whose mismatch makes the overall status Failed;
// mismatches in other groups downgrade to Partial.
func Verify(expected profile.DeviceProfile, actual adapter.DeviceState, criticalGroups map[Group]bool) Report {
	specs := buildSpecs(expected)

	rep := Report{ByGroup: map[Group]Status{}}
	groupWorst := map[Group]Status{}

	for _, s := range specs {
		if s.expected == "" {
			continue // nothing expected → nothing to check
		}
		c := Check{Group: s.group, Field: s.field, Expected: s.expected, Severity: s.severity}
		got, present := s.source(actual, s.actualKey)
		switch {
		case !present:
			c.Status = StatusSkipped
			rep.Counts.Skipped++
		case valuesMatch(s.expected, got):
			c.Actual = got
			c.Status = StatusPassed
			rep.Counts.Passed++
		default:
			c.Actual = got
			c.Status = StatusFailed
			rep.Counts.Failed++
			rep.Mismatches = append(rep.Mismatches, c)
		}
		rep.Checks = append(rep.Checks, c)
		groupWorst[s.group] = worse(groupWorst[s.group], c.Status)
	}

	// Roll up per-group and overall status.
	overall := StatusPassed
	for g, st := range groupWorst {
		rep.ByGroup[g] = st
		switch st {
		case StatusFailed:
			if criticalGroups[g] {
				overall = worse(overall, StatusFailed)
			} else {
				overall = worse(overall, StatusPartial)
			}
		case StatusSkipped, StatusPartial:
			overall = worse(overall, StatusPartial)
		}
	}
	if len(rep.Checks) == 0 {
		overall = StatusSkipped
	}
	rep.Status = overall

	sort.Slice(rep.Mismatches, func(i, j int) bool {
		return sevRank(rep.Mismatches[i].Severity) > sevRank(rep.Mismatches[j].Severity)
	})
	return rep
}

// buildSpecs maps a profile to the list of field checks.
func buildSpecs(p profile.DeviceProfile) []spec {
	return []spec{
		{GroupIdentity, "model", p.Model, "ro.product.model", propSource, SeverityHigh},
		{GroupIdentity, "brand", p.Brand, "ro.product.brand", propSource, SeverityMedium},
		{GroupIdentity, "manufacturer", p.Manufacturer, "ro.product.manufacturer", propSource, SeverityMedium},
		{GroupIdentity, "device", p.Device, "ro.product.device", propSource, SeverityMedium},
		{GroupBuild, "fingerprint", p.Fingerprint, "ro.build.fingerprint", propSource, SeverityHigh},
		{GroupBuild, "build_id", p.BuildID, "ro.build.display.id", propSource, SeverityMedium},
		{GroupBuild, "security_patch", p.SecurityPatch, "ro.build.version.security_patch", propSource, SeverityLow},
		{GroupEnvironment, "qemu", "0", "ro.kernel.qemu", propSource, SeverityHigh},
		{GroupDisplay, "resolution", p.Resolution, "resolution", displaySource, SeverityLow},
		{GroupDisplay, "density", itoa(p.Density), "density", displaySource, SeverityLow},
		{GroupBattery, "level", itoa(p.Battery.Level), "level", batterySource, SeverityLow},
		{GroupBattery, "status", p.Battery.Status, "status", batterySource, SeverityLow},
		{GroupNetwork, "mac", p.Network.MACAddress, "mac", networkSource, SeverityMedium},
		{GroupNetwork, "imei", p.Network.IMEI, "imei", networkSource, SeverityMedium},
	}
}
