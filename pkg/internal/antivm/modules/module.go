// Package modules defines the Module contract and the concrete feature modules.
//
// A Module turns a DeviceProfile into a set of Operations, applies them through
// a DeviceAdapter, and — crucially — verifies the result by reading device
// state back. A module never reports success merely because a command exited 0;
// Verify re-reads the device and diffs it against the expected profile.
package modules

import (
	"context"
	"time"

	"mega-analyzer/pkg/internal/antivm/adapter"
	"mega-analyzer/pkg/internal/antivm/profile"
	"mega-analyzer/pkg/internal/antivm/verifier"
)

// Operation is a single planned unit of work within a module. The planner uses
// Critical/Timeout/RetryCount to decide how to run and whether failure aborts.
type Operation struct {
	Name       string
	Module     string
	Critical   bool
	Timeout    time.Duration
	RetryCount int
	// Config is the transport payload this operation applies.
	Config adapter.TestConfig
}

// Module is the uniform contract every feature module implements.
type Module interface {
	// Name is the stable module identifier (e.g. "identity").
	Name() string
	// Validate checks the profile has everything this module needs.
	Validate(p profile.DeviceProfile) error
	// Plan turns the profile into the operations this module will apply.
	Plan(p profile.DeviceProfile) []Operation
	// Apply executes the module's operations through the adapter.
	Apply(ctx context.Context, dev adapter.DeviceAdapter) (adapter.ApplyResult, error)
	// Verify re-reads device state and checks it against the profile. It must
	// not trust Apply's return value.
	Verify(ctx context.Context, dev adapter.DeviceAdapter) (verifier.Report, error)
}

// verifyGroups runs the shared verify path: read state, diff against the
// profile, keeping only the checks belonging to this module's groups.
func verifyGroups(ctx context.Context, dev adapter.DeviceAdapter, p profile.DeviceProfile, groups map[verifier.Group]bool, critical map[verifier.Group]bool) (verifier.Report, error) {
	st, err := dev.ReadState(ctx)
	if err != nil {
		return verifier.Report{}, err
	}
	full := verifier.Verify(p, st, critical)
	return filterReport(full, groups), nil
}

// filterReport keeps only checks whose group is in groups, recomputing counts
// and overall status for that subset.
func filterReport(full verifier.Report, groups map[verifier.Group]bool) verifier.Report {
	out := verifier.Report{ByGroup: map[verifier.Group]verifier.Status{}}
	for _, c := range full.Checks {
		if !groups[c.Group] {
			continue
		}
		out.Checks = append(out.Checks, c)
		switch c.Status {
		case verifier.StatusPassed:
			out.Counts.Passed++
		case verifier.StatusFailed:
			out.Counts.Failed++
			out.Mismatches = append(out.Mismatches, c)
		case verifier.StatusSkipped:
			out.Counts.Skipped++
		case verifier.StatusPartial:
			out.Counts.Partial++
		}
	}
	for g, st := range full.ByGroup {
		if groups[g] {
			out.ByGroup[g] = st
		}
	}
	out.Status = rollup(out)
	return out
}

func rollup(r verifier.Report) verifier.Status {
	if len(r.Checks) == 0 {
		return verifier.StatusSkipped
	}
	if r.Counts.Failed > 0 {
		return verifier.StatusFailed
	}
	if r.Counts.Skipped > 0 || r.Counts.Partial > 0 {
		return verifier.StatusPartial
	}
	return verifier.StatusPassed
}
