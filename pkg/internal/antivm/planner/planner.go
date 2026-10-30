// Package planner orchestrates a run: it validates the profile, applies each
// module's operations in order, and verifies the result by reading device
// state. Critical failures abort the run; non-critical failures are recorded as
// warnings and downgrade the overall status to partial rather than turning a
// failure into a success.
package planner

import (
	"context"
	"errors"
	"fmt"
	"time"

	"mega-analyzer/pkg/internal/antivm/adapter"
	"mega-analyzer/pkg/internal/antivm/modules"
	"mega-analyzer/pkg/internal/antivm/profile"
	"mega-analyzer/pkg/internal/antivm/verifier"
)

// Options tune a run.
type Options struct {
	// DryRun plans and logs but does not apply or verify.
	DryRun bool
	// Strict turns any module failure (even non-critical) into an abort.
	Strict bool
	// Only, when non-empty, restricts the run to modules whose Name() is listed.
	Only map[string]bool
}

// ModuleResult captures one module's outcome.
type ModuleResult struct {
	Module   string              `json:"module"`
	Applied  adapter.ApplyResult `json:"applied"`
	Verify   verifier.Report     `json:"verify"`
	Err      string              `json:"error,omitempty"`
	Critical bool                `json:"critical"`
}

// RunReport is the aggregate result of a planner run. There is no coarse
// "applied: true" — the truth is Status plus the per-module results.
type RunReport struct {
	Status     verifier.Status `json:"status"`
	Modules    []ModuleResult  `json:"modules"`
	Operations []PlannedOp     `json:"operations"`
	Warnings   []string        `json:"warnings,omitempty"`
	Aborted    bool            `json:"aborted"`
	AbortedBy  string          `json:"aborted_by,omitempty"`
	StartedAt  time.Time       `json:"started_at"`
	FinishedAt time.Time       `json:"finished_at"`
}

// PlannedOp is a flattened view of the plan for reporting / dry-run.
type PlannedOp struct {
	Name     string `json:"name"`
	Module   string `json:"module"`
	Critical bool   `json:"critical"`
}

// Planner runs a sequence of modules against a device.
type Planner struct {
	profile profile.DeviceProfile
	mods    []modules.Module
}

// New builds a Planner for a profile and an ordered module list.
func New(p profile.DeviceProfile, mods []modules.Module) *Planner {
	return &Planner{profile: p, mods: mods}
}

// Plan returns the flattened operation list without executing anything.
func (pl *Planner) Plan(opts Options) []PlannedOp {
	var ops []PlannedOp
	for _, m := range pl.mods {
		if opts.Only != nil && !opts.Only[m.Name()] {
			continue
		}
		for _, op := range m.Plan(pl.profile) {
			ops = append(ops, PlannedOp{Name: op.Name, Module: op.Module, Critical: op.Critical})
		}
	}
	return ops
}

// Run executes the plan. now is injected so callers control timestamps
// (keeps the function testable and free of ambient time in scripts).
func (pl *Planner) Run(ctx context.Context, dev adapter.DeviceAdapter, opts Options, now func() time.Time) (RunReport, error) {
	rep := RunReport{StartedAt: now(), Status: verifier.StatusPassed}
	rep.Operations = pl.Plan(opts)

	// Step 1: validate the whole profile up front. A malformed profile aborts.
	if res := profile.Validate(pl.profile); !res.OK() {
		rep.Aborted = true
		rep.AbortedBy = "profile-validation"
		rep.Status = verifier.StatusFailed
		rep.FinishedAt = now()
		return rep, fmt.Errorf("profile invalid: %w", res.Err())
	}

	if opts.DryRun {
		rep.FinishedAt = now()
		rep.Status = verifier.StatusSkipped
		return rep, nil
	}

	for _, m := range pl.mods {
		if opts.Only != nil && !opts.Only[m.Name()] {
			continue
		}
		mr := pl.runModule(ctx, dev, m)
		rep.Modules = append(rep.Modules, mr)

		if mr.Err != "" || mr.Verify.Status == verifier.StatusFailed {
			isCritical := mr.Critical || opts.Strict
			if isCritical {
				rep.Aborted = true
				rep.AbortedBy = m.Name()
				rep.Status = verifier.StatusFailed
				rep.FinishedAt = now()
				return rep, fmt.Errorf("module %s failed critically", m.Name())
			}
			// Non-critical failure: warn, downgrade, continue.
			rep.Warnings = append(rep.Warnings, fmt.Sprintf("%s: %s", m.Name(), moduleProblem(mr)))
			rep.Status = downgrade(rep.Status, verifier.StatusPartial)
		} else if mr.Verify.Status == verifier.StatusPartial || mr.Verify.Status == verifier.StatusSkipped {
			rep.Status = downgrade(rep.Status, verifier.StatusPartial)
		}
	}

	rep.FinishedAt = now()
	return rep, nil
}

// runModule validates, applies (with retries), and verifies one module.
func (pl *Planner) runModule(ctx context.Context, dev adapter.DeviceAdapter, m modules.Module) ModuleResult {
	mr := ModuleResult{Module: m.Name(), Critical: moduleCritical(m, pl.profile)}

	if err := m.Validate(pl.profile); err != nil {
		mr.Err = err.Error()
		return mr
	}

	// Apply with retries derived from the module's plan.
	retries := maxRetries(m.Plan(pl.profile))
	var applyErr error
	for attempt := 0; attempt <= retries; attempt++ {
		mr.Applied, applyErr = m.Apply(ctx, dev)
		if applyErr == nil {
			break
		}
	}
	if applyErr != nil {
		mr.Err = applyErr.Error()
		return mr
	}

	// Verify by reading device state — never trust Apply alone.
	report, err := m.Verify(ctx, dev)
	if err != nil {
		mr.Err = err.Error()
		return mr
	}
	mr.Verify = report
	return mr
}

// moduleCritical reports whether any of a module's operations is critical.
func moduleCritical(m modules.Module, p profile.DeviceProfile) bool {
	for _, op := range m.Plan(p) {
		if op.Critical {
			return true
		}
	}
	return false
}

func maxRetries(ops []modules.Operation) int {
	max := 0
	for _, op := range ops {
		if op.RetryCount > max {
			max = op.RetryCount
		}
	}
	return max
}

func moduleProblem(mr ModuleResult) string {
	if mr.Err != "" {
		return mr.Err
	}
	if len(mr.Verify.Mismatches) > 0 {
		return fmt.Sprintf("%d verification mismatch(es)", len(mr.Verify.Mismatches))
	}
	return "verification not passed"
}

// downgrade returns the worse of two statuses (failed > partial > skipped >
// passed), never upgrading a bad status back to good.
func downgrade(cur, next verifier.Status) verifier.Status {
	rank := map[verifier.Status]int{
		verifier.StatusPassed: 0, verifier.StatusSkipped: 1,
		verifier.StatusPartial: 2, verifier.StatusFailed: 3,
	}
	if rank[next] > rank[cur] {
		return next
	}
	return cur
}

// ErrAborted is returned wrapped when a run stops on a critical failure.
var ErrAborted = errors.New("run aborted")
