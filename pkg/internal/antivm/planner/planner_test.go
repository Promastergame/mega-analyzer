package planner

import (
	"context"
	"testing"
	"time"

	"mega-analyzer/pkg/internal/antivm/adapter"
	"mega-analyzer/pkg/internal/antivm/modules"
	"mega-analyzer/pkg/internal/antivm/profile"
	"mega-analyzer/pkg/internal/antivm/verifier"
)

func fixedNow() func() time.Time {
	base := time.Date(2026, 7, 16, 23, 5, 0, 0, time.UTC)
	return func() time.Time { return base }
}

func goodProfile(t *testing.T) profile.DeviceProfile {
	t.Helper()
	p, err := profile.Generate(profile.GenSpec{Mode: profile.ModeSeeded, Model: "Pixel 7", API: 34, Seed: 1})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func mods(p profile.DeviceProfile) []modules.Module {
	return []modules.Module{
		modules.NewIdentityModule(p),
		modules.NewEnvironmentModule(p),
		modules.NewBatteryModule(p),
	}
}

func TestPlanner_HappyPath(t *testing.T) {
	p := goodProfile(t)
	dev := adapter.NewMockAdapter()
	pl := New(p, mods(p))

	rep, err := pl.Run(context.Background(), dev, Options{}, fixedNow())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	// Battery group is skipped by the mock (dumpsys not reflected), so overall
	// is partial — but identity+environment must have passed and nothing aborted.
	if rep.Aborted {
		t.Errorf("unexpected abort by %q", rep.AbortedBy)
	}
	if rep.Status == verifier.StatusFailed {
		t.Errorf("status should not be failed: %+v", rep)
	}
	if len(rep.Modules) != 3 {
		t.Errorf("expected 3 module results, got %d", len(rep.Modules))
	}
}

func TestPlanner_DryRun(t *testing.T) {
	p := goodProfile(t)
	dev := adapter.NewMockAdapter()
	pl := New(p, mods(p))

	rep, err := pl.Run(context.Background(), dev, Options{DryRun: true}, fixedNow())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Status != verifier.StatusSkipped {
		t.Errorf("dry run status = %q, want skipped", rep.Status)
	}
	if dev.ApplyCount != 0 {
		t.Errorf("dry run applied %d configs, want 0", dev.ApplyCount)
	}
	if len(rep.Operations) == 0 {
		t.Error("dry run should still produce a plan")
	}
}

func TestPlanner_InvalidProfileAborts(t *testing.T) {
	p := goodProfile(t)
	p.APILevel = 99 // makes Validate fail
	dev := adapter.NewMockAdapter()
	pl := New(p, mods(p))

	rep, err := pl.Run(context.Background(), dev, Options{}, fixedNow())
	if err == nil {
		t.Fatal("expected error for invalid profile")
	}
	if !rep.Aborted || rep.AbortedBy != "profile-validation" {
		t.Errorf("expected profile-validation abort, got %+v", rep)
	}
}

func TestPlanner_CriticalFailureAborts(t *testing.T) {
	p := goodProfile(t)
	dev := adapter.NewMockAdapter()
	// Force identity props to not stick → identity (critical) verify fails.
	dev.FailProps = map[string]bool{
		"ro.product.model":     true,
		"ro.build.fingerprint": true,
	}
	dev.State.Props["ro.product.model"] = "sdk_gphone64"
	dev.State.Props["ro.build.fingerprint"] = "generic/sdk/test-keys"

	pl := New(p, mods(p))
	rep, err := pl.Run(context.Background(), dev, Options{}, fixedNow())
	if err == nil {
		t.Fatal("expected critical abort error")
	}
	if rep.AbortedBy != "identity" {
		t.Errorf("aborted by %q, want identity", rep.AbortedBy)
	}
	if rep.Status != verifier.StatusFailed {
		t.Errorf("status = %q, want failed", rep.Status)
	}
}

func TestPlanner_StrictPromotesNonCritical(t *testing.T) {
	p := goodProfile(t)
	dev := adapter.NewMockAdapter()
	pl := New(p, []modules.Module{modules.NewBatteryModule(p)})

	// Battery verify will be skipped (no reflected state) under the mock, which
	// is not a failure. Force a genuine failure by making the device report a
	// wrong level so the battery group fails.
	dev.State.Battery["level"] = "1"
	dev.State.Battery["status"] = p.Battery.Status

	// Non-strict: non-critical failure → partial, no abort.
	rep, _ := pl.Run(context.Background(), dev, Options{}, fixedNow())
	if rep.Aborted {
		t.Error("non-strict run should not abort on non-critical failure")
	}

	// Strict: same failure now aborts.
	dev2 := adapter.NewMockAdapter()
	dev2.State.Battery["level"] = "1"
	dev2.State.Battery["status"] = p.Battery.Status
	rep2, err := pl.Run(context.Background(), dev2, Options{Strict: true}, fixedNow())
	if err == nil || !rep2.Aborted {
		t.Errorf("strict run should abort on failure: %+v", rep2)
	}
}

func TestPlanner_OnlyFilter(t *testing.T) {
	p := goodProfile(t)
	dev := adapter.NewMockAdapter()
	pl := New(p, mods(p))

	rep, err := pl.Run(context.Background(), dev, Options{Only: map[string]bool{"identity": true}}, fixedNow())
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Modules) != 1 || rep.Modules[0].Module != "identity" {
		t.Errorf("Only filter failed: %+v", rep.Modules)
	}
}

func TestPlanner_VerifyOnlyDoesNotRepairState(t *testing.T) {
	p := goodProfile(t)
	dev := adapter.NewMockAdapter()
	dev.State.Props["ro.product.model"] = "sdk_gphone64"
	rep, err := New(p, mods(p)).Run(context.Background(), dev, Options{VerifyOnly: true}, fixedNow())
	if err == nil || rep.Status != verifier.StatusFailed || !rep.VerifyOnly {
		t.Fatalf("verify-only must report the original mismatch: %+v, %v", rep, err)
	}
	if dev.ApplyCount != 0 || dev.State.Props["ro.product.model"] != "sdk_gphone64" {
		t.Fatal("verify-only mutated the device")
	}
}

func TestPlanner_CommandFailureCannotPassMatchingState(t *testing.T) {
	p := goodProfile(t)
	dev := adapter.NewMockAdapter()
	// Every checked field matches, but a planned command that used to be
	// unverified fails. The module must still report a critical failure.
	dev.State.Props["ro.secure"] = "1"
	dev.FailProps = map[string]bool{"ro.secure": true}
	rep, err := New(p, []modules.Module{modules.NewEnvironmentModule(p)}).Run(context.Background(), dev, Options{}, fixedNow())
	if err == nil || rep.Status != verifier.StatusFailed || rep.Modules[0].Verify.Status != verifier.StatusPassed {
		t.Fatalf("command failure was lost: %+v, %v", rep, err)
	}
}

func TestPlanner_ContinueKeepsFailureAndRunsRemainingModules(t *testing.T) {
	p := goodProfile(t)
	for _, strict := range []bool{false, true} {
		dev := adapter.NewMockAdapter()
		dev.FailProps = map[string]bool{"ro.product.model": true}
		dev.State.Props["ro.product.model"] = "sdk_gphone64"
		rep, err := New(p, mods(p)).Run(context.Background(), dev, Options{ContinueOnFailure: true, Strict: strict}, fixedNow())
		if err == nil || rep.Status != verifier.StatusFailed {
			t.Fatalf("continued run lost its failure: %+v, %v", rep, err)
		}
		want := 3
		if strict {
			want = 1
		}
		if len(rep.Modules) != want || rep.Aborted != strict {
			t.Fatalf("strict=%v report=%+v", strict, rep)
		}
	}
}
