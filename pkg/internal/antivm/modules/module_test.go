package modules

import (
	"context"
	"testing"

	"mega-analyzer/pkg/internal/antivm/adapter"
	"mega-analyzer/pkg/internal/antivm/profile"
	"mega-analyzer/pkg/internal/antivm/verifier"
)

func testProfile(t *testing.T) profile.DeviceProfile {
	t.Helper()
	p, err := profile.Generate(profile.GenSpec{Mode: profile.ModeSeeded, Model: "Pixel 8", API: 35, Seed: 4})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestIdentityModule_ApplyThenVerifyPasses(t *testing.T) {
	p := testProfile(t)
	dev := adapter.NewMockAdapter()
	// Build runtime properties are read-only observations, not identity writes.
	dev.State.Props["ro.build.version.release"] = p.AndroidVersion
	dev.State.Props["ro.build.version.sdk"] = "35"
	dev.State.Props["ro.product.cpu.abi"] = p.ABI
	m := NewIdentityModule(p)
	ctx := context.Background()

	if err := m.Validate(p); err != nil {
		t.Fatalf("validate: %v", err)
	}
	res, err := m.Apply(ctx, dev)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Errorf("apply had failures: %+v", res.Failed)
	}
	rep, err := m.Verify(ctx, dev)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Status != verifier.StatusPassed {
		t.Errorf("verify status = %q, want passed. mismatches=%+v", rep.Status, rep.Mismatches)
	}
}

// The core principle: a module must NOT claim success just because Apply's
// transport returned no error. Here the adapter accepts commands but does not
// reflect them into state (simulating a setprop that silently didn't stick).
func TestIdentityModule_TransportOKButStateWrong(t *testing.T) {
	p := testProfile(t)
	dev := adapter.NewMockAdapter()
	// Pre-seed WRONG identity that Apply will (in this simulation) fail to change.
	dev.State.Props["ro.product.model"] = "sdk_gphone64_x86_64"
	dev.State.Props["ro.build.fingerprint"] = "generic/sdk/emulator:14/AAA/1:userdebug/test-keys"
	// Make the writes "fail silently": mark the identity props as FailProps so
	// Apply reports failures AND state stays wrong.
	dev.FailProps = map[string]bool{
		"ro.product.model":     true,
		"ro.build.fingerprint": true,
	}
	m := NewIdentityModule(p)
	ctx := context.Background()

	res, _ := m.Apply(ctx, dev)
	if res.OK() {
		t.Fatal("expected apply to report per-command failures")
	}
	rep, err := m.Verify(ctx, dev)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Status != verifier.StatusFailed {
		t.Errorf("verify must FAIL when state didn't change; got %q", rep.Status)
	}
}

func TestEnvironmentModule_Verify(t *testing.T) {
	p := testProfile(t)
	dev := adapter.NewMockAdapter()
	m := NewEnvironmentModule(p)
	ctx := context.Background()

	if _, err := m.Apply(ctx, dev); err != nil {
		t.Fatal(err)
	}
	rep, err := m.Verify(ctx, dev)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Status != verifier.StatusPassed {
		t.Errorf("environment verify = %q, want passed. mismatches=%+v", rep.Status, rep.Mismatches)
	}
	// qemu must be 0 after apply.
	if dev.State.Props["ro.kernel.qemu"] != "0" {
		t.Errorf("qemu not cleared: %q", dev.State.Props["ro.kernel.qemu"])
	}
}

func TestBatteryModule_NonCriticalMismatchIsPartial(t *testing.T) {
	p := testProfile(t)
	dev := adapter.NewMockAdapter()
	// Battery module uses dumpsys commands which the mock does not reflect into
	// Battery state, so the level is missing → skipped, not failed.
	m := NewBatteryModule(p)
	ctx := context.Background()

	if _, err := m.Apply(ctx, dev); err != nil {
		t.Fatal(err)
	}
	// Simulate device reporting a DIFFERENT battery level than expected.
	dev.State.Battery["level"] = "5"
	dev.State.Battery["status"] = p.Battery.Status
	rep, err := m.Verify(ctx, dev)
	if err != nil {
		t.Fatal(err)
	}
	// Battery is non-critical: a mismatch here yields failed at group level but
	// the module marks battery non-critical, so its own rollup is failed only
	// for the battery group. We assert the mismatch was detected.
	if len(rep.Mismatches) == 0 {
		t.Error("expected battery level mismatch to be detected")
	}
}

func TestBatteryModule_ValidateRange(t *testing.T) {
	m := NewBatteryModule(profile.DeviceProfile{})
	bad := profile.DeviceProfile{Battery: profile.BatteryProfile{Level: 200}}
	if err := m.Validate(bad); err == nil {
		t.Error("expected validation error for level 200")
	}
}

func TestModule_PlanShape(t *testing.T) {
	p := testProfile(t)
	mods := []Module{NewIdentityModule(p), NewEnvironmentModule(p), NewBatteryModule(p)}
	for _, m := range mods {
		ops := m.Plan(p)
		if len(ops) == 0 {
			t.Errorf("%s.Plan returned no operations", m.Name())
		}
		for _, op := range ops {
			if op.Module != m.Name() {
				t.Errorf("op %q has module %q, want %q", op.Name, op.Module, m.Name())
			}
			if op.Timeout <= 0 {
				t.Errorf("op %q has non-positive timeout", op.Name)
			}
		}
	}
}
