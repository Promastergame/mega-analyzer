package verifier

import (
	"testing"

	"mega-analyzer/pkg/internal/antivm/adapter"
	"mega-analyzer/pkg/internal/antivm/profile"
)

func sampleProfile(t *testing.T) profile.DeviceProfile {
	t.Helper()
	p, err := profile.Generate(profile.GenSpec{Mode: profile.ModeSeeded, Model: "Pixel 7", API: 34, Seed: 1})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// stateMatching builds a DeviceState that fully satisfies the profile.
func stateMatching(p profile.DeviceProfile) adapter.DeviceState {
	st := adapter.NewDeviceState()
	st.Props["ro.product.model"] = p.Model
	st.Props["ro.product.brand"] = p.Brand
	st.Props["ro.product.manufacturer"] = p.Manufacturer
	st.Props["ro.product.device"] = p.Device
	st.Props["ro.build.fingerprint"] = p.Fingerprint
	st.Props["ro.build.display.id"] = p.BuildID
	st.Props["ro.build.version.security_patch"] = p.SecurityPatch
	st.Props["ro.kernel.qemu"] = "0"
	st.Display["resolution"] = p.Resolution
	st.Display["density"] = itoa(p.Density)
	st.Battery["level"] = itoa(p.Battery.Level)
	st.Battery["status"] = p.Battery.Status
	st.Network["mac"] = p.Network.MACAddress
	st.Network["imei"] = p.Network.IMEI
	return st
}

var criticals = map[Group]bool{GroupIdentity: true, GroupBuild: true, GroupEnvironment: true}

func TestVerify_AllPass(t *testing.T) {
	p := sampleProfile(t)
	rep := Verify(p, stateMatching(p), criticals)
	if rep.Status != StatusPassed {
		t.Errorf("status = %q, want passed. mismatches=%+v", rep.Status, rep.Mismatches)
	}
	if rep.Counts.Failed != 0 {
		t.Errorf("unexpected failures: %d", rep.Counts.Failed)
	}
}

func TestVerify_CriticalMismatchFails(t *testing.T) {
	p := sampleProfile(t)
	st := stateMatching(p)
	st.Props["ro.product.model"] = "sdk_gphone64_x86_64" // identity is critical
	rep := Verify(p, st, criticals)
	if rep.Status != StatusFailed {
		t.Errorf("status = %q, want failed", rep.Status)
	}
	if len(rep.Mismatches) == 0 || rep.Mismatches[0].Field != "model" {
		t.Errorf("expected model mismatch first, got %+v", rep.Mismatches)
	}
	if rep.Mismatches[0].Severity != SeverityHigh {
		t.Errorf("model mismatch should be high severity")
	}
}

func TestVerify_NonCriticalMismatchPartial(t *testing.T) {
	p := sampleProfile(t)
	st := stateMatching(p)
	st.Battery["level"] = "5" // battery is non-critical
	rep := Verify(p, st, criticals)
	if rep.Status != StatusPartial {
		t.Errorf("status = %q, want partial", rep.Status)
	}
}

func TestVerify_MissingReadableSkips(t *testing.T) {
	p := sampleProfile(t)
	st := stateMatching(p)
	delete(st.Display, "resolution")
	delete(st.Display, "density")
	rep := Verify(p, st, criticals)
	if rep.Counts.Skipped == 0 {
		t.Error("expected some skipped checks")
	}
	if rep.ByGroup[GroupDisplay] != StatusSkipped {
		t.Errorf("display group = %q, want skipped", rep.ByGroup[GroupDisplay])
	}
	// Display is non-critical & skipped → overall partial, not failed.
	if rep.Status != StatusPartial {
		t.Errorf("status = %q, want partial", rep.Status)
	}
}

func TestVerify_EmptyStateAllSkipped(t *testing.T) {
	p := sampleProfile(t)
	rep := Verify(p, adapter.NewDeviceState(), criticals)
	if rep.Counts.Passed != 0 || rep.Counts.Failed != 0 {
		t.Errorf("expected nothing passed/failed on empty state: %+v", rep.Counts)
	}
	if rep.Status != StatusPartial && rep.Status != StatusSkipped {
		t.Errorf("status = %q, want partial or skipped", rep.Status)
	}
}

func TestWorseOrdering(t *testing.T) {
	if worse(StatusPassed, StatusFailed) != StatusFailed {
		t.Error("failed should dominate passed")
	}
	if worse(StatusPartial, StatusSkipped) != StatusPartial {
		t.Error("partial should dominate skipped")
	}
	if worse(StatusPassed, "") != StatusPassed {
		t.Error("empty treated as passed")
	}
}
