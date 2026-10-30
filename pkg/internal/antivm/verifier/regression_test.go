package verifier

import (
	"context"
	"path/filepath"
	"testing"

	"mega-analyzer/pkg/internal/antivm/adapter"
	"mega-analyzer/pkg/internal/antivm/profile"
)

// TestRegression_AllAPILevels loads each shipped fixture (API 33/34/35/36) and
// verifies it against a replayed device state built to match. Every fixture
// must fully pass, guarding against drift in the profile→verify pipeline across
// Android releases.
func TestRegression_AllAPILevels(t *testing.T) {
	fixtures := []string{
		"pixel-7-api-33.json",
		"pixel-7-api-34.json",
		"pixel-8-api-35.json",
		"pixel-9-api-36.json",
	}
	crit := map[Group]bool{GroupIdentity: true, GroupBuild: true, GroupEnvironment: true}

	for _, f := range fixtures {
		t.Run(f, func(t *testing.T) {
			p, err := profile.LoadValid(filepath.Join("..", "profiles", f))
			if err != nil {
				t.Fatalf("load fixture: %v", err)
			}
			st := matchingState(p)
			rep := Verify(p, st, crit)
			if rep.Status != StatusPassed {
				t.Errorf("fixture %s did not fully pass: status=%s mismatches=%+v",
					f, rep.Status, rep.Mismatches)
			}
		})
	}
}

// matchingState builds a DeviceState that fully satisfies the profile, as if
// captured from a correctly-patched device (a stand-in for a replay capture).
func matchingState(p profile.DeviceProfile) adapter.DeviceState {
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

// TestRegression_ViaReplayAdapter proves the same through the ReplayAdapter,
// exercising the exact offline-verification path the CLI's `session verify
// --replay` uses.
func TestRegression_ViaReplayAdapter(t *testing.T) {
	p, err := profile.LoadValid(filepath.Join("..", "profiles", "pixel-8-api-35.json"))
	if err != nil {
		t.Fatal(err)
	}
	dev := adapter.NewReplayAdapter(matchingState(p))
	st, _ := dev.ReadState(context.Background())
	rep := Verify(p, st, map[Group]bool{GroupIdentity: true})
	if rep.Status != StatusPassed {
		t.Errorf("replay verify failed: %+v", rep.Mismatches)
	}
}
