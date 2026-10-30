package modules

import (
	"context"
	"fmt"
	"time"

	"mega-analyzer/pkg/internal/antivm/adapter"
	"mega-analyzer/pkg/internal/antivm/profile"
	"mega-analyzer/pkg/internal/antivm/verifier"
)

// BatteryModule fakes a realistic battery state via dumpsys. It is a
// non-critical module: a wrong battery level is a weak emulator signal, so its
// failure should downgrade a run to partial, not fail it.
type BatteryModule struct {
	profile profile.DeviceProfile
}

// NewBatteryModule creates a BatteryModule bound to a profile.
func NewBatteryModule(p profile.DeviceProfile) *BatteryModule {
	return &BatteryModule{profile: p}
}

func (m *BatteryModule) Name() string { return "battery" }

func (m *BatteryModule) Validate(p profile.DeviceProfile) error {
	if p.Battery.Level < 0 || p.Battery.Level > 100 {
		return fmt.Errorf("battery: level %d out of range", p.Battery.Level)
	}
	return nil
}

func (m *BatteryModule) commands() []adapter.ShellCmd {
	b := m.profile.Battery
	status := "3" // discharging
	if b.Status == "charging" {
		status = "2"
	} else if b.Status == "full" {
		status = "5"
	}
	return []adapter.ShellCmd{
		{Cmd: "dumpsys battery unplug"},
		{Cmd: fmt.Sprintf("dumpsys battery set level %d", b.Level)},
		{Cmd: "dumpsys battery set status " + status},
	}
}

func (m *BatteryModule) Plan(p profile.DeviceProfile) []Operation {
	return []Operation{{
		Name:       "battery.dumpsys",
		Module:     m.Name(),
		Critical:   false,
		Timeout:    20 * time.Second,
		RetryCount: 0,
		Config:     adapter.TestConfig{Commands: m.commands()},
	}}
}

func (m *BatteryModule) Apply(ctx context.Context, dev adapter.DeviceAdapter) (adapter.ApplyResult, error) {
	return dev.ApplyTestConfig(ctx, adapter.TestConfig{Commands: m.commands()})
}

func (m *BatteryModule) Verify(ctx context.Context, dev adapter.DeviceAdapter) (verifier.Report, error) {
	groups := map[verifier.Group]bool{verifier.GroupBattery: true}
	// Battery is non-critical.
	critical := map[verifier.Group]bool{}
	return verifyGroups(ctx, dev, m.profile, groups, critical)
}

var _ Module = (*BatteryModule)(nil)
