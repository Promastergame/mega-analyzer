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
	if batteryStatusCode(p.Battery.Status) == "" {
		return fmt.Errorf("battery: unsupported status %q", p.Battery.Status)
	}
	if batteryHealthCode(p.Battery.Health) == "" && p.Battery.Health != "" {
		return fmt.Errorf("battery: unsupported health %q", p.Battery.Health)
	}
	switch p.Battery.Plugged {
	case "", "none", "ac", "usb", "wireless":
	default:
		return fmt.Errorf("battery: unsupported power source %q", p.Battery.Plugged)
	}
	return nil
}

func (m *BatteryModule) commands() []adapter.ShellCmd {
	b := m.profile.Battery
	commands := []adapter.ShellCmd{
		{Cmd: "dumpsys battery unplug"},
		{Cmd: fmt.Sprintf("dumpsys battery set level %d", b.Level)},
		{Cmd: "dumpsys battery set status " + batteryStatusCode(b.Status)},
	}
	if b.Temperature != 0 {
		commands = append(commands, adapter.ShellCmd{Cmd: fmt.Sprintf("dumpsys battery set temp %d", b.Temperature)})
	}
	if health := batteryHealthCode(b.Health); health != "" {
		commands = append(commands, adapter.ShellCmd{Cmd: "dumpsys battery set health " + health})
	}
	if b.Plugged != "" && b.Plugged != "none" {
		commands = append(commands, adapter.ShellCmd{Cmd: "dumpsys battery set " + b.Plugged + " 1"})
	}
	return commands
}

func batteryStatusCode(status string) string {
	return map[string]string{"charging": "2", "discharging": "3", "not-charging": "4", "full": "5"}[status]
}

func batteryHealthCode(health string) string {
	return map[string]string{"unknown": "1", "good": "2", "overheat": "3", "dead": "4", "over-voltage": "5", "unspecified-failure": "6", "cold": "7"}[health]
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
