package modules

import (
	"context"
	"time"

	"mega-analyzer/pkg/internal/antivm/adapter"
	"mega-analyzer/pkg/internal/antivm/profile"
	"mega-analyzer/pkg/internal/antivm/verifier"
)

// EnvironmentModule clears emulator-specific environment signals (qemu flags,
// goldfish services, debug flags) so the environment group verifies clean.
type EnvironmentModule struct {
	profile profile.DeviceProfile
}

// NewEnvironmentModule creates an EnvironmentModule bound to a profile.
func NewEnvironmentModule(p profile.DeviceProfile) *EnvironmentModule {
	return &EnvironmentModule{profile: p}
}

func (m *EnvironmentModule) Name() string { return "environment" }

// Validate has no profile prerequisites — the environment target is fixed.
func (m *EnvironmentModule) Validate(p profile.DeviceProfile) error { return nil }

func (m *EnvironmentModule) props() []adapter.PropSet {
	return []adapter.PropSet{
		{Key: "ro.kernel.qemu", Value: "0"},
		{Key: "ro.boot.qemu", Value: "0"},
		{Key: "ro.debuggable", Value: "0"},
		{Key: "ro.secure", Value: "1"},
		{Key: "ro.build.type", Value: "user"},
		{Key: "ro.build.tags", Value: "release-keys"},
		{Key: "init.svc.goldfish-setup", Value: ""},
		{Key: "init.svc.goldfish-logcat", Value: ""},
	}
}

func (m *EnvironmentModule) Plan(p profile.DeviceProfile) []Operation {
	return []Operation{{
		Name:       "environment.deqemu",
		Module:     m.Name(),
		Critical:   true,
		Timeout:    30 * time.Second,
		RetryCount: 1,
		Config:     adapter.TestConfig{Props: m.props()},
	}}
}

func (m *EnvironmentModule) Apply(ctx context.Context, dev adapter.DeviceAdapter) (adapter.ApplyResult, error) {
	return dev.ApplyTestConfig(ctx, adapter.TestConfig{Props: m.props()})
}

func (m *EnvironmentModule) Verify(ctx context.Context, dev adapter.DeviceAdapter) (verifier.Report, error) {
	groups := map[verifier.Group]bool{verifier.GroupEnvironment: true}
	critical := map[verifier.Group]bool{verifier.GroupEnvironment: true}
	return verifyGroups(ctx, dev, m.profile, groups, critical)
}

var _ Module = (*EnvironmentModule)(nil)
