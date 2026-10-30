package modules

import (
	"context"
	"fmt"
	"time"

	"mega-analyzer/pkg/internal/antivm/adapter"
	"mega-analyzer/pkg/internal/antivm/profile"
	"mega-analyzer/pkg/internal/antivm/verifier"
)

// DisplayModule patches screen resolution and density via wm commands.
type DisplayModule struct {
	profile profile.DeviceProfile
}

// NewDisplayModule creates a DisplayModule bound to a profile.
func NewDisplayModule(p profile.DeviceProfile) *DisplayModule {
	return &DisplayModule{profile: p}
}

func (m *DisplayModule) Name() string { return "display" }

func (m *DisplayModule) Validate(p profile.DeviceProfile) error {
	if p.Resolution == "" || p.Density == 0 {
		return fmt.Errorf("display: resolution and density are required")
	}
	return nil
}

func (m *DisplayModule) commands() []adapter.ShellCmd {
	return []adapter.ShellCmd{
		{Cmd: fmt.Sprintf("wm size %s", m.profile.Resolution)},
		{Cmd: fmt.Sprintf("wm density %d", m.profile.Density)},
	}
}

func (m *DisplayModule) Plan(p profile.DeviceProfile) []Operation {
	return []Operation{{
		Name:       "display.resolution",
		Module:     m.Name(),
		Critical:   false,
		Timeout:    30 * time.Second,
		RetryCount: 0,
		Config:     adapter.TestConfig{Commands: m.commands()},
	}}
}

func (m *DisplayModule) Apply(ctx context.Context, dev adapter.DeviceAdapter) (adapter.ApplyResult, error) {
	return dev.ApplyTestConfig(ctx, adapter.TestConfig{Commands: m.commands()})
}

func (m *DisplayModule) Verify(ctx context.Context, dev adapter.DeviceAdapter) (verifier.Report, error) {
	groups := map[verifier.Group]bool{verifier.GroupDisplay: true}
	critical := map[verifier.Group]bool{}
	return verifyGroups(ctx, dev, m.profile, groups, critical)
}

var _ Module = (*DisplayModule)(nil)
