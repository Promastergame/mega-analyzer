package modules

import (
	"context"
	"fmt"
	"time"

	"mega-analyzer/pkg/internal/antivm/adapter"
	"mega-analyzer/pkg/internal/antivm/profile"
	"mega-analyzer/pkg/internal/antivm/verifier"
)

// LocaleModule patches the device locale, timezone, and language via system
// properties. These are soft settings that don't require a reboot.
type LocaleModule struct {
	profile profile.DeviceProfile
}

// NewLocaleModule creates a LocaleModule bound to a profile.
func NewLocaleModule(p profile.DeviceProfile) *LocaleModule {
	return &LocaleModule{profile: p}
}

func (m *LocaleModule) Name() string { return "locale" }

func (m *LocaleModule) Validate(p profile.DeviceProfile) error {
	if p.Locale == "" || p.Timezone == "" {
		return fmt.Errorf("locale: locale and timezone are required")
	}
	return nil
}

func (m *LocaleModule) props() []adapter.PropSet {
	return []adapter.PropSet{
		{Key: "persist.sys.locale", Value: m.profile.Locale},
		{Key: "persist.sys.timezone", Value: m.profile.Timezone},
	}
}

func (m *LocaleModule) Plan(p profile.DeviceProfile) []Operation {
	return []Operation{{
		Name:       "locale.settings",
		Module:     m.Name(),
		Critical:   false,
		Timeout:    30 * time.Second,
		RetryCount: 0,
		Config:     adapter.TestConfig{Props: m.props()},
	}}
}

func (m *LocaleModule) Apply(ctx context.Context, dev adapter.DeviceAdapter) (adapter.ApplyResult, error) {
	return dev.ApplyTestConfig(ctx, adapter.TestConfig{Props: m.props()})
}

func (m *LocaleModule) Verify(ctx context.Context, dev adapter.DeviceAdapter) (verifier.Report, error) {
	groups := map[verifier.Group]bool{}
	critical := map[verifier.Group]bool{}
	return verifyGroups(ctx, dev, m.profile, groups, critical)
}

var _ Module = (*LocaleModule)(nil)
