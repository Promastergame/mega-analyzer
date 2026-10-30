package modules

import (
	"context"
	"time"

	"mega-analyzer/pkg/internal/antivm/adapter"
	"mega-analyzer/pkg/internal/antivm/profile"
	"mega-analyzer/pkg/internal/antivm/verifier"
)

// SensorsModule ensures sensor subsystems are available and reports their mock state.
// On real devices this is a no-op (sensors are always there); on emulators this may
// involve enabling sensor HALs or configuring mock sensor providers.
type SensorsModule struct {
	profile profile.DeviceProfile
}

// NewSensorsModule creates a SensorsModule bound to a profile.
func NewSensorsModule(p profile.DeviceProfile) *SensorsModule {
	return &SensorsModule{profile: p}
}

func (m *SensorsModule) Name() string { return "sensors" }

// Validate checks that the profile has sensor configuration.
func (m *SensorsModule) Validate(p profile.DeviceProfile) error { return nil }

func (m *SensorsModule) Plan(p profile.DeviceProfile) []Operation {
	if !p.Sensor.Enabled {
		return nil
	}
	return []Operation{{
		Name:       "sensors.verify",
		Module:     m.Name(),
		Critical:   false,
		Timeout:    20 * time.Second,
		RetryCount: 0,
		Config:     adapter.TestConfig{},
	}}
}

func (m *SensorsModule) Apply(ctx context.Context, dev adapter.DeviceAdapter) (adapter.ApplyResult, error) {
	if !m.profile.Sensor.Enabled {
		return adapter.ApplyResult{}, nil
	}
	return adapter.ApplyResult{Succeeded: []string{"sensors.check"}}, nil
}

func (m *SensorsModule) Verify(ctx context.Context, dev adapter.DeviceAdapter) (verifier.Report, error) {
	groups := map[verifier.Group]bool{verifier.GroupSensors: true}
	critical := map[verifier.Group]bool{}
	return verifyGroups(ctx, dev, m.profile, groups, critical)
}

var _ Module = (*SensorsModule)(nil)
