package modules

import (
	"context"
	"time"

	"mega-analyzer/pkg/internal/antivm/adapter"
	"mega-analyzer/pkg/internal/antivm/profile"
	"mega-analyzer/pkg/internal/antivm/verifier"
)

// SensorsModule applies a thermal fixture and bounded emulator sensor playback.
type SensorsModule struct {
	profile profile.DeviceProfile
}

// NewSensorsModule creates a SensorsModule bound to a profile.
func NewSensorsModule(p profile.DeviceProfile) *SensorsModule {
	return &SensorsModule{profile: p}
}

func (m *SensorsModule) Name() string { return "sensors" }

// Validate checks that the profile has sensor configuration.
func (m *SensorsModule) Validate(p profile.DeviceProfile) error {
	return validateMotionProfile(p.Sensor)
}

func (m *SensorsModule) Plan(p profile.DeviceProfile) []Operation {
	if !p.Sensor.Enabled {
		return nil
	}
	return []Operation{{
		Name:       "sensors.thermal",
		Module:     m.Name(),
		Critical:   false,
		Timeout:    60 * time.Second,
		RetryCount: 0,
		Config:     m.config(),
	}}
}

func (m *SensorsModule) Apply(ctx context.Context, dev adapter.DeviceAdapter) (adapter.ApplyResult, error) {
	if !m.profile.Sensor.Enabled {
		return adapter.ApplyResult{}, nil
	}
	return dev.ApplyTestConfig(ctx, m.config())
}

func (m *SensorsModule) config() adapter.TestConfig {
	cfg := thermalConfig()
	cfg.Motion = motionConfig(m.profile.Sensor)
	return cfg
}

func thermalConfig() adapter.TestConfig {
	return adapter.TestConfig{
		EmulatorOnly: true,
		Commands:     []adapter.ShellCmd{{Cmd: thermalTemperatureCommand()}},
	}
}

func (m *SensorsModule) Verify(ctx context.Context, dev adapter.DeviceAdapter) (verifier.Report, error) {
	groups := map[verifier.Group]bool{verifier.GroupSensors: true}
	critical := map[verifier.Group]bool{}
	return verifyGroups(ctx, dev, m.profile, groups, critical)
}

var _ Module = (*SensorsModule)(nil)
