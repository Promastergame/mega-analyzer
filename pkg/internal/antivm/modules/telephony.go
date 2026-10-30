package modules

import (
	"context"
	"fmt"
	"time"

	"mega-analyzer/pkg/internal/antivm/adapter"
	"mega-analyzer/pkg/internal/antivm/profile"
	"mega-analyzer/pkg/internal/antivm/verifier"
)

// TelephonyModule patches operator and SIM identity (MCC/MNC, operator names).
type TelephonyModule struct {
	profile profile.DeviceProfile
}

// NewTelephonyModule creates a TelephonyModule bound to a profile.
func NewTelephonyModule(p profile.DeviceProfile) *TelephonyModule {
	return &TelephonyModule{profile: p}
}

func (m *TelephonyModule) Name() string { return "telephony" }

func (m *TelephonyModule) Validate(p profile.DeviceProfile) error {
	if p.Operator.Numeric == "" || p.Operator.Name == "" {
		return fmt.Errorf("telephony: operator numeric and name are required")
	}
	return nil
}

func (m *TelephonyModule) props() []adapter.PropSet {
	op := m.profile.Operator
	return []adapter.PropSet{
		{Key: "gsm.operator.alpha", Value: op.Name},
		{Key: "gsm.sim.operator.alpha", Value: op.Name},
		{Key: "gsm.operator.numeric", Value: op.Numeric},
		{Key: "gsm.sim.operator.numeric", Value: op.Numeric},
	}
}

func (m *TelephonyModule) Plan(p profile.DeviceProfile) []Operation {
	return []Operation{{
		Name:       "telephony.operator",
		Module:     m.Name(),
		Critical:   false,
		Timeout:    30 * time.Second,
		RetryCount: 0,
		Config:     adapter.TestConfig{Props: m.props()},
	}}
}

func (m *TelephonyModule) Apply(ctx context.Context, dev adapter.DeviceAdapter) (adapter.ApplyResult, error) {
	return dev.ApplyTestConfig(ctx, adapter.TestConfig{Props: m.props()})
}

func (m *TelephonyModule) Verify(ctx context.Context, dev adapter.DeviceAdapter) (verifier.Report, error) {
	groups := map[verifier.Group]bool{verifier.GroupNetwork: true}
	critical := map[verifier.Group]bool{}
	return verifyGroups(ctx, dev, m.profile, groups, critical)
}

var _ Module = (*TelephonyModule)(nil)
