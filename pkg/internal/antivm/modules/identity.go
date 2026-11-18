package modules

import (
	"context"
	"fmt"
	"strings"
	"time"

	"mega-analyzer/pkg/internal/antivm/adapter"
	"mega-analyzer/pkg/internal/antivm/profile"
	"mega-analyzer/pkg/internal/antivm/verifier"
)

// IdentityModule patches the device identity properties (model, brand, build,
// fingerprint) so the running device matches the profile.
type IdentityModule struct {
	profile profile.DeviceProfile
}

// NewIdentityModule creates an IdentityModule bound to a profile.
func NewIdentityModule(p profile.DeviceProfile) *IdentityModule {
	return &IdentityModule{profile: p}
}

func (m *IdentityModule) Name() string { return "identity" }

func (m *IdentityModule) Validate(p profile.DeviceProfile) error {
	if p.Model == "" || p.Brand == "" || p.Fingerprint == "" {
		return fmt.Errorf("identity: model, brand and fingerprint are required")
	}
	return nil
}

func (m *IdentityModule) props() []adapter.PropSet {
	p := m.profile
	props := []adapter.PropSet{
		{Key: "ro.product.model", Value: p.Model},
		{Key: "ro.product.brand", Value: p.Brand},
		{Key: "ro.product.manufacturer", Value: p.Manufacturer},
		{Key: "ro.product.device", Value: p.Device},
		{Key: "ro.product.name", Value: p.Product},
		{Key: "ro.build.fingerprint", Value: p.Fingerprint},
		{Key: "ro.build.id", Value: p.BuildID},
		{Key: "ro.build.display.id", Value: p.BuildID},
		{Key: "ro.build.version.security_patch", Value: p.SecurityPatch},
		{Key: "ro.build.product", Value: p.Device},
		{Key: "ro.build.description", Value: strings.Join([]string{p.Product + "-user", p.AndroidVersion, p.BuildID, "release-keys"}, " ")},
	}
	if p.Hardware != "" {
		props = append(props, adapter.PropSet{Key: "ro.hardware", Value: p.Hardware})
	}
	if p.Board != "" {
		props = append(props, adapter.PropSet{Key: "ro.product.board", Value: p.Board})
	}
	// Partition aliases are independent on recent Android releases. Keep them
	// consistent with the primary identity rather than leaving SDK aliases behind.
	for _, partition := range []string{"system", "vendor", "product", "odm", "system_ext"} {
		for _, field := range []adapter.PropSet{{Key: "model", Value: p.Model}, {Key: "brand", Value: p.Brand}, {Key: "manufacturer", Value: p.Manufacturer}, {Key: "device", Value: p.Device}, {Key: "name", Value: p.Product}} {
			props = append(props, adapter.PropSet{Key: "ro.product." + partition + "." + field.Key, Value: field.Value})
		}
		props = append(props, adapter.PropSet{Key: "ro." + partition + ".build.fingerprint", Value: p.Fingerprint})
	}
	props = append(props, adapter.PropSet{Key: "ro.bootimage.build.fingerprint", Value: p.Fingerprint})
	return props
}

func (m *IdentityModule) Plan(p profile.DeviceProfile) []Operation {
	return []Operation{{
		Name:       "identity.properties",
		Module:     m.Name(),
		Critical:   true,
		Timeout:    90 * time.Second,
		RetryCount: 1,
		Config:     adapter.TestConfig{Props: m.props()},
	}}
}

func (m *IdentityModule) Apply(ctx context.Context, dev adapter.DeviceAdapter) (adapter.ApplyResult, error) {
	return dev.ApplyTestConfig(ctx, adapter.TestConfig{Props: m.props()})
}

func (m *IdentityModule) Verify(ctx context.Context, dev adapter.DeviceAdapter) (verifier.Report, error) {
	groups := map[verifier.Group]bool{verifier.GroupIdentity: true, verifier.GroupBuild: true}
	critical := map[verifier.Group]bool{verifier.GroupIdentity: true, verifier.GroupBuild: true}
	return verifyGroups(ctx, dev, m.profile, groups, critical)
}

var _ Module = (*IdentityModule)(nil)
