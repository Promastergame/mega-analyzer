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

// NetworkModule patches network identity: MAC address, WiFi SSID, IMEI, serial.
// These are mostly read-only from the device perspective, so verification may
// often skip or show partial results.
type NetworkModule struct {
	profile profile.DeviceProfile
}

// NewNetworkModule creates a NetworkModule bound to a profile.
func NewNetworkModule(p profile.DeviceProfile) *NetworkModule {
	return &NetworkModule{profile: p}
}

func (m *NetworkModule) Name() string { return "network" }

func (m *NetworkModule) Validate(p profile.DeviceProfile) error {
	if p.Network.MACAddress == "" || p.Network.IMEI == "" || p.Network.Serial == "" {
		return fmt.Errorf("network: mac_address, imei, and serial are required")
	}
	return nil
}

func (m *NetworkModule) commands() []adapter.ShellCmd {
	net := m.profile.Network
	return []adapter.ShellCmd{
		{Cmd: fmt.Sprintf("ip link set wlan0 address %s", strings.ToLower(net.MACAddress))},
	}
}

func (m *NetworkModule) props() []adapter.PropSet {
	net := m.profile.Network
	return []adapter.PropSet{
		{Key: "ro.serialno", Value: net.Serial},
		{Key: "ro.boot.serialno", Value: net.Serial},
		{Key: "gsm.sim.operator.imei", Value: net.IMEI},
		{Key: "ril.deviceid", Value: net.IMEI},
		{Key: "persist.radio.device.imei", Value: net.IMEI},
		{Key: "wifi.interface.ssid", Value: net.WiFiSSID},
	}
}

func (m *NetworkModule) Plan(p profile.DeviceProfile) []Operation {
	return []Operation{{
		Name:       "network.identity",
		Module:     m.Name(),
		Critical:   false,
		Timeout:    30 * time.Second,
		RetryCount: 0,
		Config: adapter.TestConfig{
			Props:    m.props(),
			Commands: m.commands(),
		},
	}}
}

func (m *NetworkModule) Apply(ctx context.Context, dev adapter.DeviceAdapter) (adapter.ApplyResult, error) {
	return dev.ApplyTestConfig(ctx, adapter.TestConfig{
		Props:    m.props(),
		Commands: m.commands(),
	})
}

func (m *NetworkModule) Verify(ctx context.Context, dev adapter.DeviceAdapter) (verifier.Report, error) {
	groups := map[verifier.Group]bool{verifier.GroupNetwork: true}
	critical := map[verifier.Group]bool{}
	return verifyGroups(ctx, dev, m.profile, groups, critical)
}

var _ Module = (*NetworkModule)(nil)
