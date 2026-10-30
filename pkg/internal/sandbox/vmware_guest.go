package sandbox

import (
	"context"
	"fmt"
	"net"
)

// RunVMwareGuest is the guest-only entry point used by the VMware collector.
// It cannot turn the web server's host runner into a native execution fallback.
// No NIC may be up: disconnection is configured by the host before VM boot.
func RunVMwareGuest(ctx context.Context, cfg Config) (*Report, error) {
	if err := verifyVMwareGuestHardware(); err != nil {
		return nil, err
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("проверить сетевые интерфейсы гостя: %w", err)
	}
	for _, nic := range interfaces {
		if nic.Flags&net.FlagUp != 0 && nic.Flags&net.FlagLoopback == 0 {
			return nil, fmt.Errorf("сетевой интерфейс %s включён внутри гостя; запуск отменён", nic.Name)
		}
	}
	cfg.AllowHostExecution = true
	cfg.BlockNetwork = true
	cfg.externalNetworkIsolation = "vmware_disconnected"
	return Run(ctx, cfg)
}
