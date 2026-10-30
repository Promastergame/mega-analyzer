//go:build !windows

package sandbox

import "fmt"

func verifyVMwareGuestHardware() error {
	return fmt.Errorf("гостевой сборщик VMware требует Windows")
}
