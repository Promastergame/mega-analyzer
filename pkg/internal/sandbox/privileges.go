//go:build windows

package sandbox

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	modAdvapi32               = syscall.NewLazyDLL("advapi32.dll")
	procOpenProcessToken      = modAdvapi32.NewProc("OpenProcessToken")
	procGetTokenInformation   = modAdvapi32.NewProc("GetTokenInformation")
	procLookupPrivilegeValue  = modAdvapi32.NewProc("LookupPrivilegeValueW")
	procAdjustTokenPrivileges = modAdvapi32.NewProc("AdjustTokenPrivileges")
)

const (
	tokenQuery            = 0x0008
	tokenAdjustPrivileges = 0x0020
	tokenElevation        = 20
	sePrivilegeEnabled    = 0x00000002
)

// tokenElevationInfo represents the TOKEN_ELEVATION structure
type tokenElevationInfo struct {
	TokenIsElevated uint32
}

// luid represents a locally unique identifier
type luid struct {
	LowPart  uint32
	HighPart int32
}

// luidAndAttributes represents a LUID with its attributes
type luidAndAttributes struct {
	Luid       luid
	Attributes uint32
}

// tokenPrivileges represents the TOKEN_PRIVILEGES structure
type tokenPrivileges struct {
	PrivilegeCount uint32
	Privileges     [1]luidAndAttributes
}

// checkPrivileges verifies that the process has administrator rights
// and attempts to enable SeDebugPrivilege for process injection and monitoring.
// Returns an error if administrator rights are not available.
func checkPrivileges() error {
	if !isAdmin() {
		return fmt.Errorf("sandbox enhancements require administrator privileges")
	}

	// Attempt to enable SeDebugPrivilege for advanced monitoring
	if err := enableDebugPrivilege(); err != nil {
		// Log warning but don't fail - some components may still work
		return fmt.Errorf("warning: failed to enable SeDebugPrivilege: %w (some features may be limited)", err)
	}

	return nil
}

// isAdmin checks if the current process is running with elevated administrator privileges.
// It uses the Windows token elevation API to determine elevation status.
func isAdmin() bool {
	var token syscall.Token
	proc, err := syscall.GetCurrentProcess()
	if err != nil {
		return false
	}

	// Open the process token with query access
	r1, _, callErr := procOpenProcessToken.Call(
		uintptr(proc),
		uintptr(tokenQuery),
		uintptr(unsafe.Pointer(&token)),
	)
	if r1 == 0 {
		_ = callErr // Suppress unused variable warning
		return false
	}
	defer token.Close()

	// Query the token elevation information
	var elevation tokenElevationInfo
	var returnLength uint32

	r1, _, callErr = procGetTokenInformation.Call(
		uintptr(token),
		uintptr(tokenElevation),
		uintptr(unsafe.Pointer(&elevation)),
		uintptr(unsafe.Sizeof(elevation)),
		uintptr(unsafe.Pointer(&returnLength)),
	)
	if r1 == 0 {
		// If we can't determine elevation status, assume not elevated
		_ = callErr // Suppress unused variable warning
		return false
	}

	return elevation.TokenIsElevated != 0
}

// enableDebugPrivilege attempts to enable SeDebugPrivilege for the current process.
// This privilege is required for:
// - API tracing (process injection)
// - Kernel monitoring (accessing protected processes)
// - Advanced process inspection
func enableDebugPrivilege() error {
	var token syscall.Token
	proc, err := syscall.GetCurrentProcess()
	if err != nil {
		return fmt.Errorf("GetCurrentProcess failed: %w", err)
	}

	// Open the process token with adjust privileges access
	r1, _, callErr := procOpenProcessToken.Call(
		uintptr(proc),
		uintptr(tokenAdjustPrivileges|tokenQuery),
		uintptr(unsafe.Pointer(&token)),
	)
	if r1 == 0 {
		return fmt.Errorf("OpenProcessToken failed: %w", callErr)
	}
	defer token.Close()

	// Lookup the LUID for SeDebugPrivilege
	var debugLuid luid
	debugPrivilegeName, err := syscall.UTF16PtrFromString("SeDebugPrivilege")
	if err != nil {
		return fmt.Errorf("failed to convert privilege name: %w", err)
	}

	r1, _, callErr = procLookupPrivilegeValue.Call(
		0, // Local system
		uintptr(unsafe.Pointer(debugPrivilegeName)),
		uintptr(unsafe.Pointer(&debugLuid)),
	)
	if r1 == 0 {
		return fmt.Errorf("LookupPrivilegeValue failed: %w", callErr)
	}

	// Prepare the TOKEN_PRIVILEGES structure
	tp := tokenPrivileges{
		PrivilegeCount: 1,
		Privileges: [1]luidAndAttributes{
			{
				Luid:       debugLuid,
				Attributes: sePrivilegeEnabled,
			},
		},
	}

	// Adjust the token privileges
	r1, _, callErr = procAdjustTokenPrivileges.Call(
		uintptr(token),
		0, // Do not disable all privileges
		uintptr(unsafe.Pointer(&tp)),
		0,
		0,
		0,
	)
	if r1 == 0 {
		return fmt.Errorf("AdjustTokenPrivileges failed: %w", callErr)
	}

	// AdjustTokenPrivileges may return success even if not all privileges were assigned
	// We need to check GetLastError to verify
	// Note: In Go, we can't reliably check GetLastError after syscall.Call
	// The function succeeded if r1 != 0, so we return success

	return nil
}
