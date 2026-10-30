// Package adapter defines the DeviceAdapter contract — the boundary between
// business logic (profiles, modules, planner) and the transport that actually
// talks to a device. ADB is only a transport here; no policy lives in it.
//
// Three implementations exist:
//
//	mock   — programmable in-memory device for unit tests
//	adb    — a real Android Studio / Pixel AVD driven over adb
//	replay — replays a previously captured DeviceState (regression)
package adapter

import "context"

// DeviceState is the observable state of a device, read back from it. It mirrors
// the fields a DeviceProfile expects, so the verifier can diff expected vs
// actual field-by-field. Keys are stable, transport-independent names.
type DeviceState struct {
	Props   map[string]string `json:"props"`   // system properties (getprop)
	Battery map[string]string `json:"battery"` // dumpsys battery fields
	Network map[string]string `json:"network"` // mac, ssid, etc.
	Sensors map[string]string `json:"sensors"` // sensor availability / markers
	Display map[string]string `json:"display"` // resolution, density
	Extra   map[string]string `json:"extra"`   // free-form evidence
}

// NewDeviceState returns a DeviceState with all maps initialised.
func NewDeviceState() DeviceState {
	return DeviceState{
		Props:   map[string]string{},
		Battery: map[string]string{},
		Network: map[string]string{},
		Sensors: map[string]string{},
		Display: map[string]string{},
		Extra:   map[string]string{},
	}
}

// Evidence is the raw environment fingerprint collected from a device — the
// signals malware would inspect to detect an emulator.
type Evidence struct {
	Props     map[string]string `json:"props"`
	Files     map[string]bool   `json:"files"`     // path -> exists
	Processes []string          `json:"processes"` // running process names
	Collected bool              `json:"collected"`
}

// TestConfig is a batch of setprop / shell operations a module wants applied.
// The adapter executes them as pure transport and reports per-command results.
type TestConfig struct {
	Props    []PropSet  `json:"props"`
	Commands []ShellCmd `json:"commands"`
}

// PropSet is a single system-property assignment.
type PropSet struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// ShellCmd is a raw shell command to run on the device.
type ShellCmd struct {
	Cmd string `json:"cmd"`
}

// DeviceAdapter abstracts a device's lifecycle and I/O. All methods take a
// context so callers control timeouts and cancellation. Errors are always
// returned — never swallowed — so modules can decide criticality.
type DeviceAdapter interface {
	Start(ctx context.Context) error
	WaitForBoot(ctx context.Context) error
	ReadState(ctx context.Context) (DeviceState, error)
	ApplyTestConfig(ctx context.Context, cfg TestConfig) (ApplyResult, error)
	CollectEvidence(ctx context.Context) (Evidence, error)
	Stop(ctx context.Context) error
}

// ApplyResult reports the outcome of each command in a TestConfig. A non-nil
// error from ApplyTestConfig means the transport itself failed; per-command
// failures are captured here so partial application is visible.
type ApplyResult struct {
	Succeeded []string   `json:"succeeded"`
	Failed    []CmdError `json:"failed"`
}

// CmdError pairs a failed command with its error text.
type CmdError struct {
	Cmd string `json:"cmd"`
	Err string `json:"err"`
}

// OK reports whether every command in the batch succeeded.
func (r ApplyResult) OK() bool { return len(r.Failed) == 0 }
