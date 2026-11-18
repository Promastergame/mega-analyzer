package antivm

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"mega-analyzer/pkg/internal/antivm/adapter"
	"mega-analyzer/pkg/internal/antivm/modules"
	vmprofile "mega-analyzer/pkg/internal/antivm/profile"
	"mega-analyzer/pkg/internal/antivm/verifier"
)

// Evasion is the interface for an anti-VM evasion engine.
type Evasion interface {
	// Apply patches the running emulator to look like a real device.
	Apply(ctx context.Context, adbPath string, serial string) error
	// Report returns a summary of what was applied.
	Report() EvasionReport
}

// EvasionReport summarises the anti-VM patching that was applied.
type EvasionReport struct {
	Applied                  bool           `json:"applied"`
	DeviceProfile            DeviceProfile  `json:"device_profile"`
	IMEI                     string         `json:"imei"`
	SerialNumber             string         `json:"serial_number"`
	MACAddress               string         `json:"mac_address"`
	WiFiSSID                 string         `json:"wifi_ssid"`
	OperatorName             string         `json:"operator_name"`
	OperatorNumeric          string         `json:"operator_numeric"`
	BatteryLevel             int            `json:"battery_level"`
	SensorNoiseActive        bool           `json:"sensor_noise_active"`
	ThermalTemperatureMilliC int            `json:"thermal_temperature_millic,omitempty"`
	PropertiesSet            []PropertyPair `json:"properties_set"`
	Warnings                 []string       `json:"warnings,omitempty"`
	AppliedAt                time.Time      `json:"applied_at"`
}

// PropertyPair is a key=value system property change.
type PropertyPair struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// EvasionConfig controls what the engine patches.
type EvasionConfig struct {
	Enabled       bool   `json:"enabled"`
	DeviceModel   string `json:"device_model,omitempty"` // specific model or "" for random
	RandomizeIMEI bool   `json:"randomize_imei"`
	SensorNoise   bool   `json:"sensor_noise"`
	PatchBattery  bool   `json:"patch_battery"`
	PatchNetwork  bool   `json:"patch_network"`
	PatchOperator bool   `json:"patch_operator"`
}

// DefaultEvasionConfig returns a config with all evasion features enabled.
func DefaultEvasionConfig() EvasionConfig {
	return EvasionConfig{
		Enabled:       true,
		RandomizeIMEI: true,
		SensorNoise:   true,
		PatchBattery:  true,
		PatchNetwork:  true,
		PatchOperator: true,
	}
}

// EvasionEngine applies anti-VM patches to a running Android emulator via ADB.
//
// Deprecated: this setprop-only engine is the legacy path. The maintained
// architecture lives in the sub-packages profile/, adapter/, modules/,
// verifier/, planner/ and session/, which apply changes AND verify them by
// reading device state (rather than assuming a command that exited 0 worked).
// This type is retained so androidruntime and existing callers keep compiling.
type EvasionEngine struct {
	cfg           EvasionConfig
	report        EvasionReport
	sensorAdapter *adapter.ADBAdapter
}

// NewEvasionEngine creates a new anti-VM evasion engine.
func NewEvasionEngine(cfg EvasionConfig) *EvasionEngine {
	return &EvasionEngine{cfg: cfg}
}

// Apply runs all configured anti-VM patches against the emulator.
func (e *EvasionEngine) Apply(ctx context.Context, adbPath string, serial string) error {
	if !e.cfg.Enabled {
		return nil
	}

	// Generate device identity.
	var profile DeviceProfile
	if e.cfg.DeviceModel != "" {
		profile = DeviceProfileByModel(e.cfg.DeviceModel)
	} else {
		profile = RandomDeviceProfile()
	}

	e.report.DeviceProfile = profile
	e.report.AppliedAt = time.Now().UTC()

	adb := &adbClient{
		path:   adbPath,
		serial: serial,
	}

	// Build property patches — the core anti-detection layer.
	props := []PropertyPair{
		// Remove emulator signatures.
		{"ro.hardware", profile.Hardware},
		{"ro.product.model", profile.Model},
		{"ro.product.brand", profile.Brand},
		{"ro.product.manufacturer", profile.Manufacturer},
		{"ro.product.device", profile.Device},
		{"ro.product.name", profile.Product},
		{"ro.build.fingerprint", profile.Fingerprint},
		{"ro.build.display.id", profile.BuildID},

		// Kill common goldfish/ranchu/generic indicators.
		{"ro.hardware.chipname", profile.Chipset},
		{"ro.boot.hardware.chipset", profile.Chipset},

		// Disable debug mode (malware checks ro.debuggable).
		{"ro.debuggable", "0"},
		{"ro.secure", "1"},

		// Build description without "sdk" or "test-keys".
		{"ro.build.description", fmt.Sprintf("%s-user %s %s release-keys",
			profile.Product, profile.Fingerprint, profile.BuildID)},
		{"ro.build.type", "user"},
		{"ro.build.tags", "release-keys"},

		// Fake security patch level.
		{"ro.build.version.security_patch", profile.SecurityPatch},

		// Hide emulator-specific props.
		{"ro.kernel.qemu", "0"},
		{"ro.kernel.android.qemud", ""},
		{"init.svc.goldfish-logcat", ""},
		{"init.svc.goldfish-setup", ""},
		{"ro.bootimage.build.fingerprint", profile.Fingerprint},
		{"ro.vendor.build.fingerprint", profile.Fingerprint},
		{"ro.system.build.fingerprint", profile.Fingerprint},
	}

	// Apply build properties.
	for _, prop := range props {
		if err := adb.setProp(ctx, prop.Key, prop.Value); err != nil {
			e.report.Warnings = append(e.report.Warnings,
				fmt.Sprintf("setprop %s failed: %v", prop.Key, err))
		}
	}
	e.report.PropertiesSet = props

	// Generate and set IMEI.
	if e.cfg.RandomizeIMEI {
		imei := RandomIMEI()
		e.report.IMEI = imei
		// IMEI injection via service call (Android telephony subsystem).
		if err := adb.injectIMEI(ctx, imei); err != nil {
			e.report.Warnings = append(e.report.Warnings,
				fmt.Sprintf("IMEI injection failed: %v", err))
		}
	}

	// Serial number.
	serial2 := RandomSerial()
	e.report.SerialNumber = serial2
	if err := adb.setProp(ctx, "ro.serialno", serial2); err != nil {
		e.report.Warnings = append(e.report.Warnings,
			fmt.Sprintf("serial number patch failed: %v", err))
	}
	if err := adb.setProp(ctx, "ro.boot.serialno", serial2); err != nil {
		e.report.Warnings = append(e.report.Warnings,
			fmt.Sprintf("boot serial number patch failed: %v", err))
	}

	// warn records a non-fatal failure into the report rather than swallowing it.
	warn := func(err error, format string, args ...interface{}) {
		if err != nil {
			e.report.Warnings = append(e.report.Warnings,
				fmt.Sprintf(format+": %v", append(args, err)...))
		}
	}

	// Operator patching.
	if e.cfg.PatchOperator {
		opName, opNumeric := RandomOperator()
		e.report.OperatorName = opName
		e.report.OperatorNumeric = opNumeric

		for _, key := range []string{
			"gsm.operator.alpha",
			"gsm.sim.operator.alpha",
		} {
			warn(adb.setProp(ctx, key, opName), "setprop %s", key)
		}
		for _, key := range []string{
			"gsm.operator.numeric",
			"gsm.sim.operator.numeric",
		} {
			warn(adb.setProp(ctx, key, opNumeric), "setprop %s", key)
		}
		warn(adb.setProp(ctx, "gsm.version.baseband", fmt.Sprintf("g5300g-%s", randomHex(8))), "setprop baseband")
	}

	// Network: MAC address, WiFi SSID.
	if e.cfg.PatchNetwork {
		mac := RandomMAC()
		e.report.MACAddress = mac
		// Some malware checks wlan0 MAC.
		warn(adb.shell(ctx, fmt.Sprintf("ip link set wlan0 address %s", strings.ToLower(mac))), "set wlan0 mac")

		ssid := RandomSSID()
		e.report.WiFiSSID = ssid
		warn(adb.setProp(ctx, "wifi.interface.ssid", ssid), "setprop wifi ssid")
	}

	// Battery: set realistic level and status.
	if e.cfg.PatchBattery {
		level := RandomBatteryLevel()
		e.report.BatteryLevel = level
		// Use dumpsys battery to fake battery state.
		warn(adb.shell(ctx, "dumpsys battery unplug"), "battery unplug")
		warn(adb.shell(ctx, fmt.Sprintf("dumpsys battery set level %d", level)), "battery set level")
		warn(adb.shell(ctx, "dumpsys battery set status 3"), "battery set status") // 3 = DISCHARGING
	}

	// Replay actual emulator sensor vectors, then observe Android event queues.
	if e.cfg.SensorNoise {
		if err := e.StopSensorNoise(ctx); err != nil {
			warn(err, "stop prior sensor playback")
		}
		e.report.ThermalTemperatureMilliC = 0
		e.report.SensorNoiseActive = false
		// The legacy runtime uses the same verified thermal fixture as the CLI.
		// Resolve the selected device before allowing an emulator-only mutation.
		thermalSerial, err := adb.selectedSerial(ctx)
		if err != nil {
			warn(err, "thermal device selection")
		} else {
			dev := adapter.NewADBAdapter(adbPath, thermalSerial)
			e.sensorAdapter = dev
			dev.BindSensorLifetime(ctx)
			p := vmprofile.DeviceProfile{Sensor: vmprofile.SensorProfile{Enabled: true, Accelerometer: true, Gyroscope: true}}
			m := modules.NewSensorsModule(p)
			res, err := m.Apply(ctx, dev)
			warn(err, "thermal fixture")
			for _, failure := range res.Failed {
				e.report.Warnings = append(e.report.Warnings, "thermal fixture: "+failure.Err)
			}
			if err == nil {
				rep, err := m.Verify(ctx, dev)
				warn(err, "thermal verification")
				if err == nil {
					passed := map[string]bool{}
					for _, check := range rep.Checks {
						passed[check.Field] = check.Status == verifier.StatusPassed
					}
					if res.OK() && passed["thermal_temperature"] {
						e.report.ThermalTemperatureMilliC = vmprofile.ThermalTemperatureMilliC
					}
					motionApplied := false
					for _, operation := range res.Succeeded {
						if operation == "sensor motion playback" {
							motionApplied = true
						}
					}
					e.report.SensorNoiseActive = motionApplied && passed["motion.active"] && passed["acceleration.available"] && passed["acceleration.moving"] && passed["gyroscope.available"] && passed["gyroscope.moving"]
					if rep.Status != verifier.StatusPassed {
						e.report.Warnings = append(e.report.Warnings, "sensor event/thermal verification did not pass")
					}
				}
			}
		}
	}

	e.report.Applied = true
	return nil
}

// Report returns the evasion report.
func (e *EvasionEngine) Report() EvasionReport {
	report := e.report
	if e.sensorAdapter != nil {
		status := e.sensorAdapter.SensorPlaybackStatus()
		report.SensorNoiseActive = report.SensorNoiseActive && status.Active
		if status.Error != "" {
			report.Warnings = append(append([]string(nil), report.Warnings...), "sensor playback: "+status.Error)
		}
	}
	return report
}

// StopSensorNoise waits for playback to stop and the original vectors to be restored.
func (e *EvasionEngine) StopSensorNoise(ctx context.Context) error {
	if e.sensorAdapter == nil {
		return nil
	}
	return e.sensorAdapter.Stop(ctx)
}

// ── ADB Client ───────────────────────────────────────────────

// adbClient wraps ADB command execution.
type adbClient struct {
	path   string
	serial string
}

func (a *adbClient) selectedSerial(ctx context.Context) (string, error) {
	if a.serial != "" {
		return a.serial, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, a.path, "get-serialno").Output()
	if err != nil {
		return "", fmt.Errorf("read selected ADB serial: %w", err)
	}
	serial := strings.TrimSpace(string(out))
	if serial == "" || serial == "unknown" {
		return "", fmt.Errorf("no unique ADB device selected")
	}
	return serial, nil
}

// adbArgs builds the base ADB argument list.
func (a *adbClient) adbArgs(args ...string) []string {
	if a.serial != "" {
		return append([]string{"-s", a.serial}, args...)
	}
	return args
}

// setProp sets an Android system property via ADB shell.
func (a *adbClient) setProp(ctx context.Context, key, value string) error {
	return a.shell(ctx, fmt.Sprintf("setprop %s '%s'", key, value))
}

// shell runs an ADB shell command.
func (a *adbClient) shell(ctx context.Context, command string) error {
	args := a.adbArgs("shell", command)
	cmd := exec.CommandContext(ctx, a.path, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("adb shell %q: %w (output: %s)", command, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// injectIMEI attempts to inject an IMEI via Android's telephony service.
func (a *adbClient) injectIMEI(ctx context.Context, imei string) error {
	// First try: write IMEI to the emulator's ril daemon configuration.
	err := a.setProp(ctx, "gsm.sim.operator.imei", imei)
	if err != nil {
		return err
	}
	// Also set device ID properties that some malware reads.
	_ = a.setProp(ctx, "ril.deviceid", imei)
	_ = a.setProp(ctx, "persist.radio.device.imei", imei)
	return nil
}

// markerAlive reports whether a marker file exists on the device, used to prove
// a background looper actually started rather than trusting the launch command.
func (a *adbClient) markerAlive(ctx context.Context, path string) bool {
	out, err := a.shellOutput(ctx, fmt.Sprintf("[ -e %s ] && echo yes || echo no", path))
	return err == nil && strings.TrimSpace(out) == "yes"
}

// shellOutput runs a shell command and returns its trimmed stdout.
func (a *adbClient) shellOutput(ctx context.Context, command string) (string, error) {
	args := a.adbArgs("shell", command)
	cmd := exec.CommandContext(ctx, a.path, args...)
	out, err := cmd.Output()
	return string(out), err
}

// waitForDevice blocks until the emulator is reachable via ADB.
func (a *adbClient) waitForDevice(ctx context.Context, timeout time.Duration) error {
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	args := a.adbArgs("wait-for-device")
	cmd := exec.CommandContext(waitCtx, a.path, args...)
	return cmd.Run()
}

// waitForBoot polls getprop sys.boot_completed until it returns "1".
func (a *adbClient) waitForBoot(ctx context.Context, timeout time.Duration) error {
	deadline := time.After(timeout)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline:
			return fmt.Errorf("boot timeout after %v", timeout)
		case <-ticker.C:
			args := a.adbArgs("shell", "getprop", "sys.boot_completed")
			cmd := exec.CommandContext(ctx, a.path, args...)
			out, err := cmd.Output()
			if err != nil {
				continue
			}
			if strings.TrimSpace(string(out)) == "1" {
				return nil
			}
		}
	}
}

// getprop reads a single Android system property.
func (a *adbClient) getprop(ctx context.Context, key string) (string, error) {
	args := a.adbArgs("shell", "getprop", key)
	cmd := exec.CommandContext(ctx, a.path, args...)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// listProps reads all system properties.
func (a *adbClient) listProps(ctx context.Context) (map[string]string, error) {
	args := a.adbArgs("shell", "getprop")
	cmd := exec.CommandContext(ctx, a.path, args...)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	props := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		// Format: [key]: [value]
		if !strings.HasPrefix(line, "[") {
			continue
		}
		idx := strings.Index(line, "]: [")
		if idx < 0 {
			continue
		}
		key := line[1:idx]
		value := strings.TrimSuffix(line[idx+4:], "]")
		props[key] = value
	}
	return props, nil
}
