package adapter

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ADBAdapter drives a real Android emulator over the `adb` binary. It is pure
// transport: it runs commands and reads state, but makes no decisions about
// what a "correct" device looks like — that is the verifier's job. Every
// failure is returned to the caller; nothing is swallowed.
type ADBAdapter struct {
	Path             string        // path to the adb binary
	Serial           string        // device serial, e.g. "emulator-5554" ("" = default)
	BootTimeout      time.Duration // how long WaitForBoot polls before giving up
	ResetpropPath    string        // optional root-only property writer in the guest
	RestartFramework bool          // refresh zygote's cached android.os.Build fields
	motionMu         sync.Mutex
	motion           *motionRun
	motionLife       context.Context
	probeReady       bool
}

// NewADBAdapter constructs an ADBAdapter with a sane default boot timeout.
func NewADBAdapter(path, serial string) *ADBAdapter {
	return &ADBAdapter{Path: path, Serial: serial, BootTimeout: 120 * time.Second}
}

var _ DeviceAdapter = (*ADBAdapter)(nil)

// args prepends the -s serial selector when a serial is set.
func (a *ADBAdapter) args(rest ...string) []string {
	if a.Serial != "" {
		return append([]string{"-s", a.Serial}, rest...)
	}
	return rest
}

// run executes an adb subcommand and returns trimmed combined output.
func (a *ADBAdapter) run(ctx context.Context, rest ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, a.Path, a.args(rest...)...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return strings.TrimSpace(string(out)), fmt.Errorf("adb %s: %w", strings.Join(rest, " "), ctx.Err())
	}
	if err != nil {
		diagnostic := strings.TrimSpace(string(out))
		if diagnostic != "" {
			return diagnostic, fmt.Errorf("adb %s: %w (output: %s)", strings.Join(rest, " "), err, diagnostic)
		}
		return "", fmt.Errorf("adb %s: %w", strings.Join(rest, " "), err)
	}
	return strings.TrimSpace(string(out)), nil
}

// shell runs a single shell command on the device.
func (a *ADBAdapter) shell(ctx context.Context, command string) (string, error) {
	return a.run(ctx, "shell", command)
}

// Start brings the device connection up. For an already-running AVD this is a
// no-op beyond ensuring the daemon can see it; launching an AVD is the
// responsibility of a higher layer (session manager) in later phases.
func (a *ADBAdapter) Start(ctx context.Context) error {
	a.BindSensorLifetime(ctx)
	state, err := a.run(ctx, "get-state")
	if err != nil {
		return err
	}
	if state != "device" {
		return fmt.Errorf("device is not connected: %s", state)
	}
	return nil
}

// WaitForBoot polls sys.boot_completed until it reads "1" or the timeout fires.
func (a *ADBAdapter) WaitForBoot(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, a.BootTimeout)
	defer cancel()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			if ctx.Err() == context.DeadlineExceeded {
				return fmt.Errorf("boot timeout after %v: %w", a.BootTimeout, ctx.Err())
			}
			return ctx.Err()
		case <-ticker.C:
			out, err := a.shell(ctx, "getprop sys.boot_completed")
			if err == nil && out == "1" {
				return nil
			}
		}
	}
}

// ReadState reads back the device state the verifier compares against a profile.
func (a *ADBAdapter) ReadState(ctx context.Context) (DeviceState, error) {
	st := NewDeviceState()

	props, err := a.listProps(ctx)
	if err != nil {
		return st, fmt.Errorf("read props: %w", err)
	}
	st.Props = props

	// Display: `wm size` / `wm density`.
	if out, err := a.shell(ctx, "wm size"); err == nil {
		if size := parseWMSize(out); size != "" {
			st.Display["resolution"] = size
		}
	}
	if out, err := a.shell(ctx, "wm density"); err == nil {
		if density := parseWMDensity(out); density != "" {
			st.Display["density"] = density
		}
	}

	// Battery via dumpsys.
	if out, err := a.shell(ctx, "dumpsys battery"); err == nil {
		for k, v := range parseDumpsysBattery(out) {
			st.Battery[k] = v
		}
	}
	if out, err := a.shell(ctx, "cat "+quoteShell(ThermalTemperaturePath)); err == nil {
		st.Sensors[ThermalTemperatureKey] = out
	} else {
		st.Extra["unreadable:"+ThermalTemperaturePath] = err.Error()
	}
	a.readMotionState(ctx, &st)
	// Keep observable guest artifacts in the capture, so a property-only
	// profile match cannot hide residual kernel/device fingerprints from diff.
	for _, path := range emulatorFiles {
		out, err := a.shell(ctx, "[ -e "+quoteShell(path)+" ] && echo yes || echo no")
		if err != nil {
			st.Extra["unreadable:"+path] = err.Error()
			continue
		}
		st.Extra["file:"+path] = out
	}
	if err := ctx.Err(); err != nil {
		return st, err
	}
	return st, nil
}

var emulatorFiles = []string{"/dev/socket/qemud", "/dev/qemu_pipe", "/dev/goldfish_pipe", "/sys/devices/platform/goldfish_pipe", "/system/lib/libc_malloc_debug_qemu.so"}
var propertyKey = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

func quoteShell(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

// ConfigureResetprop selects an explicitly installed guest helper. This does
// not root a device or install anything, and requires an explicit AVD serial.
func (a *ADBAdapter) ConfigureResetprop(ctx context.Context, path string, restart bool) error {
	if !strings.HasPrefix(a.Serial, "emulator-") {
		return fmt.Errorf("resetprop requires an explicit emulator serial")
	}
	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\r\n\x00") {
		return fmt.Errorf("resetprop must be an absolute guest executable path")
	}
	uid, err := a.shell(ctx, "id -u")
	if err != nil {
		return err
	}
	if uid != "0" {
		return fmt.Errorf("resetprop requires a root ADB shell; current uid is %s", uid)
	}
	if _, err := a.shell(ctx, "test -x "+quoteShell(path)); err != nil {
		return fmt.Errorf("resetprop helper is not executable: %w", err)
	}
	a.ResetpropPath = path
	a.RestartFramework = restart
	return nil
}

func (a *ADBAdapter) propertyCommand(p PropSet) string {
	if a.ResetpropPath != "" {
		// -n writes the property area without triggering init actions.
		return quoteShell(a.ResetpropPath) + " -n " + p.Key + " " + quoteShell(p.Value)
	}
	return "setprop " + p.Key + " " + quoteShell(p.Value)
}

func (a *ADBAdapter) preserveHALSelectors(ctx context.Context, cfg TestConfig, res *ApplyResult) error {
	changesHardware := false
	for _, prop := range cfg.Props {
		if prop.Key == "ro.hardware" {
			changesHardware = true
			break
		}
	}
	if !changesHardware || a.ResetpropPath == "" {
		return nil
	}
	original, err := a.shell(ctx, "getprop ro.hardware")
	if err != nil {
		return err
	}
	for _, module := range []string{"gralloc", "hwcomposer", "sensors", "camera", "gps", "gatekeeper", "fingerprint", "power"} {
		key := "ro.hardware." + module
		if selected, err := a.shell(ctx, "getprop "+key); err != nil {
			return err
		} else if selected != "" {
			continue
		}
		var checks []string
		for _, directory := range []string{"/vendor/lib64/hw/", "/vendor/lib/hw/", "/system/lib64/hw/", "/system/lib/hw/"} {
			checks = append(checks, "[ -e "+quoteShell(directory+module+"."+original+".so")+" ]")
		}
		present, err := a.shell(ctx, "if "+strings.Join(checks, " || ")+"; then echo yes; else echo no; fi")
		if err != nil {
			return err
		}
		if present != "yes" {
			continue
		}
		command := a.propertyCommand(PropSet{Key: key, Value: original})
		if _, err := a.shell(ctx, command); err != nil {
			return fmt.Errorf("preserve %s HAL selector: %w", module, err)
		}
		res.Succeeded = append(res.Succeeded, command)
	}
	return nil
}

func (a *ADBAdapter) refreshFramework(ctx context.Context) error {
	// Zygote preloads Build, and a fresh app fork still inherits its old values.
	// Restart zygote without restarting the graphics/HAL services. Retain the
	// boot marker so Android recognises this as a runtime restart, not cold boot.
	oldPID, err := a.shell(ctx, "pidof system_server")
	if err != nil {
		return fmt.Errorf("read system_server PID: %w", err)
	}
	if _, err := a.shell(ctx, "setprop ctl.restart zygote"); err != nil {
		return fmt.Errorf("restart zygote: %w", err)
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for refreshed Android framework: %w", ctx.Err())
		case <-ticker.C:
			pid, err := a.shell(ctx, "pidof system_server")
			if err != nil || pid == "" || pid == oldPID {
				continue
			}
			if out, err := a.shell(ctx, "pm path android"); err != nil || !strings.HasPrefix(out, "package:") {
				continue
			}
			if out, err := a.shell(ctx, "dumpsys window policy"); err != nil || !strings.Contains(out, "mSystemBooted=true") {
				continue
			}
			// Package manager and window policy can be ready before user 0's
			// credential-encrypted app components are available again.
			if out, err := a.shell(ctx, "am get-started-user-state 0"); err == nil && out == "RUNNING_UNLOCKED" {
				return nil
			}
		}
	}
}

// ApplyTestConfig runs each prop/command as pure transport, recording per-item
// success and failure. A returned error means the transport is unusable; item
// failures are reported in ApplyResult without aborting the batch.
func (a *ADBAdapter) ApplyTestConfig(ctx context.Context, cfg TestConfig) (ApplyResult, error) {
	var res ApplyResult
	if cfg.EmulatorOnly && !strings.HasPrefix(a.Serial, "emulator-") {
		return res, fmt.Errorf("this configuration requires an explicit emulator serial")
	}
	if err := a.preserveEGLDrivers(ctx, cfg, &res); err != nil {
		return res, err
	}
	// HAL modules must continue loading the emulator's implementation after
	// Build.HARDWARE changes. Pin existing implementations before changing it.
	if err := a.preserveHALSelectors(ctx, cfg, &res); err != nil {
		return res, err
	}
	for _, p := range cfg.Props {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		if !propertyKey.MatchString(p.Key) {
			res.Failed = append(res.Failed, CmdError{Cmd: "setprop", Err: "invalid property key: " + p.Key})
			continue
		}
		cmd := a.propertyCommand(p)
		if _, err := a.shell(ctx, cmd); err != nil {
			res.Failed = append(res.Failed, CmdError{Cmd: cmd, Err: err.Error()})
		} else {
			res.Succeeded = append(res.Succeeded, cmd)
		}
	}
	for _, c := range cfg.Commands {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		if _, err := a.shell(ctx, c.Cmd); err != nil {
			res.Failed = append(res.Failed, CmdError{Cmd: c.Cmd, Err: err.Error()})
		} else {
			res.Succeeded = append(res.Succeeded, c.Cmd)
		}
	}
	if cfg.Motion != nil {
		if err := a.startMotion(ctx, *cfg.Motion); err != nil {
			res.Failed = append(res.Failed, CmdError{Cmd: "sensor motion playback", Err: err.Error()})
		} else {
			res.Succeeded = append(res.Succeeded, "sensor motion playback")
		}
	}
	if len(cfg.Props) > 0 && res.OK() && a.ResetpropPath != "" && a.RestartFramework {
		if err := a.refreshFramework(ctx); err != nil {
			return res, err
		}
		res.Succeeded = append(res.Succeeded, "restart zygote and wait for framework/user 0 unlock")
	}
	return res, nil
}

// CollectEvidence gathers the emulator-detection signals a module may inspect.
func (a *ADBAdapter) CollectEvidence(ctx context.Context) (Evidence, error) {
	ev := Evidence{Props: map[string]string{}, Files: map[string]bool{}}
	props, err := a.listProps(ctx)
	if err != nil {
		return ev, fmt.Errorf("collect evidence props: %w", err)
	}
	// Retain the props most commonly checked for emulator detection.
	for _, k := range []string{
		"ro.kernel.qemu", "ro.hardware", "ro.product.model",
		"ro.build.fingerprint", "ro.bootmode", "init.svc.goldfish-setup",
	} {
		if v, ok := props[k]; ok {
			ev.Props[k] = v
		}
	}
	// Files that exist on emulators but not on real devices.
	for _, path := range emulatorFiles {
		out, err := a.shell(ctx, "[ -e "+quoteShell(path)+" ] && echo yes || echo no")
		if err != nil {
			return ev, fmt.Errorf("collect evidence file %s: %w", path, err)
		}
		ev.Files[path] = out == "yes"
	}
	ev.Collected = true
	return ev, nil
}

// Stop is a no-op for ADBAdapter: shutting down the AVD is the session
// manager's responsibility (later phase). Present to satisfy the interface.
func (a *ADBAdapter) Stop(ctx context.Context) error { return a.stopMotion(ctx) }

// listProps parses `adb shell getprop` into a map.
func (a *ADBAdapter) listProps(ctx context.Context) (map[string]string, error) {
	out, err := a.shell(ctx, "getprop")
	if err != nil {
		return nil, err
	}
	props := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "[") {
			continue
		}
		idx := strings.Index(line, "]: [")
		if idx < 0 {
			continue
		}
		key := line[1:idx]
		val := strings.TrimSuffix(line[idx+4:], "]")
		props[key] = val
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("parse getprop: %w", err)
	}
	return props, nil
}
