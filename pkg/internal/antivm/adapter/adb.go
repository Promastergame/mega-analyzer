package adapter

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// ADBAdapter drives a real Android emulator over the `adb` binary. It is pure
// transport: it runs commands and reads state, but makes no decisions about
// what a "correct" device looks like — that is the verifier's job. Every
// failure is returned to the caller; nothing is swallowed.
type ADBAdapter struct {
	Path        string        // path to the adb binary
	Serial      string        // device serial, e.g. "emulator-5554" ("" = default)
	BootTimeout time.Duration // how long WaitForBoot polls before giving up
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
	cmd := exec.CommandContext(ctx, a.Path, a.args(rest...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return strings.TrimSpace(string(out)), fmt.Errorf("adb %s: %w", strings.Join(rest, " "), err)
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
	_, err := a.run(ctx, "wait-for-device")
	return err
}

// WaitForBoot polls sys.boot_completed until it reads "1" or the timeout fires.
func (a *ADBAdapter) WaitForBoot(ctx context.Context) error {
	deadline := time.After(a.BootTimeout)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline:
			return fmt.Errorf("boot timeout after %v", a.BootTimeout)
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
		st.Display["resolution"] = parseWMSize(out)
	}
	if out, err := a.shell(ctx, "wm density"); err == nil {
		st.Display["density"] = parseWMDensity(out)
	}

	// Battery via dumpsys.
	if out, err := a.shell(ctx, "dumpsys battery"); err == nil {
		for k, v := range parseDumpsysBattery(out) {
			st.Battery[k] = v
		}
	}
	return st, nil
}

// ApplyTestConfig runs each prop/command as pure transport, recording per-item
// success and failure. A returned error means the transport is unusable; item
// failures are reported in ApplyResult without aborting the batch.
func (a *ADBAdapter) ApplyTestConfig(ctx context.Context, cfg TestConfig) (ApplyResult, error) {
	var res ApplyResult
	for _, p := range cfg.Props {
		cmd := fmt.Sprintf("setprop %s '%s'", p.Key, p.Value)
		if _, err := a.shell(ctx, cmd); err != nil {
			res.Failed = append(res.Failed, CmdError{Cmd: cmd, Err: err.Error()})
		} else {
			res.Succeeded = append(res.Succeeded, cmd)
		}
	}
	for _, c := range cfg.Commands {
		if _, err := a.shell(ctx, c.Cmd); err != nil {
			res.Failed = append(res.Failed, CmdError{Cmd: c.Cmd, Err: err.Error()})
		} else {
			res.Succeeded = append(res.Succeeded, c.Cmd)
		}
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
	for _, path := range []string{
		"/dev/socket/qemud", "/dev/qemu_pipe", "/system/lib/libc_malloc_debug_qemu.so",
	} {
		out, _ := a.shell(ctx, fmt.Sprintf("[ -e %s ] && echo yes || echo no", path))
		ev.Files[path] = out == "yes"
	}
	ev.Collected = true
	return ev, nil
}

// Stop is a no-op for ADBAdapter: shutting down the AVD is the session
// manager's responsibility (later phase). Present to satisfy the interface.
func (a *ADBAdapter) Stop(ctx context.Context) error { return nil }

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
	return props, nil
}
