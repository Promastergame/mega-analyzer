package modules

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/antivm/adapter"
	"mega-analyzer/pkg/internal/antivm/verifier"
)

func TestSensorsVerifyReadsKernelTemperature(t *testing.T) {
	p := testProfile(t)
	p.Sensor.Accelerometer, p.Sensor.Gyroscope = false, false
	m := NewSensorsModule(p)
	for _, tc := range []struct {
		name, reading string
		status        verifier.Status
	}{
		{"correct", "28000", verifier.StatusPassed},
		{"zero", "0", verifier.StatusFailed},
		{"wrong units", "28", verifier.StatusFailed},
		{"unreadable", "", verifier.StatusPartial},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dev := adapter.NewMockAdapter()
			if tc.reading != "" {
				dev.State.Sensors[adapter.ThermalTemperatureKey] = tc.reading
			}
			// Accepting the configuration is not evidence of a changed reading.
			if _, err := m.Apply(context.Background(), dev); err != nil {
				t.Fatal(err)
			}
			rep, err := m.Verify(context.Background(), dev)
			if err != nil || rep.Status != tc.status || len(rep.Checks) != 1 {
				t.Fatalf("report=%+v err=%v", rep, err)
			}
		})
	}
}

func TestThermalCommandRequiresRoot(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("POSIX shell is not available")
	}
	command := thermalTemperatureCommand()
	if out, err := exec.Command(sh, "-n", "-c", command).CombinedOutput(); err != nil {
		t.Fatalf("invalid guest shell syntax: %s, %v", out, err)
	}
	out, err := exec.Command(sh, "-c", "id() { echo 2000; }; "+command).CombinedOutput()
	if err == nil || !strings.Contains(string(out), "requires a root ADB shell") {
		t.Fatalf("unrooted fixture was accepted: %s, %v", out, err)
	}
}

func TestThermalScriptFixtureScenarios(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("POSIX shell is not available")
	}
	for _, scenario := range []string{"missing zone", "zero", "already fixed", "mount failed", "mount ignored", "existing links", "non-symlink entry", "SELinux denied"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			root := filepath.Join(dir, "thermal")
			fixture := filepath.Join(dir, "fixture")
			if err := os.Mkdir(root, 0755); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(root, "thermal_zone0", "temp")
			if scenario == "zero" || scenario == "already fixed" || scenario == "mount failed" || scenario == "mount ignored" || scenario == "SELinux denied" {
				if err := os.Mkdir(filepath.Dir(target), 0755); err != nil {
					t.Fatal(err)
				}
				reading := "0\n"
				if scenario == "already fixed" {
					reading = "28000\n"
				}
				if err := os.WriteFile(target, []byte(reading), 0644); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "non-symlink entry" {
				if err := os.Mkdir(filepath.Join(root, "unrelated"), 0755); err != nil {
					t.Fatal(err)
				}
			}
			// Emulate bind mounts on temporary paths; never mount the host sysfs.
			prelude := `getenforce() { echo Disabled; }
mount() {
  [ "$1" = --bind ] || return 1
  if [ -d "$2" ]; then cp -a "$2/." "$3/"; else cat "$2" > "$3"; fi
}
`
			if scenario == "existing links" {
				// Create a relative class symlink and check the mirror resolves it
				// to the device path outside the class being overlaid.
				device := filepath.Join(dir, "device")
				if err := os.Mkdir(device, 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(device, "marker"), []byte("preserved"), 0644); err != nil {
					t.Fatal(err)
				}
				link := quoteThermalShell(filepath.ToSlash(filepath.Join(root, "cooling_device0")))
				prelude += "ln -s '../device' " + link + " && [ -L " + link + " ] || exit 77\n"
			}
			if scenario == "mount failed" {
				prelude += "mount() { echo 'mount denied' >&2; return 1; }\n"
			}
			if scenario == "mount ignored" {
				prelude += "mount() { return 0; }\n"
			}
			if scenario == "already fixed" {
				prelude += "mount() { echo 'unexpected mount' >&2; return 1; }\n"
			}
			if scenario == "SELinux denied" {
				prelude += "getenforce() { echo Enforcing; }\nls() { echo 'u:object_r:sysfs_thermal:s0 file'; }\nchcon() { echo 'relabel denied' >&2; return 1; }\n"
			}
			script := prelude + thermalTemperatureScript(filepath.ToSlash(root), filepath.ToSlash(fixture))
			cmd := exec.Command(sh, "-c", script)
			// Git's shell otherwise copies symlink targets on Windows.
			cmd.Env = append(os.Environ(), "MSYS=winsymlinks:nativestrict")
			out, runErr := cmd.CombinedOutput()
			if exitErr, ok := runErr.(*exec.ExitError); ok && exitErr.ExitCode() == 77 {
				t.Skip("native symlinks are unavailable to the shell")
			}
			wantFailure := scenario == "mount failed" || scenario == "mount ignored" || scenario == "non-symlink entry" || scenario == "SELinux denied"
			if (runErr != nil) != wantFailure {
				t.Fatalf("err=%v output=%s", runErr, out)
			}
			if wantFailure {
				if len(out) == 0 {
					t.Fatal("failure diagnostic was lost")
				}
				return
			}
			reading, err := os.ReadFile(target)
			if err != nil || strings.TrimSpace(string(reading)) != "28000" {
				t.Fatalf("reading=%q err=%v", reading, err)
			}
			if scenario == "existing links" {
				cmd := exec.Command(sh, "-c", "cat "+quoteThermalShell(filepath.ToSlash(filepath.Join(root, "cooling_device0", "marker"))))
				out, err := cmd.CombinedOutput()
				if err != nil || string(out) != "preserved" {
					t.Fatalf("existing link lost: %s, %v", out, err)
				}
			}
		})
	}
}
