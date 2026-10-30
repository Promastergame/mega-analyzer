package androidruntime

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadProfileAppliesDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.json")
	if err := os.WriteFile(path, []byte(`{"mode":"android-sdk","avd_name":"Lab35"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	profile, err := LoadProfile(path)
	if err != nil {
		t.Fatalf("LoadProfile() error = %v", err)
	}
	if profile.Locale == "" {
		t.Fatal("expected default locale")
	}
	if profile.Network.NetSpeed == "" {
		t.Fatal("expected default network speed")
	}
}

func TestBuildEmulatorArgs(t *testing.T) {
	args, err := BuildEmulatorArgs(Profile{
		Mode:    ModeAndroidSDK,
		AVDName: "Lab35",
		Network: NetworkProfile{
			WifiEnabled: false,
			DNSServers:  []string{"10.0.2.3", "10.0.2.4"},
			NetSpeed:    "lte",
			NetDelay:    "none",
		},
		Snapshot: SnapshotProfile{
			Enabled:     true,
			Name:        "clean",
			LoadOnStart: true,
			SaveOnExit:  false,
		},
	})
	if err != nil {
		t.Fatalf("BuildEmulatorArgs() error = %v", err)
	}
	joined := strings.Join(args, " ")
	for _, expected := range []string{"@Lab35", "-dns-server 10.0.2.3,10.0.2.4", "-netspeed lte", "-feature -Wifi", "-snapshot clean", "-no-snapshot-save"} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("args %q missing %q", joined, expected)
		}
	}
}

func TestBuildEmulatorArgsScrcpyDisplayAndMITM(t *testing.T) {
	profile := DefaultProfile()
	profile.Display.Mode = "scrcpy"
	profile.Display.GPU = "host"
	profile.Display.Skin = "pixel_7"
	profile.MITM.Enabled = true
	profile.MITM.HTTPProxy = "127.0.0.1:8080"
	profile.MITM.CACertPath = "/tmp/lab-ca.crt"
	profile.MITM.AllowUserCAForApps = true

	args, err := BuildEmulatorArgs(profile)
	if err != nil {
		t.Fatalf("BuildEmulatorArgs() error = %v", err)
	}
	joined := strings.Join(args, " ")
	for _, expected := range []string{"-http-proxy 127.0.0.1:8080", "-gpu host", "-skin pixel_7"} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("args %q missing %q", joined, expected)
		}
	}
	if strings.Contains(joined, "-no-window") {
		t.Fatalf("scrcpy display mode should keep emulator window visible: %q", joined)
	}

	commands, err := BuildMITMAdbCommands(profile)
	if err != nil {
		t.Fatalf("BuildMITMAdbCommands() error = %v", err)
	}
	commandsJoined := strings.Join(commands, "\n")
	for _, expected := range []string{"shell settings put global http_proxy 127.0.0.1:8080", "push /tmp/lab-ca.crt", "android.credentials.INSTALL"} {
		if !strings.Contains(commandsJoined, expected) {
			t.Fatalf("commands %q missing %q", commandsJoined, expected)
		}
	}
}
