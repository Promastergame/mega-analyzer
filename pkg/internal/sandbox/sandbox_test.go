package sandbox

import (
	"strings"
	"testing"
	"time"
)

func TestSplitRawArgs(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    []string
		wantErr bool
	}{
		{
			name: "empty",
			raw:  "",
			want: nil,
		},
		{
			name: "simple args",
			raw:  "--check --fast",
			want: []string{"--check", "--fast"},
		},
		{
			name: "quoted args",
			raw:  "--name \"John Doe\" --mode 'safe run'",
			want: []string{"--name", "John Doe", "--mode", "safe run"},
		},
		{
			name:    "unterminated quote",
			raw:     "\"oops",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := splitRawArgs(tt.raw)
			if (err != nil) != tt.wantErr {
				t.Fatalf("splitRawArgs() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if strings.Join(got, "|") != strings.Join(tt.want, "|") {
				t.Fatalf("splitRawArgs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDiffSnapshots(t *testing.T) {
	before := map[string]fileFingerprint{
		"app.exe": {Path: "app.exe", Size: 10, SHA256: "aaa"},
		"old.txt": {Path: "old.txt", Size: 5, SHA256: "bbb"},
	}
	after := map[string]fileFingerprint{
		"app.exe": {Path: "app.exe", Size: 11, SHA256: "ccc"},
		"new.txt": {Path: "new.txt", Size: 7, SHA256: "ddd"},
	}

	changes := diffSnapshots(before, after)

	if len(changes.Created) != 1 || changes.Created[0].Path != "new.txt" {
		t.Fatalf("created = %+v, want new.txt", changes.Created)
	}
	if len(changes.Modified) != 1 || changes.Modified[0].Path != "app.exe" {
		t.Fatalf("modified = %+v, want app.exe", changes.Modified)
	}
	if len(changes.Deleted) != 1 || changes.Deleted[0].Path != "old.txt" {
		t.Fatalf("deleted = %+v, want old.txt", changes.Deleted)
	}
}

func TestParseNetstatOutput(t *testing.T) {
	raw := `
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    127.0.0.1:5000         127.0.0.1:6000         ESTABLISHED     4321
  TCP    10.0.0.5:49152         93.184.216.34:443      SYN_SENT        9999
  UDP    0.0.0.0:5353           *:*                                    4321
`

	pids := map[int]struct{}{4321: {}}
	connections := parseNetstatOutput(raw, pids)
	if len(connections) != 2 {
		t.Fatalf("connections = %+v, want 2 entries", connections)
	}
	if connections[0].PID != 4321 || connections[1].PID != 4321 {
		t.Fatalf("unexpected PIDs: %+v", connections)
	}
}

func TestBuildBehaviorSummary(t *testing.T) {
	report := &Report{
		NetworkMode: "blocked",
		Processes: []ObservedProcess{
			{PID: 100},
			{PID: 101},
		},
		Connections: []ObservedConnection{
			{RemoteAddr: "93.184.216.34:443"},
		},
		FileChanges: FileChanges{
			Created: []FileArtifact{
				{Path: "dropper.exe"},
				{Path: "scripts/loader.ps1"},
			},
			Modified: []FileArtifact{
				{Path: "config.json"},
			},
		},
		RegistryChanges: RegistryChanges{
			Added: []RegistryValue{{Key: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, Name: "bad"}},
		},
		AndroidProfile: &AndroidProfile{
			HighRiskPermissionCount: 1,
			ExportedComponents: []AndroidComponent{
				{Kind: "receiver", Name: "BootReceiver", Exported: true},
			},
		},
	}

	summary := buildBehaviorSummary(report)

	if summary.ChildProcessCount != 1 {
		t.Fatalf("ChildProcessCount = %d, want 1", summary.ChildProcessCount)
	}
	if summary.PublicConnectionCount != 1 {
		t.Fatalf("PublicConnectionCount = %d, want 1", summary.PublicConnectionCount)
	}
	if summary.DroppedExecutableCount != 1 {
		t.Fatalf("DroppedExecutableCount = %d, want 1", summary.DroppedExecutableCount)
	}
	if summary.DroppedScriptCount != 1 {
		t.Fatalf("DroppedScriptCount = %d, want 1", summary.DroppedScriptCount)
	}
	if len(summary.Highlights) == 0 {
		t.Fatal("expected non-empty highlights")
	}
}

func TestBuildSandboxPermissions(t *testing.T) {
	cfg := Config{MaxMemoryMB: 768, BlockNetwork: true}
	layout := &sessionLayout{
		workspaceDir: "C:/sandbox/workspace",
		tempDir:      "C:/sandbox/tmp",
		homeDir:      "C:/sandbox/home",
		appDataDir:   "C:/sandbox/appdata",
		localAppData: "C:/sandbox/localappdata",
		programData:  "C:/sandbox/programdata",
		publicDir:    "C:/sandbox/public",
	}

	permissions := buildSandboxPermissions(cfg, layout)

	if permissions.NetworkAccess != "blocked" {
		t.Fatalf("NetworkAccess = %q, want blocked", permissions.NetworkAccess)
	}
	if permissions.MaxMemoryMB != 768 {
		t.Fatalf("MaxMemoryMB = %d, want 768", permissions.MaxMemoryMB)
	}
	if len(permissions.ExposedWritePaths) != 7 {
		t.Fatalf("ExposedWritePaths = %d, want 7", len(permissions.ExposedWritePaths))
	}
	if len(permissions.MonitoredRegistryKeys) == 0 {
		t.Fatal("expected monitored registry keys")
	}
}

func TestRequestedComponentsAndEffectiveConfig(t *testing.T) {
	cfg := Config{
		OutputDir:           "out",
		Duration:            30 * time.Second,
		MaxMemoryMB:         1024,
		MonitorEvery:        500 * time.Millisecond,
		SandboxProfile:      "forensic",
		VSSRevert:           true,
		EnableKernelMonitor: true,
		EnableVSS:           true,
		EnableWFP:           true,
		TimeScaleFactor:     5,
	}

	components := requestedComponents(cfg)
	if strings.Join(components, ",") != "kernel_monitor,vss,wfp" {
		t.Fatalf("components = %v", components)
	}

	effective := buildEffectiveConfig(cfg, "out")
	if effective.SandboxProfile != "forensic" {
		t.Fatalf("SandboxProfile = %q", effective.SandboxProfile)
	}
	if !effective.VSSRevert || effective.TimeScaleFactor != 5 {
		t.Fatalf("effective config missing fields: %+v", effective)
	}
}
