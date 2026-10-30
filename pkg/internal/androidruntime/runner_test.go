package androidruntime

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"mega-analyzer/pkg/internal/labdns"
)

// ── Mock Dependencies ────────────────────────────────────────

// mockDNSServer implements labdns.DNSServer for unit tests.
type mockDNSServer struct {
	addr    string
	queries []labdns.DNSQueryRecord
	stats   labdns.DNSStats
	started bool
	stopped bool
}

func (m *mockDNSServer) Start(_ context.Context) error     { m.started = true; return nil }
func (m *mockDNSServer) Stop() error                       { m.stopped = true; return nil }
func (m *mockDNSServer) Addr() string                      { return m.addr }
func (m *mockDNSServer) QueryLog() []labdns.DNSQueryRecord { return m.queries }
func (m *mockDNSServer) Stats() labdns.DNSStats            { return m.stats }

// mockEvasionReport matches antivm.EvasionReport JSON shape.
type mockEvasionReport struct {
	Applied      bool   `json:"applied"`
	Model        string `json:"model"`
	IMEI         string `json:"imei"`
	SerialNumber string `json:"serial_number"`
	MACAddress   string `json:"mac_address"`
	BatteryLevel int    `json:"battery_level"`
}

// mockEvasion implements the local evasionEngine interface for unit tests.
type mockEvasion struct {
	applied bool
	report  mockEvasionReport
}

func (m *mockEvasion) Apply(_ context.Context, _ string, _ string) error {
	m.applied = true
	m.report = mockEvasionReport{
		Applied:      true,
		Model:        "Pixel 7",
		IMEI:         "354652061234567",
		SerialNumber: "ABCD1234",
		MACAddress:   "3C:5A:B4:AA:BB:CC",
		BatteryLevel: 72,
	}
	return nil
}

func (m *mockEvasion) Report() interface{} { return m.report }

// ── Runner Config Validation Tests ───────────────────────────

func TestNewEmulatorRunnerValidation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     RunnerConfig
		wantErr string
	}{
		{
			name:    "missing emulator binary",
			cfg:     RunnerConfig{ADBBin: "adb", Profile: DefaultProfile()},
			wantErr: "emulator binary path is required",
		},
		{
			name:    "missing adb binary",
			cfg:     RunnerConfig{EmulatorBin: "emulator", Profile: DefaultProfile()},
			wantErr: "adb binary path is required",
		},
		{
			name: "invalid profile mode",
			cfg: RunnerConfig{
				EmulatorBin: "emulator",
				ADBBin:      "adb",
				Profile:     Profile{Mode: "invalid"},
			},
			wantErr: "invalid android runtime mode",
		},
		{
			name: "valid config",
			cfg: RunnerConfig{
				EmulatorBin: "emulator",
				ADBBin:      "adb",
				Profile:     DefaultProfile(),
			},
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewEmulatorRunner(tt.cfg)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q should contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestNewEmulatorRunnerSessionDir(t *testing.T) {
	dir := t.TempDir()
	runner, err := NewEmulatorRunner(RunnerConfig{
		EmulatorBin: "emulator",
		ADBBin:      "adb",
		Profile:     DefaultProfile(),
		SessionDir:  dir,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if runner.stdoutPath == "" {
		t.Error("expected stdout path to be set")
	}
	if runner.stderrPath == "" {
		t.Error("expected stderr path to be set")
	}
}

// ── State Machine Tests ──────────────────────────────────────

func TestRunnerStateString(t *testing.T) {
	tests := []struct {
		state RunnerState
		want  string
	}{
		{StateIdle, "idle"},
		{StateStarting, "starting"},
		{StateBooting, "booting"},
		{StateApplyingEvasion, "applying-evasion"},
		{StateRunning, "running"},
		{StateStopping, "stopping"},
		{StateStopped, "stopped"},
		{StateFailed, "failed"},
		{RunnerState(99), "unknown"},
	}
	for _, tt := range tests {
		got := tt.state.String()
		if got != tt.want {
			t.Errorf("RunnerState(%d).String() = %q, want %q", tt.state, got, tt.want)
		}
	}
}

func TestRunnerInitialState(t *testing.T) {
	runner, err := NewEmulatorRunner(RunnerConfig{
		EmulatorBin: "emulator",
		ADBBin:      "adb",
		Profile:     DefaultProfile(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if runner.State() != StateIdle {
		t.Errorf("initial state = %s, want idle", runner.State())
	}
}

func TestRunnerWaitWithoutStart(t *testing.T) {
	runner, _ := NewEmulatorRunner(RunnerConfig{
		EmulatorBin: "emulator",
		ADBBin:      "adb",
		Profile:     DefaultProfile(),
	})
	err := runner.Wait()
	if err == nil {
		t.Fatal("expected error calling Wait without Start")
	}
}

// ── GenerateReport Tests ─────────────────────────────────────

func TestRunnerGenerateReport(t *testing.T) {
	dnsQueries := []labdns.DNSQueryRecord{
		{QueryName: "evil.test", Action: "sinked", AnswerIP: "127.0.0.1"},
		{QueryName: "google.com", Action: "forwarded", AnswerIP: "142.250.80.46"},
	}
	dnsStats := labdns.DNSStats{
		TotalQueries:   2,
		ForwardedCount: 1,
		SinkholeCount:  1,
		UniqueNames:    2,
	}

	mockDNS := &mockDNSServer{
		addr:    "127.0.0.1:15353",
		queries: dnsQueries,
		stats:   dnsStats,
	}

	mockEv := &mockEvasion{}
	mockEv.Apply(context.Background(), "", "")

	snapshotMgr := NewNoopSnapshotManager()
	snapshotMgr.Save(context.Background(), "clean")

	runner, err := NewEmulatorRunner(RunnerConfig{
		EmulatorBin: "emulator",
		ADBBin:      "adb",
		Profile:     DefaultProfile(),
		DNSServer:   mockDNS,
		SnapshotMgr: snapshotMgr,
		Evasion:     mockEv,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Simulate some state.
	runner.startedAt = time.Now().UTC().Add(-5 * time.Minute)
	runner.stoppedAt = time.Now().UTC()
	runner.emulatorPID = 12345
	runner.consolePort = 5554

	report := runner.GenerateReport()

	if report.SessionID == "" {
		t.Error("session ID should be set")
	}
	if report.EmulatorPID != 12345 {
		t.Errorf("PID = %d, want 12345", report.EmulatorPID)
	}
	if report.ConsolePort != 5554 {
		t.Errorf("port = %d, want 5554", report.ConsolePort)
	}
	if report.DurationMs <= 0 {
		t.Error("duration should be positive")
	}

	// DNS.
	if len(report.DNSLog) != 2 {
		t.Errorf("DNS log count = %d, want 2", len(report.DNSLog))
	}
	if report.DNSStats.TotalQueries != 2 {
		t.Errorf("DNS stats total = %d, want 2", report.DNSStats.TotalQueries)
	}

	// Snapshots.
	if len(report.SnapshotOps) != 1 {
		t.Errorf("snapshot ops = %d, want 1", len(report.SnapshotOps))
	}

	// Anti-VM - extract via JSON round-trip since AntiVMApplied is interface{}.
	rawAntiVM, _ := json.Marshal(report.AntiVMApplied)
	var antiVMMap map[string]interface{}
	_ = json.Unmarshal(rawAntiVM, &antiVMMap)

	if applied, ok := antiVMMap["applied"].(bool); !ok || !applied {
		t.Error("anti-VM should be applied")
	}

	if dp, ok := antiVMMap["device_profile"].(map[string]interface{}); ok {
		if model, ok := dp["model"].(string); !ok || model != "Pixel 7" {
			t.Errorf("model = %q, want Pixel 7", dp["model"])
		}
	}
}

// ── Build Args with LabDNS Injection ─────────────────────────

func TestBuildEmulatorArgsWithLabDNS(t *testing.T) {
	profile := DefaultProfile()
	profile.Network.DNSServers = nil // clear explicit DNS
	profile.LabDNS.Enabled = true
	profile.LabDNS.ListenAddr = "127.0.0.1:15353"

	args, err := BuildEmulatorArgs(profile)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "-dns-server 127.0.0.1") {
		t.Errorf("expected LabDNS address injected, got: %s", joined)
	}
}

func TestBuildEmulatorArgsExplicitDNSOverridesLabDNS(t *testing.T) {
	profile := DefaultProfile()
	profile.Network.DNSServers = []string{"1.1.1.1", "1.0.0.1"}
	profile.LabDNS.Enabled = true
	profile.LabDNS.ListenAddr = "127.0.0.1:15353"

	args, err := BuildEmulatorArgs(profile)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "-dns-server 1.1.1.1,1.0.0.1") {
		t.Errorf("explicit DNS should take priority, got: %s", joined)
	}
}

func TestBuildEmulatorArgsTimezone(t *testing.T) {
	profile := DefaultProfile()
	profile.Timezone = "America/New_York"

	args, err := BuildEmulatorArgs(profile)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "-timezone America/New_York") {
		t.Errorf("timezone not set: %s", joined)
	}
}

func TestBuildEmulatorArgsHeadlessFlags(t *testing.T) {
	profile := DefaultProfile()
	args, err := BuildEmulatorArgs(profile)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	joined := strings.Join(args, " ")
	for _, flag := range []string{"-no-window", "-no-audio", "-no-boot-anim"} {
		if !strings.Contains(joined, flag) {
			t.Errorf("missing headless flag %q in: %s", flag, joined)
		}
	}
}

// ── Warnings Tests ───────────────────────────────────────────

func TestRunnerWarnings(t *testing.T) {
	runner, _ := NewEmulatorRunner(RunnerConfig{
		EmulatorBin: "emulator",
		ADBBin:      "adb",
		Profile:     DefaultProfile(),
	})

	runner.addWarning("test warning 1")
	runner.addWarning("test warning 2")

	warnings := runner.Warnings()
	if len(warnings) != 2 {
		t.Fatalf("expected 2 warnings, got %d", len(warnings))
	}
	if warnings[0] != "test warning 1" {
		t.Errorf("wrong warning: %q", warnings[0])
	}
}

// ── ExtractHost Tests ────────────────────────────────────────

func TestExtractHost(t *testing.T) {
	tests := []struct {
		addr string
		want string
	}{
		{"127.0.0.1:15353", "127.0.0.1"},
		{"0.0.0.0:53", "0.0.0.0"},
		{"localhost", "localhost"},
		{"[::1]:53", "[::1]"},
	}
	for _, tt := range tests {
		got := extractHost(tt.addr)
		if got != tt.want {
			t.Errorf("extractHost(%q) = %q, want %q", tt.addr, got, tt.want)
		}
	}
}
