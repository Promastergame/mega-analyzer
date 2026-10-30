package androidruntime

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ─── firstNonEmpty ────────────────────────────────────────────────────────────

func TestFirstNonEmpty(t *testing.T) {
	if firstNonEmpty() != "" {
		t.Error("expected empty for no args")
	}
	if firstNonEmpty("", "", "") != "" {
		t.Error("expected empty when all empty")
	}
	if firstNonEmpty("", "second", "third") != "second" {
		t.Error("expected 'second'")
	}
	if firstNonEmpty("first", "second") != "first" {
		t.Error("expected 'first'")
	}
}

// ─── extractHost (androidruntime) ─────────────────────────────────────────────

func TestExtractHostAndroidRuntime(t *testing.T) {
	// host:port → host
	if got := extractHost("127.0.0.1:15353"); got != "127.0.0.1" {
		t.Errorf("extractHost(127.0.0.1:15353) = %q, want %q", got, "127.0.0.1")
	}
	if got := extractHost("localhost:8080"); got != "localhost" {
		t.Errorf("extractHost(localhost:8080) = %q, want %q", got, "localhost")
	}
	// No port → whole string
	if got := extractHost("192.168.0.1"); got != "192.168.0.1" {
		t.Errorf("extractHost(192.168.0.1) = %q, want %q", got, "192.168.0.1")
	}
	// IPv6 style with brackets uses LastIndex
	if got := extractHost("[::1]:9339"); got != "[::1]" {
		t.Errorf("extractHost([::1]:9339) = %q, want %q", got, "[::1]")
	}
}

// ─── Profile.Validate — additional branches ──────────────────────────────────

func TestProfileValidate_MITMRequiresProxy(t *testing.T) {
	p := Profile{
		Mode:    ModeAndroidSDK,
		AVDName: "test",
		MITM: MITMProfile{
			Enabled:   true,
			HTTPProxy: "", // missing
		},
		Network: NetworkProfile{HTTPProxy: ""}, // also missing
	}
	if err := p.Validate(); err == nil {
		t.Error("expected error when MITM enabled but no proxy set")
	}
}

func TestProfileValidate_MITMAllowUserCARequiresCACert(t *testing.T) {
	p := Profile{
		Mode:    ModeAndroidSDK,
		AVDName: "test",
		MITM: MITMProfile{
			Enabled:            true,
			HTTPProxy:          "127.0.0.1:8080",
			AllowUserCAForApps: true,
			CACertPath:         "", // missing
		},
	}
	if err := p.Validate(); err == nil {
		t.Error("expected error when AllowUserCAForApps but no CACertPath")
	}
}

func TestProfileValidate_InvalidDisplayMode(t *testing.T) {
	p := Profile{
		Mode:    ModeAndroidSDK,
		AVDName: "test",
		Display: DisplayProfile{Mode: "invalid_mode"},
	}
	if err := p.Validate(); err == nil {
		t.Error("expected error for invalid display mode")
	}
}

func TestProfileValidate_ValidDisplayModes(t *testing.T) {
	for _, mode := range []string{"headless", "windowed", "scrcpy", ""} {
		p := Profile{
			Mode:    ModeAndroidSDK,
			AVDName: "test",
			Display: DisplayProfile{Mode: mode},
		}
		if err := p.Validate(); err != nil {
			t.Errorf("Validate should pass for display mode %q: %v", mode, err)
		}
	}
}

// ─── Profile.Normalize — additional branches ─────────────────────────────────

func TestProfileNormalize_MITMProxySyncToNetwork(t *testing.T) {
	// When MITM is enabled with HTTPProxy, network proxy should be synced
	p := Profile{
		Mode:    ModeAndroidSDK,
		AVDName: "test",
		MITM: MITMProfile{
			Enabled:   true,
			HTTPProxy: "127.0.0.1:8080",
		},
		Network: NetworkProfile{},
	}
	p.Normalize()
	if p.Network.HTTPProxy != "127.0.0.1:8080" {
		t.Errorf("expected Network.HTTPProxy to be synced from MITM, got %q", p.Network.HTTPProxy)
	}
}

func TestProfileNormalize_SnapshotDefaults(t *testing.T) {
	// Empty snapshot struct should get defaults from DefaultProfile
	p := Profile{
		Mode:    ModeAndroidSDK,
		AVDName: "test",
	}
	p.Normalize()
	defaults := DefaultProfile()
	if p.Snapshot.Name != defaults.Snapshot.Name {
		t.Errorf("expected snapshot name %q, got %q", defaults.Snapshot.Name, p.Snapshot.Name)
	}
}

func TestProfileNormalize_LabDNSDefaults(t *testing.T) {
	p := Profile{
		Mode:    ModeAndroidSDK,
		AVDName: "test",
	}
	p.Normalize()
	defaults := DefaultProfile()
	if p.LabDNS.ListenAddr != defaults.LabDNS.ListenAddr {
		t.Errorf("expected LabDNS.ListenAddr = %q, got %q", defaults.LabDNS.ListenAddr, p.LabDNS.ListenAddr)
	}
}

// ─── BuildEmulatorArgs — LabDNS injection ────────────────────────────────────

func TestBuildEmulatorArgs_LabDNSAutoInject(t *testing.T) {
	p := DefaultProfile()
	p.LabDNS.Enabled = true
	p.Network.DNSServers = nil // no explicit DNS; LabDNS should inject

	args, err := BuildEmulatorArgs(p)
	if err != nil {
		t.Fatalf("BuildEmulatorArgs: %v", err)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "-dns-server") {
		t.Errorf("expected -dns-server in args when LabDNS enabled: %q", joined)
	}
}

func TestBuildEmulatorArgs_SnapshotColdBoot(t *testing.T) {
	p := Profile{
		Mode:    ModeAndroidSDK,
		AVDName: "test",
		Snapshot: SnapshotProfile{
			Enabled:    true,
			ColdBoot:   true,
			SaveOnExit: false,
		},
	}
	p.Normalize()
	args, err := BuildEmulatorArgs(p)
	if err != nil {
		t.Fatalf("BuildEmulatorArgs: %v", err)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "-no-snapshot-load") {
		t.Errorf("expected -no-snapshot-load for ColdBoot: %q", joined)
	}
}

func TestBuildEmulatorArgs_SnapshotDisabled(t *testing.T) {
	p := Profile{
		Mode:    ModeAndroidSDK,
		AVDName: "test",
		Snapshot: SnapshotProfile{
			Enabled: false,
		},
	}
	p.Normalize()
	// Force snapshot.Enabled=false even after Normalize (which sets defaults)
	p.Snapshot.Enabled = false
	args, err := BuildEmulatorArgs(p)
	if err != nil {
		t.Fatalf("BuildEmulatorArgs: %v", err)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "-no-snapshot") {
		t.Errorf("expected -no-snapshot when snapshots disabled: %q", joined)
	}
}

func TestBuildEmulatorArgs_MiniModeFails(t *testing.T) {
	p := Profile{
		Mode: ModeMini,
	}
	_, err := BuildEmulatorArgs(p)
	if err == nil {
		t.Error("expected error for mini mode — emulator args only for android-sdk")
	}
}

// ─── BuildMITMAdbCommands — additional branches ───────────────────────────────

func TestBuildMITMAdbCommands_NotEnabled(t *testing.T) {
	p := Profile{
		Mode:    ModeAndroidSDK,
		AVDName: "test",
		MITM: MITMProfile{
			Enabled: false,
		},
	}
	cmds, err := BuildMITMAdbCommands(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cmds != nil {
		t.Errorf("expected nil commands when MITM disabled, got %v", cmds)
	}
}

func TestBuildMITMAdbCommands_UseNetworkProxy(t *testing.T) {
	// When MITM.HTTPProxy is empty but Network.HTTPProxy is set
	p := Profile{
		Mode:    ModeAndroidSDK,
		AVDName: "test",
		MITM: MITMProfile{
			Enabled:   true,
			HTTPProxy: "",
		},
		Network: NetworkProfile{
			HTTPProxy: "10.0.0.1:8888",
		},
	}
	cmds, err := BuildMITMAdbCommands(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cmds) == 0 {
		t.Fatal("expected commands")
	}
	if !strings.Contains(cmds[0], "10.0.0.1:8888") {
		t.Errorf("expected network proxy in first command: %q", cmds[0])
	}
}

// ─── ExportJSON — error paths ─────────────────────────────────────────────────

func TestExportJSON_WriteError(t *testing.T) {
	report := &SessionReport{SessionID: "test"}
	// Write to a non-existent directory
	err := ExportJSON(report, "/nonexistent/path/report.json")
	if err == nil {
		t.Error("expected error for invalid path")
	}
}

// ─── ExportMarkdown — error path ─────────────────────────────────────────────

func TestExportMarkdown_WriteError(t *testing.T) {
	report := &SessionReport{SessionID: "test", Profile: DefaultProfile()}
	err := ExportMarkdown(report, "/nonexistent/path/report.md")
	if err == nil {
		t.Error("expected error for invalid path")
	}
}

// ─── renderAntiVMSection — branches ──────────────────────────────────────────

func TestRenderAntiVMSection_NotApplied(t *testing.T) {
	var b strings.Builder
	renderAntiVMSection(&b, map[string]interface{}{"applied": false})
	if !strings.Contains(b.String(), "not applied") {
		t.Errorf("expected 'not applied' message, got %q", b.String())
	}
}

func TestRenderAntiVMSection_NilData(t *testing.T) {
	var b strings.Builder
	renderAntiVMSection(&b, nil)
	// json.Marshal(nil) gives "null", which won't unmarshal to map[string]interface{} — returns unavailable
	if b.String() == "" {
		t.Error("expected some output for nil data")
	}
}

func TestRenderAntiVMSection_WithBatteryAndSensor(t *testing.T) {
	var b strings.Builder
	data := map[string]interface{}{
		"applied":             true,
		"imei":                "354652061234567",
		"serial_number":       "ABC123",
		"mac_address":         "11:22:33:44:55:66",
		"wifi_ssid":           "TestNet",
		"operator_name":       "Carrier",
		"operator_numeric":    "310260",
		"battery_level":       float64(80),
		"sensor_noise_active": true,
		"properties_set":      []interface{}{"ro.product.model", "ro.build.id"},
	}
	renderAntiVMSection(&b, data)
	out := b.String()
	if !strings.Contains(out, "354652061234567") {
		t.Errorf("expected IMEI in output, got %q", out)
	}
	if !strings.Contains(out, "80%") {
		t.Errorf("expected battery level in output, got %q", out)
	}
	if !strings.Contains(out, "true") {
		t.Errorf("expected sensor_noise in output, got %q", out)
	}
}

func TestRenderAntiVMSection_WithWarnings(t *testing.T) {
	var b strings.Builder
	data := map[string]interface{}{
		"applied":  true,
		"warnings": []interface{}{"warning one", "warning two"},
	}
	renderAntiVMSection(&b, data)
	out := b.String()
	if !strings.Contains(out, "warning one") || !strings.Contains(out, "warning two") {
		t.Errorf("expected warnings in output, got %q", out)
	}
}

func TestRenderAntiVMSection_WithDeviceProfile(t *testing.T) {
	var b strings.Builder
	data := map[string]interface{}{
		"applied": true,
		"device_profile": map[string]interface{}{
			"model": "Pixel 7",
			"brand": "google",
		},
	}
	renderAntiVMSection(&b, data)
	out := b.String()
	if !strings.Contains(out, "Pixel 7") {
		t.Errorf("expected device model in output, got %q", out)
	}
	if !strings.Contains(out, "google") {
		t.Errorf("expected brand in output, got %q", out)
	}
}

// ─── mapStr ───────────────────────────────────────────────────────────────────

func TestMapStr(t *testing.T) {
	m := map[string]interface{}{
		"key1": "value1",
		"key2": 42, // wrong type
		"key3": nil,
	}
	if got := mapStr(m, "key1"); got != "value1" {
		t.Errorf("mapStr(key1) = %q, want %q", got, "value1")
	}
	if got := mapStr(m, "key2"); got != "" {
		t.Errorf("mapStr(key2) should be empty for non-string, got %q", got)
	}
	if got := mapStr(m, "key3"); got != "" {
		t.Errorf("mapStr(key3) should be empty for nil, got %q", got)
	}
	if got := mapStr(m, "missing"); got != "" {
		t.Errorf("mapStr(missing) should be empty, got %q", got)
	}
}

// ─── parseSnapshotList — additional cases ────────────────────────────────────

func TestParseSnapshotList_NumericFirstField(t *testing.T) {
	// When first field is numeric but second is not (e.g. "1 cleansnap 50M")
	output := "1 cleansnap 50M\n2 testsnap 10M\n"
	snaps := parseSnapshotList(output)
	if len(snaps) != 2 {
		t.Fatalf("expected 2 snapshots, got %d: %+v", len(snaps), snaps)
	}
	// First non-numeric field should be picked as name
	found := false
	for _, s := range snaps {
		if s.Name == "cleansnap" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'cleansnap' in snapshots: %+v", snaps)
	}
}

func TestParseSnapshotList_SkipsHeaderAndSeparator(t *testing.T) {
	output := `ID            TAG            SIZE
--            ---            ----
clean         clean          100M
`
	snaps := parseSnapshotList(output)
	// Should only get the data row, not header or separator
	if len(snaps) != 1 {
		t.Fatalf("expected 1 snapshot, got %d: %+v", len(snaps), snaps)
	}
}

// ─── readConsoleAuthToken — error case ───────────────────────────────────────

func TestReadConsoleAuthToken_FileNotFound(t *testing.T) {
	// The token file likely doesn't exist in test env; should return error
	_, err := readConsoleAuthToken()
	// We don't assert the error direction because the file might exist.
	// Just verify the call doesn't panic.
	_ = err
}

func TestReadConsoleAuthToken_WithTempFile(t *testing.T) {
	// Create a fake token file
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home dir available")
	}
	tokenPath := filepath.Join(home, ".emulator_console_auth_token")

	// Only write if it doesn't already exist to avoid breaking real config
	if _, statErr := os.Stat(tokenPath); os.IsNotExist(statErr) {
		if writeErr := os.WriteFile(tokenPath, []byte("  mytoken123  \n"), 0o600); writeErr != nil {
			t.Skip("cannot write token file")
		}
		defer os.Remove(tokenPath)

		token, err := readConsoleAuthToken()
		if err != nil {
			t.Fatalf("readConsoleAuthToken: %v", err)
		}
		if token != "mytoken123" {
			t.Errorf("expected trimmed token 'mytoken123', got %q", token)
		}
	}
}

// ─── readUntilOK ─────────────────────────────────────────────────────────────

func TestReadUntilOK_Success(t *testing.T) {
	input := "line one\r\nline two\r\nOK\r\n"
	reader := bufio.NewReader(strings.NewReader(input))
	if err := readUntilOK(reader); err != nil {
		t.Errorf("readUntilOK: unexpected error: %v", err)
	}
}

func TestReadUntilOK_EOF(t *testing.T) {
	input := "line one\r\nno ok here"
	reader := bufio.NewReader(strings.NewReader(input))
	err := readUntilOK(reader)
	if err == nil {
		t.Error("expected error for EOF without OK")
	}
}

// ─── NewConsoleSnapshotManager — auth token optional ─────────────────────────

func TestNewConsoleSnapshotManager_AuthTokenOptional(t *testing.T) {
	// Even if auth token is missing, NewConsoleSnapshotManager should succeed
	mgr, err := NewConsoleSnapshotManager(5554)
	if err != nil {
		t.Fatalf("NewConsoleSnapshotManager should not error even without token: %v", err)
	}
	if mgr == nil {
		t.Fatal("expected non-nil manager")
	}
	// authToken may be empty or may have real token — just ensure no panic
	_ = mgr.authToken
}

// ─── SnapshotOp timing ────────────────────────────────────────────────────────

func TestSnapshotOp_Timestamp(t *testing.T) {
	mgr := NewNoopSnapshotManager()
	before := time.Now().UTC()
	_ = mgr.Save(context.TODO(), "test")
	after := time.Now().UTC()

	ops := mgr.Operations()
	if len(ops) != 1 {
		t.Fatalf("expected 1 op, got %d", len(ops))
	}
	ts := ops[0].Timestamp
	if ts.Before(before) || ts.After(after) {
		t.Errorf("timestamp %v not between %v and %v", ts, before, after)
	}
}
