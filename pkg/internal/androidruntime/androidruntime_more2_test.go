package androidruntime

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mega-analyzer/pkg/internal/labdns"
)

// ─── Profile.Validate — additional branches ───────────────────────────────────

func TestProfileValidate_ModeMini_NoAVD(t *testing.T) {
	// Mini mode does not require AVD name
	p := Profile{Mode: ModeMini}
	if err := p.Validate(); err != nil {
		t.Errorf("mini mode should be valid without AVD, got: %v", err)
	}
}

func TestProfileValidate_ModeAndroidSDK_NoAVD(t *testing.T) {
	p := Profile{Mode: ModeAndroidSDK, AVDName: ""}
	if err := p.Validate(); err == nil {
		t.Error("expected error: android-sdk without avd_name")
	}
}

func TestProfileValidate_InvalidMode(t *testing.T) {
	p := Profile{Mode: "invalid-mode"}
	if err := p.Validate(); err == nil {
		t.Error("expected error for invalid mode")
	}
}

func TestProfileValidate_MITMAllowUserCA_WithCACertPath(t *testing.T) {
	// AllowUserCAForApps with a CACertPath must succeed
	p := Profile{
		Mode:    ModeAndroidSDK,
		AVDName: "test",
		MITM: MITMProfile{
			Enabled:            true,
			HTTPProxy:          "127.0.0.1:8080",
			AllowUserCAForApps: true,
			CACertPath:         "/some/path/ca.crt",
		},
	}
	if err := p.Validate(); err != nil {
		t.Errorf("expected no error when CACertPath set: %v", err)
	}
}

func TestProfileValidate_MITMNetworkProxySuffices(t *testing.T) {
	// MITM enabled without MITM.HTTPProxy but with Network.HTTPProxy is valid
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
	if err := p.Validate(); err != nil {
		t.Errorf("expected no error when Network.HTTPProxy set: %v", err)
	}
}

// ─── Profile.Normalize — additional branches ─────────────────────────────────

func TestProfileNormalize_EmptyProfileGetsAllDefaults(t *testing.T) {
	var p Profile
	p.Normalize()
	def := DefaultProfile()
	if p.Name != def.Name {
		t.Errorf("Name: got %q, want %q", p.Name, def.Name)
	}
	if p.Mode != def.Mode {
		t.Errorf("Mode: got %q, want %q", p.Mode, def.Mode)
	}
	if p.AVDName != def.AVDName {
		t.Errorf("AVDName: got %q, want %q", p.AVDName, def.AVDName)
	}
	if p.Locale != def.Locale {
		t.Errorf("Locale: got %q, want %q", p.Locale, def.Locale)
	}
	if p.Timezone != def.Timezone {
		t.Errorf("Timezone: got %q, want %q", p.Timezone, def.Timezone)
	}
	if p.SystemTag != def.SystemTag {
		t.Errorf("SystemTag: got %q, want %q", p.SystemTag, def.SystemTag)
	}
}

func TestProfileNormalize_PreservesExistingValues(t *testing.T) {
	p := Profile{
		Mode:    ModeAndroidSDK,
		AVDName: "my-avd",
		Locale:  "fr-FR",
	}
	p.Normalize()
	if p.AVDName != "my-avd" {
		t.Errorf("AVDName was overwritten, got %q", p.AVDName)
	}
	if p.Locale != "fr-FR" {
		t.Errorf("Locale was overwritten, got %q", p.Locale)
	}
}

func TestProfileNormalize_NetworkDefaults(t *testing.T) {
	p := Profile{Mode: ModeAndroidSDK, AVDName: "test"}
	p.Normalize()
	def := DefaultProfile()
	if p.Network.NetSpeed != def.Network.NetSpeed {
		t.Errorf("NetSpeed: got %q, want %q", p.Network.NetSpeed, def.Network.NetSpeed)
	}
	if p.Network.NetDelay != def.Network.NetDelay {
		t.Errorf("NetDelay: got %q, want %q", p.Network.NetDelay, def.Network.NetDelay)
	}
}

func TestProfileNormalize_DisplayDefaults(t *testing.T) {
	p := Profile{Mode: ModeAndroidSDK, AVDName: "test"}
	p.Normalize()
	def := DefaultProfile()
	if p.Display.Mode != def.Display.Mode {
		t.Errorf("Display.Mode: got %q, want %q", p.Display.Mode, def.Display.Mode)
	}
	if p.Display.GPU != def.Display.GPU {
		t.Errorf("Display.GPU: got %q, want %q", p.Display.GPU, def.Display.GPU)
	}
}

func TestProfileNormalize_MITMNotSyncedWhenDisabled(t *testing.T) {
	p := Profile{
		Mode:    ModeAndroidSDK,
		AVDName: "test",
		MITM: MITMProfile{
			Enabled:   false,
			HTTPProxy: "127.0.0.1:9999",
		},
		Network: NetworkProfile{},
	}
	p.Normalize()
	// Network proxy should NOT be set when MITM is disabled
	if p.Network.HTTPProxy == "127.0.0.1:9999" {
		t.Error("Network.HTTPProxy should not be synced when MITM is disabled")
	}
}

// ─── ExportJSON — success path ────────────────────────────────────────────────

func TestExportJSON_Success(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	report := &SessionReport{
		SessionID: "test-session-123",
		Profile:   DefaultProfile(),
	}
	if err := ExportJSON(report, path); err != nil {
		t.Fatalf("ExportJSON: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(string(data), "test-session-123") {
		t.Errorf("exported JSON should contain session ID")
	}
}

// ─── ExportMarkdown — success path ───────────────────────────────────────────

func TestExportMarkdown_Success(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.md")
	report := &SessionReport{
		SessionID: "sess-md-test",
		Profile:   DefaultProfile(),
	}
	if err := ExportMarkdown(report, path); err != nil {
		t.Fatalf("ExportMarkdown: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(string(data), "sess-md-test") {
		t.Errorf("exported Markdown should contain session ID")
	}
}

// ─── RenderMarkdownReport — full coverage ────────────────────────────────────

func TestRenderMarkdownReport_WithDNSLog(t *testing.T) {
	// Make 55 DNS log entries to trigger the "> 50 more" branch
	dnsLog := make([]labdns.DNSQueryRecord, 55)
	for i := range dnsLog {
		dnsLog[i] = labdns.DNSQueryRecord{
			Timestamp: time.Now(),
			QueryName: "example.com",
			QueryType: "A",
			Action:    "forwarded",
		}
	}
	report := &SessionReport{
		SessionID:  "dns-test",
		Profile:    DefaultProfile(),
		DurationMs: 5000,
		DNSLog:     dnsLog,
	}
	md := RenderMarkdownReport(report)
	if !strings.Contains(md, "DNS") {
		t.Error("expected DNS section in report")
	}
	if !strings.Contains(md, "more queries") {
		t.Errorf("expected 'more queries' when log has >50 entries, got: %q", md)
	}
}

func TestRenderMarkdownReport_WithTopDomains(t *testing.T) {
	report := &SessionReport{
		SessionID: "topdomain-test",
		Profile:   DefaultProfile(),
		DNSStats: labdns.DNSStats{
			TopDomains: []labdns.DomainCount{
				{Name: "api.example.com", Count: 10},
				{Name: "cdn.example.com", Count: 5},
			},
		},
	}
	md := RenderMarkdownReport(report)
	if !strings.Contains(md, "api.example.com") {
		t.Errorf("expected top domain in report, got: %q", md)
	}
}

func TestRenderMarkdownReport_WithSinkholedNames(t *testing.T) {
	report := &SessionReport{
		SessionID: "sinkhole-test",
		Profile:   DefaultProfile(),
		DNSStats: labdns.DNSStats{
			SinkholedNames: []string{"evil.com", "tracker.net"},
		},
	}
	md := RenderMarkdownReport(report)
	if !strings.Contains(md, "evil.com") {
		t.Errorf("expected sinkholed domain in report")
	}
}

func TestRenderMarkdownReport_WithC2Candidates(t *testing.T) {
	report := &SessionReport{
		SessionID: "c2-test",
		Profile:   DefaultProfile(),
		DNSStats: labdns.DNSStats{
			C2Candidates: []string{"suspicious-dga-domain.xyz"},
		},
	}
	md := RenderMarkdownReport(report)
	if !strings.Contains(md, "suspicious-dga-domain.xyz") {
		t.Errorf("expected C2 candidate in report")
	}
}

func TestRenderMarkdownReport_WithSnapshotOps(t *testing.T) {
	report := &SessionReport{
		SessionID: "snap-test",
		Profile:   DefaultProfile(),
		SnapshotOps: []SnapshotOp{
			{Action: "save", Name: "clean", Duration: 250},
			{Action: "load", Name: "clean", Duration: 300, Error: "timeout"},
		},
	}
	md := RenderMarkdownReport(report)
	if !strings.Contains(md, "Snapshot") {
		t.Errorf("expected Snapshot section in report")
	}
	if !strings.Contains(md, "timeout") {
		t.Errorf("expected error detail in snapshot op")
	}
}

func TestRenderMarkdownReport_WithWarnings(t *testing.T) {
	report := &SessionReport{
		SessionID: "warn-test",
		Profile:   DefaultProfile(),
		Warnings:  []string{"warning beta", "warning alpha"},
	}
	md := RenderMarkdownReport(report)
	if !strings.Contains(md, "Warnings") {
		t.Errorf("expected Warnings section")
	}
	// Warnings should be sorted
	alphaIdx := strings.Index(md, "warning alpha")
	betaIdx := strings.Index(md, "warning beta")
	if alphaIdx < 0 || betaIdx < 0 {
		t.Error("expected both warnings in output")
	} else if alphaIdx > betaIdx {
		t.Error("warnings should be sorted alphabetically")
	}
}

func TestRenderMarkdownReport_WithAntiVM(t *testing.T) {
	report := &SessionReport{
		SessionID: "antivm-test",
		Profile:   DefaultProfile(),
		AntiVMApplied: map[string]interface{}{
			"applied": true,
			"imei":    "123456789012345",
		},
	}
	md := RenderMarkdownReport(report)
	if !strings.Contains(md, "Anti-VM") {
		t.Errorf("expected Anti-VM section")
	}
}

func TestRenderMarkdownReport_NilAntiVM(t *testing.T) {
	report := &SessionReport{
		SessionID:     "no-antivm",
		Profile:       DefaultProfile(),
		AntiVMApplied: nil,
	}
	md := RenderMarkdownReport(report)
	if !strings.Contains(md, "not applied") {
		t.Errorf("expected 'not applied' when AntiVMApplied is nil, got: %q", md)
	}
}

// ─── renderAntiVMSection — remaining branches ─────────────────────────────────

func TestRenderAntiVMSection_PropertiesSet(t *testing.T) {
	var b strings.Builder
	data := map[string]interface{}{
		"applied":        true,
		"properties_set": []interface{}{"ro.product.model", "ro.build.id", "ro.build.fingerprint"},
	}
	renderAntiVMSection(&b, data)
	out := b.String()
	if !strings.Contains(out, "3") {
		t.Errorf("expected '3' properties patched in output, got: %q", out)
	}
}

func TestRenderAntiVMSection_DeviceProfileMissingFields(t *testing.T) {
	var b strings.Builder
	data := map[string]interface{}{
		"applied": true,
		"device_profile": map[string]interface{}{
			"model": "Galaxy S21",
			// brand intentionally missing
		},
	}
	renderAntiVMSection(&b, data)
	out := b.String()
	if !strings.Contains(out, "Galaxy S21") {
		t.Errorf("expected model in output, got: %q", out)
	}
}

// ─── LoadProfile — success and error paths ───────────────────────────────────

func TestLoadProfile_FileNotFound(t *testing.T) {
	_, err := LoadProfile("/nonexistent/path/profile.json")
	if err == nil {
		t.Error("expected error for non-existent profile file")
	}
}

func TestLoadProfile_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("{invalid json"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadProfile(path)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestLoadProfile_ValidProfile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.json")
	p := DefaultProfile()
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadProfile(path)
	if err != nil {
		t.Fatalf("LoadProfile: %v", err)
	}
	if loaded.AVDName != p.AVDName {
		t.Errorf("AVDName: got %q, want %q", loaded.AVDName, p.AVDName)
	}
}

// ─── NewSessionAggregator ─────────────────────────────────────────────────────

func TestNewSessionAggregator(t *testing.T) {
	p := DefaultProfile()
	before := time.Now().UTC()
	agg := NewSessionAggregator(p)
	after := time.Now().UTC()

	if agg == nil {
		t.Fatal("expected non-nil aggregator")
	}
	if agg.startedAt.Before(before) || agg.startedAt.After(after) {
		t.Errorf("startedAt %v out of range [%v, %v]", agg.startedAt, before, after)
	}
	if agg.warnings == nil {
		t.Error("expected initialized warnings slice")
	}
}

// ─── AntiVMProfile.ToEvasionConfig ───────────────────────────────────────────

func TestAntiVMProfile_ToEvasionConfig(t *testing.T) {
	a := AntiVMProfile{
		Enabled:       true,
		DeviceModel:   "Pixel 7",
		RandomizeIMEI: true,
		SensorNoise:   true,
		PatchBattery:  false,
		PatchNetwork:  true,
		PatchOperator: false,
	}
	cfg := a.ToEvasionConfig()
	if !cfg.Enabled {
		t.Error("Enabled should be true")
	}
	if cfg.DeviceModel != "Pixel 7" {
		t.Errorf("DeviceModel: got %q", cfg.DeviceModel)
	}
	if !cfg.RandomizeIMEI {
		t.Error("RandomizeIMEI should be true")
	}
	if cfg.PatchBattery {
		t.Error("PatchBattery should be false")
	}
}

// ─── BuildEmulatorArgs — additional branches ─────────────────────────────────

func TestBuildEmulatorArgs_WithHTTPProxy(t *testing.T) {
	p := Profile{
		Mode:    ModeAndroidSDK,
		AVDName: "test",
		Network: NetworkProfile{HTTPProxy: "proxy.example.com:3128"},
	}
	p.Normalize()
	args, err := BuildEmulatorArgs(p)
	if err != nil {
		t.Fatalf("BuildEmulatorArgs: %v", err)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "-http-proxy") {
		t.Errorf("expected -http-proxy in args, got: %q", joined)
	}
	if !strings.Contains(joined, "proxy.example.com:3128") {
		t.Errorf("expected proxy address in args, got: %q", joined)
	}
}

func TestBuildEmulatorArgs_Scrcpy_NoWindow(t *testing.T) {
	p := Profile{
		Mode:    ModeAndroidSDK,
		AVDName: "test",
		Display: DisplayProfile{Mode: "scrcpy"},
	}
	p.Normalize()
	// scrcpy mode should NOT add -no-window
	args, err := BuildEmulatorArgs(p)
	if err != nil {
		t.Fatalf("BuildEmulatorArgs: %v", err)
	}
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "-no-window") {
		t.Errorf("scrcpy mode should not have -no-window: %q", joined)
	}
}

func TestBuildEmulatorArgs_Headless_HasNoWindow(t *testing.T) {
	p := Profile{
		Mode:    ModeAndroidSDK,
		AVDName: "test",
		Display: DisplayProfile{Mode: "headless"},
	}
	p.Normalize()
	args, err := BuildEmulatorArgs(p)
	if err != nil {
		t.Fatalf("BuildEmulatorArgs: %v", err)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "-no-window") {
		t.Errorf("headless mode should have -no-window: %q", joined)
	}
}

func TestBuildEmulatorArgs_Timezone(t *testing.T) {
	p := Profile{
		Mode:     ModeAndroidSDK,
		AVDName:  "test",
		Timezone: "America/New_York",
	}
	p.Normalize()
	// Preserve our timezone (Normalize won't overwrite non-empty)
	p.Timezone = "America/New_York"
	args, err := BuildEmulatorArgs(p)
	if err != nil {
		t.Fatalf("BuildEmulatorArgs: %v", err)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "America/New_York") {
		t.Errorf("expected timezone in args, got: %q", joined)
	}
}

func TestBuildEmulatorArgs_WithSkin(t *testing.T) {
	p := Profile{
		Mode:    ModeAndroidSDK,
		AVDName: "test",
		Display: DisplayProfile{Skin: "nexus_5x"},
	}
	p.Normalize()
	args, err := BuildEmulatorArgs(p)
	if err != nil {
		t.Fatalf("BuildEmulatorArgs: %v", err)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "-skin") {
		t.Errorf("expected -skin in args, got: %q", joined)
	}
	if !strings.Contains(joined, "nexus_5x") {
		t.Errorf("expected skin name in args, got: %q", joined)
	}
}

func TestBuildEmulatorArgs_SnapshotStoragePath(t *testing.T) {
	p := Profile{
		Mode:    ModeAndroidSDK,
		AVDName: "test",
		Snapshot: SnapshotProfile{
			Enabled:     true,
			StoragePath: "/tmp/snapshots",
		},
	}
	p.Normalize()
	args, err := BuildEmulatorArgs(p)
	if err != nil {
		t.Fatalf("BuildEmulatorArgs: %v", err)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "-snapstorage") {
		t.Errorf("expected -snapstorage in args: %q", joined)
	}
}

func TestBuildEmulatorArgs_SnapshotSaveOnExit(t *testing.T) {
	p := Profile{
		Mode:    ModeAndroidSDK,
		AVDName: "test",
		Snapshot: SnapshotProfile{
			Enabled:    true,
			SaveOnExit: true,
		},
	}
	p.Normalize()
	args, err := BuildEmulatorArgs(p)
	if err != nil {
		t.Fatalf("BuildEmulatorArgs: %v", err)
	}
	joined := strings.Join(args, " ")
	// When SaveOnExit=true, -no-snapshot-save should NOT be present
	if strings.Contains(joined, "-no-snapshot-save") {
		t.Errorf("should not have -no-snapshot-save when SaveOnExit=true: %q", joined)
	}
}

func TestBuildEmulatorArgs_WithDNSServers(t *testing.T) {
	p := Profile{
		Mode:    ModeAndroidSDK,
		AVDName: "test",
		Network: NetworkProfile{
			DNSServers: []string{"8.8.8.8", "8.8.4.4"},
		},
	}
	p.Normalize()
	args, err := BuildEmulatorArgs(p)
	if err != nil {
		t.Fatalf("BuildEmulatorArgs: %v", err)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "-dns-server") {
		t.Errorf("expected -dns-server in args: %q", joined)
	}
	if !strings.Contains(joined, "8.8.8.8") {
		t.Errorf("expected DNS server in args: %q", joined)
	}
}

// ─── BuildMITMAdbCommands — with CA cert and AllowUserCA ─────────────────────

func TestBuildMITMAdbCommands_WithCACert(t *testing.T) {
	p := Profile{
		Mode:    ModeAndroidSDK,
		AVDName: "test",
		MITM: MITMProfile{
			Enabled:       true,
			HTTPProxy:     "127.0.0.1:8080",
			CACertPath:    "/tmp/ca.crt",
			InstallUserCA: true,
		},
	}
	cmds, err := BuildMITMAdbCommands(p)
	if err != nil {
		t.Fatalf("BuildMITMAdbCommands: %v", err)
	}
	if len(cmds) < 3 {
		t.Errorf("expected at least 3 commands (proxy + push + install), got %d: %v", len(cmds), cmds)
	}
	// First command sets proxy
	if !strings.Contains(cmds[0], "http_proxy") {
		t.Errorf("first command should set http_proxy: %q", cmds[0])
	}
	// Should include push command
	found := false
	for _, c := range cmds {
		if strings.Contains(c, "push") && strings.Contains(c, "ca.crt") {
			found = true
		}
	}
	if !found {
		t.Error("expected push command with ca.crt")
	}
}

func TestBuildMITMAdbCommands_AllowUserCAForApps(t *testing.T) {
	p := Profile{
		Mode:    ModeAndroidSDK,
		AVDName: "test",
		MITM: MITMProfile{
			Enabled:            true,
			HTTPProxy:          "127.0.0.1:8080",
			AllowUserCAForApps: true,
			CACertPath:         "/tmp/ca.crt",
		},
	}
	cmds, err := BuildMITMAdbCommands(p)
	if err != nil {
		t.Fatalf("BuildMITMAdbCommands: %v", err)
	}
	hasPortalMode := false
	for _, c := range cmds {
		if strings.Contains(c, "captive_portal_mode") {
			hasPortalMode = true
		}
	}
	if !hasPortalMode {
		t.Errorf("expected captive_portal_mode command when AllowUserCAForApps=true, got: %v", cmds)
	}
}
