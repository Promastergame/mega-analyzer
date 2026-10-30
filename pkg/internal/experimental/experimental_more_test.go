package experimental

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ─── helpers: sanitizeFile / ifEmpty / guessPackageName ──────────────────────

func TestSanitizeFile(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"exported-activity", "exported-activity"},
		{"WebView XSS!", "webview_xss_"},
		{"", "primitive"},
		{"ABC123", "abc123"},
		{"a/b\\c", "a_b_c"},
	}
	for _, tc := range cases {
		if got := sanitizeFile(tc.in); got != tc.want {
			t.Errorf("sanitizeFile(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestIfEmpty(t *testing.T) {
	if got := ifEmpty("", "alt"); got != "alt" {
		t.Errorf("empty string should return alt, got %q", got)
	}
	if got := ifEmpty("   ", "alt"); got != "alt" {
		t.Errorf("whitespace string should return alt, got %q", got)
	}
	if got := ifEmpty("hello", "alt"); got != "hello" {
		t.Errorf("non-empty string should be returned unchanged, got %q", got)
	}
}

func TestGuessPackageName_NoManifest(t *testing.T) {
	dir := testTempDir(t)
	got := guessPackageName(dir)
	if got != "com.example.target" {
		t.Errorf("missing manifest should return default, got %q", got)
	}
}

func TestGuessPackageName_WithManifest(t *testing.T) {
	dir := testTempDir(t)
	manifest := `<manifest package="com.example.myapp"/>`
	if err := os.WriteFile(filepath.Join(dir, "AndroidManifest.xml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	got := guessPackageName(dir)
	if got != "com.example.myapp" {
		t.Errorf("expected com.example.myapp, got %q", got)
	}
}

func TestGuessPackageName_ManifestNoPackage(t *testing.T) {
	dir := testTempDir(t)
	if err := os.WriteFile(filepath.Join(dir, "AndroidManifest.xml"), []byte(`<manifest/>`), 0o644); err != nil {
		t.Fatal(err)
	}
	got := guessPackageName(dir)
	if got != "com.example.target" {
		t.Errorf("manifest with no package attr should return default, got %q", got)
	}
}

// ─── findManifest ─────────────────────────────────────────────────────────────

func TestFindManifest_AllCandidates(t *testing.T) {
	dir := testTempDir(t)
	// No manifest yet.
	if got := findManifest(dir); got != "" {
		t.Errorf("empty dir should return empty, got %q", got)
	}
	// original/AndroidManifest.xml
	origDir := filepath.Join(dir, "original")
	if err := os.MkdirAll(origDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(origDir, "AndroidManifest.xml"), []byte(`<m/>`), 0o644); err != nil {
		t.Fatal(err)
	}
	got := findManifest(dir)
	if got == "" {
		t.Error("should have found manifest in original/")
	}
	// AndroidManifest.txt
	dir2 := testTempDir(t)
	if err := os.WriteFile(filepath.Join(dir2, "AndroidManifest.txt"), []byte(`<m/>`), 0o644); err != nil {
		t.Fatal(err)
	}
	got2 := findManifest(dir2)
	if got2 == "" {
		t.Error("should have found AndroidManifest.txt")
	}
}

// ─── PoC generation helpers ───────────────────────────────────────────────────

func TestGeneratePoC_AllTypes(t *testing.T) {
	p := aegPrimitive{Component: "exported-activity", Class: "com.example.Main", Details: map[string]string{"scheme": "demo", "host": "open", "permission": ""}}
	if got := generatePoC(p, "com.example.app", 1); !strings.Contains(got, "adb shell") {
		t.Errorf("exported-activity PoC missing adb command: %q", got[:min(len(got), 80)])
	}

	p.Component = "exported-receiver"
	if got := generatePoC(p, "com.example.app", 2); !strings.Contains(got, "Receiver") {
		t.Errorf("exported-receiver PoC unexpected: %q", got[:min(len(got), 80)])
	}

	p.Component = "exported-service"
	if got := generatePoC(p, "com.example.app", 3); !strings.Contains(got, "Service") {
		t.Errorf("exported-service PoC unexpected: %q", got[:min(len(got), 80)])
	}

	p.Component = "exported-provider"
	if got := generatePoC(p, "com.example.app", 4); !strings.Contains(got, "content://") {
		t.Errorf("exported-provider PoC unexpected: %q", got[:min(len(got), 80)])
	}

	p.Component = "webview-jsinterface"
	if got := generatePoC(p, "com.example.app", 5); !strings.Contains(got, "bridge") {
		t.Errorf("webview-jsinterface PoC unexpected: %q", got[:min(len(got), 80)])
	}

	p.Component = "native-loadlibrary"
	p.Details["argument"] = "libsecret"
	if got := generatePoC(p, "com.example.app", 6); !strings.Contains(got, "loadLibrary") {
		t.Errorf("native-loadlibrary PoC unexpected: %q", got[:min(len(got), 80)])
	}

	p.Component = "unknown-primitive"
	if got := generatePoC(p, "com.example.app", 7); got != "" {
		t.Errorf("unknown component should return empty, got %q", got)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestGetWebViewFridaScript(t *testing.T) {
	p := aegPrimitive{Class: "Lcom/foo/MyWebView;"}
	got := getWebViewFridaScript(p, "com.foo")
	if !strings.Contains(got, "Java.perform") {
		t.Error("frida script should contain Java.perform")
	}
	if !strings.Contains(got, "com.foo") {
		t.Error("frida script should contain package name")
	}
}

func TestGetActivityFridaScript(t *testing.T) {
	p := aegPrimitive{Class: "Lcom/foo/MainActivity;"}
	got := getActivityFridaScript(p, "com.foo")
	if !strings.Contains(got, "Java.perform") {
		t.Error("activity frida script should contain Java.perform")
	}
}

// ─── AEG smali primitive discovery ───────────────────────────────────────────

func TestAEGModule_SmaliPrimitives(t *testing.T) {
	dir := testTempDir(t)
	smaliDir := filepath.Join(dir, "smali")
	if err := os.MkdirAll(smaliDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Write a smali file with JS interface patterns
	smaliContent := `.class public Lcom/example/MyActivity;
.method public onCreate(Landroid/os/Bundle;)V
    invoke-virtual {p0}, Landroid/webkit/WebView;->setJavaScriptEnabled(Z)V
    invoke-virtual {p0, v0}, Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V
    invoke-virtual {p0, v0}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
`
	if err := os.WriteFile(filepath.Join(smaliDir, "MyActivity.smali"), []byte(smaliContent), 0o644); err != nil {
		t.Fatal(err)
	}

	m := NewAEGModule()
	res, err := m.Run(context.Background(), Input{TargetDir: dir, OutputDir: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Findings) == 0 {
		t.Errorf("expected at least one webview finding; notes=%v", res.Notes)
	}
}

func TestAEGModule_LoadLibrarySmali(t *testing.T) {
	dir := testTempDir(t)
	smaliDir := filepath.Join(dir, "smali")
	if err := os.MkdirAll(smaliDir, 0o755); err != nil {
		t.Fatal(err)
	}

	smaliContent := `.class public Lcom/example/NativeLoader;
.method public loadNative()V
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
.end method
`
	// The AEG loadLibrary regex matches ->loadLibrary( pattern
	smaliWithLoad := `.class public Lcom/example/Loader;
.method public go()V
    const-string v0, "native"
    invoke-static {v0}, ->loadLibrary("native")
.end method
`
	if err := os.WriteFile(filepath.Join(smaliDir, "Loader.smali"), []byte(smaliContent+smaliWithLoad), 0o644); err != nil {
		t.Fatal(err)
	}

	m := NewAEGModule()
	// Run should complete without error even if no loadLibrary regex matches
	_, err := m.Run(context.Background(), Input{TargetDir: dir, OutputDir: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAEGModule_NoTargetDir(t *testing.T) {
	m := NewAEGModule()
	res, err := m.Run(context.Background(), Input{TargetDir: ""})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Skipped {
		t.Error("expected module to be skipped when no target dir")
	}
}

// ─── ModuleResult helpers ─────────────────────────────────────────────────────

func TestModuleResult_AddFindingAndBump(t *testing.T) {
	r := &ModuleResult{}
	r.AddFinding(Finding{ID: "f1", Severity: SevHigh})
	r.AddFinding(Finding{ID: "f2", Severity: SevCritical})
	if len(r.Findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(r.Findings))
	}
	r.Bump("hits", 3)
	r.Bump("hits", 2)
	if r.Stats["hits"] != 5 {
		t.Errorf("expected hits=5, got %d", r.Stats["hits"])
	}
}

// ─── Result aggregation helpers ───────────────────────────────────────────────

func TestResult_TotalFindings_Nil(t *testing.T) {
	var r *Result
	if r.TotalFindings() != 0 {
		t.Error("nil result should return 0")
	}
}

func TestResult_HighestSeverity_Nil(t *testing.T) {
	var r *Result
	if r.HighestSeverity() != SevInfo {
		t.Error("nil result should return SevInfo")
	}
}

func TestResult_HighestSeverity_Order(t *testing.T) {
	r := &Result{
		Modules: []*ModuleResult{
			{Findings: []Finding{{Severity: SevLow}, {Severity: SevCritical}}},
			{Findings: []Finding{{Severity: SevMedium}}},
		},
	}
	if r.HighestSeverity() != SevCritical {
		t.Errorf("expected SevCritical, got %s", r.HighestSeverity())
	}
}

func TestResult_HighestSeverity_AllInfo(t *testing.T) {
	r := &Result{
		Modules: []*ModuleResult{
			{Findings: []Finding{{Severity: SevInfo}}},
		},
	}
	if r.HighestSeverity() != SevInfo {
		t.Errorf("expected SevInfo, got %s", r.HighestSeverity())
	}
}

// ─── Registry ─────────────────────────────────────────────────────────────────

func TestRegistry_AddNilModule(t *testing.T) {
	reg := NewRegistry()
	reg.add(nil) // should not panic
	if len(reg.All()) != 0 {
		t.Error("nil module should not be added")
	}
}

func TestRegistry_LookupNotFound(t *testing.T) {
	reg := DefaultRegistry()
	if _, ok := reg.Lookup("nonexistent"); ok {
		t.Error("nonexistent module should not be found")
	}
}

func TestRegistry_IndexOfNotFound(t *testing.T) {
	dummy := NewAEGModule()
	emptyReg := NewRegistry()
	if idx := emptyReg.IndexOf(dummy); idx != -1 {
		t.Errorf("module not in registry should return -1, got %d", idx)
	}
}

// ─── ParseSelector edge cases ─────────────────────────────────────────────────

func TestParseSelector_NilRegistry(t *testing.T) {
	_, err := ParseSelector("1", nil)
	if err == nil {
		t.Error("nil registry should return error")
	}
}

func TestParseSelector_EmptyRegistry(t *testing.T) {
	reg := NewRegistry() // empty
	_, err := ParseSelector("1", reg)
	if err == nil {
		t.Error("empty registry should return error")
	}
}

func TestParseSelector_Semicolons(t *testing.T) {
	reg := DefaultRegistry()
	mods, err := ParseSelector("macho;binsim", reg)
	if err != nil {
		t.Fatalf("semicolon separator should work: %v", err)
	}
	if len(mods) != 2 {
		t.Errorf("expected 2, got %d", len(mods))
	}
}

func TestParseSelector_Newlines(t *testing.T) {
	reg := DefaultRegistry()
	mods, err := ParseSelector("macho\nbinsim", reg)
	if err != nil {
		t.Fatalf("newline separator should work: %v", err)
	}
	if len(mods) != 2 {
		t.Errorf("expected 2, got %d", len(mods))
	}
}

func TestParseSelector_IndexOutOfRange(t *testing.T) {
	reg := DefaultRegistry()
	if _, err := ParseSelector("0", reg); err == nil {
		t.Error("index 0 should be out of range")
	}
}

func TestParseSelector_AllPresets(t *testing.T) {
	reg := DefaultRegistry()
	for name, ids := range Presets {
		mods, err := ParseSelector(name, reg)
		if err != nil {
			t.Errorf("preset %q error: %v", name, err)
			continue
		}
		if len(mods) == 0 {
			t.Errorf("preset %q returned 0 modules", name)
		}
		_ = ids
	}
}

// ─── Run orchestrator: parallel mode, timeout, callbacks ─────────────────────

func TestRun_ParallelMode(t *testing.T) {
	dir := testTempDir(t)
	reg := DefaultRegistry()
	var started, finished atomic.Int32
	res, err := Run(context.Background(), Input{TargetDir: dir, OutputDir: dir}, Options{
		Selected: reg.All(),
		Parallel: true,
		OnStart:  func(m Module) { started.Add(1) },
		OnFinish: func(m Module, r *ModuleResult, e error) { finished.Add(1) },
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Modules) != 6 {
		t.Errorf("expected 6 module results, got %d", len(res.Modules))
	}
	if starts, finishes := started.Load(), finished.Load(); starts != 6 || finishes != 6 {
		t.Errorf("expected 6 start and finish callbacks, got %d starts and %d finishes", starts, finishes)
	}
}

func TestRun_WithPerModuleTimeout(t *testing.T) {
	dir := testTempDir(t)
	reg := DefaultRegistry()
	res, err := Run(context.Background(), Input{TargetDir: dir, OutputDir: dir}, Options{
		Selected:         reg.All(),
		PerModuleTimeout: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Modules) != 6 {
		t.Errorf("expected 6 module results, got %d", len(res.Modules))
	}
}

func TestRun_Callbacks(t *testing.T) {
	dir := testTempDir(t)
	reg := NewRegistry(NewAEGModule())
	var startIDs, finishIDs []string
	_, err := Run(context.Background(), Input{TargetDir: dir, OutputDir: dir}, Options{
		Selected: reg.All(),
		OnStart:  func(m Module) { startIDs = append(startIDs, m.ID()) },
		OnFinish: func(m Module, r *ModuleResult, e error) { finishIDs = append(finishIDs, m.ID()) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(startIDs) != 1 || startIDs[0] != "aeg" {
		t.Errorf("OnStart not called correctly: %v", startIDs)
	}
	if len(finishIDs) != 1 || finishIDs[0] != "aeg" {
		t.Errorf("OnFinish not called correctly: %v", finishIDs)
	}
}

func TestSafeRun_PanicRecovery(t *testing.T) {
	// A module that panics should be recovered by safeRun.
	panicMod := &panicModule{}
	out, err := safeRun(context.Background(), panicMod, Input{})
	if out != nil {
		t.Error("panicking module should return nil result")
	}
	if err == nil || !strings.Contains(err.Error(), "panicked") {
		t.Errorf("expected panic recovery error, got %v", err)
	}
}

type panicModule struct{}

func (m *panicModule) ID() string          { return "panic-test" }
func (m *panicModule) Name() string        { return "Panic Test" }
func (m *panicModule) Description() string { return "panics" }
func (m *panicModule) Aliases() []string   { return nil }
func (m *panicModule) Tier() string        { return "test" }
func (m *panicModule) Run(ctx context.Context, in Input) (*ModuleResult, error) {
	panic("intentional panic for test")
}

// ─── Module metadata ──────────────────────────────────────────────────────────

func TestModuleMetadata(t *testing.T) {
	mods := DefaultRegistry().All()
	for _, m := range mods {
		if m.ID() == "" {
			t.Errorf("module %T has empty ID", m)
		}
		if m.Name() == "" {
			t.Errorf("module %s has empty Name", m.ID())
		}
		if m.Description() == "" {
			t.Errorf("module %s has empty Description", m.ID())
		}
		if m.Tier() == "" {
			t.Errorf("module %s has empty Tier", m.ID())
		}
	}
}

// ─── looksLikeBinary / looksLikeName ─────────────────────────────────────────

func TestLooksLikeBinary(t *testing.T) {
	if !looksLikeBinary("libfoo.so", "/lib/libfoo.so") {
		t.Error(".so should be binary")
	}
	if !looksLikeBinary("classes.dex", "/smali/classes.dex") {
		t.Error(".dex should be binary")
	}
	if looksLikeBinary("app.jar", "/app.jar") {
		t.Error(".jar should not be binary")
	}
	if !looksLikeBinary("mylib", "/lib/mylib") {
		t.Error("extensionless file under /lib/ should be binary")
	}
	if looksLikeBinary("main", "/bin/main") {
		t.Error("extensionless file outside /lib/ or /Frameworks/ should not be binary")
	}
}

func TestLooksLikeName(t *testing.T) {
	if !looksLikeName("macho") {
		t.Error("alphabetic string should look like a name")
	}
	if looksLikeName("123") {
		t.Error("numeric string should not look like a name")
	}
	if !looksLikeName("1-aeg") {
		t.Error("mixed string with letters should look like a name")
	}
}

// ─── splitSelector ────────────────────────────────────────────────────────────

func TestSplitSelector_Separators(t *testing.T) {
	got := splitSelector("a,b;c d\te\nf")
	if len(got) != 6 {
		t.Errorf("expected 6 parts, got %d: %v", len(got), got)
	}
}

func TestSplitSelector_Empty(t *testing.T) {
	got := splitSelector("   ")
	if len(got) != 0 {
		t.Errorf("expected empty result, got %v", got)
	}
}

// ─── parseRange edge cases ────────────────────────────────────────────────────

func TestParseRange_Valid(t *testing.T) {
	lo, hi, err := parseRange("2-4", 6)
	if err != nil || lo != 2 || hi != 4 {
		t.Errorf("2-4 out of 6 should work, got lo=%d hi=%d err=%v", lo, hi, err)
	}
}

func TestParseRange_Errors(t *testing.T) {
	bad := []struct {
		tok string
		max int
	}{
		{"a-b", 6}, // non-numeric
		{"3-1", 6}, // lo > hi
		{"0-3", 6}, // lo < 1
		{"1-9", 6}, // hi > max
		{"1", 6},   // no dash (SplitN returns 1 part)
	}
	for _, tc := range bad {
		if _, _, err := parseRange(tc.tok, tc.max); err == nil {
			t.Errorf("parseRange(%q, %d) should error", tc.tok, tc.max)
		}
	}
}
