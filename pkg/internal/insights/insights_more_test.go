package insights

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── graph.go ──────────────────────────────────────────────────────────��─────

func TestBuildGraph_Empty(t *testing.T) {
	g := BuildGraph("app.apk", nil, nil)
	if g == nil {
		t.Fatal("expected non-nil GraphReport")
	}
	if g.Target != "app.apk" {
		t.Errorf("Target = %q, want app.apk", g.Target)
	}
	// only the root node should be present
	if g.Summary.Nodes != 1 {
		t.Errorf("nodes = %d, want 1", g.Summary.Nodes)
	}
	if g.Summary.Edges != 0 {
		t.Errorf("edges = %d, want 0", g.Summary.Edges)
	}
}

func TestBuildGraph_WithPrivacy(t *testing.T) {
	pr := &PrivacyReport{
		Target: "app.apk",
		Permissions: []PrivacySignal{
			{Name: "android.permission.CAMERA"},
			{Name: "android.permission.CAMERA"}, // duplicate — dedup via seen map
		},
		Trackers: []PrivacySignal{{Name: "Firebase"}},
		Flows:    []PrivacyFlow{{Source: "LOCATION", Sink: "HTTP", Endpoint: "https://api.example.com"}},
	}
	g := BuildGraph("app.apk", nil, pr)
	// root + perm + tracker + 2 privacy nodes (source/sink) + 1 endpoint = 6
	if g.Summary.Nodes < 4 {
		t.Errorf("expected ≥4 nodes, got %d", g.Summary.Nodes)
	}
}

func TestRenderGraphHTML_Nil(t *testing.T) {
	html := RenderGraphHTML(nil)
	if !strings.Contains(html, "No graph data") {
		t.Errorf("expected 'No graph data' in nil output, got:\n%s", html)
	}
}

func TestRenderGraphHTML_NonNil(t *testing.T) {
	g := BuildGraph("test.apk", nil, nil)
	html := RenderGraphHTML(g)
	if !strings.Contains(html, "Graph Explorer") {
		t.Errorf("expected 'Graph Explorer' in HTML output")
	}
	if !strings.Contains(html, "graph-data") {
		t.Errorf("expected embedded JSON script tag")
	}
}

func TestShortClass(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Lcom/example/MyClass;", "MyClass"},
		{"Lcom/example/pkg/Sub;", "Sub"},
		{"Plain", "Plain"},
		{"", ""},
	}
	for _, c := range cases {
		if got := shortClass(c.in); got != c.want {
			t.Errorf("shortClass(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestTrimPermission(t *testing.T) {
	if got := trimPermission("android.permission.CAMERA"); got != "CAMERA" {
		t.Errorf("got %q", got)
	}
	if got := trimPermission("com.custom.PERM"); got != "com.custom.PERM" {
		t.Errorf("got %q", got)
	}
}

func TestPermissionSeverity(t *testing.T) {
	for _, high := range []string{"android.permission.SMS", "android.permission.CONTACTS", "android.permission.LOCATION", "RECORD_AUDIO"} {
		if s := permissionSeverity(high); s != "high" {
			t.Errorf("permissionSeverity(%q) = %q, want high", high, s)
		}
	}
	if s := permissionSeverity("android.permission.INTERNET"); s != "medium" {
		t.Errorf("got %q, want medium", s)
	}
}

func TestConfidenceSeverity(t *testing.T) {
	if s := confidenceSeverity(0.95); s != "high" {
		t.Errorf("0.95 → %q", s)
	}
	if s := confidenceSeverity(0.7); s != "medium" {
		t.Errorf("0.7 → %q", s)
	}
	if s := confidenceSeverity(0.3); s != "low" {
		t.Errorf("0.3 → %q", s)
	}
}

func TestSeverityFromScore(t *testing.T) {
	if s := severityFromScore(80); s != "high" {
		t.Errorf("80 → %q", s)
	}
	if s := severityFromScore(50); s != "medium" {
		t.Errorf("50 → %q", s)
	}
	if s := severityFromScore(10); s != "low" {
		t.Errorf("10 → %q", s)
	}
}

func TestFirstNonEmpty(t *testing.T) {
	if got := firstNonEmpty("", "  ", "yes"); got != "yes" {
		t.Errorf("got %q", got)
	}
	if got := firstNonEmpty("", ""); got != "" {
		t.Errorf("all-empty should return '', got %q", got)
	}
}

func TestEscapeText(t *testing.T) {
	got := EscapeText("<script>alert('xss')</script>")
	if strings.Contains(got, "<script>") {
		t.Errorf("EscapeText did not escape HTML: %q", got)
	}
}

// ── render.go ────────────────────────────────────────────────────────────────

func TestWriteJSON(t *testing.T) {
	out := filepath.Join(t.TempDir(), "sub", "out.json")
	if err := WriteJSON(out, map[string]int{"score": 42}); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	raw, _ := os.ReadFile(out)
	var m map[string]int
	if err := json.Unmarshal(raw, &m); err != nil || m["score"] != 42 {
		t.Errorf("round-trip failed: %v / %v", err, m)
	}
}

func TestWriteText(t *testing.T) {
	out := filepath.Join(t.TempDir(), "notes", "readme.txt")
	if err := WriteText(out, "hello world"); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	b, _ := os.ReadFile(out)
	if string(b) != "hello world" {
		t.Errorf("got %q", b)
	}
}

func TestRenderJNIMarkdown_Nil(t *testing.T) {
	md := RenderJNIMarkdown(nil)
	if !strings.Contains(md, "No JNI data") {
		t.Errorf("nil report should say 'No JNI data', got:\n%s", md)
	}
}

func TestRenderJNIMarkdown_NonNil(t *testing.T) {
	r := &JNIReport{Target: "app.apk", Score: 55}
	md := RenderJNIMarkdown(r)
	if !strings.Contains(md, "JNI Boundary") {
		t.Errorf("expected header, got:\n%s", md)
	}
	if !strings.Contains(md, "app.apk") {
		t.Errorf("expected target, got:\n%s", md)
	}
}

func TestRenderPrivacyMarkdown(t *testing.T) {
	r := &PrivacyReport{
		Target: "myapp.apk",
		Score:  20,
		Risk:   "medium",
	}
	md := RenderPrivacyMarkdown(r)
	if !strings.Contains(md, "Privacy") {
		t.Errorf("expected Privacy header, got:\n%s", md)
	}
}

func TestRenderDiffMarkdown(t *testing.T) {
	r := &DiffReport{
		OldPath: "v1.apk",
		NewPath: "v2.apk",
	}
	md := RenderDiffMarkdown(r)
	if !strings.Contains(md, "Diff") || (!strings.Contains(md, "v1") && !strings.Contains(md, "v2")) {
		t.Errorf("expected diff header/paths, got:\n%s", md)
	}
}

func TestRenderFirmwareMarkdown(t *testing.T) {
	r := &FirmwareReport{Target: "firmware.bin", Kind: "openwrt", Score: 30}
	md := RenderFirmwareMarkdown(r)
	if !strings.Contains(md, "Firmware") {
		t.Errorf("expected Firmware header, got:\n%s", md)
	}
}

// ── diff.go ──────────────────────────────────────────────────────────────────

func TestDefaultDiffOutputName(t *testing.T) {
	cases := []struct{ old, new_, want string }{
		{"v1.apk", "v2.apk", "v1_vs_v2"},
		{"/path/to/old.apk", "/path/to/new.apk", "old_vs_new"},
		{"", "v2.apk", "._vs_v2"},
		{"v1.apk", "", "v1_vs_."},
	}
	for _, c := range cases {
		if got := defaultDiffOutputName(c.old, c.new_); got != c.want {
			t.Errorf("defaultDiffOutputName(%q,%q) = %q, want %q", c.old, c.new_, got, c.want)
		}
	}
}

// ── firmware.go ───────────────────────────────────────────────────────────────

func TestClassifyFirmwareKind(t *testing.T) {
	cases := []struct{ path, want string }{
		{"firmware.zip", "zip-firmware"},
		{"update.tar", "tar-firmware"},
		{"update.tar.gz", "tar-firmware"},
		{"update.tgz", "tar-firmware"},
		{"disk.img", "disk-image"},
		{"flash.bin", "raw-binary"},
		{"some/directory", "directory-or-blob"},
		{"firmware.ROM", "directory-or-blob"}, // no matching ext
	}
	for _, c := range cases {
		if got := classifyFirmwareKind(c.path); got != c.want {
			t.Errorf("classifyFirmwareKind(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}

func TestRootHintName(t *testing.T) {
	cases := []struct{ path, want string }{
		{"etc/passwd", "linux /etc/passwd"},
		{"/var/busybox", "busybox userland"},
		{"/etc/init.d/networking", "init scripts"},
		{"/sbin/init", "init scripts"},
		{"/www/index.html", "embedded web root"},
		{"/usr/www/admin", "embedded web root"},
		{"/some/other/path", "/some/other/path"}, // fallback
	}
	for _, c := range cases {
		if got := rootHintName(c.path); got != c.want {
			t.Errorf("rootHintName(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}

func TestExtractBusyBoxVersion(t *testing.T) {
	data := "BusyBox v1.32.1 (2021-01-01) multi-call binary"
	got := extractBusyBoxVersion(data)
	if !strings.Contains(strings.ToLower(got), "busybox v1.32.1") {
		t.Errorf("extractBusyBoxVersion = %q, want version 1.32.1", got)
	}

	// No version
	got2 := extractBusyBoxVersion("hello world")
	if got2 != "version unknown" {
		t.Errorf("no version should return 'version unknown', got %q", got2)
	}
}

func TestRedactedFirmwareLine(t *testing.T) {
	// Line with password keyword should be redacted
	data := []byte("password=supersecret\nsomeline")
	result := redactedFirmwareLine(data, 1)
	if result != "redacted sensitive line" {
		t.Errorf("password line should be redacted, got %q", result)
	}

	// Normal line should pass through
	data2 := []byte("telnetd -l /bin/login\nsomething")
	result2 := redactedFirmwareLine(data2, 1)
	if result2 == "redacted sensitive line" {
		t.Error("normal line should not be redacted")
	}
	if result2 == "" {
		t.Error("normal line should not be empty")
	}

	// Empty data / line 0
	if got := redactedFirmwareLine([]byte{}, 0); got != "" {
		t.Errorf("empty data should return '', got %q", got)
	}
}

func TestFirmwareSeverityPoints(t *testing.T) {
	if got := firmwareSeverityPoints("critical"); got != 30 {
		t.Errorf("critical = %d, want 30", got)
	}
	if got := firmwareSeverityPoints("high"); got != 18 {
		t.Errorf("high = %d, want 18", got)
	}
	if got := firmwareSeverityPoints("medium"); got != 9 {
		t.Errorf("medium = %d, want 9", got)
	}
	if got := firmwareSeverityPoints("low"); got != 3 {
		t.Errorf("low = %d, want 3", got)
	}
	if got := firmwareSeverityPoints("unknown"); got != 3 {
		t.Errorf("unknown = %d, want 3 (default)", got)
	}
}

// ── scan.go helpers ───────────────────────────────────────────────────────────

func TestLooksZip(t *testing.T) {
	// by extension
	if !looksZip("firmware.apk", nil) {
		t.Error("*.apk should be zip")
	}
	if !looksZip("lib.jar", nil) {
		t.Error("*.jar should be zip")
	}
	if !looksZip("archive.zip", nil) {
		t.Error("*.zip should be zip")
	}
	// by magic bytes PK
	if !looksZip("noext", []byte{'P', 'K', 0x03, 0x04}) {
		t.Error("PK magic should be zip")
	}
	if looksZip("text.txt", []byte("hello world")) {
		t.Error("text file should not be zip")
	}
}

func TestLooksTar(t *testing.T) {
	if !looksTar("archive.tar") {
		t.Error("*.tar should be tar")
	}
	if looksTar("archive.tar.gz") {
		t.Error("*.tar.gz should not match looksTar")
	}
	if looksTar("file.zip") {
		t.Error("*.zip should not be tar")
	}
}

func TestLooksTarGZ(t *testing.T) {
	if !looksTarGZ("firmware.tar.gz") {
		t.Error("*.tar.gz should be tgz")
	}
	if !looksTarGZ("firmware.tgz") {
		t.Error("*.tgz should be tgz")
	}
	if looksTarGZ("archive.tar") {
		t.Error("*.tar should not be tgz")
	}
	if looksTarGZ("file.zip") {
		t.Error("*.zip should not be tgz")
	}
}

func TestIsLikelyText(t *testing.T) {
	// empty → text
	if !isLikelyText([]byte{}) {
		t.Error("empty should be text")
	}
	// printable ASCII → text
	if !isLikelyText([]byte("package main\n\nfunc main() {}")) {
		t.Error("Go code should be text")
	}
	// null byte → binary
	if isLikelyText([]byte{0x00, 0x01, 0x02, 0x03}) {
		t.Error("null byte should be binary")
	}
	// all binary bytes
	bin := make([]byte, 100)
	for i := range bin {
		bin[i] = 0x01 // control, non-text
	}
	if isLikelyText(bin) {
		t.Error("all 0x01 should be binary")
	}
}

func TestLineNumber(t *testing.T) {
	data := []byte("line1\nline2\nline3")
	if got := lineNumber(data, 0); got != 1 {
		t.Errorf("offset 0 → line 1, got %d", got)
	}
	if got := lineNumber(data, 6); got != 2 {
		t.Errorf("offset 6 → line 2, got %d", got)
	}
	if got := lineNumber(data, -1); got != 0 {
		t.Errorf("negative offset → 0, got %d", got)
	}
	// offset beyond data
	if got := lineNumber(data, 1000); got != 3 {
		t.Errorf("offset beyond data → last line, got %d", got)
	}
}

func TestLineAt(t *testing.T) {
	data := []byte("first\nsecond\nthird")
	if got := lineAt(data, 1); got != "first" {
		t.Errorf("line 1 = %q, want 'first'", got)
	}
	if got := lineAt(data, 2); got != "second" {
		t.Errorf("line 2 = %q, want 'second'", got)
	}
	if got := lineAt(data, 0); got != "" {
		t.Errorf("line 0 (invalid) = %q, want ''", got)
	}
	if got := lineAt(data, 100); got != "" {
		t.Errorf("line 100 (beyond) = %q, want ''", got)
	}
}

func TestLimitStrings(t *testing.T) {
	in := []string{"a", "b", "c", "d", "e"}
	// limit less than len
	got := limitStrings(in, 3)
	if len(got) != 3 {
		t.Errorf("limitStrings(5, 3) = %d items, want 3", len(got))
	}
	// limit >= len
	got2 := limitStrings(in, 10)
	if len(got2) != 5 {
		t.Errorf("limitStrings(5, 10) = %d items, want 5", len(got2))
	}
	// limit 0 → no limit
	got3 := limitStrings(in, 0)
	if len(got3) != 5 {
		t.Errorf("limitStrings(5, 0) = %d items, want 5", len(got3))
	}
}

func TestLoadFilesDir(t *testing.T) {
	dir := t.TempDir()
	// Write some text files
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.txt"), []byte("world"), 0644); err != nil {
		t.Fatal(err)
	}
	// Write a binary file (should be skipped by default)
	if err := os.WriteFile(filepath.Join(dir, "c.bin"), []byte{0x00, 0x01, 0x02}, 0644); err != nil {
		t.Fatal(err)
	}

	files, err := LoadFiles(dir, LoadOptions{})
	if err != nil {
		t.Fatalf("LoadFiles: %v", err)
	}
	// Should have a.txt and b.txt but not c.bin (binary)
	if len(files) < 2 {
		t.Errorf("expected >=2 text files, got %d", len(files))
	}
	for _, f := range files {
		if strings.HasSuffix(f.Path, "c.bin") {
			t.Error("binary file c.bin should have been skipped")
		}
	}
}

func TestLoadFilesSingleFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(path, []byte("test content"), 0644); err != nil {
		t.Fatal(err)
	}
	files, err := LoadFiles(path, LoadOptions{})
	if err != nil {
		t.Fatalf("LoadFiles: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(files))
	}
	if string(files[0].Data) != "test content" {
		t.Errorf("data = %q, want 'test content'", files[0].Data)
	}
}

func TestLoadFilesCapsSingleBinaryFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "large.bin")
	if err := os.WriteFile(path, bytes.Repeat([]byte{0x7f}, 4096), 0644); err != nil {
		t.Fatal(err)
	}
	files, err := LoadFiles(path, LoadOptions{MaxBytesPerFile: 128, MaxTotalBytes: 128, IncludeBinary: true})
	if err != nil {
		t.Fatalf("LoadFiles: %v", err)
	}
	if len(files) != 1 || len(files[0].Data) != 128 {
		t.Fatalf("expected a 128-byte capped result, got %+v", files)
	}
}

func TestLoadFilesNotExist(t *testing.T) {
	_, err := LoadFiles("/nonexistent/path/that/does/not/exist", LoadOptions{})
	if err == nil {
		t.Error("expected error for non-existent path")
	}
}

// ── render.go — uncovered helpers ─────────────────────────────────────────────

func TestWriteFindings(t *testing.T) {
	var b strings.Builder
	findings := []Finding{
		{Severity: "high", Title: "Secret found", Detail: "API key", Path: "secrets.smali", Line: 42},
		{Severity: "low", Title: "Minor issue", Detail: "nothing", Path: "", Line: 0},
	}
	writeFindings(&b, findings)
	out := b.String()
	if !strings.Contains(out, "Secret found") {
		t.Errorf("expected 'Secret found', got:\n%s", out)
	}
	if !strings.Contains(out, "secrets.smali:42") {
		t.Errorf("expected location 'secrets.smali:42', got:\n%s", out)
	}
	if !strings.Contains(out, "Minor issue") {
		t.Errorf("expected 'Minor issue', got:\n%s", out)
	}
}

func TestWriteList(t *testing.T) {
	var b strings.Builder
	writeList(&b, "Permissions", []string{"READ_SMS", "CAMERA"})
	out := b.String()
	if !strings.Contains(out, "Permissions") {
		t.Error("expected section title")
	}
	if !strings.Contains(out, "READ_SMS") {
		t.Error("expected READ_SMS")
	}
	// Empty items - should write nothing
	var b2 strings.Builder
	writeList(&b2, "Empty", nil)
	if b2.Len() > 0 {
		t.Errorf("empty items should write nothing, got %q", b2.String())
	}
}

func TestWriteDiffSection(t *testing.T) {
	var b strings.Builder
	changes := DiffChanges{
		Permissions: []string{"android.permission.SMS"},
		Endpoints:   []string{"http://api.example.com"},
	}
	writeDiffSection(&b, "Added", changes)
	out := b.String()
	if !strings.Contains(out, "Added") {
		t.Error("expected section title 'Added'")
	}
	if !strings.Contains(out, "android.permission.SMS") {
		t.Error("expected permission in output")
	}

	// Empty DiffChanges should produce nothing
	var b2 strings.Builder
	writeDiffSection(&b2, "Removed", DiffChanges{})
	if b2.Len() > 0 {
		t.Errorf("empty DiffChanges should write nothing, got %q", b2.String())
	}
}

func TestWriteFirmwareItems(t *testing.T) {
	var b strings.Builder
	items := []FirmwareItem{
		{Severity: "high", Name: "telnet daemon", Path: "/bin/telnetd", Detail: "dangerous"},
	}
	writeFirmwareItems(&b, "Services", items)
	out := b.String()
	if !strings.Contains(out, "Services") {
		t.Error("expected section title")
	}
	if !strings.Contains(out, "telnet daemon") {
		t.Error("expected 'telnet daemon'")
	}

	// Empty items
	var b2 strings.Builder
	writeFirmwareItems(&b2, "Empty", nil)
	if b2.Len() > 0 {
		t.Errorf("empty items should write nothing, got %q", b2.String())
	}
}

func TestLimitNativeMethods(t *testing.T) {
	methods := make([]NativeMethod, 10)
	for i := range methods {
		methods[i] = NativeMethod{Method: "m" + string(rune('0'+i))}
	}
	// Under limit
	if got := limitNativeMethods(methods, 20); len(got) != 10 {
		t.Errorf("limitNativeMethods under limit = %d, want 10", len(got))
	}
	// Over limit
	if got := limitNativeMethods(methods, 5); len(got) != 5 {
		t.Errorf("limitNativeMethods over limit = %d, want 5", len(got))
	}
}

func TestLimitFlows(t *testing.T) {
	flows := make([]PrivacyFlow, 10)
	if got := limitFlows(flows, 3); len(got) != 3 {
		t.Errorf("limitFlows = %d, want 3", len(got))
	}
	if got := limitFlows(flows, 100); len(got) != 10 {
		t.Errorf("limitFlows (no limit) = %d, want 10", len(got))
	}
}

func TestLimitSignals(t *testing.T) {
	sigs := make([]PrivacySignal, 10)
	if got := limitSignals(sigs, 4); len(got) != 4 {
		t.Errorf("limitSignals = %d, want 4", len(got))
	}
	if got := limitSignals(sigs, 100); len(got) != 10 {
		t.Errorf("limitSignals (no limit) = %d, want 10", len(got))
	}
}

func TestLimitFirmwareItems(t *testing.T) {
	items := make([]FirmwareItem, 10)
	if got := limitFirmwareItems(items, 3); len(got) != 3 {
		t.Errorf("limitFirmwareItems = %d, want 3", len(got))
	}
	if got := limitFirmwareItems(items, 100); len(got) != 10 {
		t.Errorf("limitFirmwareItems (no limit) = %d, want 10", len(got))
	}
}

// ── privacy.go helpers ────────────────────────────────────────────────────────

func TestSortPrivacy(t *testing.T) {
	report := &PrivacyReport{
		Permissions: []PrivacySignal{
			{Name: "B_PERM"},
			{Name: "A_PERM"},
		},
		Sources: []PrivacySignal{
			{Path: "b.smali", Line: 2},
			{Path: "a.smali", Line: 1},
		},
	}
	sortPrivacy(report)
	if report.Permissions[0].Name != "A_PERM" {
		t.Errorf("permissions not sorted: first = %q", report.Permissions[0].Name)
	}
	if report.Sources[0].Path != "a.smali" {
		t.Errorf("sources not sorted: first = %q", report.Sources[0].Path)
	}
}

func TestSignalLess(t *testing.T) {
	a := PrivacySignal{Path: "a.smali", Line: 1, Name: "X"}
	b := PrivacySignal{Path: "b.smali", Line: 1, Name: "X"}
	c := PrivacySignal{Path: "a.smali", Line: 2, Name: "X"}
	d := PrivacySignal{Path: "a.smali", Line: 1, Name: "Y"}

	if !signalLess(a, b) {
		t.Error("a < b by path")
	}
	if signalLess(b, a) {
		t.Error("b should not be < a")
	}
	if !signalLess(a, c) {
		t.Error("a < c by line")
	}
	if !signalLess(a, d) {
		t.Error("a < d by name")
	}
}

func TestScorePrivacy(t *testing.T) {
	// No bad signals → high score
	report := &PrivacyReport{}
	score, risk := scorePrivacy(report)
	if score != 100 {
		t.Errorf("empty report should score 100, got %d", score)
	}
	if risk != "low" {
		t.Errorf("empty report risk = %q, want 'low'", risk)
	}

	// Many flows → low score
	report2 := &PrivacyReport{
		Flows:    make([]PrivacyFlow, 10),  // -120
		Trackers: make([]PrivacySignal, 5), // -20
	}
	score2, risk2 := scorePrivacy(report2)
	if score2 != 0 {
		t.Errorf("heavy report score = %d, want 0", score2)
	}
	if risk2 != "high" {
		t.Errorf("heavy report risk = %q, want 'high'", risk2)
	}
}

func TestIsSensitivePermission(t *testing.T) {
	sensitive := []string{
		"android.permission.READ_SMS",
		"android.permission.READ_CONTACTS",
		"android.permission.ACCESS_FINE_LOCATION",
		"android.permission.CAMERA",
		"android.permission.RECORD_AUDIO",
		"android.permission.READ_PHONE_STATE",
		"android.permission.QUERY_ALL_PACKAGES",
		"android.permission.BLUETOOTH_SCAN",
	}
	for _, p := range sensitive {
		if !isSensitivePermission(p) {
			t.Errorf("isSensitivePermission(%q) = false, want true", p)
		}
	}
	if isSensitivePermission("android.permission.INTERNET") {
		t.Error("INTERNET should not be sensitive")
	}
	if isSensitivePermission("android.permission.VIBRATE") {
		t.Error("VIBRATE should not be sensitive")
	}
}

func TestBuildPrivacyFindings(t *testing.T) {
	report := &PrivacyReport{
		Flows:       []PrivacyFlow{{Source: "LOCATION", Sink: "HTTP", Endpoint: "http://x.com"}},
		Trackers:    []PrivacySignal{{Name: "Firebase"}, {Name: "AppsFlyer"}, {Name: "Adjust"}},
		Permissions: []PrivacySignal{{Name: "android.permission.CAMERA"}},
	}
	findings := buildPrivacyFindings(report)
	if len(findings) == 0 {
		t.Fatal("expected some findings")
	}
	// Check for flow finding
	var hasFlow bool
	for _, f := range findings {
		if strings.Contains(f.Title, "flow") {
			hasFlow = true
		}
	}
	if !hasFlow {
		t.Error("expected a flow-related finding")
	}
}

func TestReadManifestFromDir(t *testing.T) {
	dir := t.TempDir()
	// Write a mock manifest
	content := `<?xml version="1.0"?>
<manifest>
  <uses-permission android:name="android.permission.CAMERA"/>
</manifest>`
	if err := os.WriteFile(filepath.Join(dir, "AndroidManifest.xml"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	data := readManifestFromDir(dir)
	if len(data) == 0 {
		t.Error("expected manifest data, got empty")
	}
	if !strings.Contains(string(data), "CAMERA") {
		t.Errorf("expected CAMERA permission, got: %s", data)
	}
}

func TestReadManifestFromDir_NotFound(t *testing.T) {
	dir := t.TempDir()
	data := readManifestFromDir(dir)
	if data != nil {
		t.Errorf("missing manifest should return nil, got %d bytes", len(data))
	}
}

// ── loadZip / loadTar ─────────────────────────────────────────────────────────

func TestLoadFilesZip(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "test.zip")

	// Create a zip with two text files and one binary
	buf := &bytes.Buffer{}
	zw := zip.NewWriter(buf)
	addZipEntry := func(name, content string) {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	addZipEntry("hello.txt", "hello world")
	addZipEntry("code.smali", ".class public Lfoo/Bar;")
	// Binary entry
	fw, _ := zw.Create("binary.bin")
	fw.Write([]byte{0x00, 0x01, 0x02}) //nolint
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(zipPath, buf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}

	files, err := LoadFiles(zipPath, LoadOptions{})
	if err != nil {
		t.Fatalf("LoadFiles zip: %v", err)
	}
	// Binary should be excluded; text files should be included
	if len(files) < 2 {
		t.Errorf("expected >=2 text files from zip, got %d", len(files))
	}
	for _, f := range files {
		if f.Path == "binary.bin" {
			t.Error("binary.bin should have been filtered out")
		}
	}
	// Verify content
	found := false
	for _, f := range files {
		if f.Path == "hello.txt" {
			found = true
			if string(f.Data) != "hello world" {
				t.Errorf("hello.txt data = %q, want 'hello world'", f.Data)
			}
		}
	}
	if !found {
		t.Error("expected hello.txt in zip files")
	}
}

func TestLoadFilesZipCapsFileCountAndTotalBytes(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "budget.zip")
	buf := &bytes.Buffer{}
	zw := zip.NewWriter(buf)
	for _, name := range []string{"one.bin", "two.bin"} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(bytes.Repeat([]byte{0x42}, 64)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(zipPath, buf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
	files, err := LoadFiles(zipPath, LoadOptions{MaxBytesPerFile: 64, MaxTotalBytes: 64, MaxFiles: 1, IncludeBinary: true})
	if err != nil {
		t.Fatalf("LoadFiles: %v", err)
	}
	if len(files) != 1 || len(files[0].Data) != 64 {
		t.Fatalf("expected one 64-byte entry under budget, got %+v", files)
	}
}

func TestLoadFilesTar(t *testing.T) {
	dir := t.TempDir()
	tarPath := filepath.Join(dir, "test.tar")

	// Create a tar with one text file
	buf := &bytes.Buffer{}
	tw := tar.NewWriter(buf)
	content := []byte("tar text content")
	hdr := &tar.Header{Name: "data.txt", Size: int64(len(content)), Mode: 0644}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}
	// Add an empty/dir entry (should be skipped)
	dirHdr := &tar.Header{Name: "subdir/", Typeflag: tar.TypeDir}
	if err := tw.WriteHeader(dirHdr); err != nil {
		t.Fatal(err)
	}
	tw.Close()
	if err := os.WriteFile(tarPath, buf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}

	files, err := LoadFiles(tarPath, LoadOptions{})
	if err != nil {
		t.Fatalf("LoadFiles tar: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("expected 1 file from tar, got %d", len(files))
	}
	if files[0].Path != "data.txt" {
		t.Errorf("expected 'data.txt', got %q", files[0].Path)
	}
	if string(files[0].Data) != "tar text content" {
		t.Errorf("data = %q", files[0].Data)
	}
}

func TestLoadFilesTarGZ(t *testing.T) {
	dir := t.TempDir()
	tarGZPath := filepath.Join(dir, "test.tar.gz")

	// Create a .tar.gz
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	content := []byte("gzipped tar content")
	hdr := &tar.Header{Name: "notes.txt", Size: int64(len(content)), Mode: 0644}
	tw.WriteHeader(hdr) //nolint
	tw.Write(content)   //nolint
	tw.Close()

	// gzip the tar
	gzBuf := &bytes.Buffer{}
	gz := gzip.NewWriter(gzBuf)
	gz.Write(tarBuf.Bytes()) //nolint
	gz.Close()

	if err := os.WriteFile(tarGZPath, gzBuf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}

	files, err := LoadFiles(tarGZPath, LoadOptions{})
	if err != nil {
		t.Fatalf("LoadFiles tar.gz: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("expected 1 file from tar.gz, got %d", len(files))
	}
	if !strings.Contains(string(files[0].Data), "gzipped tar content") {
		t.Errorf("data = %q", files[0].Data)
	}
}
