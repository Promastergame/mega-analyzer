package artifacts

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// Classify — extension branches
// ═══════════════════════════════════════════════════════════════════════════════

func TestClassify_IgnoredExtensions(t *testing.T) {
	ignored := []string{
		"a.smali", "b.class", "c.dex", "d.odex", "e.arsc",
		"f.rsa", "g.sf", "h.mf", "i.pro", "j.version",
		"k.kotlin_metadata", "l.kotlin_module", "m.kotlin_builtins",
	}
	for _, name := range ignored {
		if got := Classify(name, nil); got != TypeIgnored {
			t.Errorf("Classify(%q) = %q, want TypeIgnored", name, got)
		}
	}
}

func TestClassify_Images(t *testing.T) {
	exts := []string{
		".png", ".jpg", ".jpeg", ".jfif", ".gif", ".webp",
		".bmp", ".tiff", ".tif", ".ico", ".heic", ".heif", ".avif", ".svg",
	}
	for _, ext := range exts {
		if got := Classify("file"+ext, nil); got != TypeImage {
			t.Errorf("Classify(%q) = %q, want TypeImage", "file"+ext, got)
		}
	}
}

func TestClassify_Model3D(t *testing.T) {
	exts := []string{".obj", ".gltf", ".glb", ".fbx", ".dae", ".stl", ".ply", ".3ds"}
	for _, ext := range exts {
		if got := Classify("file"+ext, nil); got != TypeModel3D {
			t.Errorf("Classify(%q) = %q, want TypeModel3D", "file"+ext, got)
		}
	}
}

func TestClassify_Native(t *testing.T) {
	exts := []string{".so", ".a", ".dll", ".dylib"}
	for _, ext := range exts {
		if got := Classify("file"+ext, nil); got != TypeNative {
			t.Errorf("Classify(%q) = %q, want TypeNative", "file"+ext, got)
		}
	}
}

func TestClassify_Font(t *testing.T) {
	exts := []string{".ttf", ".otf", ".woff", ".woff2", ".eot"}
	for _, ext := range exts {
		if got := Classify("file"+ext, nil); got != TypeFont {
			t.Errorf("Classify(%q) = %q, want TypeFont", "file"+ext, got)
		}
	}
}

func TestClassify_Audio(t *testing.T) {
	exts := []string{".mp3", ".wav", ".ogg", ".m4a", ".flac"}
	for _, ext := range exts {
		if got := Classify("file"+ext, nil); got != TypeAudio {
			t.Errorf("Classify(%q) = %q, want TypeAudio", "file"+ext, got)
		}
	}
}

func TestClassify_Video(t *testing.T) {
	exts := []string{".mp4", ".mov", ".webm", ".mkv", ".avi"}
	for _, ext := range exts {
		if got := Classify("file"+ext, nil); got != TypeVideo {
			t.Errorf("Classify(%q) = %q, want TypeVideo", "file"+ext, got)
		}
	}
}

func TestClassify_Archive(t *testing.T) {
	exts := []string{".zip", ".apk", ".jar", ".tar", ".gz", ".bz2", ".7z", ".rar"}
	for _, ext := range exts {
		if got := Classify("file"+ext, nil); got != TypeArchive {
			t.Errorf("Classify(%q) = %q, want TypeArchive", "file"+ext, got)
		}
	}
}

func TestClassify_Code(t *testing.T) {
	exts := []string{
		".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx",
		".html", ".htm", ".xhtml", ".css", ".proto",
		".json", ".json5", ".wasm", ".lua", ".py",
		".sh", ".bash", ".sql", ".yaml", ".yml",
		".toml", ".ini", ".cfg", ".conf", ".txt", ".md",
		".bundle", ".go", ".rs", ".c", ".h",
		".cpp", ".hpp", ".cc", ".cxx", ".hh",
		".cs", ".rb", ".php", ".swift", ".dart",
		".java", ".kt", ".kts", ".groovy", ".gradle",
		".scala", ".r", ".pl", ".pm",
		".properties", ".prof", ".plist", ".xml",
		".cmake", ".mk", ".bat", ".cmd", ".ps1",
		".env", ".csv", ".tsv", ".log",
	}
	for _, ext := range exts {
		if got := Classify("file"+ext, nil); got != TypeCode {
			t.Errorf("Classify(%q) = %q, want TypeCode", "file"+ext, got)
		}
	}
}

func TestClassify_MagicBytes_PNG(t *testing.T) {
	magic := []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}
	got := Classify("unknownext", magic)
	if got != TypeImage {
		t.Errorf("PNG magic should classify as TypeImage, got %q", got)
	}
}

func TestClassify_MagicBytes_JPEG(t *testing.T) {
	magic := []byte{0xFF, 0xD8, 0x00, 0x00}
	got := Classify("blob", magic)
	if got != TypeImage {
		t.Errorf("JPEG magic should classify as TypeImage, got %q", got)
	}
}

func TestClassify_MagicBytes_ELF(t *testing.T) {
	magic := []byte{0x7F, 'E', 'L', 'F', 0x00}
	got := Classify("noext", magic)
	if got != TypeNative {
		t.Errorf("ELF magic should classify as TypeNative, got %q", got)
	}
}

func TestClassify_MagicBytes_WASM(t *testing.T) {
	magic := []byte{0x00, 'a', 's', 'm', 0x01}
	got := Classify("noext", magic)
	if got != TypeCode {
		t.Errorf("WASM magic should classify as TypeCode, got %q", got)
	}
}

func TestClassify_MagicBytes_RIFF(t *testing.T) {
	magic := []byte{'R', 'I', 'F', 'F', 0x00}
	got := Classify("noext", magic)
	if got != TypeImage {
		t.Errorf("RIFF magic should classify as TypeImage, got %q", got)
	}
}

func TestClassify_Other(t *testing.T) {
	got := Classify("file.unknown_ext", nil)
	if got != TypeOther {
		t.Errorf("unknown extension with no data = %q, want TypeOther", got)
	}
}

func TestClassify_CaseInsensitive(t *testing.T) {
	if got := Classify("FILE.PNG", nil); got != TypeImage {
		t.Errorf("uppercase extension should still classify, got %q", got)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// DetectLanguage — extension and magic/shebang branches
// ═══════════════════════════════════════════════════════════════════════════════

func TestDetectLanguage_Extensions(t *testing.T) {
	cases := []struct {
		path string
		want CodeLanguage
	}{
		{"a.js", LangJS},
		{"a.mjs", LangJS},
		{"a.cjs", LangJS},
		{"a.jsx", LangJS},
		{"a.bundle", LangBundle},
		{"a.ts", LangTS},
		{"a.tsx", LangTS},
		{"a.html", LangHTML},
		{"a.htm", LangHTML},
		{"a.xhtml", LangHTML},
		{"a.css", LangCSS},
		{"a.proto", LangProto},
		{"a.json", LangJSON},
		{"a.json5", LangJSON},
		{"a.wasm", LangWASM},
		{"a.lua", LangLua},
		{"a.py", LangPython},
		{"a.sh", LangShell},
		{"a.bash", LangShell},
		{"a.bat", LangShell},
		{"a.cmd", LangShell},
		{"a.ps1", LangShell},
		{"a.sql", LangSQL},
		{"a.yaml", LangYAML},
		{"a.yml", LangYAML},
		{"a.toml", LangTOML},
		{"a.ini", LangINI},
		{"a.cfg", LangINI},
		{"a.conf", LangINI},
		{"a.env", LangINI},
		{"a.go", LangGo},
		{"a.rs", LangRust},
		{"a.c", LangC},
		{"a.h", LangC},
		{"a.cpp", LangCPP},
		{"a.hpp", LangCPP},
		{"a.cc", LangCPP},
		{"a.cxx", LangCPP},
		{"a.hh", LangCPP},
		{"a.java", LangJava},
		{"a.kt", LangKotlin},
		{"a.kts", LangKotlin},
		{"a.swift", LangSwift},
		{"a.dart", LangDart},
		{"a.rb", LangRuby},
		{"a.php", LangPHP},
		{"a.cs", LangCSharp},
		{"a.properties", LangProperties},
		{"a.xml", LangXML},
		{"a.plist", LangXML},
		{"a.prof", LangProf},
		{"a.log", LangProf},
		{"a.groovy", LangJava},
		{"a.gradle", LangJava},
		{"a.scala", LangJava},
		{"a.r", LangPython},
		{"a.pl", LangShell},
		{"a.pm", LangShell},
		{"a.cmake", LangShell},
		{"a.mk", LangShell},
	}

	for _, c := range cases {
		got := DetectLanguage(c.path, nil)
		if got != c.want {
			t.Errorf("DetectLanguage(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}

func TestDetectLanguage_MakefileCase(t *testing.T) {
	// ".makefile" is listed as shell-like
	got := DetectLanguage("Makefile.makefile", nil)
	if got != LangShell {
		t.Errorf("DetectLanguage(.makefile) = %q, want %q", got, LangShell)
	}
}

func TestDetectLanguage_MagicWASM(t *testing.T) {
	data := []byte{0x00, 'a', 's', 'm', 0x01, 0x00}
	got := DetectLanguage("noext", data)
	if got != LangWASM {
		t.Errorf("WASM magic → %q, want LangWASM", got)
	}
}

func TestDetectLanguage_ShebangPython(t *testing.T) {
	data := []byte("#!/usr/bin/python3\n# python script\n")
	got := DetectLanguage("script", data)
	if got != LangPython {
		t.Errorf("python shebang → %q, want LangPython", got)
	}
}

func TestDetectLanguage_ShebangNode(t *testing.T) {
	data := []byte("#!/usr/bin/env node\nconsole.log('hi')\n")
	got := DetectLanguage("script", data)
	if got != LangJS {
		t.Errorf("node shebang → %q, want LangJS", got)
	}
}

func TestDetectLanguage_ShebangLua(t *testing.T) {
	data := []byte("#!/usr/bin/env lua\nprint('hi')\n")
	got := DetectLanguage("script", data)
	if got != LangLua {
		t.Errorf("lua shebang → %q, want LangLua", got)
	}
}

func TestDetectLanguage_ShebangRuby(t *testing.T) {
	data := []byte("#!/usr/bin/env ruby\nputs 'hi'\n")
	got := DetectLanguage("script", data)
	if got != LangRuby {
		t.Errorf("ruby shebang → %q, want LangRuby", got)
	}
}

func TestDetectLanguage_ShebangPerl(t *testing.T) {
	data := []byte("#!/usr/bin/perl\nprint 'hi';\n")
	got := DetectLanguage("script", data)
	if got != LangShell {
		t.Errorf("perl shebang → %q, want LangShell", got)
	}
}

func TestDetectLanguage_ShebangBash(t *testing.T) {
	data := []byte("#!/bin/bash\necho hi\n")
	got := DetectLanguage("script", data)
	if got != LangShell {
		t.Errorf("bash shebang → %q, want LangShell", got)
	}
}

func TestDetectLanguage_ShebangSh(t *testing.T) {
	data := []byte("#!/bin/sh\necho hi\n")
	got := DetectLanguage("script", data)
	if got != LangShell {
		t.Errorf("/sh shebang → %q, want LangShell", got)
	}
}

func TestDetectLanguage_UnknownFallback(t *testing.T) {
	got := DetectLanguage("unknownfile", []byte("random bytes"))
	if got != LangText {
		t.Errorf("unknown → %q, want LangText", got)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// buildItem — per-type enrichment paths
// ═══════════════════════════════════════════════════════════════════════════════

// minimalZIP creates a valid ZIP archive containing one entry.
func minimalZIP(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, err := w.Create("entry.txt")
	if err != nil {
		t.Fatalf("zip create: %v", err)
	}
	_, _ = f.Write([]byte("content"))
	if err := w.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

// writeFile creates a file with given data in a temp dir and returns abs path.
func writeFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestBuildItem_Code_JS(t *testing.T) {
	dir := t.TempDir()
	abs := writeFile(t, dir, "script.js", []byte("console.log('hello');\n"))
	c := Candidate{
		Path:    "script.js",
		AbsPath: abs,
		Size:    22,
		Type:    TypeCode,
	}
	budget := NewBudget(10, 200)
	item := buildItem(0, c, budget, "", Options{})
	if item == nil {
		t.Fatal("expected item")
	}
	if item.Code == nil {
		t.Error("expected Code enrichment for JS file")
	}
	if item.ID != "art_0001" {
		t.Errorf("ID = %q, want art_0001", item.ID)
	}
}

func TestBuildItem_Archive_ZIP(t *testing.T) {
	dir := t.TempDir()
	zipData := minimalZIP(t)
	abs := writeFile(t, dir, "bundle.zip", zipData)
	c := Candidate{
		Path:    "bundle.zip",
		AbsPath: abs,
		Size:    int64(len(zipData)),
		Type:    TypeArchive,
	}
	budget := NewBudget(10, 200)
	item := buildItem(1, c, budget, "", Options{})
	if item == nil {
		t.Fatal("expected item")
	}
	if item.Archive == nil {
		t.Error("expected Archive enrichment")
	}
	if len(item.Archive.Files) == 0 {
		t.Error("expected at least one file in archive")
	}
}

func TestBuildItem_Archive_CorruptZIP(t *testing.T) {
	dir := t.TempDir()
	abs := writeFile(t, dir, "bad.zip", []byte("not a zip file"))
	c := Candidate{
		Path:    "bad.zip",
		AbsPath: abs,
		Size:    14,
		Type:    TypeArchive,
	}
	budget := NewBudget(10, 200)
	item := buildItem(0, c, budget, "", Options{})
	if item == nil {
		t.Fatal("expected item even for corrupt zip")
	}
	if len(item.Warnings) == 0 {
		t.Error("expected warning for corrupt zip")
	}
}

func TestBuildItem_Native_Minimal(t *testing.T) {
	dir := t.TempDir()
	// Minimal ELF-like data (just enough to not crash)
	elfData := []byte{0x7F, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00}
	elfData = append(elfData, make([]byte, 56)...) // pad to look like ELF header
	abs := writeFile(t, dir, "libfoo.so", elfData)
	c := Candidate{
		Path:    "lib/arm64-v8a/libfoo.so",
		AbsPath: abs,
		Size:    int64(len(elfData)),
		Type:    TypeNative,
	}
	budget := NewBudget(10, 200)
	item := buildItem(0, c, budget, "", Options{})
	if item == nil {
		t.Fatal("expected item for native file")
	}
	if item.Native == nil {
		t.Error("expected Native enrichment for .so file")
	}
}

func TestBuildItem_Native_WithNilLookup(t *testing.T) {
	dir := t.TempDir()
	data := []byte{0x7F, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00}
	abs := writeFile(t, dir, "libsec.so", data)
	c := Candidate{
		Path:    "libsec.so",
		AbsPath: abs,
		Size:    int64(len(data)),
		Type:    TypeNative,
	}
	budget := NewBudget(10, 200)
	// NativeScanLookup=nil: fillNative should handle gracefully
	item := buildItem(0, c, budget, "", Options{NativeScanLookup: nil})
	if item == nil {
		t.Fatal("expected item")
	}
	if item.Native == nil {
		t.Error("expected Native enrichment even with nil lookup")
	}
}

func TestBuildItem_Native_WithCorrectLookup(t *testing.T) {
	dir := t.TempDir()
	data := []byte{0x7F, 'E', 'L', 'F'}
	abs := writeFile(t, dir, "libtest.so", data)
	c := Candidate{
		Path:    "libtest.so",
		AbsPath: abs,
		Size:    int64(len(data)),
		Type:    TypeNative,
	}
	budget := NewBudget(10, 200)

	opts := Options{
		NativeScanLookup: nil, // nil lookup — fillNative should handle gracefully
		SmaliClasses:     []string{"Lcom/app/Jni;"},
		CrackPointsByPath: map[string][]string{
			abs: {"isPremium() → always returns true"},
		},
	}
	item := buildItem(0, c, budget, "", opts)
	if item == nil {
		t.Fatal("expected item")
	}
	if item.Native == nil {
		t.Error("expected Native enrichment")
	}
}

func TestBuildItem_ReadError(t *testing.T) {
	c := Candidate{
		Path:    "missing.js",
		AbsPath: "/nonexistent/path/missing.js",
		Size:    100,
		Type:    TypeCode,
	}
	budget := NewBudget(10, 200)
	item := buildItem(0, c, budget, "", Options{})
	if item == nil {
		t.Fatal("expected item even on read failure")
	}
	if len(item.Warnings) == 0 {
		t.Error("expected warning for unreadable file")
	}
}

func TestBuildItem_EmbedVsExternal(t *testing.T) {
	dir := t.TempDir()
	outDir := t.TempDir()

	// File that fits in budget
	jsData := []byte("var x = 1;")
	abs := writeFile(t, dir, "script.js", jsData)
	c := Candidate{
		Path:    "script.js",
		AbsPath: abs,
		Size:    int64(len(jsData)),
		Type:    TypeCode,
	}

	// Small budget — embed
	budget := NewBudget(10, 200)
	item := buildItem(0, c, budget, outDir, Options{})
	if item.EmbeddedDataURI == "" {
		t.Error("small file should be embedded as data URI")
	}
}

func TestBuildItem_ExternalPath(t *testing.T) {
	dir := t.TempDir()
	outDir := t.TempDir()

	// Large file that exceeds per-file budget
	largeData := make([]byte, 2*1024*1024+1) // 2 MB + 1 byte
	abs := writeFile(t, dir, "big.js", largeData)
	c := Candidate{
		Path:    "big.js",
		AbsPath: abs,
		Size:    int64(len(largeData)),
		Type:    TypeCode,
	}

	// Budget that rejects this file size
	budget := NewBudget(1, 200) // 1 MB per-file cap
	externalRoot := filepath.Join(outDir, "artifacts")
	item := buildItem(0, c, budget, externalRoot, Options{})
	if item == nil {
		t.Fatal("expected item")
	}
	// Should have external path, not embedded
	if item.EmbeddedDataURI != "" {
		t.Error("large file should not be embedded")
	}
	if item.ExternalPath == "" {
		t.Error("large file should have external path")
	}
}

func TestBuildItem_Default_Type(t *testing.T) {
	dir := t.TempDir()
	abs := writeFile(t, dir, "font.ttf", []byte("fake font data"))
	c := Candidate{
		Path:    "font.ttf",
		AbsPath: abs,
		Size:    14,
		Type:    TypeFont, // uses the default branch in switch
	}
	budget := NewBudget(10, 200)
	item := buildItem(0, c, budget, "", Options{})
	if item == nil {
		t.Fatal("expected item")
	}
	if item.Forensic.Verdict == "" {
		t.Error("expected forensic verdict for default type")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// fillCode — various language types
// ═══════════════════════════════════════════════════════════════════════════════

func TestFillCode_JSON(t *testing.T) {
	dir := t.TempDir()
	data := []byte(`{"key": "value", "num": 42}`)
	abs := writeFile(t, dir, "config.json", data)
	c := Candidate{Path: "config.json", AbsPath: abs, Size: int64(len(data)), Type: TypeCode}
	budget := NewBudget(10, 200)
	item := buildItem(0, c, budget, "", Options{})
	if item.Code == nil {
		t.Error("expected Code enrichment for JSON")
	}
}

func TestFillCode_HTML(t *testing.T) {
	dir := t.TempDir()
	data := []byte("<html><body><script>alert(1)</script></body></html>")
	abs := writeFile(t, dir, "page.html", data)
	c := Candidate{Path: "page.html", AbsPath: abs, Size: int64(len(data)), Type: TypeCode}
	budget := NewBudget(10, 200)
	item := buildItem(0, c, budget, "", Options{})
	if item.Code == nil {
		t.Error("expected Code enrichment for HTML")
	}
}

func TestFillCode_Proto(t *testing.T) {
	dir := t.TempDir()
	data := []byte("syntax = \"proto3\";\npackage example;\nmessage Foo { string bar = 1; }\n")
	abs := writeFile(t, dir, "schema.proto", data)
	c := Candidate{Path: "schema.proto", AbsPath: abs, Size: int64(len(data)), Type: TypeCode}
	budget := NewBudget(10, 200)
	item := buildItem(0, c, budget, "", Options{})
	if item.Code == nil {
		t.Error("expected Code enrichment for proto")
	}
}

func TestFillCode_Shell(t *testing.T) {
	dir := t.TempDir()
	data := []byte("#!/bin/sh\necho hello\n")
	abs := writeFile(t, dir, "run.sh", data)
	c := Candidate{Path: "run.sh", AbsPath: abs, Size: int64(len(data)), Type: TypeCode}
	budget := NewBudget(10, 200)
	item := buildItem(0, c, budget, "", Options{})
	if item.Code == nil {
		t.Error("expected Code enrichment for shell script")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// fillArchive — ZIP contents
// ═══════════════════════════════════════════════════════════════════════════════

func TestFillArchive_MultipleEntries(t *testing.T) {
	dir := t.TempDir()

	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, name := range []string{"a.txt", "b/c.json", "d.bin"} {
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.Write([]byte("data"))
	}
	_ = w.Close()

	abs := writeFile(t, dir, "multi.zip", buf.Bytes())
	c := Candidate{Path: "multi.zip", AbsPath: abs, Size: int64(buf.Len()), Type: TypeArchive}
	budget := NewBudget(10, 200)
	item := buildItem(0, c, budget, "", Options{})
	if item.Archive == nil {
		t.Fatal("expected Archive enrichment")
	}
	if len(item.Archive.Files) != 3 {
		t.Errorf("expected 3 archive entries, got %d", len(item.Archive.Files))
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// fillNative — with lookup
// ═══════════════════════════════════════════════════════════════════════════════

func TestFillNative_WithScanLookup(t *testing.T) {
	dir := t.TempDir()
	data := []byte{0x7F, 'E', 'L', 'F', 0x02}
	abs := writeFile(t, dir, "libnative.so", data)
	c := Candidate{
		Path:    "lib/x86_64/libnative.so",
		AbsPath: abs,
		Size:    int64(len(data)),
		Type:    TypeNative,
	}
	budget := NewBudget(10, 200)
	opts := Options{
		SmaliClasses:      []string{"Lcom/app/NativeLib;"},
		CrackPointsByPath: map[string][]string{abs: {"check()"}},
	}
	item := buildItem(0, c, budget, "", opts)
	if item.Native == nil {
		t.Error("expected Native enrichment")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Full Build pipeline — additional artifact types
// ═══════════════════════════════════════════════════════════════════════════════

func TestBuildPipeline_AllTypes(t *testing.T) {
	dir := t.TempDir()
	outDir := t.TempDir()

	// JS file (TypeCode)
	writeFile(t, dir, "assets/app.js", []byte("console.log('hi');"))

	// ZIP file (TypeArchive)
	writeFile(t, dir, "assets/data.zip", minimalZIP(t))

	// Native .so file
	elfData := []byte{0x7F, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00}
	writeFile(t, dir, "lib/arm64/libnative.so", append(elfData, make([]byte, 56)...))

	// Font (TypeFont — goes through default branch)
	writeFile(t, dir, "assets/font.ttf", []byte("fake font"))

	view, err := Build(Options{
		ExtractedDir: dir,
		OutputDir:    outDir,
		MaxFileMB:    10,
		BudgetMB:     200,
	})
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	if view == nil {
		t.Fatal("expected non-nil view")
	}
	if view.Summary.Total == 0 {
		t.Error("expected at least one artifact")
	}

	// Check we have code type
	if view.Summary.ByType["code"] == 0 {
		t.Error("expected code artifact")
	}
	// archive
	if view.Summary.ByType["archive"] == 0 {
		t.Error("expected archive artifact")
	}
	// native
	if view.Summary.ByType["native"] == 0 {
		t.Error("expected native artifact")
	}
}

func TestBuildPipeline_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	// Only smali files (ignored)
	writeFile(t, dir, "smali/com/app/Main.smali", []byte(".class Lcom/app/Main;"))

	view, err := Build(Options{
		ExtractedDir: dir,
		OutputDir:    t.TempDir(),
		MaxFileMB:    10,
		BudgetMB:     200,
	})
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	if view != nil {
		t.Errorf("expected nil view when only ignored files, got view with %d items", view.Summary.Total)
	}
}
