package apkloader

import (
	"archive/zip"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mega-analyzer/pkg/internal/jarloader"
)

// ═══════════════════════════════════════════
// ТЕСТЫ DETECTOR
// ═══════════════════════════════════════════

func TestDetectInputType_Directory(t *testing.T) {
	// Создаём temp директорию со smali файлом
	tmpDir, err := os.MkdirTemp("", "test_detect_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Без smali — unknown
	typ, err := DetectInputType(tmpDir)
	if err == nil {
		t.Error("expected error for empty dir")
	}

	// Создаём smali файл
	smaliDir := filepath.Join(tmpDir, "smali")
	os.MkdirAll(smaliDir, 0755)
	os.WriteFile(filepath.Join(smaliDir, "Test.smali"), []byte(".class"), 0644)

	typ, err = DetectInputType(tmpDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if typ != InputTypeSmaliFolder {
		t.Errorf("type = %d, want InputTypeSmaliFolder", typ)
	}
}

func TestDetectInputType_DEXFile(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test_*.dex")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	// Пишем DEX magic
	tmpFile.Write([]byte("dex\n035\x00"))
	tmpFile.Close()

	typ, err := DetectInputType(tmpFile.Name())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if typ != InputTypeDEXFile {
		t.Errorf("type = %d, want InputTypeDEXFile", typ)
	}
}

func TestDetectInputType_APKFile(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test_*.apk")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	// Пишем ZIP magic
	tmpFile.Write([]byte("PK\x03\x04"))
	tmpFile.Close()

	typ, err := DetectInputType(tmpFile.Name())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if typ != InputTypeAPKFile {
		t.Errorf("type = %d, want InputTypeAPKFile", typ)
	}
}

func TestDetectInputType_ArchiveFile(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test_*.obb")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write([]byte("PK\x03\x04")); err != nil {
		t.Fatal(err)
	}
	if err := tmpFile.Close(); err != nil {
		t.Fatal(err)
	}

	typ, err := DetectInputType(tmpFile.Name())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if typ != InputTypeArchiveFile {
		t.Errorf("type = %d, want InputTypeArchiveFile", typ)
	}
}

// ═══════════════════════════════════════════
// ТЕСТЫ ZIP EXTRACTION
// ═══════════════════════════════════════════

func TestExtractZipSafe_PathTraversal(t *testing.T) {
	// sibling dir: the traversal target lives next to the extract dir,
	// so "../evil.txt" would land there. We control it and know it starts empty.
	siblingDir, err := os.MkdirTemp("", "sibling_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(siblingDir)

	tmpDir, err := os.MkdirTemp("", "extract_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	tmpZip, err := os.CreateTemp("", "test_*.zip")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpZip.Name())

	w := zip.NewWriter(tmpZip)
	// Attempt to write "../<sibling>/evil.txt" — one level up then into sibling.
	f, _ := w.Create("../evil.txt")
	f.Write([]byte("malicious"))
	f2, _ := w.Create("normal.txt")
	f2.Write([]byte("safe"))
	w.Close()
	tmpZip.Close()

	e := NewExtractor()
	err = e.extractZipSafe(context.Background(), tmpZip.Name(), tmpDir)
	if err != nil {
		t.Fatalf("extractZipSafe failed: %v", err)
	}

	// evil.txt must NOT have been written outside tmpDir.
	evilPath := filepath.Join(tmpDir, "..", "evil.txt")
	if _, err := os.Stat(evilPath); err == nil {
		t.Error("path traversal attack succeeded!")
	}

	if _, err := os.Stat(filepath.Join(tmpDir, "normal.txt")); err != nil {
		t.Error("normal file not extracted")
	}
}

func TestExtractZipSafe_TooManyFiles(t *testing.T) {
	tmpZip, _ := os.CreateTemp("", "test_*.zip")
	defer os.Remove(tmpZip.Name())

	w := zip.NewWriter(tmpZip)
	// Создаём больше файлов чем лимит (но не 100000, это долго)
	// Патчим константу для теста — пропускаем этот тест
	// или делаем через мелкий лимит
	for i := 0; i < 100; i++ {
		f, _ := w.Create(fmt.Sprintf("dir/file%d.txt", i))
		f.Write([]byte("x"))
	}
	w.Close()
	tmpZip.Close()

	// Этот тест просто проверяет что ZIP с многими файлами обрабатывается
	tmpDir, _ := os.MkdirTemp("", "extract_*")
	defer os.RemoveAll(tmpDir)

	e := NewExtractor()
	err := e.extractZipSafe(context.Background(), tmpZip.Name(), tmpDir)
	if err != nil {
		t.Fatalf("extractZipSafe failed: %v", err)
	}
}

func TestExtractZipSafe_ContextCancel(t *testing.T) {
	tmpZip, _ := os.CreateTemp("", "test_*.zip")
	defer os.Remove(tmpZip.Name())

	w := zip.NewWriter(tmpZip)
	for i := 0; i < 10; i++ {
		f, _ := w.Create("file" + string(rune('0'+i)) + ".txt")
		f.Write([]byte("data"))
	}
	w.Close()
	tmpZip.Close()

	tmpDir, _ := os.MkdirTemp("", "extract_*")
	defer os.RemoveAll(tmpDir)

	// Отменённый контекст
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	e := NewExtractor()
	err := e.extractZipSafe(ctx, tmpZip.Name(), tmpDir)
	if err == nil {
		t.Error("expected context canceled error")
	}
}

// ═══════════════════════════════════════════
// ТЕСТЫ SMALI GENERATION
// ═══════════════════════════════════════════

func TestGenerateSmaliClass(t *testing.T) {
	class := &ClassDef{
		ClassName:   "Lcom/test/MyClass;",
		SuperClass:  "Ljava/lang/Object;",
		SourceFile:  "MyClass.java",
		AccessFlags: 0x0001, // public
		Interfaces:  []string{"Ljava/io/Serializable;"},
		StaticFields: []*EncodedField{
			{Name: "TAG", TypeName: "Ljava/lang/String;", AccessFlags: 0x0019},
		},
		InstanceFields: []*EncodedField{
			{Name: "value", TypeName: "I", AccessFlags: 0x0002},
		},
		DirectMethods: []*EncodedMethod{
			{
				Name:        "<init>",
				ReturnType:  "V",
				AccessFlags: 0x10001, // public constructor
				Code:        nil,     // abstract
			},
		},
	}

	parser := &DEXParser{} // пустой, для теста
	smali := generateSmaliClass(class, parser)

	checks := []string{
		".class public Lcom/test/MyClass;",
		".super Ljava/lang/Object;",
		".source \"MyClass.java\"",
		".implements Ljava/io/Serializable;",
		".field public static final TAG:Ljava/lang/String;",
		".field private value:I",
		".method public constructor <init>()V",
	}

	for _, check := range checks {
		if !strings.Contains(smali, check) {
			t.Errorf("missing: %q\n\nsmali:\n%s", check, smali)
		}
	}
}

func TestAccessFlagsToSmali(t *testing.T) {
	tests := []struct {
		flags    uint32
		expected string
	}{
		{0x0000, ""},
		{0x0001, "public "},
		{0x0002, "private "},
		{0x0009, "public static "},
		{0x0019, "public static final "},
		{0x10001, "public constructor "},
	}

	for _, tt := range tests {
		result := accessFlagsToSmali(tt.flags)
		if result != tt.expected {
			t.Errorf("flags=0x%x: got %q, want %q",
				tt.flags, result, tt.expected)
		}
	}
}

// ═══════════════════════════════════════════
// ТЕСТЫ EXTRACTOR WARNINGS
// ═══════════════════════════════════════════

func TestExtractor_Warnings(t *testing.T) {
	e := NewExtractor()

	if len(e.GetWarnings()) != 0 {
		t.Error("new extractor should have no warnings")
	}

	e.warn("test warning %d", 123)

	warnings := e.GetWarnings()
	if len(warnings) != 1 {
		t.Errorf("expected 1 warning, got %d", len(warnings))
	}
	if warnings[0] != "test warning 123" {
		t.Errorf("wrong warning: %q", warnings[0])
	}
}

// ═══════════════════════════════════════════
// ТЕСТЫ CLEANUP
// ═══════════════════════════════════════════

func TestExtractor_Cleanup(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "cleanup_test_*")
	os.WriteFile(filepath.Join(tmpDir, "test.txt"), []byte("data"), 0644)

	e := NewExtractor()
	err := e.Cleanup(tmpDir)
	if err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}

	if _, err := os.Stat(tmpDir); !os.IsNotExist(err) {
		t.Error("directory should be removed")
	}

	// Cleanup empty path — should be ok
	err = e.Cleanup("")
	if err != nil {
		t.Error("Cleanup empty path should not error")
	}
}

// ═══════════════════════════════════════════
// ИНТЕГРАЦИОННЫЙ ТЕСТ
// ═══════════════════════════════════════════

func TestExtractor_PrepareInput_SmaliFolder(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "smali_test_*")
	defer os.RemoveAll(tmpDir)

	smaliDir := filepath.Join(tmpDir, "smali")
	os.MkdirAll(smaliDir, 0755)
	os.WriteFile(filepath.Join(smaliDir, "Test.smali"), []byte(".class"), 0644)

	e := NewExtractor()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := e.PrepareInput(ctx, tmpDir)
	if err != nil {
		t.Fatalf("PrepareInput failed: %v", err)
	}

	// Для smali папки должен вернуться тот же путь
	if result != tmpDir {
		t.Errorf("result = %q, want %q", result, tmpDir)
	}
}

func TestExtractor_PrepareInput_GenericArchive(t *testing.T) {
	tmpArchive, err := os.CreateTemp("", "cache_*.obb")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpArchive.Name())

	zw := zip.NewWriter(tmpArchive)

	infoPlist, err := zw.Create("Payload/MyGame.app/Info.plist")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := infoPlist.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"></plist>`)); err != nil {
		t.Fatal(err)
	}

	configJSON, err := zw.Create("cache/config.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := configJSON.Write([]byte(`{"endpoint":"https://example.test/api","token":"abc123"}`)); err != nil {
		t.Fatal(err)
	}

	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := tmpArchive.Close(); err != nil {
		t.Fatal(err)
	}

	e := NewExtractor()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := e.PrepareInput(ctx, tmpArchive.Name())
	if err != nil {
		t.Fatalf("PrepareInput failed: %v", err)
	}
	defer os.RemoveAll(result)

	if result == "" {
		t.Fatal("expected extracted directory")
	}
	if _, err := os.Stat(filepath.Join(result, "Payload", "MyGame.app", "Info.plist")); err != nil {
		t.Fatalf("expected Info.plist to be extracted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(result, "cache", "config.json")); err != nil {
		t.Fatalf("expected config.json to be extracted: %v", err)
	}
}

func TestIsLikelyMachineCode(t *testing.T) {
	cases := map[string]bool{
		"lib.so":      true,
		"lib.bin":     true,
		"payload.exe": true,
		"some.elf":    true,
		"cool.dll":    true,
		"plain.txt":   false,
		"noextension": false,
	}
	for path, want := range cases {
		if got := isLikelyMachineCode(path); got != want {
			t.Errorf("isLikelyMachineCode(%q) = %v, want %v", path, got, want)
		}
	}
}

// ═══════════════════════════════════════════
// БЕНЧМАРКИ
// ═══════════════════════════════════════════

func BenchmarkGenerateSmaliClass(b *testing.B) {
	class := &ClassDef{
		ClassName:  "Lcom/test/Benchmark;",
		SuperClass: "Ljava/lang/Object;",
		DirectMethods: []*EncodedMethod{
			{Name: "test", ReturnType: "V", Code: &CodeItem{
				RegistersSize: 2,
				Insns:         []uint16{0x000E},
			}},
		},
	}
	parser := &DEXParser{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		generateSmaliClass(class, parser)
	}
}

func BenchmarkAccessFlagsToSmali(b *testing.B) {
	flags := uint32(0x0019) // public static final

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		accessFlagsToSmali(flags)
	}
}

func TestExtractAPK_SingleXAPK(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Create a dummy inner APK with classes.dex
	innerAPKPath := filepath.Join(tmpDir, "inner.apk")
	fInner, err := os.Create(innerAPKPath)
	if err != nil {
		t.Fatal(err)
	}
	wInner := zip.NewWriter(fInner)
	dexHeader := []byte("dex\n035\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x70\x00\x00\x00\x78\x56\x34\x12")
	wDex, err := wInner.Create("classes.dex")
	if err != nil {
		t.Fatal(err)
	}
	wDex.Write(dexHeader)
	// Minimal text manifest so writeDecodeMeta can produce omnisec-meta.json
	// even when smali decoding is skipped.
	wMf, err := wInner.Create("AndroidManifest.xml")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = wMf.Write([]byte(`<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app"><uses-permission android:name="android.permission.INTERNET"/></manifest>`))
	wInner.Close()
	fInner.Close()

	// 2. Wrap inner.apk into xapk archive
	xapkPath := filepath.Join(tmpDir, "app.xapk")
	fXapk, err := os.Create(xapkPath)
	if err != nil {
		t.Fatal(err)
	}
	wXapk := zip.NewWriter(fXapk)
	innerData, err := os.ReadFile(innerAPKPath)
	if err != nil {
		t.Fatal(err)
	}
	wInnerInXapk, err := wXapk.Create("com.example.app.apk")
	if err != nil {
		t.Fatal(err)
	}
	wInnerInXapk.Write(innerData)
	wXapk.Close()
	fXapk.Close()

	// 3. Run DecodeAPK on the XAPK
	// The dummy classes.dex is only a 40-byte header (not a valid DEX); skip
	// smali decoding here so the test exercises XAPK merging, not DEX
	// validation. Corrupt DEX must still fail when code is requested (see
	// TestDecompilerAuditCorruptDEXMustNotSucceed).
	outDir := filepath.Join(tmpDir, "decoded_out")
	extractor := NewExtractor()
	resDir, err := extractor.DecodeAPK(context.Background(), xapkPath, DecodeOptions{OutputDir: outDir, NoSmali: true})
	if err != nil {
		t.Fatalf("DecodeAPK failed: %v", err)
	}

	// Verify inner.apk was unpacked and classes.dex / smali / omnisec-meta exist
	if _, err := os.Stat(filepath.Join(resDir, "omnisec-meta.json")); err != nil {
		t.Errorf("expected omnisec-meta.json in decoded output dir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(resDir, "com.example.app.apk")); err == nil {
		t.Errorf("inner APK file should have been removed after extraction")
	}
}

func TestDescribeJavaMod_Full(t *testing.T) {
	got := describeJavaMod(jarloader.JavaMod{
		Loader:      "Fabric",
		ID:          "appleskin",
		Name:        "AppleSkin",
		Version:     "3.0.10",
		GameVersion: "1.21",
		Authors:     []string{"squeek502"},
		Dependencies: []jarloader.JavaModDep{
			{ID: "fabricloader", Version: ">=0.16", Required: true},
			{ID: "fabric-api", Required: false},
		},
	})
	for _, want := range []string{"appleskin", "AppleSkin", "3.0.10", "Fabric", "1.21", "squeek502", "2 declared deps"} {
		if !strings.Contains(got, want) {
			t.Errorf("describeJavaMod = %q, want substring %q", got, want)
		}
	}
}

func TestDescribeJavaMod_Minimal(t *testing.T) {
	got := describeJavaMod(jarloader.JavaMod{ID: "mymod"})
	if !strings.Contains(got, "mymod") {
		t.Errorf("describeJavaMod = %q, want id", got)
	}
	if strings.Contains(got, "v ") || strings.Contains(got, " by ") {
		t.Errorf("describeJavaMod = %q, want no empty version/author slots", got)
	}
}
