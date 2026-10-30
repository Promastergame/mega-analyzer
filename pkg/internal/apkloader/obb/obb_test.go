package obb

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultAnalyzerConfig(t *testing.T) {
	cfg := DefaultAnalyzerConfig()
	if !cfg.Enabled {
		t.Error("Expected Enabled to be true")
	}
	if cfg.OutputDir != "analysis_output" {
		t.Errorf("Expected OutputDir to be 'analysis_output', got %s", cfg.OutputDir)
	}
}

func TestIsOBBLike(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"foo.obb", true},
		{"foo.zip", true},
		{"foo.data", true},
		{"foo.cache", true},
		{"foo.pck", true},
		{"foo.pak", true},
		{"foo.unity3d", true},
		{"foo.assetbundle", true},
		{"foo.ab", true},
		{"main.com.game.obb", true},
		{"com.main.12345.game", true},  // contains .main.
		{"com.patch.12345.game", true}, // contains .patch.
		{"foo.txt", false},
	}

	for _, tc := range tests {
		res := isOBBLike(tc.path)
		if res != tc.expected {
			t.Errorf("isOBBLike(%q) = %v; want %v", tc.path, res, tc.expected)
		}
	}
}

func TestScanNonExistent(t *testing.T) {
	_, err := Scan("non_existent_file_12345.obb")
	if err == nil {
		t.Error("Expected error for non-existent file, got nil")
	}
}

func TestScanRawFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. UnityFS raw file
	unityPath := filepath.Join(tmpDir, "raw_unity.obb")
	unityData := append([]byte("UnityFS"), make([]byte, 10)...)
	if err := os.WriteFile(unityPath, unityData, 0644); err != nil {
		t.Fatal(err)
	}
	r, err := Scan(unityPath)
	if err != nil {
		t.Fatal(err)
	}
	if r.Engine != "unity" || r.Format != "unity-assetbundle" {
		t.Errorf("Expected unity engine and format, got %s / %s", r.Engine, r.Format)
	}

	// 2. Godot PCK raw file (GDPC magic)
	godotPath := filepath.Join(tmpDir, "raw_godot.obb")
	godotData := []byte{0x47, 0x44, 0x50, 0x43, 0, 0, 0, 0} // "GDPC"
	if err := os.WriteFile(godotPath, godotData, 0644); err != nil {
		t.Fatal(err)
	}
	r, err = Scan(godotPath)
	if err != nil {
		t.Fatal(err)
	}
	if r.Engine != "godot" || r.Format != "godot-pck" {
		t.Errorf("Expected godot engine and format, got %s / %s", r.Engine, r.Format)
	}

	// 3. Godot PCK raw file (CPDG magic)
	godotPath2 := filepath.Join(tmpDir, "raw_godot2.obb")
	godotData2 := []byte{0x43, 0x50, 0x44, 0x47, 0, 0, 0, 0} // "CPDG"
	if err := os.WriteFile(godotPath2, godotData2, 0644); err != nil {
		t.Fatal(err)
	}
	r, err = Scan(godotPath2)
	if err != nil {
		t.Fatal(err)
	}
	if r.Engine != "godot" || r.Format != "godot-pck" {
		t.Errorf("Expected godot engine and format, got %s / %s", r.Engine, r.Format)
	}

	// 4. Unrecognized raw file
	unrecognizedPath := filepath.Join(tmpDir, "raw_unrecognized.obb")
	if err := os.WriteFile(unrecognizedPath, []byte("garbage header data"), 0644); err != nil {
		t.Fatal(err)
	}
	r, err = Scan(unrecognizedPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Warnings) == 0 || r.Warnings[0] != "unrecognized raw data format" {
		t.Errorf("Expected unrecognized warning, got %v", r.Warnings)
	}
}

func TestScanZipArchive(t *testing.T) {
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "test.obb")

	// Create a mock ZIP
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)

	// Add UnityFS bundle file
	w, _ := zw.Create("assets/unityfs.unity3d")
	unityFSHeader := []byte("UnityFS\x00\x00\x00\x00Unity2021.3.15f1\x00")
	w.Write(unityFSHeader)

	// Add Legacy Unity bundle file
	w, _ = zw.Create("assets/legacy.bundle")
	legacyHeader := []byte("Unity\x00\x00\x00\x00")
	w.Write(legacyHeader)

	// Add gzip compressed unity bundle
	w, _ = zw.Create("assets/gzip.assets")
	w.Write([]byte{0x1F, 0x8B, 0, 0, 0, 0})

	// Add lzma compressed unity bundle
	w, _ = zw.Create("assets/lzma.ab")
	lzmaHeader := make([]byte, 8)
	binary.LittleEndian.PutUint32(lzmaHeader[:4], 0x5D000080)
	w.Write(lzmaHeader)

	// Add Godot PCK in zip
	w, _ = zw.Create("game.pck")
	w.Write([]byte("godot assets"))

	// Add various resources to classify
	resourcesToCreate := map[string]string{
		"res/image.png":     "png data",
		"res/audio.ogg":     "ogg data",
		"res/model.fbx":     "fbx data",
		"res/shader.shader": "shader data",
		"res/script.lua":    "lua data",
		"res/large.unknown": string(make([]byte, 1<<20+1)), // > 1MB unknown
	}
	for name, content := range resourcesToCreate {
		w, _ = zw.Create(name)
		w.Write([]byte(content))
	}

	// Add hidden payload (DEX file)
	w, _ = zw.Create("assets/hidden_dex.dex")
	w.Write([]byte("dex header bytes"))

	// Add hidden payload (SO file in bad place)
	w, _ = zw.Create("assets/hidden_lib.so")
	w.Write([]byte("elf header bytes"))

	// Add hidden ELF payload (.dat file)
	w, _ = zw.Create("assets/elf.dat")
	elfBytes := make([]byte, 4100)
	binary.BigEndian.PutUint32(elfBytes[:4], 0x7F454C46) // ELF
	w.Write(elfBytes)

	// Add hidden PE payload (.bin file)
	w, _ = zw.Create("assets/pe.bin")
	peBytes := make([]byte, 4100)
	peBytes[0] = 'M'
	peBytes[1] = 'Z' // PE
	w.Write(peBytes)

	// Add text file to extract strings & URLs & trackings
	w, _ = zw.Create("config.ini")
	w.Write([]byte("https://suspicious-c2.org/api\ngoogleads\nrandom_chars\n"))

	// Create valid Unreal PAK file
	// Let's pack Unreal Pak bytes
	// A pak file consists of some entries, a TOC, and FPakInfo at EOF.
	// FPakInfo structure (v3 example):
	// - pakMagic: uint32 (0x5A6F12E1)
	// - Version: uint32 (3)
	// - IndexOffset: uint64
	// - IndexSize: uint64
	// - IndexHash: 20 bytes
	// - Encrypted: uint8 (0 or 1)

	// Prepare TOC data
	tocBuf := new(bytes.Buffer)
	// Mount point FString: length (int32) + string bytes
	mountPoint := "../../"
	binary.Write(tocBuf, binary.LittleEndian, int32(len(mountPoint)))
	tocBuf.WriteString(mountPoint)

	// Count of entries (uint32)
	binary.Write(tocBuf, binary.LittleEndian, uint32(2))

	// Entry 1: "content.uasset"
	binary.Write(tocBuf, binary.LittleEndian, int32(len("content.uasset")))
	tocBuf.WriteString("content.uasset")
	binary.Write(tocBuf, binary.LittleEndian, uint64(100)) // Offset
	binary.Write(tocBuf, binary.LittleEndian, uint64(200)) // Size
	binary.Write(tocBuf, binary.LittleEndian, uint64(200)) // UncompressedSize
	binary.Write(tocBuf, binary.LittleEndian, uint32(1))   // CompressionMethod
	tocBuf.Write(make([]byte, 20))                         // Hash
	binary.Write(tocBuf, binary.LittleEndian, uint32(1))   // BlockCount
	tocBuf.Write(make([]byte, 16))                         // Block offset+size

	// Entry 2: "music.wav"
	binary.Write(tocBuf, binary.LittleEndian, int32(len("music.wav")))
	tocBuf.WriteString("music.wav")
	binary.Write(tocBuf, binary.LittleEndian, uint64(300)) // Offset
	binary.Write(tocBuf, binary.LittleEndian, uint64(400)) // Size
	binary.Write(tocBuf, binary.LittleEndian, uint64(400)) // UncompressedSize
	binary.Write(tocBuf, binary.LittleEndian, uint32(0))   // CompressionMethod (no compression method blocks)
	tocBuf.Write(make([]byte, 20))                         // Hash

	tocBytes := tocBuf.Bytes()

	// Now build the full pak file contents
	pakBuf := new(bytes.Buffer)
	pakBuf.Write(make([]byte, 1000)) // padding for offsets

	indexOffset := uint64(pakBuf.Len())
	pakBuf.Write(tocBytes)
	indexSize := uint64(pakBuf.Len()) - indexOffset

	// Write FPakInfo at EOF
	binary.Write(pakBuf, binary.LittleEndian, uint32(pakMagic))
	binary.Write(pakBuf, binary.LittleEndian, uint32(3)) // Version
	binary.Write(pakBuf, binary.LittleEndian, indexOffset)
	binary.Write(pakBuf, binary.LittleEndian, indexSize)
	pakBuf.Write(make([]byte, 20))                      // Hash
	binary.Write(pakBuf, binary.LittleEndian, uint8(1)) // Encrypted = true

	// Add pak file to zip
	w, _ = zw.Create("game.pak")
	w.Write(pakBuf.Bytes())

	zw.Close()
	f.Close()

	// Execute Scan
	r, err := Scan(zipPath)
	if err != nil {
		t.Fatal(err)
	}

	if r.Engine != "unity" {
		t.Errorf("Expected engine to be 'unity' (detected first), got %s", r.Engine)
	}

	// Verify asset bundles
	if len(r.AssetBundles) < 5 {
		t.Errorf("Expected at least 5 asset bundles, got %d", len(r.AssetBundles))
	}

	// Verify resources
	foundPng := false
	foundOgg := false
	foundFbx := false
	foundShader := false
	foundLua := false
	foundUnknown := false
	foundUasset := false

	for _, res := range r.Resources {
		switch res.Path {
		case "res/image.png":
			foundPng = true
			if res.Type != "texture" || res.FormatHint != "png" {
				t.Errorf("png classified incorrectly: %+v", res)
			}
		case "res/audio.ogg":
			foundOgg = true
			if res.Type != "audio" || res.FormatHint != "ogg" {
				t.Errorf("ogg classified incorrectly: %+v", res)
			}
		case "res/model.fbx":
			foundFbx = true
			if res.Type != "model" || res.FormatHint != "fbx" {
				t.Errorf("fbx classified incorrectly: %+v", res)
			}
		case "res/shader.shader":
			foundShader = true
			if res.Type != "shader" {
				t.Errorf("shader classified incorrectly: %+v", res)
			}
		case "res/script.lua":
			foundLua = true
			if res.Type != "script" || res.FormatHint != "lua" {
				t.Errorf("lua classified incorrectly: %+v", res)
			}
		case "res/large.unknown":
			foundUnknown = true
			if res.Type != "unknown" {
				t.Errorf("large unknown resource classified incorrectly: %+v", res)
			}
		case "content.uasset":
			foundUasset = true
			if res.Type != "unreal-asset" {
				t.Errorf("unreal uasset classified incorrectly: %+v", res)
			}
		}
	}

	if !foundPng || !foundOgg || !foundFbx || !foundShader || !foundLua || !foundUnknown || !foundUasset {
		t.Error("Missing classified resources")
	}

	// Verify hidden payloads
	foundDex := false
	foundSo := false
	foundElf := false
	foundPe := false

	for _, p := range r.HiddenPayloads {
		switch p.Type {
		case "dex":
			foundDex = true
		case "so":
			foundSo = true
		case "elf":
			foundElf = true
		case "pe":
			foundPe = true
		}
	}

	if !foundDex || !foundSo || !foundElf || !foundPe {
		t.Errorf("Missing hidden payloads: dex=%v, so=%v, elf=%v, pe=%v", foundDex, foundSo, foundElf, foundPe)
	}

	// Verify strings and URLs
	if len(r.SuspiciousURLs) == 0 || r.SuspiciousURLs[0] != "https://suspicious-c2.org/api" {
		t.Errorf("Expected suspicious URL 'https://suspicious-c2.org/api', got %v", r.SuspiciousURLs)
	}
	if len(r.TrackerHints) == 0 {
		t.Error("Expected tracker hints, got none")
	}
}

func TestAnalyzeDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a dummy obb file
	obbPath := filepath.Join(tmpDir, "test.obb")
	err := os.WriteFile(obbPath, []byte("UnityFS"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	cfg := DefaultAnalyzerConfig()
	cfg.OutputDir = filepath.Join(tmpDir, "out")
	cfg.MaxFileSizeMB = 1 // 1 MB limit

	ctx := context.Background()
	results, err := AnalyzeDirectory(ctx, tmpDir, cfg)
	if err != nil {
		t.Fatal(err)
	}

	if len(results) != 1 {
		t.Errorf("Expected 1 scan result, got %d", len(results))
	}

	// Check if report got written
	reportPath := filepath.Join(cfg.OutputDir, "OBB_REPORT.json")
	if _, err := os.Stat(reportPath); os.IsNotExist(err) {
		t.Error("Expected OBB_REPORT.json to exist")
	}

	// Test with cancelled context
	ctxCancel, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = AnalyzeDirectory(ctxCancel, tmpDir, cfg)
	if err == nil {
		t.Error("Expected cancelled context error, got nil")
	}
}

func TestUnrealPakEdgeCases(t *testing.T) {
	// 1. FPakInfo version 4 header size and decrypt
	tocBuf := new(bytes.Buffer)

	// Negative mount point length (UTF-16 mount point)
	mountPoint := []uint16{'/', '/', 0}
	binary.Write(tocBuf, binary.LittleEndian, int32(-len(mountPoint)))
	for _, c := range mountPoint {
		binary.Write(tocBuf, binary.LittleEndian, c)
	}

	// Count of entries (uint32)
	binary.Write(tocBuf, binary.LittleEndian, uint32(1))

	// Entry with negative string length (UTF-16 string)
	entryName := []uint16{'u', 't', 'f', '1', '6', 0}
	binary.Write(tocBuf, binary.LittleEndian, int32(-len(entryName)))
	for _, c := range entryName {
		binary.Write(tocBuf, binary.LittleEndian, c)
	}
	binary.Write(tocBuf, binary.LittleEndian, uint64(100)) // Offset
	binary.Write(tocBuf, binary.LittleEndian, uint64(200)) // Size
	binary.Write(tocBuf, binary.LittleEndian, uint64(200)) // UncompressedSize
	binary.Write(tocBuf, binary.LittleEndian, uint32(1))   // CompressionMethod (v3 compression method block)
	tocBuf.Write(make([]byte, 20))                         // Hash
	binary.Write(tocBuf, binary.LittleEndian, uint32(1))   // BlockCount
	tocBuf.Write(make([]byte, 16))                         // Block offset+size
	binary.Write(tocBuf, binary.LittleEndian, uint32(0))   // Flags for version >= 2

	tocBytes := tocBuf.Bytes()

	pakBuf := new(bytes.Buffer)
	pakBuf.Write(make([]byte, 1000)) // padding
	indexOffset := uint64(pakBuf.Len())
	pakBuf.Write(tocBytes)
	indexSize := uint64(pakBuf.Len()) - indexOffset

	// Write FPakInfo at EOF (Version 4)
	binary.Write(pakBuf, binary.LittleEndian, uint32(pakMagic))
	binary.Write(pakBuf, binary.LittleEndian, uint32(4)) // Version 4
	binary.Write(pakBuf, binary.LittleEndian, indexOffset)
	binary.Write(pakBuf, binary.LittleEndian, indexSize)
	pakBuf.Write(make([]byte, 20))                      // Hash
	binary.Write(pakBuf, binary.LittleEndian, uint8(0)) // Encrypted = false
	// Add padding for Version 4 compression method names
	pakBuf.Write(make([]byte, 1024+16))

	// Test readPakInfo & readPakTOC
	data := pakBuf.Bytes()
	info, err := readPakInfo(data)
	if err != nil {
		t.Fatal(err)
	}
	if info.Version != 4 {
		t.Errorf("Expected version 4, got %d", info.Version)
	}

	entries, err := readPakTOC(data, info)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name != "utf16" {
		t.Errorf("Expected entry name 'utf16', got %v", entries)
	}

	// Test readPakInfo error cases
	_, err = readPakInfo(make([]byte, 10))
	if err == nil {
		t.Error("Expected error for too small pak, got nil")
	}

	_, err = readPakInfo(make([]byte, 100))
	if err == nil {
		t.Error("Expected error for missing pak magic, got nil")
	}

	// Test readPakTOC out of bounds
	info.IndexOffset = 50000
	_, err = readPakTOC(data, info)
	if err == nil {
		t.Error("Expected error for out of bounds index, got nil")
	}
}
