package experimental

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestMachOModule_NoMachOInTreeLocal(t *testing.T) {
	tmp, err := os.MkdirTemp("", "macho-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmp)

	// TargetDir = "" -> Skipped
	m := NewMachOModule()
	res, err := m.Run(context.Background(), Input{TargetDir: ""})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Skipped {
		t.Error("expected module to be skipped when TargetDir is empty")
	}

	// No candidates
	res2, err := m.Run(context.Background(), Input{TargetDir: tmp})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res2.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(res2.Findings))
	}
}

func TestMachOModule_WithMockMachO(t *testing.T) {
	tmp, err := os.MkdirTemp("", "macho-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmp)

	// 1. Build a minimal 64-bit Little Endian Mach-O file
	// MachO Header (32 bytes)
	mockMachO := make([]byte, 200)
	binary.LittleEndian.PutUint32(mockMachO[0:4], machoMagic64)
	binary.LittleEndian.PutUint32(mockMachO[4:8], 16777228) // CPU_TYPE_ARM64
	binary.LittleEndian.PutUint32(mockMachO[8:12], 0)       // CPU_SUBTYPE
	binary.LittleEndian.PutUint32(mockMachO[12:16], 2)      // MH_EXECUTE (not PIE)
	binary.LittleEndian.PutUint32(mockMachO[16:20], 3)      // NCmds = 3
	binary.LittleEndian.PutUint32(mockMachO[20:24], 64)     // SizeCmds = 64
	binary.LittleEndian.PutUint32(mockMachO[24:28], 0)      // Flags (not PIE)

	// Load command 1: lcVersionMinIOS (size 16)
	binary.LittleEndian.PutUint32(mockMachO[32:36], lcVersionMinIOS)
	binary.LittleEndian.PutUint32(mockMachO[36:40], 16)
	binary.LittleEndian.PutUint32(mockMachO[40:44], 13<<16|2<<8|0) // Version 13.2.0
	binary.LittleEndian.PutUint32(mockMachO[44:48], 13<<16|2<<8|0) // SDK 13.2.0

	// Load command 2: lcLoadDylib (size 24)
	binary.LittleEndian.PutUint32(mockMachO[48:52], lcLoadDylib)
	binary.LittleEndian.PutUint32(mockMachO[52:56], 24)
	binary.LittleEndian.PutUint32(mockMachO[56:60], 12) // Name offset = 12
	copy(mockMachO[60:72], "libtest.dylib\x00")

	// Load command 3: lcEncryptionInfo (size 20)
	binary.LittleEndian.PutUint32(mockMachO[72:76], lcEncryptionInfo)
	binary.LittleEndian.PutUint32(mockMachO[76:80], 20)
	binary.LittleEndian.PutUint32(mockMachO[80:84], 100) // cryptoff
	binary.LittleEndian.PutUint32(mockMachO[84:88], 50)  // cryptsize
	binary.LittleEndian.PutUint32(mockMachO[88:92], 0)   // cryptid = 0 (decrypted FairPlay metadata)

	// Add a jailbreak hint in the remaining bytes
	copy(mockMachO[120:], "/Applications/Cydia.app\x00")

	// Write mock binary (.dylib suffix so walk detects it)
	binPath := filepath.Join(tmp, "TestApp.app/TestApp")
	if err := os.MkdirAll(filepath.Dir(binPath), 0o755); err != nil {
		t.Fatalf("failed to create dir: %v", err)
	}
	if err := os.WriteFile(binPath, mockMachO, 0o755); err != nil {
		t.Fatalf("failed to write mock Mach-O: %v", err)
	}

	m := NewMachOModule()
	res, err := m.Run(context.Background(), Input{TargetDir: tmp})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	var parsed bool
	var hasNoPie bool
	var hasDecryptedText bool
	var hasNoCodesign bool
	var hasJailbreakDetect bool

	for _, f := range res.Findings {
		switch f.ID {
		case "macho-overview":
			parsed = true
		case "macho-no-pie":
			hasNoPie = true
		case "macho-decrypted-text":
			hasDecryptedText = true
		case "macho-no-codesign":
			hasNoCodesign = true
		case "macho-jailbreak-detect":
			hasJailbreakDetect = true
		}
	}

	if !parsed {
		t.Error("expected macho-overview finding")
	}
	if !hasNoPie {
		t.Error("expected macho-no-pie finding")
	}
	if !hasDecryptedText {
		t.Error("expected macho-decrypted-text finding")
	}
	if !hasNoCodesign {
		t.Error("expected macho-no-codesign finding")
	}
	if !hasJailbreakDetect {
		t.Error("expected macho-jailbreak-detect finding")
	}
}

func TestMachOModule_WithFatBinary(t *testing.T) {
	tmp, err := os.MkdirTemp("", "macho-test-fat")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmp)

	// Build thin binary (NCmds = 1)
	thin := make([]byte, 100)
	binary.LittleEndian.PutUint32(thin[0:4], machoMagic64) // Little Endian magic
	binary.LittleEndian.PutUint32(thin[4:8], 16777228)
	binary.LittleEndian.PutUint32(thin[8:12], 0)
	binary.LittleEndian.PutUint32(thin[12:16], 2)
	binary.LittleEndian.PutUint32(thin[16:20], 1)
	binary.LittleEndian.PutUint32(thin[20:24], 16)
	binary.LittleEndian.PutUint32(thin[24:28], flagPIE) // PIE = true
	// LC 1: lcMain (size 8) -> HasMain = true
	binary.LittleEndian.PutUint32(thin[32:36], lcMain)
	binary.LittleEndian.PutUint32(thin[36:40], 8)

	// Build Fat Binary (BigEndian)
	fat := make([]byte, 32+len(thin))
	binary.BigEndian.PutUint32(fat[0:4], machoFatMagicCigam)
	binary.BigEndian.PutUint32(fat[4:8], 1)         // Count = 1
	binary.BigEndian.PutUint32(fat[8:12], 16777228) // CPU
	binary.BigEndian.PutUint32(fat[12:16], 0)
	binary.BigEndian.PutUint32(fat[16:20], 32) // Offset = 32
	binary.BigEndian.PutUint32(fat[20:24], uint32(len(thin)))
	binary.BigEndian.PutUint32(fat[24:28], 0)

	copy(fat[32:], thin)

	binPath := filepath.Join(tmp, "TestApp.dylib")
	if err := os.WriteFile(binPath, fat, 0o755); err != nil {
		t.Fatalf("failed to write mock fat Mach-O: %v", err)
	}

	m := NewMachOModule()
	res, err := m.Run(context.Background(), Input{TargetDir: tmp})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	found := false
	for _, f := range res.Findings {
		if f.ID == "macho-overview" {
			found = true
		}
	}
	if !found {
		t.Error("expected macho-overview for fat binary")
	}
}
