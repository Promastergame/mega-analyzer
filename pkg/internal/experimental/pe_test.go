package experimental

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// Helper to construct in-memory mock PE file bytes
func buildMockPE(is64Bit bool, dllChars uint16, hasSignature bool, hasLoadConfig bool, configSecCookie uint64, configSEHTable uint32) []byte {
	data := make([]byte, 2048)
	// DOS header magic
	copy(data[0:2], dosMagic)
	// e_lfanew
	elfanew := uint32(0x40)
	binary.LittleEndian.PutUint32(data[0x3C:0x40], elfanew)

	// PE Signature
	copy(data[elfanew:elfanew+4], peMagic)

	// COFF Header
	coffOff := elfanew + 4
	if is64Bit {
		binary.LittleEndian.PutUint16(data[coffOff:coffOff+2], 0x8664) // AMD64
	} else {
		binary.LittleEndian.PutUint16(data[coffOff:coffOff+2], 0x014C) // I386
	}
	binary.LittleEndian.PutUint16(data[coffOff+2:coffOff+4], 1) // 1 section

	var sizeOptHdr uint16
	if is64Bit {
		sizeOptHdr = 240 // 112 + 16 * 8
	} else {
		sizeOptHdr = 224 // 96 + 16 * 8
	}
	binary.LittleEndian.PutUint16(data[coffOff+16:coffOff+18], sizeOptHdr)

	// Optional Header
	optOff := coffOff + 20
	if is64Bit {
		binary.LittleEndian.PutUint16(data[optOff:optOff+2], 0x020B) // PE32+
		binary.LittleEndian.PutUint64(data[optOff+24:optOff+32], 0x140000000)
		binary.LittleEndian.PutUint16(data[optOff+70:optOff+72], dllChars)
		binary.LittleEndian.PutUint32(data[optOff+108:optOff+112], 16) // 16 directories
	} else {
		binary.LittleEndian.PutUint16(data[optOff:optOff+2], 0x010B) // PE32
		binary.LittleEndian.PutUint32(data[optOff+28:optOff+32], 0x400000)
		binary.LittleEndian.PutUint16(data[optOff+70:optOff+72], dllChars)
		binary.LittleEndian.PutUint32(data[optOff+92:optOff+96], 16) // 16 directories
	}

	var dirOff uint32
	if is64Bit {
		dirOff = optOff + 112
	} else {
		dirOff = optOff + 96
	}

	// Section Header: map RVA 0x1000 to raw offset 0x300
	secOff := optOff + uint32(sizeOptHdr)
	copy(data[secOff:secOff+8], ".text")
	binary.LittleEndian.PutUint32(data[secOff+8:secOff+12], 0x1000)  // VirtualSize
	binary.LittleEndian.PutUint32(data[secOff+12:secOff+16], 0x1000) // VirtualAddress
	binary.LittleEndian.PutUint32(data[secOff+16:secOff+20], 0x200)  // SizeOfRawData
	binary.LittleEndian.PutUint32(data[secOff+20:secOff+24], 0x300)  // PointerToRawData

	// Security Directory (Directory 4)
	if hasSignature {
		secDirEntryOff := dirOff + (4 * 8)
		binary.LittleEndian.PutUint32(data[secDirEntryOff:secDirEntryOff+4], 0x600)
		binary.LittleEndian.PutUint32(data[secDirEntryOff+4:secDirEntryOff+8], 0x10)
		copy(data[0x600:0x610], "MOCK_SIGNATURE")
	}

	// Base Relocation Directory (Directory 5) — RVA 0x1100 → raw 0x400.
	// Effective ASLR applies DYNAMICBASE through a relocation table, so
	// hardening-positive fixtures must ship one.
	relocEntryOff := dirOff + (5 * 8)
	binary.LittleEndian.PutUint32(data[relocEntryOff:relocEntryOff+4], 0x1100)
	binary.LittleEndian.PutUint32(data[relocEntryOff+4:relocEntryOff+8], 12)
	binary.LittleEndian.PutUint32(data[0x400:0x404], 0x1000) // PageRVA
	binary.LittleEndian.PutUint32(data[0x404:0x408], 12)     // BlockSize (one entry)
	binary.LittleEndian.PutUint16(data[0x408:0x40A], 0x3000) // HIGHLOW entry

	// Load Config Directory (Directory 10)
	if hasLoadConfig {
		loadConfigEntryOff := dirOff + (10 * 8)
		binary.LittleEndian.PutUint32(data[loadConfigEntryOff:loadConfigEntryOff+4], 0x1020)
		binary.LittleEndian.PutUint32(data[loadConfigEntryOff+4:loadConfigEntryOff+8], 148)

		// RVA 0x1020 is at raw file offset 0x320
		loadConfigOff := uint32(0x320)
		binary.LittleEndian.PutUint32(data[loadConfigOff:loadConfigOff+4], 148) // Struct size

		if is64Bit {
			binary.LittleEndian.PutUint64(data[loadConfigOff+88:loadConfigOff+96], configSecCookie)
			binary.LittleEndian.PutUint64(data[loadConfigOff+112:], 0x140001180)
			binary.LittleEndian.PutUint32(data[loadConfigOff+144:], 0x100) // GuardFlags: CF instrumented
		} else {
			binary.LittleEndian.PutUint32(data[loadConfigOff+60:loadConfigOff+64], uint32(configSecCookie))
			binary.LittleEndian.PutUint32(data[loadConfigOff+64:loadConfigOff+68], configSEHTable)
			if configSEHTable != 0 {
				binary.LittleEndian.PutUint32(data[loadConfigOff+68:loadConfigOff+72], 1)
			}
			binary.LittleEndian.PutUint32(data[loadConfigOff+72:], 0x401180)
			binary.LittleEndian.PutUint32(data[loadConfigOff+88:], 0x100) // GuardFlags
		}
	}

	return data
}

func TestPEModule_NoPEInTree(t *testing.T) {
	tmp, err := os.MkdirTemp("", "pe-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmp)

	if err := os.WriteFile(filepath.Join(tmp, "dummy.txt"), []byte("this is not a PE binary"), 0o644); err != nil {
		t.Fatalf("failed to write dummy: %v", err)
	}

	m := NewPEModule()
	res, err := m.Run(context.Background(), Input{TargetDir: tmp})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(res.Findings))
	}
}

func TestPEModule_AnalyzePE32Plus(t *testing.T) {
	tmp := testTempDir(t)

	// Build 64-bit PE with:
	// - DllCharacteristics: ASLR (0x0040) + DEP (0x0100) + CFG (0x4000)
	// - HighEntropyASLR (0x0020) disabled
	// - Invalid mock certificate (must not be treated as a verified signature)
	// - Load Config with Security Cookie (GS) active
	dllChars := uint16(0x0040 | 0x0100 | 0x4000)
	mockBytes := buildMockPE(true, dllChars, true, true, 0x1400010a0, 0)

	mockPath := filepath.Join(tmp, "binary_x64.exe")
	if err := os.WriteFile(mockPath, mockBytes, 0o755); err != nil {
		t.Fatalf("failed to write mock binary: %v", err)
	}

	m := NewPEModule()
	res, err := m.Run(context.Background(), Input{TargetDir: tmp, OutputDir: tmp})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	// We expect findings:
	// - pe-overview
	// - pe-no-high-entropy-aslr (since 0x0020 was omitted)
	var foundOverview, foundHighEntropy bool
	for _, f := range res.Findings {
		switch f.ID {
		case "pe-overview":
			foundOverview = true
		case "pe-no-high-entropy-aslr":
			foundHighEntropy = true
		case "pe-no-aslr", "pe-no-dep", "pe-no-cfg", "pe-no-stack-cookie", "pe-unsigned":
			t.Errorf("unexpected finding: %s", f.ID)
		}
	}

	if !foundOverview {
		t.Error("expected pe-overview finding")
	}
	if !foundHighEntropy {
		t.Error("expected pe-no-high-entropy-aslr finding")
	}
}

func TestPEModule_AnalyzePE32_Vulnerable(t *testing.T) {
	tmp := testTempDir(t)

	// Build 32-bit PE with NO ASLR, NO DEP, NO CFG, NO signature, NO SafeSEH, NO GS
	mockBytes := buildMockPE(false, 0, false, false, 0, 0)

	mockPath := filepath.Join(tmp, "binary_x86.dll")
	if err := os.WriteFile(mockPath, mockBytes, 0o755); err != nil {
		t.Fatalf("failed to write mock binary: %v", err)
	}

	m := NewPEModule()
	res, err := m.Run(context.Background(), Input{TargetDir: tmp, OutputDir: tmp})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	var hasASLR, hasDEP, hasCFG, hasSafeSEH, hasCookie, hasSig bool
	for _, f := range res.Findings {
		switch f.ID {
		case "pe-no-aslr":
			hasASLR = true
		case "pe-no-dep":
			hasDEP = true
		case "pe-no-cfg":
			hasCFG = true
		case "pe-no-safeseh":
			hasSafeSEH = true
		case "pe-stack-cookie-unknown":
			hasCookie = true
		case "pe-unsigned":
			hasSig = true
		}
	}

	if !hasASLR {
		t.Error("expected pe-no-aslr finding")
	}
	if !hasDEP {
		t.Error("expected pe-no-dep finding")
	}
	if !hasCFG {
		t.Error("expected pe-no-cfg finding")
	}
	if !hasSafeSEH {
		t.Error("expected pe-no-safeseh finding")
	}
	if !hasCookie {
		t.Error("expected pe-stack-cookie-unknown finding")
	}
	if !hasSig {
		t.Error("expected pe-unsigned finding")
	}
}
