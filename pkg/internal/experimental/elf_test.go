package experimental

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestIsInsecurePath(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{".", true},
		{"/usr/lib", false},
		{"/tmp", true},
		{"/tmp/libs", true},
		{"/data/local/tmp", true},
		{"/data/app/libs", false},
		{"/usr/lib:.", true},
		{"/usr/lib:/tmp", true},
		{"", true},
	}
	for _, tc := range cases {
		if got := isInsecurePath(tc.path); got != tc.want {
			t.Errorf("isInsecurePath(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestELFHeaderParsing(t *testing.T) {
	// Build a mock 64-bit Little Endian ELF Header
	mockHeader := make([]byte, 64)
	copy(mockHeader[:4], elfMagic)
	mockHeader[4] = 2 // 64-bit
	mockHeader[5] = 1 // Little Endian
	// e_type = ET_DYN (3)
	mockHeader[16] = 3
	mockHeader[17] = 0
	// e_machine = AArch64 (183 / 0xB7)
	mockHeader[18] = 0xB7
	mockHeader[19] = 0
	// e_phoff = 64
	mockHeader[32] = 64
	mockHeader[33] = 0
	// e_phentsize = 56
	mockHeader[54] = 56
	mockHeader[55] = 0
	// e_phnum = 2
	mockHeader[56] = 2
	mockHeader[57] = 0

	hdr, err := parseELFHeader(mockHeader)
	if err != nil {
		t.Fatalf("unexpected parsing error: %v", err)
	}
	if hdr.Class != 2 {
		t.Errorf("class = %d, want 2", hdr.Class)
	}
	if hdr.Data != 1 {
		t.Errorf("data = %d, want 1", hdr.Data)
	}
	if hdr.Type != 3 {
		t.Errorf("type = %d, want 3", hdr.Type)
	}
	if hdr.Machine != 0xB7 {
		t.Errorf("machine = 0x%x, want 0xB7", hdr.Machine)
	}
	if hdr.PhOff != 64 {
		t.Errorf("phoff = %d, want 64", hdr.PhOff)
	}
	if hdr.PhNum != 2 {
		t.Errorf("phnum = %d, want 2", hdr.PhNum)
	}
}

func TestELFModule_NoELFInTree(t *testing.T) {
	tmp, err := os.MkdirTemp("", "elf-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmp)

	// Create a dummy non-ELF file
	if err := os.WriteFile(filepath.Join(tmp, "dummy.txt"), []byte("this is not an ELF"), 0o644); err != nil {
		t.Fatalf("failed to write dummy file: %v", err)
	}

	m := NewELFModule()
	res, err := m.Run(context.Background(), Input{TargetDir: tmp})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings for non-ELF target, got %d", len(res.Findings))
	}
}

func TestELFModule_WithMockELF(t *testing.T) {
	tmp, err := os.MkdirTemp("", "elf-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmp)

	// Build a minimal 64-bit Little Endian ELF with missing NX and RELRO
	mockELF := make([]byte, 200)
	copy(mockELF[:4], elfMagic)
	mockELF[4] = 2 // 64-bit
	mockELF[5] = 1 // Little Endian
	// e_type = ET_EXEC (2) -> Lacks PIE!
	mockELF[16] = 2
	mockELF[17] = 0
	// e_phoff = 64
	mockELF[32] = 64
	mockELF[33] = 0
	// e_phentsize = 56
	mockELF[54] = 56
	mockELF[55] = 0
	// e_phnum = 1
	mockELF[56] = 1
	mockELF[57] = 0

	// Program Header (offset 64): PT_GNU_STACK (0x6474e551) with PF_X (1) -> Executable stack!
	// p_type = 0x6474e551
	binary.LittleEndian.PutUint32(mockELF[64:], 0x6474e551)
	// p_flags = 1 (PF_X)
	binary.LittleEndian.PutUint32(mockELF[68:], 1)

	// Write mock file
	mockPath := filepath.Join(tmp, "libtest.so")
	if err := os.WriteFile(mockPath, mockELF, 0o755); err != nil {
		t.Fatalf("failed to write mock ELF: %v", err)
	}

	m := NewELFModule()
	res, err := m.Run(context.Background(), Input{TargetDir: tmp, OutputDir: tmp})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	// We expect multiple findings:
	// - elf-overview
	// - elf-no-pie
	// - elf-executable-stack
	// - elf-no-relro
	// - elf-no-canary
	var pie, nx, relro, canary bool
	for _, f := range res.Findings {
		switch f.ID {
		case "elf-no-pie":
			pie = true
		case "elf-executable-stack":
			nx = true
		case "elf-no-relro":
			relro = true
		case "elf-no-canary":
			canary = true
		}
	}

	if !pie {
		t.Error("expected elf-no-pie finding")
	}
	if !nx {
		t.Error("expected elf-executable-stack finding")
	}
	if !relro {
		t.Error("expected elf-no-relro finding")
	}
	if !canary {
		t.Error("expected elf-no-canary finding")
	}
}
